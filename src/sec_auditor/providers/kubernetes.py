"""Read selected Kubernetes collections using the GKE workload's Google identity.

The server discovers control-plane endpoints through the GKE API. Callers never
provide URLs, paths, kubeconfig files, credentials, verbs, or arbitrary resource
types. These records are INTERNAL evidence; the service's projection layer must
filter them before returning them to an agent.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import json
import random
import re
import ssl
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.transport import CloudAPIError

if TYPE_CHECKING:
    from sec_auditor.transport import GoogleRestClient

_PROJECT = r"(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})"
_CLUSTER = re.compile(
    rf"projects/(?P<project>{_PROJECT})/locations/(?P<location>[a-z][a-z0-9-]{{0,62}})"
    r"/clusters/(?P<cluster>[a-z](?:[a-z0-9-]{0,38}[a-z0-9])?)"
)
_NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DNS_ENDPOINT = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+gke\.goog")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_CONTINUE_BYTES = 16 * 1024
_CONFIG_TTL = 300.0
_TRANSIENT_CODES = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class KubernetesKind:
    """An audited mapping to a single Kubernetes collection endpoint."""

    kind: str
    api: str
    plural: str
    namespaced: bool


_KINDS = (
    KubernetesKind("Pod", "/api/v1", "pods", True),
    KubernetesKind("Namespace", "/api/v1", "namespaces", False),
    KubernetesKind("Node", "/api/v1", "nodes", False),
    KubernetesKind("Service", "/api/v1", "services", True),
    KubernetesKind("ServiceAccount", "/api/v1", "serviceaccounts", True),
    KubernetesKind("PersistentVolume", "/api/v1", "persistentvolumes", False),
    KubernetesKind("PersistentVolumeClaim", "/api/v1", "persistentvolumeclaims", True),
    KubernetesKind("ResourceQuota", "/api/v1", "resourcequotas", True),
    KubernetesKind("LimitRange", "/api/v1", "limitranges", True),
    KubernetesKind("Deployment", "/apis/apps/v1", "deployments", True),
    KubernetesKind("DaemonSet", "/apis/apps/v1", "daemonsets", True),
    KubernetesKind("StatefulSet", "/apis/apps/v1", "statefulsets", True),
    KubernetesKind("ReplicaSet", "/apis/apps/v1", "replicasets", True),
    KubernetesKind("Job", "/apis/batch/v1", "jobs", True),
    KubernetesKind("CronJob", "/apis/batch/v1", "cronjobs", True),
    KubernetesKind("NetworkPolicy", "/apis/networking.k8s.io/v1", "networkpolicies", True),
    KubernetesKind("Ingress", "/apis/networking.k8s.io/v1", "ingresses", True),
    KubernetesKind("IngressClass", "/apis/networking.k8s.io/v1", "ingressclasses", False),
    KubernetesKind("Role", "/apis/rbac.authorization.k8s.io/v1", "roles", True),
    KubernetesKind("RoleBinding", "/apis/rbac.authorization.k8s.io/v1", "rolebindings", True),
    KubernetesKind("ClusterRole", "/apis/rbac.authorization.k8s.io/v1", "clusterroles", False),
    KubernetesKind(
        "ClusterRoleBinding", "/apis/rbac.authorization.k8s.io/v1", "clusterrolebindings", False
    ),
    KubernetesKind("StorageClass", "/apis/storage.k8s.io/v1", "storageclasses", False),
    KubernetesKind("CSIDriver", "/apis/storage.k8s.io/v1", "csidrivers", False),
    KubernetesKind("CSINode", "/apis/storage.k8s.io/v1", "csinodes", False),
    KubernetesKind("PodDisruptionBudget", "/apis/policy/v1", "poddisruptionbudgets", True),
    KubernetesKind("RuntimeClass", "/apis/node.k8s.io/v1", "runtimeclasses", False),
    KubernetesKind(
        "ValidatingWebhookConfiguration",
        "/apis/admissionregistration.k8s.io/v1",
        "validatingwebhookconfigurations",
        False,
    ),
    KubernetesKind(
        "MutatingWebhookConfiguration",
        "/apis/admissionregistration.k8s.io/v1",
        "mutatingwebhookconfigurations",
        False,
    ),
)
KUBERNETES_KINDS = {item.kind: item for item in _KINDS}


class KubernetesReadError(Exception):
    """A safe, non-payload-bearing explanation of a collection failure."""

    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass
class _Connection:
    client: httpx.AsyncClient
    endpoint_type: str
    discovered_at: float
    users: int = 0
    token_file: Path | None = None


def cluster_project(cluster: str) -> str:
    """Validate a canonical GKE cluster reference and extract its project."""
    match = _CLUSTER.fullmatch(cluster)
    if not match:
        raise ValueError("cluster must be projects/PROJECT/locations/LOCATION/clusters/NAME")
    return match.group("project")


def normalize_kind(kind: str) -> str:
    """Accept the advertised canonical kind or its provider-qualified spelling."""
    normalized = kind.removeprefix("k8s.")
    if normalized not in KUBERNETES_KINDS:
        raise ValueError("Unsupported Kubernetes kind; use the advertised capabilities")
    return normalized


def _validated_host(endpoint: Any, *, dns: bool) -> str:
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 253:
        raise KubernetesReadError("INVALID_ENDPOINT", "GKE returned an invalid endpoint")
    # No scheme, path, userinfo, query, fragment, port, zone ID, or encoded host.
    if any(char in endpoint for char in "/\\@?#%[]") or any(char.isspace() for char in endpoint):
        raise KubernetesReadError("INVALID_ENDPOINT", "GKE returned an invalid endpoint")
    if dns:
        if not _DNS_ENDPOINT.fullmatch(endpoint):
            raise KubernetesReadError(
                "INVALID_ENDPOINT", "The discovered DNS endpoint is outside gke.goog"
            )
        return endpoint
    try:
        address = ipaddress.ip_address(endpoint)
    except ValueError as exc:
        raise KubernetesReadError("INVALID_ENDPOINT", "Expected a GKE IP endpoint") from exc
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address == ipaddress.ip_address("fd20:ce::254")
    ):
        raise KubernetesReadError("INVALID_ENDPOINT", "Unsafe control-plane endpoint address")
    return f"[{address}]" if address.version == 6 else str(address)


def _select_endpoint(config: dict[str, Any], preference: str) -> tuple[str, str]:
    endpoints = config.get("controlPlaneEndpointsConfig") or {}
    if not isinstance(endpoints, dict):
        raise KubernetesReadError("INVALID_RESPONSE", "Invalid GKE endpoint configuration")
    dns = endpoints.get("dnsEndpointConfig") or {}
    ip = endpoints.get("ipEndpointsConfig") or {}
    legacy = config.get("privateClusterConfig") or {}
    if not all(isinstance(value, dict) for value in [endpoints, dns, ip, legacy]):
        raise KubernetesReadError("INVALID_RESPONSE", "Invalid GKE endpoint configuration")

    dns_enabled = dns.get("allowExternalTraffic") is True
    if preference == "dns" or (preference == "auto" and dns_enabled and dns.get("endpoint")):
        if not dns_enabled:
            raise KubernetesReadError(
                "ENDPOINT_DISABLED", "User access to the DNS endpoint is disabled"
            )
        return _validated_host(dns.get("endpoint"), dns=True), "dns"

    if ip.get("enabled") is False:
        raise KubernetesReadError("ENDPOINT_DISABLED", "GKE IP endpoints are disabled")
    private = ip.get("privateEndpoint") or legacy.get("privateEndpoint")
    public = ip.get("publicEndpoint") or legacy.get("publicEndpoint")
    public_disabled = (
        ip.get("enablePublicEndpoint") is False or legacy.get("enablePrivateEndpoint") is True
    )

    if preference == "internal":
        endpoint, endpoint_type = private, "internal"
    elif preference == "external":
        if public_disabled:
            raise KubernetesReadError("ENDPOINT_DISABLED", "The public IP endpoint is disabled")
        endpoint, endpoint_type = public or config.get("endpoint"), "external"
    elif public_disabled:
        endpoint, endpoint_type = private, "internal"
    else:
        endpoint = config.get("endpoint") or private or public
        endpoint_type = "internal" if endpoint and endpoint == private else "ip"
    if not endpoint:
        raise KubernetesReadError(
            "ENDPOINT_UNAVAILABLE", "No enabled GKE endpoint matched the selection"
        )
    return _validated_host(endpoint, dns=False), endpoint_type


def _tls_context(config: dict[str, Any], endpoint_type: str) -> ssl.SSLContext:
    if endpoint_type == "dns":
        return ssl.create_default_context()
    auth = config.get("masterAuth")
    encoded = auth.get("clusterCaCertificate") if isinstance(auth, dict) else None
    if not isinstance(encoded, str) or not encoded or len(encoded) > 192 * 1024:
        raise KubernetesReadError(
            "INVALID_CLUSTER_CA", "An IP endpoint requires the GKE cluster CA"
        )
    try:
        certificate = base64.b64decode(encoded, validate=True).decode("ascii")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=certificate)
    except (ValueError, UnicodeError, binascii.Error, ssl.SSLError) as exc:
        raise KubernetesReadError("INVALID_CLUSTER_CA", "The GKE cluster CA is invalid") from exc
    return context


def _safe_item_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or len(value) > 512
        or any(char in value for char in "/\\?#")
        or any(ord(char) < 32 for char in value)
    ):
        raise KubernetesReadError("INVALID_RESPONSE", "Kubernetes returned an invalid object name")
    return value


class KubernetesProvider:
    """Restricted collection reads; authorization of target projects is upstream."""

    name = "kubernetes"

    def __init__(
        self,
        client: GoogleRestClient,
        *,
        endpoint_preference: str = "auto",
        timeout: float = 30,
        concurrency: int = 4,
    ):
        endpoint_preference = {"private": "internal", "public": "external"}.get(
            endpoint_preference, endpoint_preference
        )
        if endpoint_preference not in {"auto", "dns", "internal", "external"}:
            raise ValueError("endpoint_preference must be auto, dns, private, or public")
        if not 0 < timeout <= 120:
            raise ValueError("Kubernetes timeout must be greater than zero and at most 120 seconds")
        if isinstance(concurrency, bool) or not 1 <= concurrency <= 64:
            raise ValueError("Kubernetes concurrency must be between 1 and 64")
        self._google = client
        self._preference = endpoint_preference
        self._timeout = timeout
        self._concurrency = concurrency
        self._gate = asyncio.Semaphore(concurrency)
        self._pool_lock = asyncio.Lock()
        self._connections: OrderedDict[str, _Connection] = OrderedDict()
        self._pool_capacity = max(16, concurrency * 4)
        self._closed = False

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {
                "kind": f"k8s.{item.kind}",
                "namespaced": item.namespaced,
                "operations": ["list"],
                "api": item.api,
                "pagination": True,
            }
            for item in _KINDS
        ]

    def _cluster_identity(self, cluster: str) -> tuple[str | None, str | None, str, str]:
        return cluster_project(cluster), None, cluster.split("/")[3], "gke"

    async def _access_token(self, connection: _Connection, refresh: bool) -> str:
        return (
            await self._google.access_token(force_refresh=True)
            if refresh
            else await self._google.access_token()
        )

    @asynccontextmanager
    async def _connection(self, cluster: str) -> AsyncIterator[_Connection]:
        async with self._pool_lock:
            if self._closed:
                raise KubernetesReadError("PROVIDER_CLOSED", "Kubernetes provider has shut down")
            connection = self._connections.get(cluster)
            if connection and time.monotonic() - connection.discovered_at <= _CONFIG_TTL:
                connection.users += 1
                self._connections.move_to_end(cluster)
            else:
                connection = None

        if connection is None:
            config = await self._google.get(f"https://container.googleapis.com/v1/{cluster}")
            if not isinstance(config, dict):
                raise KubernetesReadError("INVALID_RESPONSE", "Invalid GKE cluster response")
            host, endpoint_type = _select_endpoint(config, self._preference)
            tls = _tls_context(config, endpoint_type)
            new_connection = _Connection(
                client=httpx.AsyncClient(
                    base_url=f"https://{host}",
                    verify=tls,
                    timeout=self._timeout,
                    follow_redirects=False,
                    trust_env=False,
                    limits=httpx.Limits(
                        max_connections=self._concurrency,
                        max_keepalive_connections=self._concurrency,
                    ),
                ),
                endpoint_type=endpoint_type,
                discovered_at=time.monotonic(),
            )
            to_close: list[httpx.AsyncClient] = []
            async with self._pool_lock:
                if self._closed:
                    to_close.append(new_connection.client)
                else:
                    existing = self._connections.get(cluster)
                    # Keep active borrowers on their verified connection until done.
                    if existing and (
                        existing.users or time.monotonic() - existing.discovered_at <= _CONFIG_TTL
                    ):
                        connection = existing
                        to_close.append(new_connection.client)
                    else:
                        if existing:
                            to_close.append(existing.client)
                            del self._connections[cluster]
                        while len(self._connections) >= self._pool_capacity:
                            idle = next(
                                (
                                    name
                                    for name, value in self._connections.items()
                                    if value.users == 0
                                ),
                                None,
                            )
                            if idle is None:
                                break
                            to_close.append(self._connections.pop(idle).client)
                        connection = new_connection
                        self._connections[cluster] = connection
                    connection.users += 1
                    self._connections.move_to_end(cluster)
            for item in to_close:
                await item.aclose()
            if self._closed:
                raise KubernetesReadError("PROVIDER_CLOSED", "Kubernetes provider has shut down")

        try:
            yield connection
        finally:
            async with self._pool_lock:
                connection.users -= 1

    async def _get_json(
        self, connection: _Connection, path: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        refresh_next = False
        refreshed = False
        for attempt in range(3):
            token = await self._access_token(connection, refresh_next)
            refresh_next = False
            async with connection.client.stream(
                "GET",
                path,
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                status = response.status_code
                if status == 401 and not refreshed and attempt < 2:
                    refresh_next = True
                    refreshed = True
                    continue
                if status in _TRANSIENT_CODES and attempt < 2:
                    try:
                        delay = min(2.0, max(0.0, float(response.headers.get("Retry-After", "0"))))
                    except ValueError:
                        delay = 0.0
                    await asyncio.sleep(max(delay, random.uniform(0.1, 0.25) * (2**attempt)))
                    continue
                if 300 <= status < 400:
                    raise KubernetesReadError(
                        "REDIRECT_BLOCKED", "Kubernetes endpoint attempted a redirect"
                    )
                if status != 200:
                    code = {
                        401: "UNAUTHENTICATED",
                        403: "PERMISSION_DENIED",
                        404: "NOT_FOUND_OR_UNSUPPORTED",
                        410: "CONTINUE_EXPIRED",
                        429: "RATE_LIMITED",
                    }.get(status, "KUBERNETES_API_ERROR")
                    raise KubernetesReadError(
                        code,
                        f"Kubernetes collection request failed (HTTP {status})",
                        retryable=status in _TRANSIENT_CODES or status == 410,
                    )
                if response.headers.get("Content-Encoding", "identity").lower() not in {
                    "",
                    "identity",
                }:
                    raise KubernetesReadError(
                        "UNSUPPORTED_ENCODING",
                        "Kubernetes ignored the uncompressed-response requirement",
                    )
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    size += len(chunk)
                    if size > _MAX_RESPONSE_BYTES:
                        raise KubernetesReadError(
                            "RESPONSE_TOO_LARGE",
                            "Kubernetes page exceeds the response budget; reduce page_size",
                        )
                    chunks.append(chunk)
                try:
                    document = json.loads(b"".join(chunks))
                except (ValueError, UnicodeError) as exc:
                    raise KubernetesReadError(
                        "INVALID_RESPONSE", "Kubernetes returned invalid JSON"
                    ) from exc
                if not isinstance(document, dict):
                    raise KubernetesReadError(
                        "INVALID_RESPONSE", "Kubernetes returned a non-object response"
                    )
                return document
        raise KubernetesReadError("KUBERNETES_API_ERROR", "Kubernetes retry budget exhausted")

    async def list_objects(
        self,
        cluster: str,
        kind: str,
        *,
        namespace: str | None = None,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        project, account_id, location, platform = self._cluster_identity(cluster)
        normalized = normalize_kind(kind)
        descriptor = KUBERNETES_KINDS[normalized]
        if namespace is not None and not _NAMESPACE.fullmatch(namespace):
            raise ValueError("namespace must be a Kubernetes DNS label")
        if namespace is not None and not descriptor.namespaced:
            raise ValueError("A namespace cannot be supplied for a cluster-scoped kind")
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 500
        ):
            raise ValueError("page_size must be an integer between 1 and 500")
        if page_token is not None and (
            not isinstance(page_token, str)
            or len(page_token.encode()) > _MAX_CONTINUE_BYTES
            or any(ord(char) < 32 for char in page_token)
        ):
            raise ValueError("Invalid Kubernetes continuation token")

        path = descriptor.api
        if namespace is not None:
            path += f"/namespaces/{namespace}"
        path += f"/{descriptor.plural}"
        params: dict[str, Any] = {"limit": page_size}
        if page_token:
            params["continue"] = page_token
        target = f"{cluster}{path}"

        try:
            async with (
                asyncio.timeout(self._timeout),
                self._gate,
                self._connection(cluster) as connection,
            ):
                response = await self._get_json(connection, path, params)
                if response.get("kind") not in {None, "List", f"{normalized}List"}:
                    raise KubernetesReadError(
                        "INVALID_RESPONSE", "Unexpected Kubernetes collection type"
                    )
                items, metadata = response.get("items"), response.get("metadata", {})
                if not isinstance(items, list) or not isinstance(metadata, dict):
                    raise KubernetesReadError(
                        "INVALID_RESPONSE", "Kubernetes collection fields are invalid"
                    )
                if len(items) > page_size:
                    raise KubernetesReadError(
                        "RESPONSE_TOO_LARGE", "Kubernetes did not honor the requested page limit"
                    )
                records: list[ResourceRecord] = []
                for item in items:
                    if not isinstance(item, dict) or item.get("kind") not in {None, normalized}:
                        raise KubernetesReadError(
                            "INVALID_RESPONSE", "Unexpected Kubernetes object type"
                        )
                    object_metadata = item.get("metadata")
                    if not isinstance(object_metadata, dict):
                        raise KubernetesReadError(
                            "INVALID_RESPONSE", "Kubernetes object metadata is missing"
                        )
                    name = _safe_item_name(object_metadata.get("name"))
                    object_namespace = object_metadata.get("namespace")
                    if descriptor.namespaced:
                        if not isinstance(object_namespace, str) or not _NAMESPACE.fullmatch(
                            object_namespace
                        ):
                            raise KubernetesReadError(
                                "INVALID_RESPONSE", "Invalid object namespace"
                            )
                        if namespace is not None and object_namespace != namespace:
                            raise KubernetesReadError(
                                "INVALID_RESPONSE", "Object outside requested namespace"
                            )
                    elif object_namespace is not None:
                        raise KubernetesReadError(
                            "INVALID_RESPONSE", "Unexpected namespace for cluster object"
                        )
                    suffix = f"namespaces/{object_namespace}/" if descriptor.namespaced else ""
                    suffix += f"{descriptor.plural}/{name}"
                    records.append(
                        ResourceRecord(
                            provider="kubernetes",
                            kind=f"k8s.{normalized}",
                            name=f"{cluster}/{suffix}",
                            project=project,
                            account_id=account_id,
                            location=location,
                            data=item,
                            source=f"{platform}://{cluster}{path}",
                        )
                    )
                continuation = metadata.get("continue") or None
                if continuation is not None and (
                    not isinstance(continuation, str)
                    or len(continuation.encode()) > _MAX_CONTINUE_BYTES
                ):
                    raise KubernetesReadError(
                        "INVALID_RESPONSE", "Invalid continuation token returned"
                    )
                return CollectionResult(
                    items=records,
                    next_page_token=continuation,
                    metadata={
                        "cluster": cluster,
                        "kind": f"k8s.{normalized}",
                        "namespace": namespace,
                        "resource_version": metadata.get("resourceVersion"),
                        "remaining_item_count": metadata.get("remainingItemCount"),
                        "endpoint_type": connection.endpoint_type,
                        "collection_complete": continuation is None,
                        "untrusted_content": True,
                    },
                )
        except KubernetesReadError as exc:
            return self._failure(target, exc.code, exc.message, exc.retryable)
        except CloudAPIError as exc:
            return self._failure(
                target,
                exc.code,
                "Could not read GKE cluster metadata or obtain Google credentials",
                exc.retryable,
            )
        except (TimeoutError, httpx.TimeoutException):
            return self._failure(
                target, "DEADLINE_EXCEEDED", "Kubernetes collection timed out", True
            )
        except httpx.TransportError:
            return self._failure(
                target,
                "NETWORK_OR_TLS_ERROR",
                "Could not reach and verify the Kubernetes control plane; check routing, endpoint policy, and TLS",
                True,
            )

    @staticmethod
    def _failure(target: str, code: str, message: str, retryable: bool = False) -> CollectionResult:
        return CollectionResult(
            errors=[
                CollectionError(target=target, code=code, message=message, retryable=retryable)
            ],
            metadata={"collection_complete": False},
        )

    async def aclose(self) -> None:
        async with self._pool_lock:
            self._closed = True
            clients = [connection.client for connection in self._connections.values()]
            self._connections.clear()
        for client in clients:
            await client.aclose()
