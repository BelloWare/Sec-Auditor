"""Native ACK reads through operator-registered, TLS-verified, read-only connections.

RRSA authenticates Alibaba APIs. A separate projected Kubernetes service-account
token authenticates these Kubernetes requests; neither kubeconfigs nor cluster
administrator certificates are fetched from Alibaba APIs.
"""

import asyncio
import ipaddress
import re
import ssl
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from sec_auditor.config import Settings
from sec_auditor.providers.kubernetes import (
    KubernetesProvider,
    KubernetesReadError,
    _Connection,
)

_CLUSTER = re.compile(
    r"accounts/(?P<account>[0-9]{8,32})/regions/(?P<region>[a-z][a-z0-9-]{1,63})/clusters/(?P<id>[a-zA-Z0-9][a-zA-Z0-9_-]{0,127})"
)


def cluster_account(cluster: str) -> tuple[str, str]:
    match = _CLUSTER.fullmatch(cluster)
    if not match:
        raise ValueError("ACK cluster must be accounts/ACCOUNT/regions/REGION/clusters/ID")
    return match["account"], match["region"]


def validate_server(server: str) -> str:
    try:
        parsed = urlsplit(server)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or parsed.port not in (None, 443, 6443)
            or any(ord(char) < 33 or char in "\\%" for char in server)
        ):
            raise ValueError
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host):
                raise ValueError from None
            if host.lower() in {
                "localhost",
                "metadata.google.internal",
                "metadata",
            } or host.lower().endswith(".localhost"):
                raise ValueError from None
        else:
            if (
                address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or str(address) == "100.100.100.200"
            ):
                raise ValueError
    except ValueError as exc:
        raise ValueError(
            "Registered Kubernetes server must be a trusted HTTPS control-plane endpoint"
        ) from exc
    return server.rstrip("/")


def _read_file(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as stream:
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError
        return value.decode("ascii").strip()
    except (OSError, ValueError, UnicodeError) as exc:
        raise KubernetesReadError(
            "INVALID_CLUSTER_CREDENTIAL", "Could not load the registered Kubernetes credential file"
        ) from exc


class RegisteredKubernetesProvider(KubernetesProvider):
    """Shares the same kind allowlist, pagination, byte bounds and projection as GKE."""

    def __init__(
        self, settings: Settings, *, http_transport: httpx.AsyncBaseTransport | None = None
    ):
        super().__init__(
            None, timeout=settings.request_timeout, concurrency=settings.per_api_concurrency
        )
        self.settings = settings
        self._http_transport = http_transport
        for connection in settings.alicloud_kubernetes_clusters.values():
            validate_server(connection.server)

    def _cluster_identity(self, cluster: str) -> tuple[None, str, str, str]:
        account, region = cluster_account(cluster)
        if cluster not in self.settings.alicloud_kubernetes_clusters:
            raise ValueError("ACK cluster is not registered by the operator")
        return None, account, region, "ack"

    @asynccontextmanager
    async def _connection(self, cluster: str):
        self._cluster_identity(cluster)
        if self._closed:
            raise KubernetesReadError("PROVIDER_CLOSED", "Kubernetes provider has shut down")
        configured = self.settings.alicloud_kubernetes_clusters[cluster]
        certificate = await asyncio.to_thread(_read_file, configured.ca_file, 192 * 1024)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cadata=certificate)
        except (ssl.SSLError, ValueError) as exc:
            raise KubernetesReadError(
                "INVALID_CLUSTER_CA", "The registered cluster CA is invalid"
            ) from exc
        # Reopen credentials each request so projected token/CA rotation is observed.
        async with httpx.AsyncClient(
            base_url=validate_server(configured.server),
            verify=context,
            timeout=self._timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._http_transport,
        ) as client:
            yield _Connection(
                client, "registered", time.monotonic(), token_file=configured.token_file
            )

    async def _access_token(self, connection: _Connection, refresh: bool) -> str:
        token = await asyncio.to_thread(_read_file, connection.token_file, 16384)
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise KubernetesReadError(
                "INVALID_CLUSTER_CREDENTIAL",
                "Expected a projected Kubernetes service-account token",
            )
        return token
