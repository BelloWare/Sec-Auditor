"""Security and integration contracts for the Kubernetes API adapter."""

from __future__ import annotations

import asyncio
import base64
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sec_auditor.providers import kubernetes as module
from sec_auditor.providers.kubernetes import KubernetesProvider, _tls_context
from sec_auditor.transport import CloudAPIError

CLUSTER = "projects/prod-a/locations/us-central1/clusters/apps"
DNS = "uid.us-central1.gke.goog"
POD_URL = f"https://{DNS}/api/v1/pods"


class GoogleStub:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = (
            config
            if config is not None
            else {
                "name": "apps",
                "controlPlaneEndpointsConfig": {
                    "dnsEndpointConfig": {"endpoint": DNS, "allowExternalTraffic": True}
                },
            }
        )
        self.gets: list[str] = []
        self.refreshes: list[bool] = []
        self.token = "initial-token"

    async def get(self, url: str, params=None) -> dict[str, Any]:
        self.gets.append(url)
        return self.config

    async def access_token(self, *, force_refresh: bool = False) -> str:
        self.refreshes.append(force_refresh)
        if force_refresh:
            self.token = "renewed-token"
        return self.token


def page(
    items: list[dict[str, Any]] | None = None,
    *,
    kind: str = "Pod",
    continuation: str = "",
    version: str = "123",
) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": f"{kind}List",
        "metadata": {"resourceVersion": version, "continue": continuation},
        "items": items or [],
    }


def pod(name="web", namespace="default") -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"containers": [{"name": "web", "image": "example/web:1"}]},
    }


@pytest.fixture
def certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GKE Test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()


@respx.mock
async def test_list_preserves_snapshot_and_pagination_and_authenticated_get():
    google = GoogleStub()
    provider = KubernetesProvider(google)
    route = respx.get(POD_URL).respond(200, json=page([pod()], continuation="next/+="))
    try:
        result = await provider.list_objects(CLUSTER, "k8s.Pod", page_size=2, page_token="prior/+=")
        assert not result.errors
        assert result.items[0].kind == "k8s.Pod"
        assert result.items[0].name == f"{CLUSTER}/namespaces/default/pods/web"
        assert result.items[0].project == "prod-a"
        assert result.items[0].location == "us-central1"
        assert result.next_page_token == "next/+="
        assert result.metadata["resource_version"] == "123"
        assert result.metadata["collection_complete"] is False
        request = route.calls.last.request
        assert request.url.params["continue"] == "prior/+="
        assert request.url.params["limit"] == "2"
        assert request.headers["Authorization"] == "Bearer initial-token"
        assert request.headers["Accept-Encoding"] == "identity"
        assert google.gets == [f"https://container.googleapis.com/v1/{CLUSTER}"]
    finally:
        await provider.aclose()


@respx.mock
async def test_namespaced_and_cluster_scoped_paths_and_connection_reuse():
    google = GoogleStub()
    provider = KubernetesProvider(google)
    namespace_route = respx.get(f"https://{DNS}/apis/apps/v1/namespaces/apps/deployments").respond(
        200, json=page(kind="Deployment")
    )
    node_route = respx.get(f"https://{DNS}/api/v1/nodes").respond(200, json=page(kind="Node"))
    try:
        deployment = await provider.list_objects(CLUSTER, "Deployment", namespace="apps")
        node = await provider.list_objects(CLUSTER, "Node")
        assert not deployment.errors and not node.errors
        assert namespace_route.called and node_route.called
        assert len(google.gets) == 1
        assert node.metadata["collection_complete"] is True
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "kind",
    ["Secret", "k8s.Secret", "ConfigMap", "pods/exec", "Pod/status", "../Secret", "CustomResource"],
)
async def test_restricted_kinds_fail_before_any_network_request(kind):
    google = GoogleStub()
    provider = KubernetesProvider(google)
    with pytest.raises(ValueError, match="Unsupported"):
        await provider.list_objects(CLUSTER, kind)
    assert google.gets == []
    assert google.refreshes == []
    await provider.aclose()


@pytest.mark.parametrize(
    "cluster",
    [
        "https://evil.example/cluster",
        CLUSTER + "/../secrets",
        CLUSTER + "?alt=media",
        CLUSTER.replace("prod-a", "prod-a%2f.."),
        CLUSTER.replace("apps", "apps#fragment"),
    ],
)
async def test_invalid_cluster_reference_never_reaches_metadata_api(cluster):
    google = GoogleStub()
    provider = KubernetesProvider(google)
    with pytest.raises(ValueError, match="cluster"):
        await provider.list_objects(cluster, "Pod")
    assert not google.gets
    await provider.aclose()


@pytest.mark.parametrize(
    "namespace", ["..", "apps/../../secrets", "default?watch=true", "", "a" * 64]
)
async def test_namespace_injection_rejected(namespace):
    provider = KubernetesProvider(GoogleStub())
    with pytest.raises(ValueError, match="namespace"):
        await provider.list_objects(CLUSTER, "Pod", namespace=namespace)
    await provider.aclose()


async def test_cluster_scoped_resource_does_not_silently_ignore_namespace():
    provider = KubernetesProvider(GoogleStub())
    with pytest.raises(ValueError, match="cluster-scoped"):
        await provider.list_objects(CLUSTER, "ClusterRole", namespace="apps")
    await provider.aclose()


@respx.mock
async def test_401_refreshes_once_and_403_is_not_retried_or_exposed():
    google = GoogleStub()
    provider = KubernetesProvider(google)
    route = respx.get(POD_URL).mock(
        side_effect=[
            httpx.Response(401, json={"message": "sensitive upstream text"}),
            httpx.Response(403, json={"message": "another credential-bearing value"}),
        ]
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "PERMISSION_DENIED"
        assert result.errors[0].retryable is False
        assert "sensitive" not in result.model_dump_json()
        assert "credential-bearing" not in result.model_dump_json()
        assert route.call_count == 2
        assert route.calls[1].request.headers["Authorization"] == "Bearer renewed-token"
        assert google.refreshes == [False, True]
    finally:
        await provider.aclose()


@respx.mock
async def test_repeated_401_has_one_refresh_and_ends():
    google = GoogleStub()
    provider = KubernetesProvider(google)
    route = respx.get(POD_URL).respond(401)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "UNAUTHENTICATED"
        assert route.call_count == 2
        assert google.refreshes.count(True) == 1
    finally:
        await provider.aclose()


@respx.mock
async def test_transient_responses_have_a_finite_retry_budget(monkeypatch):
    async def immediate_sleep(_):
        return None

    monkeypatch.setattr(module.asyncio, "sleep", immediate_sleep)
    provider = KubernetesProvider(GoogleStub())
    route = respx.get(POD_URL).respond(503, headers={"Retry-After": "99999"})
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].retryable is True
        assert route.call_count == 3
    finally:
        await provider.aclose()


@respx.mock
async def test_redirect_never_forwards_a_bearer_token():
    provider = KubernetesProvider(GoogleStub())
    source = respx.get(POD_URL).respond(302, headers={"Location": "https://evil.example/secrets"})
    forbidden = respx.get("https://evil.example/secrets").respond(200)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "REDIRECT_BLOCKED"
        assert source.call_count == 1
        assert forbidden.call_count == 0
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "endpoint",
    [
        "169.254.169.254",
        "127.0.0.1",
        "0.0.0.0",
        "fd20:ce::254",
        "localhost",
        "https://example.com",
        "10.0.0.1:443",
    ],
)
async def test_unsafe_ip_endpoints_are_rejected_before_token_acquisition(endpoint):
    google = GoogleStub({"endpoint": endpoint})
    provider = KubernetesProvider(google)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "INVALID_ENDPOINT"
        assert google.refreshes == []
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "endpoint", ["evil.example", "gke.goog.evil.example", "user@uid.gke.goog", "uid.gke.goog/path"]
)
async def test_dns_endpoint_must_be_a_discovered_gke_hostname(endpoint):
    config = {
        "controlPlaneEndpointsConfig": {
            "dnsEndpointConfig": {"endpoint": endpoint, "allowExternalTraffic": True}
        }
    }
    google = GoogleStub(config)
    provider = KubernetesProvider(google)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "INVALID_ENDPOINT"
        assert google.refreshes == []
    finally:
        await provider.aclose()


@respx.mock
async def test_private_endpoint_uses_cluster_ca_and_modern_configuration(certificate):
    config = {
        "controlPlaneEndpointsConfig": {
            "dnsEndpointConfig": {"endpoint": DNS, "allowExternalTraffic": False},
            "ipEndpointsConfig": {
                "enabled": True,
                "privateEndpoint": "10.20.30.40",
                "enablePublicEndpoint": False,
            },
        },
        "masterAuth": {"clusterCaCertificate": certificate},
    }
    context = _tls_context(config, "internal")
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    expected_der = ssl.PEM_cert_to_DER_cert(base64.b64decode(certificate).decode())
    assert expected_der in context.get_ca_certs(binary_form=True)
    provider = KubernetesProvider(GoogleStub(config), endpoint_preference="private")
    route = respx.get("https://10.20.30.40/api/v1/pods").respond(200, json=page())
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert not result.errors
        assert result.metadata["endpoint_type"] == "internal"
        assert route.called
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "ca", [None, "not-base64", base64.b64encode(b"not a certificate").decode()]
)
async def test_ip_endpoint_never_disables_tls_for_missing_or_invalid_ca(ca):
    google = GoogleStub({"endpoint": "10.20.30.40", "masterAuth": {"clusterCaCertificate": ca}})
    provider = KubernetesProvider(google)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "INVALID_CLUSTER_CA"
        assert google.refreshes == []
    finally:
        await provider.aclose()


@respx.mock
async def test_unreachable_cluster_is_a_coverage_error():
    provider = KubernetesProvider(GoogleStub())
    respx.get(POD_URL).mock(side_effect=httpx.ConnectError("network failed"))
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.items == []
        assert result.metadata["collection_complete"] is False
        assert result.errors[0].code == "NETWORK_OR_TLS_ERROR"
    finally:
        await provider.aclose()


@respx.mock
async def test_response_size_budget_and_unexpected_secret_objects(monkeypatch):
    monkeypatch.setattr(module, "_MAX_RESPONSE_BYTES", 1024)
    provider = KubernetesProvider(GoogleStub())
    route = respx.get(POD_URL).respond(200, content=b" " * 1025)
    try:
        oversized = await provider.list_objects(CLUSTER, "Pod")
        assert oversized.errors[0].code == "RESPONSE_TOO_LARGE"
        secret = {
            "kind": "Secret",
            "metadata": {"name": "oops", "namespace": "default"},
            "data": {"key": "sensitive"},
        }
        route.respond(200, json=page([secret]))
        unexpected = await provider.list_objects(CLUSTER, "Pod")
        assert unexpected.items == []
        assert unexpected.errors[0].code == "INVALID_RESPONSE"
        assert "sensitive" not in unexpected.model_dump_json()
    finally:
        await provider.aclose()


@respx.mock
async def test_namespace_boundary_is_checked_in_response():
    provider = KubernetesProvider(GoogleStub())
    respx.get(f"https://{DNS}/api/v1/namespaces/apps/pods").respond(
        200, json=page([pod(namespace="other")])
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod", namespace="apps")
        assert result.items == []
        assert result.errors[0].code == "INVALID_RESPONSE"
    finally:
        await provider.aclose()


async def test_gke_metadata_permission_denial_is_reported():
    class DeniedGoogle(GoogleStub):
        async def get(self, url, params=None):
            raise CloudAPIError("PERMISSION_DENIED", "private diagnostic", status_code=403)

    provider = KubernetesProvider(DeniedGoogle())
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "PERMISSION_DENIED"
        assert "private diagnostic" not in result.model_dump_json()
    finally:
        await provider.aclose()


@respx.mock
async def test_shared_concurrency_budget_applies_across_calls():
    in_flight = 0
    peak = 0

    async def handler(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return httpx.Response(200, json=page())

    respx.get(POD_URL).mock(side_effect=handler)
    provider = KubernetesProvider(GoogleStub(), concurrency=2)
    try:
        results = await asyncio.gather(*(provider.list_objects(CLUSTER, "Pod") for _ in range(6)))
        assert all(not result.errors for result in results)
        assert peak == 2
    finally:
        await provider.aclose()


@respx.mock
async def test_deadline_covers_network_work():
    async def slow_response(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json=page())

    respx.get(POD_URL).mock(side_effect=slow_response)
    provider = KubernetesProvider(GoogleStub(), timeout=0.05)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "DEADLINE_EXCEEDED"
        assert result.errors[0].retryable is True
    finally:
        await provider.aclose()


@respx.mock
async def test_auth_refresh_is_not_repeated_by_a_transient_retry(monkeypatch):
    async def immediate_sleep(_):
        return None

    monkeypatch.setattr(module.asyncio, "sleep", immediate_sleep)
    google = GoogleStub()
    provider = KubernetesProvider(google)
    route = respx.get(POD_URL).mock(
        side_effect=[httpx.Response(401), httpx.Response(503), httpx.Response(200, json=page())]
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert not result.errors
        assert route.call_count == 3
        assert google.refreshes.count(True) == 1
        assert route.calls[-1].request.headers["Authorization"] == "Bearer renewed-token"
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    ("preference", "config"),
    [
        (
            "dns",
            {
                "controlPlaneEndpointsConfig": {
                    "dnsEndpointConfig": {"endpoint": DNS, "allowExternalTraffic": False}
                }
            },
        ),
        ("public", {"controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enabled": False}}}),
        (
            "public",
            {"privateClusterConfig": {"publicEndpoint": "35.1.2.3", "enablePrivateEndpoint": True}},
        ),
    ],
)
async def test_disabled_endpoints_are_not_used(preference, config):
    google = GoogleStub(config)
    provider = KubernetesProvider(google, endpoint_preference=preference)
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "ENDPOINT_DISABLED"
        assert google.refreshes == []
    finally:
        await provider.aclose()


@respx.mock
async def test_collection_snapshot_expiry_is_explicit():
    provider = KubernetesProvider(GoogleStub())
    route = respx.get(POD_URL).respond(410)
    try:
        result = await provider.list_objects(CLUSTER, "Pod", page_token="expired-token")
        assert result.errors[0].code == "CONTINUE_EXPIRED"
        assert result.metadata["collection_complete"] is False
        assert route.call_count == 1
    finally:
        await provider.aclose()
