"""Native ACK reads retain the Kubernetes no-content and endpoint boundaries."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sec_auditor.config import Settings
from sec_auditor.projection import project_record
from sec_auditor.providers import kubernetes as shared
from sec_auditor.providers.kubernetes_registered import (
    RegisteredKubernetesProvider,
    cluster_account,
    validate_server,
)

ACCOUNT = "1234567890123456"
REGION = "cn-hangzhou"
CLUSTER = f"accounts/{ACCOUNT}/regions/{REGION}/clusters/c-production"
SERVER = "https://controlplane.example.com:6443"


@pytest.fixture(scope="module")
def certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACK Test CA")])
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
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def registered(tmp_path, certificate):
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(certificate)
    token_file = tmp_path / "projected-token"
    token_file.write_text("header.initial.signature")
    settings = Settings(
        allowed_alicloud_accounts=[ACCOUNT],
        allowed_alicloud_regions=[REGION],
        alicloud_kubernetes_clusters={
            CLUSTER: {"server": SERVER, "ca_file": ca_file, "token_file": token_file}
        },
    )
    return settings, ca_file, token_file


def page(items=None, continuation=""):
    return {
        "apiVersion": "v1",
        "kind": "PodList",
        "metadata": {"resourceVersion": "104", "continue": continuation},
        "items": items or [],
    }


def pod():
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "web", "namespace": "apps"},
        "spec": {
            "containers": [
                {
                    "name": "web",
                    "image": "example/web:1",
                    "env": [
                        {"name": "PASSWORD", "value": "must-not-reach-agent"},
                        {
                            "name": "REFERENCED",
                            "valueFrom": {"secretKeyRef": {"name": "credential", "key": "token"}},
                        },
                    ],
                }
            ]
        },
    }


async def test_registered_ack_pods_have_correct_identity_paging_and_safe_projection(registered):
    settings, _, _ = registered
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=page([pod()], continuation="next-token"))

    provider = RegisteredKubernetesProvider(settings, http_transport=httpx.MockTransport(handler))
    try:
        result = await provider.list_objects(
            CLUSTER, "Pod", namespace="apps", page_size=2, page_token="prior-token"
        )
        assert not result.errors
        record = result.items[0]
        assert record.provider == "kubernetes"
        assert record.project is None
        assert record.account_id == ACCOUNT
        assert record.location == REGION
        assert record.source == f"ack://{CLUSTER}/api/v1/namespaces/apps/pods"
        assert record.name == f"{CLUSTER}/namespaces/apps/pods/web"
        assert result.next_page_token == "next-token"
        assert result.metadata["resource_version"] == "104"
        assert not result.metadata["collection_complete"]
        request = seen[0]
        assert request.method == "GET"
        assert str(request.url).startswith(SERVER + "/api/v1/namespaces/apps/pods?")
        assert dict(request.url.params) == {"limit": "2", "continue": "prior-token"}
        assert request.headers["authorization"] == "Bearer header.initial.signature"
        assert request.headers["accept-encoding"] == "identity"
        projected = project_record(record)
        assert "must-not-reach-agent" not in str(projected)
        assert (
            projected["data"]["spec"]["containers"][0]["env"][1]["valueFrom"]["secretKeyRef"][
                "name"
            ]
            == "credential"
        )
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "kind", ["Secret", "ConfigMap", "k8s.Secret", "Pod/exec", "pods/log", "CustomResource"]
)
async def test_ack_cannot_read_forbidden_kinds_even_with_registered_cluster(registered, kind):
    settings, ca_file, token_file = registered
    ca_file.unlink()
    token_file.unlink()
    provider = RegisteredKubernetesProvider(
        settings, http_transport=httpx.MockTransport(lambda _: pytest.fail("No network allowed"))
    )
    try:
        with pytest.raises(ValueError, match="Unsupported"):
            await provider.list_objects(CLUSTER, kind)
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "cluster",
    [
        CLUSTER + "-unregistered",
        CLUSTER.replace(ACCOUNT, "9876543210987654"),
        CLUSTER.replace(REGION, "us-west-1"),
        "projects/gcp-app/locations/us-central1/clusters/apps",
        "https://evil.example/",
        CLUSTER + "/../secrets",
    ],
)
async def test_only_exact_operator_registered_ack_cluster_is_readable(registered, cluster):
    settings, _, _ = registered
    provider = RegisteredKubernetesProvider(
        settings, http_transport=httpx.MockTransport(lambda _: pytest.fail("No network allowed"))
    )
    try:
        with pytest.raises(ValueError):
            await provider.list_objects(cluster, "Pod")
    finally:
        await provider.aclose()


async def test_projected_token_is_reloaded_after_rotation_and_401(registered):
    settings, _, token_file = registered
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        if len(seen) == 1:
            token_file.write_text("header.rotated.signature")
            return httpx.Response(401)
        return httpx.Response(200, json=page())

    provider = RegisteredKubernetesProvider(settings, http_transport=httpx.MockTransport(handler))
    try:
        first = await provider.list_objects(CLUSTER, "Pod")
        assert not first.errors
        token_file.write_text("header.rotatedAgain.signature")
        second = await provider.list_objects(CLUSTER, "Pod")
        assert not second.errors
        assert seen == [
            "Bearer header.initial.signature",
            "Bearer header.rotated.signature",
            "Bearer header.rotatedAgain.signature",
        ]
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "token",
    ["", "raw-token", "header.payload.signature\r\nINJECT: yes", "a" * 16385, "\N{SNOWMAN}"],
)
async def test_invalid_token_file_fails_before_network_and_never_leaks_content(registered, token):
    settings, _, token_file = registered
    token_file.write_text(token)
    provider = RegisteredKubernetesProvider(
        settings, http_transport=httpx.MockTransport(lambda _: pytest.fail("No network allowed"))
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "INVALID_CLUSTER_CREDENTIAL"
        assert "INJECT" not in result.model_dump_json()
    finally:
        await provider.aclose()


@pytest.mark.parametrize("content", [b"", b"not a CA certificate", b"x" * (192 * 1024 + 1)])
async def test_invalid_or_empty_ca_is_a_typed_failure(registered, content):
    settings, ca_file, _ = registered
    ca_file.write_bytes(content)
    provider = RegisteredKubernetesProvider(
        settings, http_transport=httpx.MockTransport(lambda _: pytest.fail("No network allowed"))
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code in {"INVALID_CLUSTER_CA", "INVALID_CLUSTER_CREDENTIAL"}
        assert not result.metadata["collection_complete"]
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    "server",
    [
        "http://controlplane.example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://169.254.169.254",
        "https://metadata.google.internal",
        "https://0.0.0.0",
        "https://224.0.0.1",
        "https://user:password@example.com",
        "https://example.com/other",
        "https://example.com?query=1",
        "https://example.com#token",
        "https://example.com:8080",
        "https://example.com%2ffoo",
    ],
)
def test_registered_server_validator_rejects_unsafe_endpoints(server):
    with pytest.raises(ValueError):
        validate_server(server)


@pytest.mark.parametrize(
    "server",
    ["https://10.0.0.10:6443", "https://controlplane.example.com/", "https://[fd00::1]:6443"],
)
def test_registered_server_supports_private_control_planes(server):
    assert validate_server(server) == server.rstrip("/")


async def test_ack_redirect_does_not_forward_token(registered):
    settings, _, _ = registered
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example/secrets"})

    provider = RegisteredKubernetesProvider(settings, http_transport=httpx.MockTransport(handler))
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "REDIRECT_BLOCKED"
        assert len(seen) == 1
    finally:
        await provider.aclose()


async def test_ack_page_response_is_bounded(registered, monkeypatch):
    settings, _, _ = registered
    monkeypatch.setattr(shared, "_MAX_RESPONSE_BYTES", 64)
    provider = RegisteredKubernetesProvider(
        settings,
        http_transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 65)),
    )
    try:
        result = await provider.list_objects(CLUSTER, "Pod")
        assert result.errors[0].code == "RESPONSE_TOO_LARGE"
    finally:
        await provider.aclose()


async def test_closed_registered_provider_reports_typed_failure(registered):
    settings, _, _ = registered
    provider = RegisteredKubernetesProvider(
        settings, http_transport=httpx.MockTransport(lambda _: pytest.fail("No network allowed"))
    )
    await provider.aclose()
    result = await provider.list_objects(CLUSTER, "Pod")
    assert result.errors[0].code == "PROVIDER_CLOSED"


def test_cluster_account_parser_is_exact():
    assert cluster_account(CLUSTER) == (ACCOUNT, REGION)
    with pytest.raises(ValueError):
        cluster_account(CLUSTER + "/extra")
