"""Assembled MCP transport, authentication, projection, and lifecycle tests."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from sec_auditor.__main__ import main
from sec_auditor.config import Settings
from sec_auditor.models import CollectionResult, ResourceRecord
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.providers.kubernetes import normalize_kind
from sec_auditor.server import build_server, create_app
from sec_auditor.service import SecurityService
from sec_auditor.transport import CloudAPIError

PUBLIC_URL = "https://audit.example.com/mcp"
CLUSTER = "projects/prod-a/locations/us-central1/clusters/apps"
TOKENS = {"agent-a": "integration-token-a", "agent-b": "integration-token-b"}
TOOLS = {
    "capabilities",
    "list_security_checks",
    "search_inventory",
    "collect_resources",
    "inspect_kubernetes",
    "get_iam_context",
    "query_logs",
    "run_security_checks",
    "get_evidence",
    "start_assessment",
    "get_assessment",
    "list_assessment_results",
    "cancel_assessment",
}


class FakeGoogle:
    """Native API fixtures; real GCP adapters and scope checks remain assembled."""

    def __init__(self):
        self.calls = []
        self.closed = False

    async def get(self, url, params=None):
        self.calls.append(("GET", url, copy.deepcopy(params)))
        parsed = urlsplit(url)
        if parsed.hostname == "cloudresourcemanager.googleapis.com":
            identifier = parsed.path.rsplit("/", 1)[-1]
            identities = {
                "prod-a": ("prod-a", "123456", "organizations/123"),
                "123456": ("prod-a", "123456", "organizations/123"),
                "prod-b": ("prod-b", "654321", "organizations/999"),
            }
            if identifier not in identities:
                raise CloudAPIError(
                    "PERMISSION_DENIED", "Google API returned HTTP 403", status_code=403
                )
            project, number, parent = identities[identifier]
            return {
                "name": f"projects/{number}",
                "projectId": project,
                "state": "ACTIVE",
                "parent": parent,
            }
        if parsed.hostname == "compute.googleapis.com" and parsed.path.endswith(
            "/aggregated/instances"
        ):
            second_page = bool((params or {}).get("pageToken"))
            name = "vm-two" if second_page else "vm-one"
            response = {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [
                            {
                                "name": name,
                                "selfLink": f"https://www.googleapis.com/compute/v1/projects/prod-a/zones/us-central1-a/instances/{name}",
                                "status": "RUNNING",
                                "canIpForward": False,
                                "shieldedInstanceConfig": {
                                    "enableSecureBoot": False,
                                    "enableVtpm": True,
                                    "enableIntegrityMonitoring": True,
                                },
                                "networkInterfaces": [
                                    {"accessConfigs": [{"natIP": "198.51.100.10"}]}
                                ],
                                "metadata": {
                                    "items": [
                                        {"key": "enable-oslogin", "value": "TRUE"},
                                        {
                                            "key": "startup-script",
                                            "value": "PRIVATE-STARTUP-CONTENT",
                                        },
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
            if not second_page:
                response["nextPageToken"] = "native-next"
            return response
        if parsed.hostname == "compute.googleapis.com" and parsed.path.endswith(
            "/aggregated/disks"
        ):
            raise CloudAPIError(
                "PERMISSION_DENIED", "Google API returned HTTP 403", status_code=403
            )
        if parsed.hostname == "cloudasset.googleapis.com" and parsed.path.endswith(
            ":searchAllResources"
        ):
            return {
                "results": [
                    {
                        "name": "//compute.googleapis.com/projects/prod-a/zones/us-central1-a/instances/vm-one",
                        "assetType": "compute.googleapis.com/Instance",
                        "project": "projects/123456",
                    }
                ]
            }
        raise AssertionError(f"Unexpected native API fixture: {url}")

    async def post_read(self, url, json=None):
        self.calls.append(("POST", url, copy.deepcopy(json)))
        if url.endswith(":getIamPolicy"):
            return {
                "version": 3,
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["serviceAccount:reader@prod-a.iam.gserviceaccount.com"],
                        "condition": {
                            "title": "bounded",
                            "expression": 'resource.name.startsWith("projects/prod-a")',
                        },
                    }
                ],
            }
        if url == "https://logging.googleapis.com/v2/entries:list":
            return {
                "entries": [
                    {
                        "logName": "projects/prod-a/logs/cloudaudit.googleapis.com%2Factivity",
                        "insertId": "event-one",
                        "timestamp": "2026-11-11T00:00:00Z",
                        "protoPayload": {
                            "serviceName": "compute.googleapis.com",
                            "methodName": "v1.compute.instances.insert",
                            "authenticationInfo": {"principalEmail": "operator@example.com"},
                            "request": {"anything": "PRIVATE-AUDIT-REQUEST"},
                        },
                        "textPayload": "PRIVATE-LOG-TEXT",
                    }
                ]
            }
        raise AssertionError(f"Unexpected native API fixture: {url}")

    async def aclose(self):
        self.closed = True


class FakeKubernetes:
    def __init__(self):
        self.calls = []
        self.closed = False

    def capabilities(self):
        return [{"kind": "k8s.Pod", "namespaced": True, "operations": ["list"]}]

    async def list_objects(self, cluster, kind, *, namespace=None, page_size=100, page_token=None):
        kind = normalize_kind(kind)
        self.calls.append((cluster, kind, namespace, page_size, page_token))
        if kind != "Pod":
            return CollectionResult()
        namespace = namespace or "apps"
        return CollectionResult(
            items=[
                ResourceRecord(
                    provider="kubernetes",
                    kind="k8s.Pod",
                    project="prod-a",
                    location="us-central1",
                    name=f"{cluster}/namespaces/{namespace}/pods/web",
                    data={
                        "kind": "Pod",
                        "metadata": {"name": "web", "namespace": namespace},
                        "spec": {
                            "hostNetwork": False,
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "example/web:1",
                                    "securityContext": {"privileged": True},
                                    "env": [{"name": "APP_SETTING", "value": "PRIVATE-POD-ENV"}],
                                }
                            ],
                        },
                    },
                )
            ]
        )

    async def aclose(self):
        self.closed = True


@pytest.fixture
def setup(tmp_path):
    settings = Settings(
        allowed_projects=["prod-a"],
        auth_mode="static",
        public_url=PUBLIC_URL,
        static_tokens={
            actor: hashlib.sha256(token.encode()).hexdigest() for actor, token in TOKENS.items()
        },
        state_path=tmp_path / "state" / "service.sqlite3",
    )
    google = FakeGoogle()
    kubernetes = FakeKubernetes()
    service = SecurityService(
        settings, client=google, gcp=GCPProvider(google), kubernetes=kubernetes
    )
    return SimpleNamespace(settings=settings, google=google, kubernetes=kubernetes, service=service)


def rpc(client, method, params=None, *, actor="agent-a", version="2026-07-28", headers=None):
    params = dict(params or {})
    actual_headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
    }
    if actor is not None:
        actual_headers["Authorization"] = f"Bearer {TOKENS[actor]}"
    if version == "2026-07-28":
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        actual_headers["MCP-Method"] = method
        if method == "tools/call":
            actual_headers["MCP-Name"] = params["name"]
    actual_headers.update(headers or {})
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=actual_headers,
    )


def call(client, name, arguments=None, *, actor="agent-a", version="2026-07-28"):
    response = rpc(
        client,
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        actor=actor,
        version=version,
    )
    assert response.status_code == 200, response.text
    assert "PRIVATE-" not in response.text, (
        "Sensitive fixture content reached the MCP wire response"
    )
    envelope = response.json()
    assert "error" not in envelope, envelope
    tool_result = envelope["result"]
    assert not tool_result.get("isError", False), tool_result
    assert "structuredContent" in tool_result, tool_result
    return tool_result["structuredContent"]


def test_http_lifespan_health_and_authentication_boundary(setup):
    assert setup.service.ready is False
    app = create_app(setup.settings, service=setup.service)
    with TestClient(app, base_url=PUBLIC_URL.removesuffix("/mcp")) as client:
        assert setup.service.ready is True
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json() == {"status": "ready"}
        assert rpc(client, "tools/list", actor=None).status_code == 401
        assert (
            rpc(client, "tools/list", headers={"Authorization": "Bearer wrong-token"}).status_code
            == 401
        )
        assert setup.google.calls == []
    assert setup.service.ready is False
    assert setup.google.closed is True
    assert setup.kubernetes.closed is True


@pytest.mark.parametrize("version", ["2026-07-28", "2025-11-25"])
def test_all_tools_are_discoverable_and_callable_over_http(setup, version):
    app = create_app(setup.settings, service=setup.service)
    with TestClient(app, base_url=PUBLIC_URL.removesuffix("/mcp")) as client:
        if version == "2025-11-25":
            initialized = rpc(
                client,
                "initialize",
                {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "sec-auditor-tests", "version": "1"},
                },
                version=version,
            )
            assert initialized.status_code == 200
            assert initialized.json()["result"]["protocolVersion"] == version
        listing = rpc(client, "tools/list", version=version)
        assert listing.status_code == 200, listing.text
        assert {tool["name"] for tool in listing.json()["result"]["tools"]} == TOOLS
        observed = set()

        def invoke(name, arguments=None):
            observed.add(name)
            return call(client, name, arguments, version=version)

        capability = invoke("capabilities")
        assert capability["providers"] == ["gcp"]
        assert capability["boundaries"]["object_downloads"] is False
        definitions = invoke("list_security_checks", {"resource_kind": "gcp.compute.instances"})
        assert definitions["count"] > 0
        inventory = invoke("search_inventory", {"scope": "projects/prod-a"})
        assert inventory["items"][0]["freshness"] == "inventory"
        resource_query = {"kind": "gcp.compute.instances", "project": "prod-a"}
        resources = invoke("collect_resources", {"queries": [resource_query]})
        first = resources["results"][0]
        assert first["items"][0]["data"]["metadata"]["items"][1]["value"] == "[REDACTED]"
        assert first["next_cursor"]
        assert first["coverage"]["collection_complete"] is False
        pods = invoke("inspect_kubernetes", {"queries": [{"cluster": CLUSTER, "kind": "Pod"}]})
        assert (
            pods["results"][0]["items"][0]["data"]["spec"]["containers"][0]["env"][0]["value"]
            == "[REDACTED]"
        )
        policies = invoke("get_iam_context", {"scope": "projects/prod-a"})
        assert policies["items"][0]["data"]["bindings"][0]["condition"]["title"] == "bounded"
        logs = invoke("query_logs", {"queries": [{"project": "prod-a", "category": "audit"}]})
        assert "PRIVATE" not in json.dumps(logs)
        assert (
            logs["results"][0]["items"][0]["data"]["protoPayload"]["authenticationInfo"][
                "principalEmail"
            ]
            == "operator@example.com"
        )
        checks = invoke(
            "run_security_checks", {"queries": [resource_query], "include_passes": True}
        )
        assert checks["results"][0]["evaluation"]["checks_evaluated"] > 0
        evidence = invoke("get_evidence", {"evidence_id": first["evidence_id"]})
        assert evidence["items"] == first["items"]
        job = invoke(
            "start_assessment",
            {
                "request": {
                    "projects": ["prod-a"],
                    "resource_kinds": ["gcp.compute.instances"],
                    "include_kubernetes": False,
                }
            },
        )
        identifier = job["assessment_id"]
        status = invoke("get_assessment", {"assessment_id": identifier})
        assert status["status"] in {"queued", "running", "completed"}
        result = invoke("list_assessment_results", {"assessment_id": identifier})
        assert result["assessment_id"] == identifier
        cancellation = invoke("cancel_assessment", {"assessment_id": identifier})
        assert cancellation["id"] == identifier
        assert observed == TOOLS
        assert "PRIVATE" not in json.dumps(resources)


def test_caller_isolation_survives_http_dispatch_evidence_and_cursor_roundtrips(setup):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        query = {"kind": "gcp.compute.instances", "project": "prod-a", "page_size": 1}
        first = call(client, "collect_resources", {"queries": [query]})["results"][0]
        evidence_id, cursor = first["evidence_id"], first["next_cursor"]
        owned = call(client, "get_evidence", {"evidence_id": evidence_id})
        assert owned["items"][0]["data"]["name"] == "vm-one"
        denied = call(client, "get_evidence", {"evidence_id": evidence_id}, actor="agent-b")
        assert denied["error"]["code"] == "INVALID_ARGUMENT"
        assert "vm-one" not in json.dumps(denied)
        before = len(setup.google.calls)
        wrong_cursor = call(
            client, "collect_resources", {"queries": [{**query, "cursor": cursor}]}, actor="agent-b"
        )
        assert wrong_cursor["results"][0]["errors"][0]["code"] == "INVALID_ARGUMENT"
        assert len(setup.google.calls) == before
        continued = call(client, "collect_resources", {"queries": [{**query, "cursor": cursor}]})
        assert continued["results"][0]["items"][0]["data"]["name"] == "vm-two"
        assert continued["results"][0]["next_cursor"] is None
        assert continued["results"][0]["coverage"]["collection_complete"] is True


def test_http_partial_failures_preserve_successes_and_coverage(setup):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        result = call(
            client,
            "collect_resources",
            {
                "queries": [
                    {"kind": "gcp.compute.instances", "project": "prod-a"},
                    {"kind": "gcp.compute.disks", "project": "prod-a"},
                    {"kind": "gcp.compute.instances", "project": "prod-b"},
                ]
            },
        )
        assert result["targets_requested"] == 3
        assert result["targets_with_errors"] == 2
        assert result["results"][0]["items"]
        assert result["results"][1]["errors"][0]["code"] == "PERMISSION_DENIED"
        assert result["results"][2]["errors"][0]["code"] == "SCOPE_DENIED"
        assert all(not item["coverage"]["collection_complete"] for item in result["results"][1:])
        assert not any(
            "compute.googleapis.com" in url and "/prod-b/" in url
            for _, url, _ in setup.google.calls
        )


@pytest.mark.parametrize(
    "tool,arguments",
    [
        (
            "collect_resources",
            {
                "queries": [
                    {
                        "kind": "gcp.compute.instances",
                        "project": "prod-a",
                        "url": "https://evil.example",
                    }
                ]
            },
        ),
        (
            "collect_resources",
            {
                "queries": [
                    {"kind": "gcp.compute.instances", "project": "prod-a", "method": "DELETE"}
                ]
            },
        ),
        (
            "collect_resources",
            {"queries": [{"kind": "gcp.compute.instances", "project": "prod-a", "page_size": 0}]},
        ),
        (
            "inspect_kubernetes",
            {"queries": [{"cluster": CLUSTER, "kind": "Pod", "path": "/api/v1/secrets"}]},
        ),
        ("query_logs", {"queries": [{"project": "prod-a", "category": "raw_payload"}]}),
        ("start_assessment", {"request": {}}),
    ],
)
def test_mcp_input_schema_blocks_extra_operations_and_invalid_shapes(setup, tool, arguments):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        response = rpc(client, "tools/call", {"name": tool, "arguments": arguments})
        assert response.status_code == 200
        result = response.json()
        assert "error" in result or result["result"].get("isError") is True
        assert setup.google.calls == []
        assert setup.kubernetes.calls == []


def test_arbitrary_tools_resource_kinds_and_secret_reads_have_no_execution_path(setup):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        unknown = rpc(
            client, "tools/call", {"name": "run_gcloud", "arguments": {"command": "anything"}}
        )
        assert unknown.status_code == 200
        envelope = unknown.json()
        assert "error" in envelope or envelope["result"].get("isError") is True
        resource = rpc(
            client,
            "tools/call",
            {
                "name": "collect_resources",
                "arguments": {"queries": [{"kind": "https://evil.example", "project": "prod-a"}]},
            },
        )
        assert resource.status_code == 200
        assert resource.json()["result"]["isError"] is True
        secrets = call(
            client, "inspect_kubernetes", {"queries": [{"cluster": CLUSTER, "kind": "Secret"}]}
        )
        assert secrets["results"][0]["errors"][0]["code"] == "INVALID_ARGUMENT"
        assert setup.kubernetes.calls == []
        assert all(
            url.startswith("https://cloudresourcemanager.googleapis.com/")
            for _, url, _ in setup.google.calls
        )


def test_dns_rebinding_and_origin_controls_guard_the_mcp_endpoint(setup):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        wrong_host = rpc(client, "tools/list", headers={"Host": "evil.example"})
        assert wrong_host.status_code in {400, 403, 421}
        assert "host" in wrong_host.text.lower()
        wrong_origin = rpc(client, "tools/list", headers={"Origin": "https://evil.example"})
        assert wrong_origin.status_code in {400, 403, 421}
        assert setup.google.calls == []


def test_http_request_budget_and_routing_header_mismatch_are_rejected(setup):
    with TestClient(
        create_app(setup.settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        oversized = rpc(
            client,
            "tools/call",
            {"name": "capabilities", "arguments": {"padding": "x" * 1_048_576}},
        )
        assert oversized.status_code == 413
        mismatch = rpc(client, "tools/list", headers={"MCP-Method": "tools/call"})
        assert mismatch.status_code == 400
        assert setup.google.calls == []


def test_jwt_metadata_discovery_and_authenticated_call(setup, monkeypatch):
    issuer = "https://issuer.example.com/"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        jwt.PyJWKClient,
        "get_signing_key_from_jwt",
        lambda self, token: SimpleNamespace(key=key.public_key()),
    )
    settings = setup.settings.model_copy(
        update={
            "auth_mode": "jwt",
            "jwt_issuer": issuer,
            "jwt_audience": PUBLIC_URL,
            "jwks_url": issuer + "jwks.json",
            "allowed_subjects": ["jwt-agent"],
        }
    )
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": PUBLIC_URL,
            "sub": "jwt-agent",
            "iat": now - 1,
            "exp": now + 600,
            "scope": "security:read",
        },
        key,
        algorithm="RS256",
    )
    with TestClient(
        create_app(settings, service=setup.service), base_url=PUBLIC_URL.removesuffix("/mcp")
    ) as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == PUBLIC_URL
        assert metadata.json()["authorization_servers"] == [issuer]
        unauthenticated = rpc(client, "tools/list", actor=None)
        assert unauthenticated.status_code == 401
        assert "resource_metadata=" in unauthenticated.headers["WWW-Authenticate"]
        response = rpc(
            client,
            "tools/call",
            {
                "name": "collect_resources",
                "arguments": {"queries": [{"kind": "gcp.compute.instances", "project": "prod-a"}]},
            },
            actor=None,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]["structuredContent"]
        identifier = result["results"][0]["evidence_id"]
        assert setup.service.store.get_evidence("jwt-agent", identifier)
        with pytest.raises(ValueError):
            setup.service.store.get_evidence("agent-a", identifier)


async def test_stdio_build_and_direct_tools_do_not_require_http_auth_or_adc(setup):
    settings = setup.settings.model_copy(
        update={"auth_mode": "jwt", "allowed_subjects": [], "jwt_issuer": ""}
    )
    server, service, verifier = build_server(settings, service=setup.service, http=False)
    try:
        assert verifier is None
        assert {tool.name for tool in await server.list_tools()} == TOOLS
        response = await server.call_tool("capabilities", {})
        assert response.structured_content["service"] == "Sec-Auditor"
        collected = await server.call_tool(
            "collect_resources",
            {"queries": [{"kind": "gcp.compute.instances", "project": "prod-a"}]},
        )
        identifier = collected.structured_content["results"][0]["evidence_id"]
        assert service.store.get_evidence("local-stdio", identifier)
    finally:
        await service.close()


def test_offline_cli_checks_and_private_token_hashing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sec-auditor", "checks"])
    main()
    definitions = json.loads(capsys.readouterr().out)
    assert definitions and all("id" in item for item in definitions)
    token = "example-random-token-for-cli-test-only"
    monkeypatch.setattr(sys, "argv", ["sec-auditor", "hash-token"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    main()
    output = capsys.readouterr()
    assert output.out.strip() == hashlib.sha256(token.encode()).hexdigest()
    assert token not in output.out + output.err
