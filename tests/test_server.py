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
from sec_auditor.connector import CloudConnector
from sec_auditor.models import CollectionResult, ResourceRecord
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.providers.kubernetes import normalize_kind
from sec_auditor.server import build_server, create_app
from sec_auditor.transport import CloudAPIError

PUBLIC_URL = "https://audit.example.com/mcp"
CLUSTER = "projects/prod-a/locations/us-central1/clusters/apps"
TOKENS = {"agent-a": "integration-token-a", "agent-b": "integration-token-b"}
TOOLS = {
    "capabilities",
    "search_inventory",
    "collect_resources",
    "inspect_kubernetes",
    "get_iam_context",
    "query_logs",
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

    async def get_object(self, cluster, kind, resource_id, *, namespace=None):
        assert resource_id == "web"
        assert namespace == "apps"
        return await self.list_objects(cluster, kind, namespace=namespace, page_size=1)

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
    )
    google = FakeGoogle()
    kubernetes = FakeKubernetes()
    connector = CloudConnector(
        settings, client=google, gcp=GCPProvider(google), kubernetes=kubernetes
    )
    return SimpleNamespace(
        settings=settings, google=google, kubernetes=kubernetes, connector=connector
    )


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
    assert setup.connector.ready is False
    app = create_app(setup.settings, connector=setup.connector)
    with TestClient(app, base_url=PUBLIC_URL.removesuffix("/mcp")) as client:
        assert setup.connector.ready is True
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json() == {"status": "ready"}
        assert rpc(client, "tools/list", actor=None).status_code == 401
        assert (
            rpc(client, "tools/list", headers={"Authorization": "Bearer wrong-token"}).status_code
            == 401
        )
        assert setup.google.calls == []
    assert setup.connector.ready is False
    assert setup.google.closed is True
    assert setup.kubernetes.closed is True


@pytest.mark.parametrize("version", ["2026-07-28", "2025-11-25"])
def test_all_tools_are_discoverable_and_callable_over_http(setup, version):
    app = create_app(setup.settings, connector=setup.connector)
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
        assert observed == TOOLS
        assert "PRIVATE" not in json.dumps(resources)


def test_caller_isolation_survives_http_dispatch_and_cursor_roundtrips(setup):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        query = {"kind": "gcp.compute.instances", "project": "prod-a", "page_size": 1}
        first = call(client, "collect_resources", {"queries": [query]})["results"][0]
        cursor = first["next_cursor"]
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
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
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
    ],
)
def test_mcp_input_schema_blocks_extra_operations_and_invalid_shapes(setup, tool, arguments):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        response = rpc(client, "tools/call", {"name": tool, "arguments": arguments})
        assert response.status_code == 200
        result = response.json()
        assert "error" in result or result["result"].get("isError") is True
        assert setup.google.calls == []
        assert setup.kubernetes.calls == []


def test_arbitrary_tools_resource_kinds_and_secret_reads_have_no_execution_path(setup):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
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
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        wrong_host = rpc(client, "tools/list", headers={"Host": "evil.example"})
        assert wrong_host.status_code in {400, 403, 421}
        assert "host" in wrong_host.text.lower()
        wrong_origin = rpc(client, "tools/list", headers={"Origin": "https://evil.example"})
        assert wrong_origin.status_code in {400, 403, 421}
        assert setup.google.calls == []


def test_http_request_budget_and_routing_header_mismatch_are_rejected(setup):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
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
    callers = []
    original_collect = setup.connector.collect_resources

    async def collect_as(caller, queries):
        callers.append(caller)
        return await original_collect(caller, queries)

    monkeypatch.setattr(setup.connector, "collect_resources", collect_as)
    with TestClient(
        create_app(settings, connector=setup.connector), base_url=PUBLIC_URL.removesuffix("/mcp")
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
        assert result["results"][0]["items"][0]["data"]["name"] == "vm-one"
        assert callers == ["jwt-agent"]
        assert "evidence_id" not in result["results"][0]


async def test_stdio_build_and_direct_tools_do_not_require_http_auth_or_adc(setup):
    settings = setup.settings.model_copy(
        update={"auth_mode": "jwt", "allowed_subjects": [], "jwt_issuer": ""}
    )
    server, connector, verifier = build_server(settings, connector=setup.connector, http=False)
    try:
        assert verifier is None
        assert {tool.name for tool in await server.list_tools()} == TOOLS
        response = await server.call_tool("capabilities", {})
        assert response.structured_content["service"] == "Sec-Auditor"
        collected = await server.call_tool(
            "collect_resources",
            {"queries": [{"kind": "gcp.compute.instances", "project": "prod-a"}]},
        )
        result = collected.structured_content["results"][0]
        assert result["items"][0]["data"]["name"] == "vm-one"
        assert "evidence_id" not in result
        assert not hasattr(connector, "store")
    finally:
        await connector.close()


def test_offline_cli_catalog_and_private_token_hashing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sec-auditor", "catalog"])
    main()
    definitions = json.loads(capsys.readouterr().out)
    assert set(definitions) == {"gcp", "alicloud", "kubernetes"}
    assert all("get" in item["operations"] for item in definitions["kubernetes"])
    token = "example-random-token-for-cli-test-only"
    monkeypatch.setattr(sys, "argv", ["sec-auditor", "hash-token"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))
    main()
    output = capsys.readouterr()
    assert output.out.strip() == hashlib.sha256(token.encode()).hexdigest()
    assert token not in output.out + output.err


@pytest.mark.parametrize(
    "name",
    [
        "list_security_checks",
        "run_security_checks",
        "get_evidence",
        "start_assessment",
        "get_assessment",
        "list_assessment_results",
        "cancel_assessment",
    ],
)
def test_removed_auditor_tools_are_not_executable(setup, name):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        response = rpc(client, "tools/call", {"name": name, "arguments": {}})
        payload = response.json()
        assert "error" in payload or payload["result"].get("isError") is True
        assert setup.google.calls == []
        assert setup.kubernetes.calls == []
        assert not hasattr(setup.connector, "store")


def test_capabilities_pagination_discovers_every_kind_and_binds_the_caller(setup):
    expected = {item["kind"] for item in setup.connector.capabilities()["gcp_resources"]}
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        arguments = {"provider": "gcp", "page_size": 25}
        seen = []
        first_cursor = None
        while True:
            result = call(client, "capabilities", arguments)
            assert "error" not in result
            assert len(json.dumps(result).encode()) <= setup.settings.max_response_bytes
            assert not result["alicloud_resources"] and not result["kubernetes_resources"]
            assert result["discovery"]["matched_kinds"] == len(expected)
            seen.extend(item["kind"] for item in result["gcp_resources"])
            assert result["discovery"]["returned_kinds"] == len(result["gcp_resources"])
            if not result["next_cursor"]:
                assert result["discovery"]["complete"]
                break
            first_cursor = first_cursor or result["next_cursor"]
            arguments["cursor"] = result["next_cursor"]
        assert set(seen) == expected
        assert len(seen) == len(expected)
        denied = call(
            client, "capabilities", {**arguments, "cursor": first_cursor}, actor="agent-b"
        )
        assert denied["error"]["code"] == "INVALID_ARGUMENT"
        assert setup.google.calls == []


def test_capabilities_adapts_to_small_response_budget_without_storing_results(setup):
    setup.settings.max_response_bytes = 10_000
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        result = call(
            client,
            "capabilities",
            {"provider": "gcp", "kind_prefix": "gcp.compute", "page_size": 200},
        )
        assert "error" not in result
        assert result["gcp_resources"]
        assert result["next_cursor"]
        assert result["discovery"]["returned_kinds"] < result["discovery"]["matched_kinds"]
        assert len(json.dumps(result, separators=(",", ":")).encode()) <= 10_000
        assert not hasattr(setup.connector, "store")


def test_named_kubernetes_read_and_field_selection_still_redact_values(setup):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        result = call(
            client,
            "inspect_kubernetes",
            {
                "queries": [
                    {
                        "cluster": CLUSTER,
                        "kind": "Pod",
                        "operation": "get",
                        "namespace": "apps",
                        "resource_id": "web",
                        "fields": [
                            "data.spec.containers.0.env.0.value",
                            "data.spec.containers.0.image",
                        ],
                    }
                ]
            },
        )["results"][0]
        assert not result["errors"]
        assert result["next_cursor"] is None
        assert result["items"][0]["selected"]["data.spec.containers.0.env.0.value"] == "[REDACTED]"
        assert result["items"][0]["selected"]["data.spec.containers.0.image"] == "example/web:1"
        assert "evidence_id" not in result


def test_all_mcp_tools_advertise_read_only_behavior(setup):
    with TestClient(
        create_app(setup.settings, connector=setup.connector),
        base_url=PUBLIC_URL.removesuffix("/mcp"),
    ) as client:
        tools = rpc(client, "tools/list").json()["result"]["tools"]
        assert len(tools) == 6
        assert all(item["annotations"]["readOnlyHint"] for item in tools)
        assert all(not item["annotations"]["destructiveHint"] for item in tools)
