"""Integration of scope policy, collectors, evidence, checks and public cursors."""

import json
from pathlib import Path

import pytest

from sec_auditor.checks import list_checks
from sec_auditor.config import Settings
from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.requests import KubernetesQuery, LogQuery, ResourceQuery
from sec_auditor.service import SecurityService


class Google:
    def __init__(self):
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append((url, params))
        identifier = url.rsplit("/", 1)[-1]
        identities = {
            "project-a": ("project-a", "100", "123"),
            "100": ("project-a", "100", "123"),
            "project-b": ("project-b", "200", "999"),
            "200": ("project-b", "200", "999"),
        }
        project, number, org = identities[identifier]
        return {
            "name": f"projects/{number}",
            "projectId": project,
            "parent": f"organizations/{org}",
            "state": "ACTIVE",
        }

    async def aclose(self):
        pass


class GCP:
    def __init__(self):
        self.calls = []
        self.paged = False
        self.error = False

    def capabilities(self):
        return []

    async def list_resources(self, kind, project, **kwargs):
        self.calls.append((kind, project, kwargs))
        return CollectionResult(
            items=[
                ResourceRecord(
                    kind=kind,
                    name=f"projects/{project}/instances/vm-a",
                    project=project,
                    data={
                        "name": "vm-a",
                        "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}]}],
                        "metadata": {
                            "items": [
                                {"key": "startup-script", "value": "SENSITIVE-STARTUP-CONTENT"},
                                {"key": "enable-oslogin", "value": "true"},
                            ]
                        },
                    },
                )
            ],
            next_page_token="native-page-two"
            if self.paged and not kwargs.get("page_token")
            else None,
            errors=[
                CollectionError(target=project, code="PARTIAL", message="One zone was unavailable")
            ]
            if self.error
            else [],
        )

    async def search_assets(self, scope, query="", asset_types=None, **kwargs):
        self.calls.append(("search", scope, kwargs))
        return CollectionResult(
            items=[
                ResourceRecord(
                    kind="gcp.asset.search",
                    name="projects/100",
                    data={"project": "projects/100"},
                    freshness="inventory",
                )
            ]
        )

    async def list_assets(self, scope, asset_types=None, **kwargs):
        return await self.search_assets(scope, asset_types=asset_types, **kwargs)

    async def search_iam_policies(self, scope, query="", asset_types=None, **kwargs):
        return await self.search_assets(scope, query, asset_types, **kwargs)

    async def get_iam_policy(self, scope):
        return CollectionResult(
            items=[ResourceRecord(kind="gcp.iam.policy", name=scope, data={"bindings": []})]
        )


class Kubernetes:
    def __init__(self):
        self.calls = []

    def capabilities(self):
        return []

    async def list_objects(self, cluster, kind, **kwargs):
        self.calls.append((cluster, kind, kwargs))
        return CollectionResult(
            items=[
                ResourceRecord(
                    kind="k8s.Pod",
                    name=cluster + "/namespaces/default/pods/test",
                    data={
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "example/app:v1",
                                    "env": [{"name": "PASSWORD", "value": "POD-SENSITIVE-LITERAL"}],
                                    "securityContext": {"privileged": True},
                                }
                            ]
                        }
                    },
                )
            ]
        )

    async def aclose(self):
        pass


def make_service(tmp_path: Path, **overrides):
    settings = Settings(
        allowed_organizations=["123"], state_path=tmp_path / "state.sqlite3", **overrides
    )
    client, gcp, kubernetes = Google(), GCP(), Kubernetes()
    return SecurityService(settings, client=client, gcp=gcp, kubernetes=kubernetes)


def vm_query(**kwargs):
    return ResourceQuery(kind="gcp.compute.instances", project="project-a", **kwargs)


async def test_bulk_scope_denial_is_partial_and_never_calls_unauthorized_collector(tmp_path):
    service = make_service(tmp_path)
    result = await service.collect_resources(
        "agent-a", [vm_query(), ResourceQuery(kind="gcp.compute.instances", project="project-b")]
    )
    assert result["targets_requested"] == 2
    assert result["targets_with_errors"] == 1
    assert len(service.gcp.calls) == 1
    assert service.gcp.calls[0][1] == "project-a"
    denied = result["results"][1]
    assert denied["errors"][0]["code"] == "SCOPE_DENIED"
    assert not denied["coverage"]["collection_complete"]


async def test_raw_secrets_do_not_reach_inline_or_stored_evidence(tmp_path):
    service = make_service(tmp_path)
    response = await service.collect_resources("agent-a", [vm_query()])
    page = response["results"][0]
    evidence = await service.evidence("agent-a", page["evidence_id"])
    assert "SENSITIVE-STARTUP-CONTENT" not in json.dumps(response)
    assert "SENSITIVE-STARTUP-CONTENT" not in json.dumps(evidence)
    assert "enable-oslogin" in json.dumps(evidence)
    assert page["items"][0]["data"]["metadata"]["items"][1]["value"] == "true"
    with pytest.raises(ValueError, match="not found"):
        await service.evidence("agent-b", page["evidence_id"])


async def test_pagination_is_bound_to_caller_and_complete_query(tmp_path):
    service = make_service(tmp_path)
    service.gcp.paged = True
    first = (await service.collect_resources("agent-a", [vm_query()]))["results"][0]
    assert not first["coverage"]["collection_complete"]
    cursor = first["next_cursor"]
    assert cursor and cursor != "native-page-two"
    for actor, query in [
        ("agent-b", vm_query(cursor=cursor)),
        ("agent-a", vm_query(cursor=cursor, page_size=10)),
    ]:
        before = len(service.gcp.calls)
        denied = await service.collect_resources(actor, [query])
        assert denied["targets_with_errors"] == 1
        assert len(service.gcp.calls) == before
    second = (await service.collect_resources("agent-a", [vm_query(cursor=cursor)]))["results"][0]
    assert service.gcp.calls[-1][2]["page_token"] == "native-page-two"
    assert second["next_cursor"] is None
    assert second["coverage"]["collection_complete"]


async def test_partial_source_failure_does_not_hide_successful_items(tmp_path):
    service = make_service(tmp_path)
    service.gcp.error = True
    result = (await service.collect_resources("agent-a", [vm_query()]))["results"][0]
    assert result["items"]
    assert result["errors"][0]["code"] == "PARTIAL"
    assert result["coverage"]["source_errors"] == 1
    assert not result["coverage"]["collection_complete"]


async def test_kubernetes_is_scoped_and_projected(tmp_path):
    service = make_service(tmp_path)
    result = await service.inspect_kubernetes(
        "agent-a",
        [KubernetesQuery(cluster="projects/project-a/locations/us-central1/clusters/apps")],
    )
    assert result["targets_with_errors"] == 0
    assert "POD-SENSITIVE-LITERAL" not in json.dumps(result)
    assert (
        result["results"][0]["items"][0]["data"]["spec"]["containers"][0]["securityContext"][
            "privileged"
        ]
        is True
    )
    denied = await service.inspect_kubernetes(
        "agent-a",
        [KubernetesQuery(cluster="projects/project-b/locations/us-central1/clusters/apps")],
    )
    assert denied["targets_with_errors"] == 1
    assert len(service.kubernetes.calls) == 1


async def test_output_budget_provides_evidence_instead_of_dropping_rows(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    records = [
        ResourceRecord(
            kind="gcp.compute.instances", name=f"vm-{i}", data={"description": "a" * 1500}
        )
        for i in range(10)
    ]
    result = await service._envelope("agent-a", "test", {}, CollectionResult(items=records))
    assert result["response_truncated"]
    assert result["coverage"]["observed_items"] == 10
    seen = list(result["items"])
    cursor = result["next_evidence_cursor"]
    while cursor:
        page = await service.evidence("agent-a", result["evidence_id"], cursor=cursor)
        seen.extend(page["items"])
        cursor = page["next_cursor"]
    assert len(seen) == 10


async def test_oversized_evidence_can_be_retrieved_with_explicit_field_projection(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    identifier = service.store.put_evidence(
        "agent-a", [{"name": "large", "data": {"large": "a" * 15000, "safe": True}}]
    )
    oversized = await service.evidence("agent-a", identifier)
    assert oversized["oversized_item"] == 0
    assert oversized["response_truncated"]
    projected = await service.evidence("agent-a", identifier, fields=["data.safe"])
    assert projected["items"][0]["selected"] == {"data.safe": True}


async def test_checks_evaluate_internal_config_and_link_sanitized_evidence(tmp_path):
    service = make_service(tmp_path)
    check = next(
        check
        for check in list_checks()
        if check.resource_kind == "gcp.compute.instances" and "external" in check.id
    )
    response = await service.run_checks("agent-a", [vm_query()], [], [check.id], False)
    page = response["results"][0]
    assert page["evaluation"]["checks_evaluated"] == 1
    assert page["evaluation"]["status_counts"] == {"fail": 1}
    assert page["items"][0]["status"] == "fail"
    stored = await service.evidence("agent-a", page["items"][0]["evidence_id"])
    assert stored["items"][0]["kind"] == "gcp.compute.instances"
    assert "SENSITIVE-STARTUP-CONTENT" not in json.dumps(stored)


async def test_unsupported_check_id_fails_before_read(tmp_path):
    service = make_service(tmp_path)
    with pytest.raises(ValueError, match="Unknown"):
        await service.run_checks("agent-a", [vm_query()], [], ["invented.check"], False)
    assert service.gcp.calls == []


async def test_no_matching_checks_is_not_a_pass(tmp_path):
    service = make_service(tmp_path)
    response = await service.run_checks("agent-a", [vm_query()], [], [], False)
    page = response["results"][0]
    assert page["evaluation"]["checks_evaluated"] == 0
    assert any("not a passing" in message for message in page["warnings"])


async def test_log_cursor_reuses_original_default_time_window(tmp_path):
    service = make_service(tmp_path)

    class Logs:
        def __init__(self):
            self.calls = []

        async def query(self, project, **kwargs):
            self.calls.append(kwargs)
            return CollectionResult(
                next_page_token="next" if not kwargs["page_token"] else None,
                metadata={"start_time": "2025-01-01T00:00:00Z", "end_time": "2025-01-01T01:00:00Z"},
            )

    service.logs = Logs()
    first = await service.query_logs("agent-a", [LogQuery(project="project-a")])
    cursor = first["results"][0]["next_cursor"]
    await service.query_logs("agent-a", [LogQuery(project="project-a", cursor=cursor)])
    assert service.logs.calls[-1]["start_time"] == "2025-01-01T00:00:00Z"
    assert service.logs.calls[-1]["end_time"] == "2025-01-01T01:00:00Z"


async def test_inventory_scope_and_cursor_boundaries(tmp_path):
    service = make_service(tmp_path)
    allowed = await service.inventory("agent-a", "organizations/123")
    assert allowed["items"]
    with pytest.raises(ValueError):
        await service.inventory("agent-a", "organizations/999")
    assert len(service.gcp.calls) == 1


async def test_invalid_page_size_and_oversized_batch_do_not_call_backend(tmp_path):
    service = make_service(tmp_path, max_batch_size=1)
    with pytest.raises(ValueError):
        await service.collect_resources("agent-a", [vm_query(), vm_query()])
    response = await service.collect_resources("agent-a", [vm_query(page_size=500)])
    assert response["targets_with_errors"] == 1
    assert service.gcp.calls == []
