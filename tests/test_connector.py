"""Integration of stateless reads, scope policy, projection and public cursors."""

import asyncio
import json
from pathlib import Path

import pytest

from sec_auditor.config import Settings
from sec_auditor.connector import CloudConnector
from sec_auditor.cursors import canonical_json
from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.requests import KubernetesQuery, LogQuery, ResourceQuery


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
    settings = Settings(allowed_organizations=["123"], **overrides)
    client, gcp, kubernetes = Google(), GCP(), Kubernetes()
    return CloudConnector(settings, client=client, gcp=gcp, kubernetes=kubernetes)


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


async def test_raw_secrets_do_not_reach_responses_and_no_records_are_stored(tmp_path):
    service = make_service(tmp_path)
    response = await service.collect_resources("agent-a", [vm_query()])
    page = response["results"][0]
    assert "SENSITIVE-STARTUP-CONTENT" not in json.dumps(response)
    assert "enable-oslogin" in json.dumps(response)
    assert page["items"][0]["data"]["metadata"]["items"][1]["value"] == "true"
    assert "evidence_id" not in page
    assert not hasattr(service, "store")
    assert not list(tmp_path.iterdir())


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


async def test_output_budget_rejects_whole_page_without_skipping_rows(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    records = [
        ResourceRecord(
            kind="gcp.compute.instances", name=f"vm-{i}", data={"description": "a" * 1500}
        )
        for i in range(10)
    ]
    result = await service._envelope(
        "agent-a", "test", {}, CollectionResult(items=records, next_page_token="after-large-page")
    )
    assert result["response_truncated"]
    assert result["coverage"]["observed_items"] == 10
    assert result["coverage"]["returned_items"] == 0
    assert not result["coverage"]["collection_complete"]
    assert result["items"] == []
    assert result["next_cursor"] is None
    assert result["errors"][0]["code"] == "RESPONSE_TOO_LARGE"
    assert result["metadata"]["retry_same_input_cursor"]
    assert not list(tmp_path.iterdir())
    selected = await service._envelope(
        "agent-a", "test", {}, CollectionResult(items=records), fields=["name"]
    )
    assert len(selected["items"]) == 10
    assert [row["name"] for row in selected["items"]] == [f"vm-{i}" for i in range(10)]
    assert selected["coverage"]["collection_complete"]


async def test_field_selection_cannot_bypass_security_projection(tmp_path):
    service = make_service(tmp_path)
    response = await service.collect_resources(
        "agent-a", [vm_query(fields=["data.metadata.items.0.value", "data.metadata.items.1.value"])]
    )
    record = response["results"][0]["items"][0]
    assert "SENSITIVE-STARTUP-CONTENT" not in json.dumps(record)
    assert record["selected"]["data.metadata.items.1.value"] == "true"
    assert record["redacted_path_count"] > 0
    assert record["redacted_paths"]
    assert record["provider"] == "gcp"
    assert record["projection"] == "security"


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


async def test_oversized_following_page_can_retry_same_cursor_with_selected_fields(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    calls = []

    async def read(kind, project, **kwargs):
        token = kwargs.get("page_token")
        calls.append(token)
        if token is None:
            return CollectionResult(
                items=[ResourceRecord(kind=kind, name="small", data={"name": "small"})],
                next_page_token="large-page",
            )
        return CollectionResult(
            items=[
                ResourceRecord(
                    kind=kind,
                    name="large",
                    data={"name": "large", **{f"field{i}": "a" * 3000 for i in range(6)}},
                )
            ]
        )

    service.gcp.list_resources = read
    first = (await service.collect_resources("caller", [vm_query()]))["results"][0]
    cursor = first["next_cursor"]
    oversized = (await service.collect_resources("caller", [vm_query(cursor=cursor)]))["results"][0]
    assert oversized["errors"][0]["code"] == "RESPONSE_TOO_LARGE"
    assert not oversized["items"] and oversized["next_cursor"] is None
    narrowed = (
        await service.collect_resources("caller", [vm_query(cursor=cursor, fields=["data.name"])])
    )["results"][0]
    assert narrowed["items"][0]["selected"] == {"data.name": "large"}
    assert narrowed["coverage"]["collection_complete"]
    assert calls == [None, "large-page", "large-page"]


async def test_small_response_budget_enforces_aggregate_batch_bound(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    service.gcp.paged = True
    queries = [vm_query() for _ in range(4)]
    response = await service.collect_resources("caller", queries)
    assert len(canonical_json(response).encode()) <= 10000
    assert len(response["results"]) == 4
    before = len(service.gcp.calls)
    with pytest.raises(ValueError, match="smaller batch"):
        await service.collect_resources("caller", queries + [vm_query()])
    assert len(service.gcp.calls) == before


async def test_metadata_and_error_overflow_cannot_escape_response_budget(tmp_path):
    service = make_service(tmp_path, max_response_bytes=10000)
    response = await service._envelope(
        "caller",
        "test",
        {},
        CollectionResult(
            metadata={f"large{i}": "a" * 3000 for i in range(12)},
            errors=[CollectionError(target="p", code="PARTIAL", message="failure")],
        ),
    )
    assert response["errors"][0]["code"] == "RESPONSE_TOO_LARGE"
    assert response["coverage"]["source_errors"] == 1
    assert len(canonical_json(response).encode()) <= 10000


async def test_dictionary_queries_and_model_copies_receive_the_same_validation(tmp_path):
    service = make_service(tmp_path)
    valid = vm_query().model_dump()
    invalid_copy = vm_query().model_copy(update={"provider": "other-cloud"})
    response = await service.collect_resources("caller", [valid, invalid_copy])
    assert response["targets_with_errors"] == 1
    assert len(service.gcp.calls) == 1
    assert response["results"][1]["errors"][0]["code"] == "INVALID_ARGUMENT"


async def test_named_kubernetes_get_is_scoped_and_uses_normal_projection(tmp_path):
    service = make_service(tmp_path)
    calls = []

    async def get(cluster, kind, resource_id, *, namespace=None):
        calls.append((cluster, kind, resource_id, namespace))
        return await service.kubernetes.list_objects(cluster, kind, namespace=namespace)

    service.kubernetes.get_object = get
    result = await service.inspect_kubernetes(
        "caller",
        [
            {
                "cluster": "projects/project-a/locations/us-central1/clusters/apps",
                "kind": "Pod",
                "namespace": "default",
                "operation": "get",
                "resource_id": "test",
                "fields": ["data.spec.containers.0.env", "data.spec.containers.0.securityContext"],
            }
        ],
    )
    assert result["targets_with_errors"] == 0
    assert calls[0][2:] == ("test", "default")
    assert "POD-SENSITIVE-LITERAL" not in json.dumps(result)
    assert result["results"][0]["items"][0]["selected"][
        "data.spec.containers.0.securityContext"
    ] == {"privileged": True}


@pytest.mark.parametrize("kind", ["Secret", "ConfigMap", "Pod/log", "pods/exec", "CustomResource"])
async def test_forbidden_kubernetes_kinds_fail_before_scope_or_cloud_reads(tmp_path, kind):
    service = make_service(tmp_path)
    result = await service.inspect_kubernetes(
        "caller",
        [
            {
                "cluster": "projects/project-a/locations/us-central1/clusters/apps",
                "kind": kind,
            }
        ],
    )
    assert result["targets_with_errors"] == 1
    assert service.client.calls == service.kubernetes.calls == []


async def test_inventory_and_iam_support_projection_without_storing_records(tmp_path):
    service = make_service(tmp_path)
    inventory = await service.inventory("caller", "organizations/123", fields=["data.project"])
    assert inventory["items"][0]["selected"] == {"data.project": "projects/100"}
    iam = await service.iam_context("caller", "organizations/123", fields=["data.bindings"])
    assert iam["items"][0]["selected"] == {"data.bindings": []}
    assert not list(tmp_path.iterdir())


async def test_invalid_fields_fail_before_inventory_or_iam_calls(tmp_path):
    service = make_service(tmp_path)
    with pytest.raises(ValueError, match="fields"):
        await service.inventory("caller", "organizations/123", fields=["data..project"])
    with pytest.raises(ValueError, match="fields"):
        await service.iam_context("caller", "organizations/123", fields=[])
    assert service.gcp.calls == service.client.calls == []


async def test_concurrency_is_bounded_across_simultaneous_batches(tmp_path):
    service = make_service(tmp_path, max_concurrency=2)
    active = peak = 0

    async def read(kind, project, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return CollectionResult()
        finally:
            active -= 1

    service.gcp.list_resources = read
    first, second = await asyncio.gather(
        service.collect_resources("caller-a", [vm_query() for _ in range(4)]),
        service.collect_resources("caller-b", [vm_query() for _ in range(4)]),
    )
    assert first["targets_with_errors"] == second["targets_with_errors"] == 0
    assert peak == 2
