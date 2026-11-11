"""Durable assessments preserve budgets, partial coverage, and caller ownership."""

import asyncio
import time

import pytest

from sec_auditor.config import Settings
from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.requests import AssessmentRequest
from sec_auditor.service import SecurityService
from sec_auditor.state import StateStore
from sec_auditor.transport import CloudAPIError

KIND = "gcp.compute.instances"
CHECK = "gcp.compute.instance.no_ip_forwarding"
CLUSTER = "projects/project-a/locations/us-central1/clusters/apps"


class FakeClient:
    def __init__(self):
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append(url)
        identifier = url.rsplit("/", 1)[-1]
        if identifier in {"project-a", "10001"}:
            return {
                "projectId": "project-a",
                "name": "projects/10001",
                "state": "ACTIVE",
                "parent": "organizations/123",
            }
        if identifier in {"project-b", "20002"}:
            return {
                "projectId": "project-b",
                "name": "projects/20002",
                "state": "ACTIVE",
                "parent": "organizations/999",
            }
        raise CloudAPIError("PERMISSION_DENIED", "Project lookup denied", status_code=403)

    async def aclose(self):
        pass


class FakeGCP:
    def __init__(self, pages=None, discovery=None, callback=None):
        self.pages = pages or {}
        self.discovery = discovery or {}
        self.callback = callback
        self.calls = []
        self.discovery_calls = []

    def capabilities(self):
        return []

    async def list_resources(self, kind, project, *, location=None, page_size=100, page_token=None):
        self.calls.append((kind, project, page_token))
        if self.callback:
            await self.callback(kind, project, page_token)
        value = self.pages.get((kind, page_token), CollectionResult())
        if isinstance(value, Exception):
            raise value
        return value.model_copy(deep=True)

    async def search_assets(
        self, scope, query="", asset_types=None, *, page_size=100, page_token=None
    ):
        self.discovery_calls.append((scope, page_token))
        value = self.discovery.get(page_token, CollectionResult())
        if isinstance(value, Exception):
            raise value
        return value.model_copy(deep=True)


class FakeKubernetes:
    def __init__(self, pages=None):
        self.pages = pages or {}
        self.calls = []

    def capabilities(self):
        return []

    async def list_objects(self, cluster, kind, *, namespace=None, page_size=100, page_token=None):
        self.calls.append((cluster, kind, page_token))
        value = self.pages.get((kind, page_token), CollectionResult())
        if isinstance(value, Exception):
            raise value
        return value.model_copy(deep=True)

    async def aclose(self):
        pass


def vm(name="vm", *, forwarding=True, data=None):
    return ResourceRecord(
        kind=KIND,
        name=f"projects/project-a/zones/us-central1-a/instances/{name}",
        project="project-a",
        data={"canIpForward": forwarding} if data is None else data,
    )


def request(**changes):
    values = {
        "projects": ["project-a"],
        "resource_kinds": [KIND],
        "check_ids": [CHECK],
        "include_kubernetes": False,
    }
    values.update(changes)
    return AssessmentRequest(**values)


def service(tmp_path, *, gcp=None, kubernetes=None, **settings):
    config = Settings(
        allowed_organizations=["123"], state_path=tmp_path / "state.sqlite3", **settings
    )
    return SecurityService(
        config, client=FakeClient(), gcp=gcp or FakeGCP(), kubernetes=kubernetes or FakeKubernetes()
    )


async def execute(service, request_, *, actor="caller-a", before=None):
    job_id = service.store.enqueue(actor, request_.model_dump())
    claimed = service.store.claim()
    assert claimed is not None and claimed["id"] == job_id
    if before:
        before(job_id)
    result = await service._assessment(actor, request_, job_id=job_id)
    service.store.finish(job_id, result, status="cancelled" if result["cancelled"] else "completed")
    return job_id, result


async def test_assessment_follows_empty_native_pages_and_preserves_unknowns(tmp_path):
    provider = FakeGCP(
        {
            (KIND, None): CollectionResult(next_page_token="page-2"),
            (KIND, "page-2"): CollectionResult(
                items=[vm("unknown", data={})], next_page_token="page-3"
            ),
            (KIND, "page-3"): CollectionResult(items=[vm("passing", forwarding=False)]),
        }
    )
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request())
    assert [token for _, _, token in provider.calls] == [None, "page-2", "page-3"]
    assert outcome["coverage"]["api_pages"] == 3
    assert outcome["coverage"]["resources_examined"] == 2
    assert outcome["check_status_counts"] == {"unknown": 1, "pass": 1}
    assert outcome["evaluation_has_unknowns"] is True
    assert outcome["coverage_complete"] is True  # Read coverage is distinct from check success.
    assert [item["status"] for item in outcome["findings"]] == ["unknown"]
    await audit.close()


async def test_partial_errors_prevent_complete_coverage_even_when_checks_pass(tmp_path):
    provider = FakeGCP(
        {
            (KIND, None): CollectionResult(
                items=[vm(forwarding=False)],
                errors=[
                    CollectionError(
                        target="zone", code="PERMISSION_DENIED", message="One scope was denied"
                    )
                ],
            )
        }
    )
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request())
    assert outcome["check_status_counts"] == {"pass": 1}
    assert outcome["coverage_complete"] is False
    assert outcome["error_count"] == 1
    assert outcome["coverage"]["collections_with_errors"] == 1
    await audit.close()


async def test_outside_project_never_reaches_collector_and_is_not_a_clean_result(tmp_path):
    provider = FakeGCP({(KIND, None): CollectionResult(items=[vm(forwarding=False)])})
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request(projects=["project-b"]))
    assert provider.calls == []
    assert outcome["coverage_complete"] is False
    assert outcome["errors"][0]["code"] == "SCOPE_DENIED"
    assert outcome["check_status_counts"] == {}
    assert any("does not establish" in warning for warning in outcome["warnings"])
    await audit.close()


async def test_empty_collection_never_produces_passing_check_rows(tmp_path):
    audit = service(tmp_path)
    _, outcome = await execute(audit, request())
    assert outcome["findings"] == []
    assert outcome["check_status_counts"] == {}
    assert outcome["coverage"].get("checks_evaluated", 0) == 0
    assert any("No applicable checks" in warning for warning in outcome["warnings"])
    await audit.close()


async def test_inaccessible_discovery_does_not_imply_empty_organization(tmp_path):
    provider = FakeGCP(
        discovery={
            None: CloudAPIError("PERMISSION_DENIED", "Inventory unavailable", status_code=403)
        }
    )
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request(projects=[], scope="organizations/123"))
    assert outcome["coverage_complete"] is False
    assert outcome["errors"][0]["code"] == "PERMISSION_DENIED"
    assert outcome["coverage"]["projects_discovered"] == 0
    assert provider.calls == []
    await audit.close()


async def test_discovery_can_continue_after_an_empty_page(tmp_path):
    project = ResourceRecord(
        kind="gcp.asset", name="//cloudresourcemanager.googleapis.com/projects/10001", data={}
    )
    provider = FakeGCP(
        discovery={
            None: CollectionResult(next_page_token="more-projects"),
            "more-projects": CollectionResult(items=[project]),
        }
    )
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request(projects=[], scope="organizations/123"))
    assert provider.discovery_calls == [
        ("organizations/123", None),
        ("organizations/123", "more-projects"),
    ]
    assert provider.calls == [(KIND, "project-a", None)]
    assert outcome["coverage"]["projects_discovered"] == 1
    await audit.close()


async def test_repeated_native_token_stops_with_pagination_error(tmp_path):
    provider = FakeGCP(
        {
            (KIND, None): CollectionResult(next_page_token="same"),
            (KIND, "same"): CollectionResult(next_page_token="same"),
        }
    )
    audit = service(tmp_path, gcp=provider)
    _, outcome = await execute(audit, request())
    assert len(provider.calls) == 2
    assert outcome["coverage_complete"] is False
    assert any(error["code"] == "PAGINATION_LOOP" for error in outcome["errors"])
    await audit.close()


async def test_resource_budget_truncation_is_explicit(tmp_path):
    provider = FakeGCP({(KIND, None): CollectionResult(items=[vm(str(i)) for i in range(5)])})
    audit = service(tmp_path, gcp=provider, max_scan_resources=2)
    _, outcome = await execute(audit, request())
    assert outcome["coverage"]["resources_examined"] == 2
    assert len(outcome["findings"]) == 2
    assert "max_scan_resources" in outcome["limits_reached"]
    assert outcome["coverage_complete"] is False
    await audit.close()


async def test_page_budget_is_shared_atomically_across_concurrent_collectors(tmp_path, monkeypatch):
    provider = FakeGCP()
    audit = service(tmp_path, gcp=provider, max_scan_pages=1, max_concurrency=8)
    heartbeat = audit.store.heartbeat

    def delayed_heartbeat(*args, **kwargs):
        time.sleep(0.005)  # Make simultaneous budget checks overlap deterministically.
        return heartbeat(*args, **kwargs)

    monkeypatch.setattr(audit.store, "heartbeat", delayed_heartbeat)
    _, outcome = await execute(
        audit, request(resource_kinds=[KIND, "gcp.storage.buckets", "gcp.compute.firewalls"])
    )
    assert len(provider.calls) <= 1
    assert outcome["coverage"]["api_pages"] <= 1
    assert outcome["coverage_complete"] is False
    assert "max_scan_pages" in outcome["limits_reached"]
    await audit.close()


async def test_missing_location_is_explicit_unchecked_coverage(tmp_path):
    audit = service(tmp_path)
    _, outcome = await execute(
        audit,
        request(resource_kinds=["gcp.run.services"], check_ids=["gcp.run.restricted_ingress"]),
    )
    assert audit.gcp.calls == []
    assert outcome["coverage_complete"] is False
    assert outcome["coverage"]["collections_not_started"] == 1
    assert outcome["errors"][0]["code"] == "LOCATION_REQUIRED"
    await audit.close()


async def test_requested_cancellation_before_collection_reads_no_resources(tmp_path):
    audit = service(tmp_path)
    _, outcome = await execute(
        audit, request(), before=lambda identifier: audit.store.cancel("caller-a", identifier)
    )
    assert audit.gcp.calls == []
    assert outcome["cancelled"] is True
    assert outcome["coverage_complete"] is False
    await audit.close()


async def test_cancellation_during_final_page_is_reflected_in_terminal_result(tmp_path):
    audit = service(tmp_path)
    job_id = audit.store.enqueue("caller-a", request().model_dump())
    audit.store.claim()

    async def cancel_during_read(*_args):
        audit.store.cancel("caller-a", job_id)

    audit.gcp = FakeGCP({(KIND, None): CollectionResult(items=[vm()])}, callback=cancel_during_read)
    outcome = await audit._assessment("caller-a", request(), job_id=job_id)
    assert outcome["cancelled"] is True
    assert outcome["coverage_complete"] is False
    await audit.close()


async def test_ignored_explicit_cluster_request_is_rejected(tmp_path):
    audit = service(tmp_path)
    with pytest.raises(ValueError):
        invalid = AssessmentRequest(clusters=[CLUSTER], include_kubernetes=False)
        await audit.start_assessment("caller-a", invalid)
    assert audit.gcp.calls == []
    await audit.close()


async def test_outside_cluster_project_is_rejected_before_kubernetes_call(tmp_path):
    audit = service(tmp_path)
    _, outcome = await execute(
        audit,
        request(
            projects=[],
            clusters=[CLUSTER.replace("project-a", "project-b")],
            resource_kinds=[],
            include_kubernetes=True,
            kubernetes_kinds=["Pod"],
            check_ids=["k8s.pod.privileged"],
        ),
    )
    assert audit.kubernetes.calls == []
    assert outcome["coverage_complete"] is False
    assert any(error["code"] == "SCOPE_DENIED" for error in outcome["errors"])
    await audit.close()


async def test_findings_and_evidence_remain_owned_by_the_original_caller(tmp_path):
    private = "NEVER_PERSIST_RAW_METADATA_VALUE"
    provider = FakeGCP(
        {
            (KIND, None): CollectionResult(
                items=[
                    vm(
                        str(i),
                        data={
                            "canIpForward": True,
                            "metadata": {"items": [{"key": "unrelated", "value": private}]},
                        },
                    )
                    for i in range(3)
                ]
            )
        }
    )
    audit = service(tmp_path, gcp=provider)
    identifier, outcome = await execute(audit, request())
    first = await audit.assessment_results("caller-a", identifier, page_size=1)
    second = await audit.assessment_results(
        "caller-a", identifier, page_size=1, cursor=first["next_cursor"]
    )
    assert first["items"][0]["resource"] != second["items"][0]["resource"]
    assert second["offset"] == 1
    evidence_id = outcome["findings"][0]["evidence_id"]
    with pytest.raises(ValueError):
        await audit.assessment_results("caller-b", identifier, cursor=first["next_cursor"])
    with pytest.raises(ValueError):
        await audit.get_assessment("caller-b", identifier)
    with pytest.raises(ValueError):
        await audit.cancel_assessment("caller-b", identifier)
    with pytest.raises(ValueError):
        await audit.evidence("caller-b", evidence_id)
    assert private not in str(audit.store.get_evidence("caller-a", evidence_id))
    with audit.store.connection() as conn:
        assert all(private not in row[0] for row in conn.execute("SELECT payload FROM evidence"))
    await audit.close()


async def test_assessment_cursor_cannot_be_reused_for_another_job(tmp_path):
    provider = FakeGCP({(KIND, None): CollectionResult(items=[vm(str(i)) for i in range(2)])})
    audit = service(tmp_path, gcp=provider)
    first_id, _ = await execute(audit, request())
    second_id, _ = await execute(audit, request())
    page = await audit.assessment_results("caller-a", first_id, page_size=1)
    with pytest.raises(ValueError):
        await audit.assessment_results("caller-a", second_id, cursor=page["next_cursor"])
    await audit.close()


async def test_oversized_finding_does_not_produce_an_unexplained_cursor_loop(tmp_path):
    audit = service(tmp_path, max_response_bytes=10000)
    identifier = audit.store.enqueue("caller-a", request().model_dump())
    audit.store.claim()
    outcome = {
        "coverage_complete": True,
        "findings": [
            {"check_id": CHECK, "resource": "vm", "summary": "x" * 12000},
            {"check_id": CHECK, "resource": "second-vm"},
        ],
    }
    audit.store.finish(identifier, outcome)
    page = await audit.assessment_results("caller-a", identifier, page_size=1)
    assert page["items"] == []
    assert page["oversized_finding_index"] == 0
    evidence_id = page["oversized_finding_evidence_id"]
    selected = await audit.evidence("caller-a", evidence_id, fields=["check_id", "resource"])
    assert selected["items"][0]["selected"]["resource"] == "vm"
    next_page = await audit.assessment_results(
        "caller-a", identifier, page_size=1, cursor=page["next_cursor"]
    )
    assert next_page["items"][0]["resource"] == "second-vm"
    with pytest.raises(ValueError):
        await audit.evidence("caller-b", evidence_id)
    await audit.close()


async def test_expired_running_job_replays_safely_after_restart(tmp_path):
    initial = service(tmp_path)
    identifier = initial.store.enqueue("caller-a", request().model_dump())
    initial.store.claim()
    with initial.store.connection() as conn:
        conn.execute("UPDATE jobs SET lease_until=? WHERE id=?", (time.time() - 1, identifier))
    await initial.close()
    provider = FakeGCP(
        {
            (KIND, None): CollectionResult(next_page_token="second"),
            (KIND, "second"): CollectionResult(items=[vm()]),
        }
    )
    restarted = service(tmp_path, gcp=provider)
    await restarted.start()
    try:
        async with asyncio.timeout(3):
            while True:
                status = await restarted.get_assessment("caller-a", identifier)
                if status["status"] in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(0.01)
        assert status["status"] == "completed"
        assert status["summary"]["coverage_complete"] is True
        assert status["stored_findings"] == 1
        assert [token for _, _, token in provider.calls] == [None, "second"]
    finally:
        await restarted.close()


async def test_queued_cancellation_survives_store_reopen(tmp_path):
    audit = service(tmp_path)
    identifier = audit.store.enqueue("caller-a", request().model_dump())
    audit.store.cancel("caller-a", identifier)
    reopened = StateStore(audit.settings.state_path)
    assert reopened.claim() is None
    assert reopened.get_job("caller-a", identifier)["status"] == "cancelled"
    await audit.close()
