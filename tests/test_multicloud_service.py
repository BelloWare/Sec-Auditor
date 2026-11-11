"""Real provider adapters behind the shared authorization/evidence service."""

import json
from collections import deque

import pytest
from pydantic import ValidationError

from sec_auditor.config import Settings
from sec_auditor.models import CollectionResult, ResourceRecord
from sec_auditor.providers.alicloud import AlibabaProvider
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.requests import AssessmentRequest, KubernetesQuery, LogQuery, ResourceQuery
from sec_auditor.service import SecurityService

ACCOUNT = "1234567890123456"
OTHER_ACCOUNT = "9876543210987654"
REGION = "ap-southeast-1"
ACK = f"accounts/{ACCOUNT}/regions/{REGION}/clusters/c-audit"


class GoogleClient:
    def __init__(self, *responses):
        self.responses = deque(responses)
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append(("GET", url, params))
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/"):
            identifier = url.rsplit("/", 1)[-1]
            names = {
                "project-a": ("project-a", "100", "123"),
                "100": ("project-a", "100", "123"),
                "project-b": ("project-b", "200", "999"),
                "200": ("project-b", "200", "999"),
            }
            project, number, organization = names[identifier]
            return {
                "name": f"projects/{number}",
                "projectId": project,
                "parent": f"organizations/{organization}",
                "state": "ACTIVE",
            }
        if url.endswith("/v3/folders/456"):
            return {"name": "folders/456", "parent": "organizations/123", "state": "ACTIVE"}
        if url.endswith("/v3/folders/789"):
            return {"name": "folders/789", "parent": "organizations/999", "state": "ACTIVE"}
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    async def post_read(self, url, json, params=None):
        self.calls.append(("POST", url, json, params))
        return self.responses.popleft()

    async def aclose(self):
        pass


class AlibabaClient:
    def __init__(self, settings, *responses):
        self.settings = settings
        self.responses = deque(responses)
        self.calls = []

    async def execute(self, account_id, operation_id, *, region=None, parameters=None):
        self.calls.append((account_id, operation_id, region, parameters))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    async def aclose(self):
        pass


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
                    provider="alicloud",
                    account_id=ACCOUNT,
                    kind="k8s.Pod",
                    name=cluster + "/namespaces/default/pods/app",
                    data={
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "env": [{"name": "PRIVATE", "value": "POD-LITERAL-CONTENT"}],
                                }
                            ]
                        }
                    },
                )
            ]
        )

    async def aclose(self):
        pass


def make_service(tmp_path, *, google=(), alibaba=(), registered=False, **settings):
    if registered:
        settings["alicloud_kubernetes_clusters"] = {
            ACK: {
                "server": "https://ack.example.invalid",
                "ca_file": tmp_path / "ca.pem",
                "token_file": tmp_path / "token",
            }
        }
    config = Settings(
        allowed_organizations=["123"],
        allowed_alicloud_accounts=[ACCOUNT],
        allowed_alicloud_regions=[REGION],
        state_path=tmp_path / "state.sqlite3",
        **settings,
    )
    google_client = GoogleClient(*google)
    alibaba_client = AlibabaClient(config, *alibaba)
    kubernetes = Kubernetes()
    return SecurityService(
        config,
        client=google_client,
        gcp=GCPProvider(google_client),
        alicloud_client=alibaba_client,
        alicloud=AlibabaProvider(alibaba_client),
        kubernetes=Kubernetes(),
        registered_kubernetes=kubernetes,
    )


def gcp_query(**kwargs):
    return ResourceQuery(kind="gcp.compute.instances", project="project-a", **kwargs)


def ali_query(**kwargs):
    values = {
        "provider": "alicloud",
        "account_id": ACCOUNT,
        "location": REGION,
        "kind": "alicloud.ecs.instances",
    }
    values.update(kwargs)
    return ResourceQuery(**values)


async def execute_assessment(service, request):
    queued = await service.start_assessment("agent-a", request)
    job = service.store.claim()
    assert job["id"] == queued["assessment_id"]
    result = await service._assessment("agent-a", request, job_id=job["id"])
    service.store.finish(job["id"], result)
    return result


@pytest.mark.parametrize(
    "values",
    [
        {"provider": "alicloud", "kind": "gcp.compute.instances", "account_id": ACCOUNT},
        {"kind": "gcp.compute.instances", "project": "project-a", "scope": "organizations/123"},
        {"kind": "gcp.compute.instances", "project": "project-a", "account_id": ACCOUNT},
        {
            "provider": "alicloud",
            "kind": "alicloud.ecs.instances",
            "account_id": ACCOUNT,
            "project": "project-a",
        },
        {"kind": "gcp.compute.instances"},
    ],
)
def test_query_schema_rejects_mixed_or_missing_authority(values):
    with pytest.raises(ValidationError):
        ResourceQuery(**values)


async def test_legacy_gcp_and_alibaba_bulk_route_and_project_evidence(tmp_path):
    service = make_service(
        tmp_path,
        google=(
            {
                "items": {
                    "zones/us-central1-a": {
                        "instances": [{"name": "vm-gcp", "canIpForward": False}]
                    }
                }
            },
        ),
        alibaba=(
            {
                "Instances": {
                    "Instance": [{"InstanceId": "i-ali", "UserData": "ALI-BOOTSTRAP-SECRET"}]
                },
                "RequestId": "r",
            },
        ),
    )
    response = await service.collect_resources("agent-a", [gcp_query(), ali_query()])
    assert response["targets_with_errors"] == 0
    first, second = response["results"]
    assert first["items"][0]["provider"] == "gcp"
    assert second["items"][0]["provider"] == "alicloud"
    assert second["items"][0]["account_id"] == ACCOUNT
    assert service.alicloud_client.calls[0][:3] == (ACCOUNT, "ecs.DescribeInstances", REGION)
    evidence = await service.evidence("agent-a", second["evidence_id"])
    assert "ALI-BOOTSTRAP-SECRET" not in json.dumps(response)
    assert "ALI-BOOTSTRAP-SECRET" not in json.dumps(evidence)
    with pytest.raises(ValueError, match="not found"):
        await service.evidence("other-agent", second["evidence_id"])
    await service.close()


async def test_mixed_bulk_retains_success_and_never_calls_denied_alibaba_targets(tmp_path):
    service = make_service(
        tmp_path,
        google=({"items": {}},),
        alibaba=({"Instances": {"Instance": []}, "RequestId": "r"},),
    )
    result = await service.collect_resources(
        "agent-a",
        [
            gcp_query(),
            ali_query(),
            ali_query(account_id=OTHER_ACCOUNT),
            ali_query(location="cn-hangzhou"),
        ],
    )
    assert result["targets_requested"] == 4
    assert result["targets_with_errors"] == 2
    assert len(service.alicloud_client.calls) == 1
    assert all(page["coverage"]["collection_complete"] for page in result["results"][:2])
    for denied in result["results"][2:]:
        assert denied["errors"][0]["code"] == "SCOPE_DENIED"
        assert not denied["coverage"]["collection_complete"]
    await service.close()


async def test_alibaba_native_cursor_binds_actor_provider_account_and_query(tmp_path):
    service = make_service(
        tmp_path,
        alibaba=(
            {"Instances": {"Instance": []}, "NextToken": "ali-next"},
            {"Instances": {"Instance": []}, "RequestId": "r"},
        ),
    )
    first = (await service.collect_resources("agent-a", [ali_query()]))["results"][0]
    cursor = first["next_cursor"]
    assert cursor and cursor != "ali-next"
    for actor, query in [
        ("other-agent", ali_query(cursor=cursor)),
        ("agent-a", ali_query(account_id=OTHER_ACCOUNT, cursor=cursor)),
        ("agent-a", ali_query(page_size=11, cursor=cursor)),
        ("agent-a", gcp_query(cursor=cursor)),
    ]:
        before = len(service.client.calls), len(service.alicloud_client.calls)
        result = await service.collect_resources(actor, [query])
        assert result["targets_with_errors"] == 1
        assert before == (len(service.client.calls), len(service.alicloud_client.calls))
    last = (await service.collect_resources("agent-a", [ali_query(cursor=cursor)]))["results"][0]
    assert last["coverage"]["collection_complete"]
    assert service.alicloud_client.calls[-1][3]["NextToken"] == "ali-next"
    await service.close()


async def test_actiontrail_cursor_freezes_default_time_window_at_service_boundary(tmp_path):
    service = make_service(
        tmp_path,
        alibaba=({"Events": [], "NextToken": "next-log-page"}, {"Events": [], "RequestId": "r"}),
    )
    query = LogQuery(provider="alicloud", account_id=ACCOUNT, location=REGION)
    first = (await service.query_logs("agent-a", [query]))["results"][0]
    assert first["next_cursor"]
    resumed = query.model_copy(update={"cursor": first["next_cursor"]})
    second = (await service.query_logs("agent-a", [resumed]))["results"][0]
    assert second["coverage"]["collection_complete"]
    first_parameters = service.alicloud_client.calls[0][3]
    second_parameters = service.alicloud_client.calls[1][3]
    assert second_parameters["StartTime"] == first_parameters["StartTime"]
    assert second_parameters["EndTime"] == first_parameters["EndTime"]
    assert second_parameters["NextToken"] == "next-log-page"
    await service.close()


async def test_org_query_uses_authorized_scope_and_denies_foreign_organization(tmp_path):
    service = make_service(tmp_path, google=({"principalAccessBoundaryPolicies": []},))
    result = await service.collect_resources(
        "agent-a",
        [
            ResourceQuery(
                kind="gcp.iam.principalAccessBoundaryPolicies", scope="organizations/123"
            ),
            ResourceQuery(
                kind="gcp.iam.principalAccessBoundaryPolicies", scope="organizations/999"
            ),
        ],
    )
    assert result["targets_with_errors"] == 1
    assert service.client.calls[0][1].endswith(
        "/organizations/123/locations/global/principalAccessBoundaryPolicies"
    )
    assert len(service.client.calls) == 1
    assert result["results"][1]["errors"][0]["code"] == "SCOPE_DENIED"
    await service.close()


async def test_project_scope_alias_and_parent_id_work_after_shared_authorization(tmp_path):
    service = make_service(tmp_path, google=({"views": []},))
    query = ResourceQuery(
        kind="gcp.logging.views",
        scope="projects/project-a",
        parent="projects/project-a/locations/global/buckets/_Default",
    )
    response = await service.collect_resources("agent-a", [query])
    assert response["targets_with_errors"] == 0
    assert response["results"][0]["metadata"]["scope"] == "projects/100"
    assert service.client.calls[-1][1].endswith(
        "/projects/project-a/locations/global/buckets/_Default/views"
    )
    await service.close()


async def test_foreign_nested_parent_stops_before_upstream_configuration(tmp_path):
    service = make_service(tmp_path)
    query = ResourceQuery(
        kind="gcp.kms.cryptoKeyVersions",
        scope="projects/project-a",
        parent="projects/project-b/locations/global/keyRings/ring/cryptoKeys/key",
    )
    result = await service.collect_resources("agent-a", [query])
    assert result["results"][0]["errors"][0]["code"] == "INVALID_ARGUMENT"
    assert all("cloudresourcemanager.googleapis.com" in call[1] for call in service.client.calls)
    assert not any("project-b" in call[1] for call in service.client.calls)
    await service.close()


async def test_registered_ack_is_scoped_and_uses_shared_projection(tmp_path):
    service = make_service(tmp_path, registered=True)
    queries = [
        KubernetesQuery(provider="alicloud", cluster=ACK),
        KubernetesQuery(provider="alicloud", cluster=ACK.replace("c-audit", "c-other")),
    ]
    result = await service.inspect_kubernetes("agent-a", queries)
    assert result["targets_with_errors"] == 1
    assert len(service.registered_kubernetes.calls) == 1
    assert "POD-LITERAL-CONTENT" not in json.dumps(result)
    assert result["results"][1]["errors"][0]["code"] == "SCOPE_DENIED"
    assert not service.kubernetes.calls
    assert not service.client.calls
    await service.close()


async def test_explicit_assessment_query_works_without_fake_check_coverage(tmp_path):
    service = make_service(tmp_path, google=({"spec": {"rules": [{"enforce": True}]}},))
    request = AssessmentRequest(
        queries=[
            ResourceQuery(
                kind="gcp.orgpolicy.effectivePolicies",
                scope="organizations/123",
                operation="get",
                resource_id="compute.requireOsLogin",
            )
        ],
        resource_kinds=[],
        check_ids=[],
        include_kubernetes=False,
    )
    result = await execute_assessment(service, request)
    assert result["coverage"]["collections_complete"] == 1
    assert result["coverage"]["resources_examined"] == 1
    assert result["coverage"]["checks_evaluated"] == 0
    assert any("No applicable checks" in message for message in result["warnings"])
    assert result["findings"] == []
    assert len(result["evidence_pages"]) == 1
    assert result["evidence_pages"][0]["kind"] == "gcp.orgpolicy.effectivePolicies"
    evidence_id = result["evidence_pages"][0]["evidence_id"]
    evidence = await service.evidence("agent-a", evidence_id)
    assert evidence["items"][0]["data"]["spec"]["rules"][0]["enforce"]
    with pytest.raises(ValueError, match="not found"):
        await service.evidence("other-agent", evidence_id)
    await service.close()


async def test_alibaba_assessment_respects_page_budget_and_reports_incomplete(tmp_path):
    service = make_service(
        tmp_path,
        max_scan_pages=2,
        alibaba=(
            {"Instances": {"Instance": [{"InstanceId": "i-first"}]}, "NextToken": "more-1"},
            {"Instances": {"Instance": [{"InstanceId": "i-second"}]}, "NextToken": "more-2"},
        ),
    )
    request = AssessmentRequest(
        accounts=[ACCOUNT],
        locations=[REGION],
        resource_kinds=["alicloud.ecs.instances"],
        check_ids=[],
        include_kubernetes=False,
    )
    result = await execute_assessment(service, request)
    assert len(service.alicloud_client.calls) == 2
    assert result["coverage"]["api_pages"] == 2
    assert result["coverage"]["collections_incomplete"] == 1
    assert result["coverage"]["accounts_attempted"] == 1
    assert "max_scan_pages" in result["limits_reached"]
    assert not result["coverage_complete"]
    assert not service.client.calls
    await service.close()


async def test_alibaba_assessment_requires_explicit_nested_queries(tmp_path):
    service = make_service(tmp_path)
    request = AssessmentRequest(
        accounts=[ACCOUNT],
        locations=[REGION],
        resource_kinds=["alicloud.ecs.securityGroupRules"],
        check_ids=[],
        include_kubernetes=False,
    )
    result = await execute_assessment(service, request)
    assert not result["coverage_complete"]
    assert result["errors"][0]["code"] == "EXPLICIT_QUERY_REQUIRED"
    assert service.alicloud_client.calls == []
    await service.close()


async def test_discovery_has_uniform_per_operation_requirements_for_both_providers(tmp_path):
    service = make_service(tmp_path)
    capabilities = service.capabilities()
    assert capabilities["providers"] == ["gcp", "alicloud"]
    for section in ("gcp_resources", "alicloud_resources"):
        assert capabilities[section]
        for kind in capabilities[section]:
            assert kind["provider"] in {"gcp", "alicloud"}
            for operation in kind["operations"]:
                assert operation in kind["queries"]
                assert kind["queries"][operation]["scope_types"]
    await service.close()
