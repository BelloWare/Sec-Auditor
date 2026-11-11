from collections import deque

import pytest

from sec_auditor.providers.catalog import RESOURCE_SPECS, SAFE_ASSET_TYPES
from sec_auditor.providers.gcp import GCPProvider, validate_scope
from sec_auditor.transport import CloudAPIError, validate_google_url


class FakeClient:
    def __init__(self, *responses):
        self.responses = deque(responses)
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append(("GET", url, params))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    async def post_read(self, url, json):
        self.calls.append(("POST", url, json))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


async def test_compute_aggregate_preserves_pages_and_scope_failures():
    client = FakeClient(
        {
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {
                            "name": "vm-a",
                            "zone": "zones/us-central1-a",
                            "selfLink": "https://www.googleapis.com/compute/v1/projects/audit-project/zones/us-central1-a/instances/vm-a",
                        }
                    ]
                },
                "zones/us-central1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}},
                "zones/us-central1-c": {"warning": {"code": "UNREACHABLE"}},
            },
            "nextPageToken": "native-next",
        }
    )
    result = await GCPProvider(client).list_resources(
        "gcp.compute.instances", "audit-project", page_size=20
    )
    assert len(result.items) == 1
    assert result.items[0].location == "us-central1-a"
    assert result.items[0].project == "audit-project"
    assert result.next_page_token == "native-next"
    assert len(result.errors) == 1
    assert result.errors[0].target.endswith("zones/us-central1-c")
    assert client.calls[0] == (
        "GET",
        "https://compute.googleapis.com/compute/v1/projects/audit-project/aggregated/instances",
        {"maxResults": 20, "returnPartialSuccess": "true"},
    )


async def test_short_or_empty_page_still_preserves_next_token():
    client = FakeClient({"nextPageToken": "more"})
    result = await GCPProvider(client).list_resources(
        "gcp.compute.firewalls", "audit-project", page_token="before"
    )
    assert result.items == []
    assert result.next_page_token == "more"
    assert client.calls[0][2]["pageToken"] == "before"


async def test_network_firewall_policy_rest_collection_name():
    client = FakeClient({"items": [{"name": "network-policy", "rules": []}]})
    result = await GCPProvider(client).list_resources(
        "gcp.compute.networkFirewallPolicies", "audit-project"
    )
    assert (
        client.calls[0][1]
        == "https://compute.googleapis.com/compute/v1/projects/audit-project/global/firewallPolicies"
    )
    assert len(result.items) == 1


@pytest.mark.parametrize(
    "project",
    [
        "../outside",
        "projects/audit-project",
        "audit-project?alt=media",
        "audit-project%2fother",
        "audit-project#bad",
        "https://evil.invalid",
        "audit\nproject",
    ],
)
async def test_reject_project_route_injection_before_request(project):
    client = FakeClient()
    with pytest.raises(ValueError):
        await GCPProvider(client).list_resources("gcp.compute.instances", project)
    assert client.calls == []


@pytest.mark.parametrize(
    "scope",
    [
        "organizations/not-a-number",
        "folders/12/../34",
        "projects/audit-project:delete",
        "billingAccounts/123",
        "organizations/1?x=y",
    ],
)
def test_scope_validation_rejects_non_resource_paths(scope):
    with pytest.raises(ValueError):
        validate_scope(scope)


async def test_location_requirements_are_explicit():
    client = FakeClient()
    provider = GCPProvider(client)
    with pytest.raises(ValueError, match="requires an explicit location"):
        await provider.list_resources("gcp.run.services", "audit-project")
    with pytest.raises(ValueError, match="Invalid location"):
        await provider.list_resources("gcp.run.services", "audit-project", location="-")
    with pytest.raises(ValueError, match="does not accept location"):
        await provider.list_resources(
            "gcp.compute.instances", "audit-project", location="us-central1"
        )
    assert client.calls == []


async def test_cloud_run_uses_concrete_region():
    client = FakeClient(
        {
            "services": [{"name": "projects/audit-project/locations/us-central1/services/api"}],
            "unreachable": ["us-west1"],
        }
    )
    result = await GCPProvider(client).list_resources(
        "gcp.run.services", "audit-project", location="us-central1"
    )
    assert (
        client.calls[0][1]
        == "https://run.googleapis.com/v2/projects/audit-project/locations/us-central1/services"
    )
    assert result.errors[0].code == "UNREACHABLE_SCOPE"


async def test_gke_local_pages_are_explicit_and_canonical():
    response = {
        "clusters": [
            {"name": "second", "location": "us-central1"},
            {"name": "first", "location": "us-central1"},
        ],
        "missingZones": ["us-west1"],
    }
    client = FakeClient(response, response)
    provider = GCPProvider(client)
    first = await provider.list_resources("gcp.container.clusters", "audit-project", page_size=1)
    second = await provider.list_resources(
        "gcp.container.clusters", "audit-project", page_size=1, page_token=first.next_page_token
    )
    assert first.items[0].name.endswith("/clusters/first")
    assert second.items[0].name.endswith("/clusters/second")
    assert first.next_page_token == "offset:1"
    assert second.next_page_token is None
    assert first.metadata["pagination_consistency"] == "best_effort"
    assert first.warnings and first.errors
    assert client.calls[0][2] is None


async def test_gke_invalid_cursor_is_rejected_before_request():
    client = FakeClient()
    with pytest.raises(ValueError, match="pagination token"):
        await GCPProvider(client).list_resources(
            "gcp.container.clusters", "audit-project", page_token="../../"
        )
    assert not client.calls


async def test_permission_denial_is_coverage_error_not_empty_success():
    client = FakeClient(CloudAPIError("PERMISSION_DENIED", "Denied", status_code=403))
    result = await GCPProvider(client).list_resources("gcp.storage.buckets", "audit-project")
    assert not result.items
    assert len(result.errors) == 1
    assert result.errors[0].code == "PERMISSION_DENIED"
    assert result.errors[0].retryable is False


async def test_bucket_collection_only_uses_project_scoped_metadata_endpoint():
    client = FakeClient(
        {
            "items": [
                {
                    "name": "audit-bucket",
                    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
                }
            ]
        }
    )
    result = await GCPProvider(client).list_resources("gcp.storage.buckets", "audit-project")
    assert client.calls == [
        (
            "GET",
            "https://storage.googleapis.com/storage/v1/b",
            {"project": "audit-project", "projection": "noAcl", "maxResults": 100},
        )
    ]
    assert result.items[0].name == "//storage.googleapis.com/audit-bucket"
    assert "iamConfiguration" in result.items[0].data


async def test_policy_read_requests_conditional_policy_version():
    client = FakeClient(
        {
            "version": 3,
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:person@example.com"],
                    "condition": {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"},
                }
            ],
        }
    )
    result = await GCPProvider(client).get_iam_policy("organizations/123456")
    assert client.calls == [
        (
            "POST",
            "https://cloudresourcemanager.googleapis.com/v3/organizations/123456:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
        )
    ]
    assert result.metadata["policy_semantics"] == "direct_allow_policy"
    assert result.items[0].data["bindings"][0]["condition"]


async def test_dataset_summary_is_enriched_but_denial_remains_visible():
    client = FakeClient(
        {
            "datasets": [
                {"datasetReference": {"projectId": "audit-project", "datasetId": "private_data"}}
            ]
        },
        CloudAPIError("PERMISSION_DENIED", "Denied", status_code=403),
    )
    result = await GCPProvider(client).list_resources("gcp.bigquery.datasets", "audit-project")
    assert (
        client.calls[1][1]
        == "https://bigquery.googleapis.com/bigquery/v2/projects/audit-project/datasets/private_data"
    )
    assert result.errors[0].code == "PERMISSION_DENIED"
    assert result.items[0].data["_collection"]["enrichment_failed"] is True


async def test_dataset_enrichment_rejects_cross_project_reference():
    client = FakeClient(
        {"datasets": [{"datasetReference": {"projectId": "outside-project", "datasetId": "data"}}]}
    )
    result = await GCPProvider(client).list_resources("gcp.bigquery.datasets", "audit-project")
    assert len(client.calls) == 1
    assert result.errors[0].code == "INVALID_RESPONSE"


async def test_key_metadata_excludes_key_bytes_and_retains_account_page():
    client = FakeClient(
        {
            "accounts": [
                {
                    "email": "auditor@audit-project.iam.gserviceaccount.com",
                    "name": "projects/audit-project/serviceAccounts/auditor@audit-project.iam.gserviceaccount.com",
                }
            ],
            "nextPageToken": "more-accounts",
        },
        {
            "keys": [
                {
                    "name": "projects/audit-project/serviceAccounts/auditor@audit-project.iam.gserviceaccount.com/keys/123",
                    "keyType": "USER_MANAGED",
                    "privateKeyData": "must-not-return",
                    "publicKeyData": "also-not-needed",
                }
            ]
        },
    )
    result = await GCPProvider(client).list_resources(
        "gcp.iam.serviceAccountKeys", "audit-project", page_size=100
    )
    assert result.next_page_token == "more-accounts"
    assert client.calls[0][2]["pageSize"] == 20
    assert client.calls[1][2] == {"keyTypes": "USER_MANAGED"}
    assert result.metadata["page_unit"] == "service_accounts"
    assert "privateKeyData" not in result.items[0].data
    assert "publicKeyData" not in result.items[0].data


async def test_per_account_key_denial_is_preserved():
    client = FakeClient(
        {
            "accounts": [
                {"email": "auditor@audit-project.iam.gserviceaccount.com", "name": "account"}
            ]
        },
        CloudAPIError("PERMISSION_DENIED", "Denied", status_code=403),
    )
    result = await GCPProvider(client).list_resources("gcp.iam.serviceAccountKeys", "audit-project")
    assert result.errors[0].target == "account"
    assert result.metadata["accounts_examined"] == 0


@pytest.mark.parametrize(
    "kind",
    [
        "gcp.storage.objects",
        "gcp.secretmanager.versions",
        "gcp.compute.serialOutput",
        "gcp.unknown.anything",
    ],
)
async def test_data_content_and_unknown_kinds_have_no_route(kind):
    client = FakeClient()
    with pytest.raises(ValueError, match="Unsupported"):
        await GCPProvider(client).list_resources(kind, "audit-project")
    assert not client.calls


@pytest.mark.parametrize(
    "asset_type",
    [
        "k8s.io/Secret",
        "storage.googleapis.com/Object",
        ".*",
        "secretmanager.googleapis.com/SecretVersion",
    ],
)
async def test_inventory_content_types_are_allowlisted(asset_type):
    client = FakeClient()
    with pytest.raises(ValueError, match="Unsupported asset type"):
        await GCPProvider(client).list_assets("organizations/123456", [asset_type])
    assert not client.calls


async def test_inventory_preserves_read_time_and_native_resource_payload():
    client = FakeClient(
        {
            "assets": [
                {
                    "name": "//compute.googleapis.com/projects/audit-project/zones/us-central1-a/instances/a",
                    "assetType": "compute.googleapis.com/Instance",
                    "resource": {"data": {"canIpForward": True}},
                    "ancestors": ["projects/123", "organizations/456"],
                    "updateTime": "2026-11-01T00:00:00Z",
                }
            ],
            "readTime": "2026-11-11T00:00:00Z",
            "nextPageToken": "inventory-next",
        }
    )
    result = await GCPProvider(client).list_assets(
        "organizations/456", ["compute.googleapis.com/Instance"]
    )
    assert result.items[0].kind == "gcp.compute.instances"
    assert result.items[0].data["canIpForward"] is True
    assert result.items[0].project == "123"
    assert result.items[0].freshness == "inventory"
    assert result.metadata["read_time"] == "2026-11-11T00:00:00Z"
    assert result.next_page_token == "inventory-next"


async def test_inventory_unexpected_secret_response_is_rejected():
    client = FakeClient(
        {
            "assets": [
                {"assetType": "k8s.io/Secret", "resource": {"data": {"password": "not-returned"}}}
            ]
        }
    )
    result = await GCPProvider(client).list_assets(
        "projects/audit-project", ["compute.googleapis.com/Instance"]
    )
    assert result.items == []
    assert result.errors[0].code == "INVALID_RESPONSE"


async def test_iam_search_marks_filtered_bindings():
    client = FakeClient(
        {
            "results": [
                {
                    "resource": "//storage.googleapis.com/audit-bucket",
                    "assetType": "storage.googleapis.com/Bucket",
                    "project": "projects/123",
                    "policy": {
                        "bindings": [
                            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                        ]
                    },
                }
            ],
            "nextPageToken": "iam-next",
        }
    )
    result = await GCPProvider(client).search_iam_policies("organizations/456", "policy:allUsers")
    assert result.metadata["complete_policies"] is False
    assert result.items[0].data["_collection"]["query_filtered_bindings"] is True
    assert result.items[0].freshness == "inventory"
    assert result.next_page_token == "iam-next"


async def test_kms_inventory_is_not_labeled_live():
    client = FakeClient(
        {
            "cryptoKeys": [
                {"name": "projects/audit-project/locations/global/keyRings/ring/cryptoKeys/key"}
            ]
        }
    )
    result = await GCPProvider(client).list_resources("gcp.kms.cryptoKeys", "audit-project")
    assert result.items[0].freshness == "inventory"


async def test_service_usage_resolves_numeric_project_name():
    client = FakeClient(
        {"name": "projects/123456", "projectId": "audit-project"},
        {
            "services": [
                {"name": "projects/123456/services/compute.googleapis.com", "state": "ENABLED"}
            ]
        },
    )
    result = await GCPProvider(client).list_resources("gcp.serviceusage.services", "audit-project")
    assert client.calls[1][1] == "https://serviceusage.googleapis.com/v1/projects/123456/services"
    assert result.items[0].project == "audit-project"


async def test_numeric_project_resolution_rejects_cross_project_response():
    client = FakeClient({"name": "projects/123456", "projectId": "outside-project"})
    result = await GCPProvider(client).list_resources("gcp.serviceusage.services", "audit-project")
    assert result.errors[0].code == "INVALID_RESPONSE"
    assert len(client.calls) == 1


async def test_upstream_ignored_page_size_is_visible():
    client = FakeClient(
        {
            "policies": [
                {"name": "projects/audit-project/policies/a"},
                {"name": "projects/audit-project/policies/b"},
            ]
        }
    )
    result = await GCPProvider(client).list_resources(
        "gcp.orgpolicy.policies", "audit-project", page_size=1
    )
    assert len(result.items) == 2
    assert result.metadata["upstream_page_size_exceeded"] is True
    assert result.warnings


def test_catalog_routes_fit_transport_boundary_and_are_discoverable():
    provider = GCPProvider(FakeClient())
    assert len(provider.capabilities()) >= 40
    for spec in RESOURCE_SPECS.values():
        url = spec.url.format(project="audit-project", location="us-central1")
        method = "POST" if spec.pagination == "policy" else "GET"
        validate_google_url(method, url)
        assert spec.permissions
        capability = spec.capability()
        assert capability["description"]
        assert capability["requires_location"] == (spec.location_mode == "required")
    assert "compute.googleapis.com/NetworkFirewallPolicy" not in SAFE_ASSET_TYPES
    assert "cloudfunctions.googleapis.com/Function" in SAFE_ASSET_TYPES
