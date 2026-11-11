"""Security-query regressions: route semantics, scope proof and missing evidence."""

from collections import deque

import pytest

from sec_auditor.providers.catalog import RESOURCE_SPECS
from sec_auditor.providers.gcp import GCPProvider
from sec_auditor.providers.gcp_queries import QUERY_SPECS
from sec_auditor.transport import CloudAPIError, validate_google_url


class FakeClient:
    def __init__(self, *responses):
        self.responses = deque(responses)
        self.calls = []

    async def get(self, url, params=None):
        validate_google_url("GET", url)
        self.calls.append(("GET", url, params))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    async def post_read(self, url, json, params=None):
        validate_google_url("POST", url)
        self.calls.append(("POST", url, json, params))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


async def test_legacy_list_still_preserves_native_pagination():
    client = FakeClient({"nextPageToken": "next"})
    result = await GCPProvider(client).query_resources(
        "gcp.compute.instances", "projects/audit-project", page_token="before"
    )
    assert result.next_page_token == "next"
    assert client.calls[0][1].endswith("/projects/audit-project/aggregated/instances")
    assert client.calls[0][2]["pageToken"] == "before"


async def test_hierarchy_lists_direct_children_with_explicit_parent():
    client = FakeClient(
        {"folders": [], "nextPageToken": "more"},
        {"projects": []},
        {"name": "folders/456", "parent": "organizations/123"},
    )
    provider = GCPProvider(client)
    result = await provider.query_resources("gcp.resourcemanager.folders", "organizations/123")
    await provider.query_resources(
        "gcp.resourcemanager.projects", "folders/456", page_token="before"
    )
    await provider.query_resources("gcp.resourcemanager.folder", "folders/456", operation="get")
    assert result.next_page_token == "more"
    assert client.calls[0][1:] == (
        "https://cloudresourcemanager.googleapis.com/v3/folders",
        {"parent": "organizations/123", "pageSize": 100},
    )
    assert client.calls[1][2] == {"parent": "folders/456", "pageSize": 100, "pageToken": "before"}
    assert client.calls[2][1].endswith("/folders/456")


async def test_kms_exact_get_is_live_even_when_list_kind_is_inventory():
    client = FakeClient(
        {"name": "projects/audit-project/locations/global/keyRings/ring/cryptoKeys/key"}
    )
    result = await GCPProvider(client).query_resources(
        "gcp.kms.cryptoKeys",
        "audit-project",
        operation="get",
        parent="projects/audit-project/locations/global/keyRings/ring",
        resource_id="key",
    )
    assert result.items[0].kind == "gcp.kms.cryptoKeys"
    assert result.items[0].freshness == "live"
    assert client.calls[0][1].startswith("https://cloudkms.googleapis.com/")
    assert RESOURCE_SPECS["gcp.kms.cryptoKeys"].freshness == "inventory"


@pytest.mark.parametrize(
    "kind,location,selectors,suffix",
    [
        ("gcp.compute.instances", "us-central1-a", {}, "zones/us-central1-a/instances/test"),
        (
            "gcp.compute.disks",
            "us-central1",
            {"location_type": "regions"},
            "regions/us-central1/disks/test",
        ),
        (
            "gcp.compute.backendServices",
            None,
            {"location_type": "global"},
            "global/backendServices/test",
        ),
        (
            "gcp.compute.networkEndpointGroups",
            "us-east1-b",
            {"location_type": "zones"},
            "zones/us-east1-b/networkEndpointGroups/test",
        ),
        ("gcp.compute.networkFirewallPolicies", None, {}, "global/firewallPolicies/test"),
        (
            "gcp.compute.regionNetworkFirewallPolicies",
            "us-central1",
            {},
            "regions/us-central1/firewallPolicies/test",
        ),
        ("gcp.run.services", "us-central1", {}, "locations/us-central1/services/test"),
        ("gcp.container.clusters", "us-central1-a", {}, "locations/us-central1-a/clusters/test"),
    ],
)
async def test_exact_get_uses_actual_scope_and_not_aggregate(kind, location, selectors, suffix):
    client = FakeClient({"name": "test"})
    result = await GCPProvider(client).query_resources(
        kind,
        "audit-project",
        operation="get",
        resource_id="test",
        location=location,
        selectors=selectors,
    )
    assert not result.errors
    assert client.calls[0][1].endswith("/projects/audit-project/" + suffix)
    assert client.calls[0][2] is None
    assert result.metadata["operation"] == "get"
    assert result.items[0].freshness == "live"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"location": "us-central1"},
        {"location": "us-central1-a", "selectors": {"location_type": "global"}},
        {"location": "us-central1", "selectors": {"location_type": "zones"}},
        {"location": "us-central1-a", "selectors": {"location_type": "regions"}},
        {"selectors": {"location_type": "global", "url": "https://evil.invalid"}},
    ],
)
async def test_ambiguous_or_inconsistent_compute_location_rejected(kwargs):
    client = FakeClient()
    with pytest.raises(ValueError):
        await GCPProvider(client).query_resources(
            "gcp.compute.networkEndpointGroups",
            "audit-project",
            operation="get",
            resource_id="target",
            **kwargs,
        )
    assert not client.calls


@pytest.mark.parametrize(
    "resource_id", ["../keys", "foo/bar", "foo%2Fbar", "name:delete", "x?alt=media", ".."]
)
async def test_exact_get_cannot_smuggle_paths_or_methods(resource_id):
    client = FakeClient()
    with pytest.raises(ValueError):
        await GCPProvider(client).query_resources(
            "gcp.secretmanager.secrets", "audit-project", operation="get", resource_id=resource_id
        )
    assert not client.calls


async def test_effective_nic_firewalls_has_fixed_read_route_and_selector():
    client = FakeClient({"firewalls": [], "firewallPolicys": []})
    result = await GCPProvider(client).query_resources(
        "gcp.compute.effectiveFirewalls",
        "audit-project",
        operation="get",
        location="us-central1-a",
        resource_id="vm-a",
        selectors={"network_interface": "nic1"},
    )
    assert client.calls == [
        (
            "GET",
            "https://compute.googleapis.com/compute/v1/projects/audit-project/zones/us-central1-a/instances/vm-a/getEffectiveFirewalls",
            {"networkInterface": "nic1"},
        )
    ]
    assert result.items[0].data == {"firewalls": [], "firewallPolicys": []}


async def test_organization_deny_list_is_explicitly_metadata_only_then_get_rules():
    client = FakeClient(
        {"policies": [{"name": "deny-a"}], "nextPageToken": "more"},
        {"rules": [{"denyRule": {"deniedPermissions": ["iam.serviceAccounts.getAccessToken"]}}]},
    )
    provider = GCPProvider(client)
    listed = await provider.query_resources(
        "gcp.iam.denyPolicies", "organizations/123", page_size=3
    )
    exact = await provider.query_resources(
        "gcp.iam.denyPolicies", "organizations/123", operation="get", resource_id="deny-a"
    )
    encoded = "https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%2Forganizations%2F123/denypolicies"
    assert client.calls[0] == ("GET", encoded, {"pageSize": 3})
    assert client.calls[1] == ("GET", encoded + "/deny-a", None)
    assert listed.next_page_token == "more"
    assert listed.metadata["detail_level"] == "metadata_without_rules"
    assert listed.warnings
    assert exact.metadata["detail_level"] == "policy_rules"
    assert exact.items[0].project is None


async def test_role_definition_scopes_and_full_permissions():
    client = FakeClient(
        {"roles": []}, {"includedPermissions": ["compute.instances.get"]}, {"roles": []}
    )
    provider = GCPProvider(client)
    await provider.query_resources("gcp.iam.roles", "organizations/123")
    await provider.query_resources(
        "gcp.iam.predefinedRoles",
        "organizations/123",
        operation="get",
        resource_id="compute.viewer",
    )
    await provider.query_resources("gcp.iam.predefinedRoles", "audit-project")
    assert client.calls[0] == (
        "GET",
        "https://iam.googleapis.com/v1/organizations/123/roles",
        {"view": "FULL", "pageSize": 100},
    )
    assert client.calls[1][1] == "https://iam.googleapis.com/v1/roles/compute.viewer"
    assert client.calls[2][2]["view"] == "FULL"


async def test_sa_and_ancestor_policy_reads_request_version_3_with_correct_transcoding():
    client = FakeClient({"version": 3, "bindings": []}, {"version": 3})
    provider = GCPProvider(client)
    result = await provider.query_resources(
        "gcp.iam.serviceAccountIamPolicy",
        "audit-project",
        operation="get",
        resource_id="audit@audit-project.iam.gserviceaccount.com",
    )
    await provider.query_resources("gcp.iam.policy", "folders/123", operation="get")
    assert client.calls[0][0] == "POST"
    assert client.calls[0][2:] == ({}, {"options.requestedPolicyVersion": 3})
    assert client.calls[1][2:] == ({"options": {"requestedPolicyVersion": 3}}, None)
    assert result.metadata["policy_semantics"] == "direct_allow_policy"


async def test_pab_policies_and_bindings_preserve_separate_scope_semantics():
    client = FakeClient(
        {"principalAccessBoundaryPolicies": [], "nextPageToken": "policy-next"},
        {"policyBindings": []},
    )
    provider = GCPProvider(client)
    result = await provider.query_resources(
        "gcp.iam.principalAccessBoundaryPolicies", "organizations/123"
    )
    await provider.query_resources("gcp.iam.policyBindings", "folders/456")
    assert result.next_page_token == "policy-next"
    assert client.calls[0][1].endswith(
        "/organizations/123/locations/global/principalAccessBoundaryPolicies"
    )
    assert client.calls[1][1].endswith("/folders/456/locations/global/policyBindings")
    with pytest.raises(ValueError):
        await provider.query_resources("gcp.iam.principalAccessBoundaryPolicies", "audit-project")


async def test_effective_org_policy_uses_constraint_id_and_does_not_substitute_direct_list():
    client = FakeClient({"spec": {"rules": [{"enforce": True}]}})
    result = await GCPProvider(client).query_resources(
        "gcp.orgpolicy.effectivePolicies",
        "folders/123",
        operation="get",
        resource_id="compute.requireOsLogin",
    )
    assert (
        client.calls[0][1]
        == "https://orgpolicy.googleapis.com/v2/folders/123/policies/compute.requireOsLogin:getEffectivePolicy"
    )
    assert result.items[0].data["spec"]["rules"][0]["enforce"]


@pytest.mark.parametrize(
    "parent",
    [
        "projects/other-project/locations/us-central1/keyRings/main/cryptoKeys/key",
        "organizations/123/locations/us-central1/keyRings/main/cryptoKeys/key",
        "projects/audit-project/locations/us-central1/keyRings/main/cryptoKeys/key/versions",
        "projects/audit-project/locations/us-central1/keyRings/../cryptoKeys/key",
        "projects/audit-project/locations/us-central1/keyRings/main/cryptoKeys/key%2Fother",
    ],
)
async def test_nested_parent_is_confined_to_same_scope_and_fixed_resource_type(parent):
    client = FakeClient()
    with pytest.raises(ValueError):
        await GCPProvider(client).query_resources(
            "gcp.kms.cryptoKeyVersions", "audit-project", parent=parent
        )
    assert not client.calls


async def test_kms_version_metadata_requests_basic_view_and_removes_material():
    parent = "projects/audit-project/locations/us-central1/keyRings/main/cryptoKeys/key"
    client = FakeClient(
        {
            "cryptoKeyVersions": [
                {
                    "name": parent + "/cryptoKeyVersions/1",
                    "state": "ENABLED",
                    "attestation": {"content": "hidden"},
                    "privateKeyData": "hidden",
                }
            ],
            "nextPageToken": "next",
        }
    )
    result = await GCPProvider(client).query_resources(
        "gcp.kms.cryptoKeyVersions", "audit-project", parent=parent, page_size=7
    )
    assert client.calls[0] == (
        "GET",
        "https://cloudkms.googleapis.com/v1/" + parent + "/cryptoKeyVersions",
        {"view": "BASIC", "pageSize": 7},
    )
    assert result.items[0].data == {"name": parent + "/cryptoKeyVersions/1", "state": "ENABLED"}
    assert result.next_page_token == "next"


async def test_project_numeric_alias_resolved_before_nested_wif_parent():
    client = FakeClient(
        {"name": "projects/123", "projectId": "audit-project"},
        {"workloadIdentityPoolProviders": []},
    )
    result = await GCPProvider(client).query_resources(
        "gcp.iam.workloadIdentityProviders",
        "audit-project",
        parent="projects/123/locations/global/workloadIdentityPools/pool",
    )
    assert not result.errors
    assert client.calls[0][1].endswith("/v3/projects/audit-project")
    assert client.calls[1][1].endswith(
        "projects/123/locations/global/workloadIdentityPools/pool/providers"
    )


async def test_wrong_numeric_project_alias_never_reads_nested_parent():
    client = FakeClient({"name": "projects/123", "projectId": "audit-project"})
    with pytest.raises(ValueError, match="outside"):
        await GCPProvider(client).query_resources(
            "gcp.kms.cryptoKeyVersions",
            "audit-project",
            parent="projects/999/locations/us-central1/keyRings/main/cryptoKeys/key",
        )
    assert len(client.calls) == 1


async def test_number_scope_can_read_parent_using_its_verified_project_id():
    client = FakeClient({"name": "projects/123", "projectId": "audit-project"}, {"views": []})
    result = await GCPProvider(client).query_resources(
        "gcp.logging.views",
        "projects/123",
        parent="projects/audit-project/locations/global/buckets/_Default",
    )
    assert not result.errors
    assert client.calls[0][1].endswith("/v3/projects/123")
    assert client.calls[1][1].endswith(
        "/projects/audit-project/locations/global/buckets/_Default/views"
    )


async def test_number_scope_rejects_foreign_project_parent_without_foreign_lookup():
    client = FakeClient({"name": "projects/123", "projectId": "audit-project"})
    with pytest.raises(ValueError, match="outside"):
        await GCPProvider(client).query_resources(
            "gcp.logging.views",
            "projects/123",
            parent="projects/other-project/locations/global/buckets/_Default",
        )
    assert len(client.calls) == 1
    assert client.calls[0][1].endswith("/v3/projects/123")


@pytest.mark.parametrize(
    "kind,suffix", [("gcp.storage.buckets", ""), ("gcp.storage.bucketIamPolicy", "/iam")]
)
async def test_bucket_metadata_and_iam_require_project_membership_first(kind, suffix):
    client = FakeClient(
        {"items": [{"name": "audit-bucket"}]},
        {"name": "audit-bucket", "acl": [{"entity": "allUsers", "role": "READER"}]},
    )
    result = await GCPProvider(client).query_resources(
        kind, "audit-project", operation="get", resource_id="audit-bucket"
    )
    assert not result.errors
    assert client.calls[0][2]["project"] == "audit-project"
    assert client.calls[0][2]["prefix"] == "audit-bucket"
    assert client.calls[1][1] == "https://storage.googleapis.com/storage/v1/b/audit-bucket" + suffix
    assert client.calls[1][2] == (
        {"optionsRequestedPolicyVersion": 3} if suffix else {"projection": "full"}
    )
    assert not any("/o" in url.removeprefix("https://") for _, url, _ in client.calls)


async def test_foreign_bucket_is_rejected_without_fetching_its_metadata():
    client = FakeClient({"items": [{"name": "other-bucket"}], "nextPageToken": "bounded"})
    result = await GCPProvider(client).query_resources(
        "gcp.storage.bucketIamPolicy",
        "audit-project",
        operation="get",
        resource_id="foreign-bucket",
    )
    assert result.errors[0].code == "RESOURCE_SCOPE_MISMATCH"
    assert not result.items
    assert len(client.calls) == 1


async def test_global_hierarchical_policy_requires_scoped_ownership():
    client = FakeClient({"items": [{"id": "789"}]}, {"id": "789", "rules": []})
    result = await GCPProvider(client).query_resources(
        "gcp.compute.hierarchicalFirewallPolicies",
        "organizations/123",
        operation="get",
        resource_id="789",
    )
    assert not result.errors
    assert client.calls[0][2] == {
        "parentId": "organizations/123",
        "filter": 'id = "789"',
        "maxResults": 500,
    }
    assert client.calls[1][1].endswith("/locations/global/firewallPolicies/789")


async def test_vpc_sc_parent_ownership_proof_honors_pagination_and_stops_cycles():
    client = FakeClient(
        {"nextPageToken": "next"},
        {"accessPolicies": [{"name": "accessPolicies/456"}]},
        {
            "servicePerimeters": [
                {"name": "accessPolicies/456/servicePerimeters/perimeter", "status": {}, "spec": {}}
            ]
        },
    )
    result = await GCPProvider(client).query_resources(
        "gcp.accesscontextmanager.servicePerimeters",
        "organizations/123",
        parent="accessPolicies/456",
    )
    assert not result.errors
    assert client.calls[0][2]["parent"] == "organizations/123"
    assert client.calls[1][2]["pageToken"] == "next"
    assert client.calls[2][1].endswith("/accessPolicies/456/servicePerimeters")
    client = FakeClient({"nextPageToken": "repeat"}, {"nextPageToken": "repeat"})
    result = await GCPProvider(client).query_resources(
        "gcp.accesscontextmanager.accessLevels", "organizations/123", parent="accessPolicies/456"
    )
    assert result.errors[0].code == "RESOURCE_SCOPE_MISMATCH"
    assert len(client.calls) == 2


async def test_org_scc_findings_keep_source_location_filter_and_partial_failure():
    client = FakeClient(
        {
            "listFindingsResults": [
                {
                    "finding": {
                        "name": "organizations/123/sources/45/locations/eu/findings/a",
                        "state": "ACTIVE",
                    }
                }
            ],
            "nextPageToken": "more",
            "unreachable": ["source-99"],
        }
    )
    result = await GCPProvider(client).query_resources(
        "gcp.securitycenter.findings",
        "organizations/123",
        location="eu",
        selectors={"source_id": "45", "state": "ACTIVE"},
        page_token="before",
        page_size=8,
    )
    assert client.calls[0][1].endswith("/organizations/123/sources/45/locations/eu/findings")
    assert client.calls[0][2] == {"filter": 'state="ACTIVE"', "pageSize": 8, "pageToken": "before"}
    assert result.next_page_token == "more"
    assert result.items[0].name.endswith("/findings/a")
    assert result.items[0].project is None
    assert result.errors[0].code == "UNREACHABLE_SCOPE"


async def test_vulnerability_filter_cannot_expose_secret_occurrences():
    client = FakeClient(
        {
            "occurrences": [
                {
                    "name": "projects/audit-project/occurrences/v",
                    "kind": "VULNERABILITY",
                    "vulnerability": {"severity": "HIGH"},
                    "secret": {"value": "not-allowed"},
                },
                {"kind": "SECRET", "secret": {"value": "not-allowed"}},
            ],
            "nextPageToken": "next",
            "unreachable": ["us-east1"],
        }
    )
    result = await GCPProvider(client).query_resources(
        "gcp.artifactanalysis.vulnerabilities", "audit-project"
    )
    assert client.calls[0][2]["filter"] == 'kind="VULNERABILITY"'
    assert client.calls[0][2]["returnPartialSuccess"] == "true"
    assert len(result.items) == 1
    assert "secret" not in result.items[0].data
    assert result.next_page_token == "next"
    assert {error.code for error in result.errors} == {
        "UNREACHABLE_SCOPE",
        "UNEXPECTED_OCCURRENCE_KIND",
    }


async def test_logs_views_and_configuration_are_scoped_not_entry_reads():
    client = FakeClient(
        {"views": [], "nextPageToken": "more"}, {"disableDefaultSink": True}, {"metrics": []}
    )
    provider = GCPProvider(client)
    result = await provider.query_resources(
        "gcp.logging.views",
        "organizations/123",
        parent="organizations/123/locations/global/buckets/_Default",
    )
    await provider.query_resources("gcp.logging.settings", "organizations/123", operation="get")
    await provider.query_resources("gcp.logging.metrics", "audit-project")
    assert result.next_page_token == "more"
    assert client.calls[0][1].endswith("/organizations/123/locations/global/buckets/_Default/views")
    assert client.calls[1][1].endswith("/organizations/123/settings")
    assert all("entries" not in call[1] for call in client.calls)


async def test_unpaged_account_keys_are_bounded_and_exclude_key_material():
    client = FakeClient(
        {
            "keys": [
                {"name": "z", "privateKeyData": "hidden"},
                {"name": "a", "publicKeyData": "hidden"},
            ]
        }
    )
    result = await GCPProvider(client).query_resources(
        "gcp.iam.serviceAccountKeyMetadata",
        "audit-project",
        parent="projects/audit-project/serviceAccounts/audit@audit-project.iam.gserviceaccount.com",
        page_size=1,
    )
    assert result.next_page_token == "offset:1"
    assert result.items[0].name == "a"
    assert result.items[0].data == {"name": "a"}
    assert client.calls[0][2] == {"keyTypes": "USER_MANAGED"}
    assert result.metadata["pagination_consistency"] == "best_effort"


async def test_optional_permission_denial_is_visible_not_clean_empty_evidence():
    client = FakeClient(CloudAPIError("PERMISSION_DENIED", "Permission denied"))
    result = await GCPProvider(client).query_resources(
        "gcp.artifactanalysis.vulnerabilities", "audit-project"
    )
    assert not result.items
    assert result.errors[0].code == "PERMISSION_DENIED"
    assert result.metadata["scope"] == "projects/audit-project"


def test_capabilities_describe_operations_parents_scopes_and_actual_permissions():
    capabilities = {item["kind"]: item for item in GCPProvider(FakeClient()).capabilities()}
    assert set(RESOURCE_SPECS) <= set(capabilities)
    assert set(capabilities["gcp.compute.instances"]["operations"]) == {"list", "get"}
    assert capabilities["gcp.iam.roles"]["queries"]["list"]["scope_types"] == [
        "projects",
        "organizations",
    ]
    assert capabilities["gcp.kms.cryptoKeyVersions"]["queries"]["list"]["requires_parent"]
    assert capabilities["gcp.compute.backendServices"]["queries"]["get"]["selectors"][
        "location_type"
    ]["required"]
    assert (
        capabilities["gcp.compute.addresses"]["queries"]["get"]["permissions_by_location_type"][
            "global"
        ]
        == "compute.globalAddresses.get"
    )
    assert RESOURCE_SPECS["gcp.compute.networkFirewallPolicies"].permissions == (
        "compute.firewallPolicies.list",
    )
    assert QUERY_SPECS[("gcp.compute.regionNetworkFirewallPolicies", "list")].permissions == (
        "compute.regionFirewallPolicies.list",
    )
    for capability in capabilities.values():
        for operation in capability["operations"]:
            assert operation in {"list", "get"}
            assert "endpoint" in capability["queries"][operation]
            assert "scope_types" in capability["queries"][operation]
