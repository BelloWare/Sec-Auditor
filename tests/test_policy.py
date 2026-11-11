"""Scope authorization must fail closed before collectors run."""

from copy import deepcopy

import pytest

from sec_auditor.config import Settings
from sec_auditor.policy import ScopeDenied, ScopePolicy, validate_project
from sec_auditor.transport import CloudAPIError


class FakeClient:
    def __init__(self, resources):
        self.resources = resources
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append(url)
        resource = url.split("/v3/", 1)[1]
        value = self.resources[resource]
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


def project(parent="organizations/123", **changes):
    data = {"name": "projects/10001", "projectId": "project-a", "parent": parent, "state": "ACTIVE"}
    data.update(changes)
    return data


def policy(resources, **settings):
    client = FakeClient(resources)
    config = Settings(allowed_organizations=["123"], **settings)
    return ScopePolicy(config, client), client


@pytest.mark.parametrize(
    "identifier",
    [
        "../project-a",
        "project-a/../project-b",
        "project-a%2fother",
        "project-a?x=1",
        "project-a#fragment",
        "project a",
        "https://example.test",
        "projects/project-a",
        "a",
        "project-a\n",
    ],
)
def test_project_path_injection_is_rejected(identifier):
    with pytest.raises(ValueError):
        validate_project(identifier)


async def test_organization_ancestry_and_alias_cache():
    guard, client = policy({"projects/project-a": project()})
    assert (await guard.authorize_project("project-a"))["name"] == "projects/10001"
    assert (await guard.authorize_project("10001"))["projectId"] == "project-a"
    assert len(client.calls) == 1


async def test_folder_chain_to_allowed_organization():
    guard, client = policy(
        {
            "projects/project-a": project("folders/45"),
            "folders/45": {"name": "folders/45", "parent": "folders/67", "state": "ACTIVE"},
            "folders/67": {"name": "folders/67", "parent": "organizations/123", "state": "ACTIVE"},
        }
    )
    assert (await guard.authorize_project("project-a"))["name"] == "projects/10001"
    assert len(client.calls) == 3


async def test_outside_organization_denied():
    guard, _ = policy({"projects/project-a": project("organizations/999")})
    with pytest.raises(ScopeDenied):
        await guard.authorize_project("project-a")


async def test_explicit_project_allowlist_can_authorize_without_org_ancestry():
    guard, client = policy(
        {"projects/project-a": project("organizations/999")}, allowed_projects=["10001"]
    )
    assert (await guard.authorize_project("project-a"))["name"] == "projects/10001"
    assert len(client.calls) == 1


async def test_denied_parent_lookup_is_not_converted_to_allowed():
    guard, _ = policy(
        {
            "projects/project-a": project("folders/45"),
            "folders/45": CloudAPIError("PERMISSION_DENIED", "denied", status_code=403),
        }
    )
    with pytest.raises(CloudAPIError, match="denied"):
        await guard.authorize_project("project-a")


async def test_deleted_project_rejected_even_when_explicitly_allowed():
    guard, _ = policy(
        {"projects/project-a": project(state="DELETE_REQUESTED")}, allowed_projects=["project-a"]
    )
    with pytest.raises(ScopeDenied):
        await guard.authorize_project("project-a")


async def test_deleted_ancestor_rejected():
    guard, _ = policy(
        {
            "projects/project-a": project("folders/45"),
            "folders/45": {
                "name": "folders/45",
                "parent": "organizations/123",
                "state": "DELETE_REQUESTED",
            },
        }
    )
    with pytest.raises(ScopeDenied):
        await guard.authorize_project("project-a")


async def test_deleted_target_folder_rejected():
    guard, _ = policy(
        {
            "folders/45": {
                "name": "folders/45",
                "parent": "organizations/123",
                "state": "DELETE_REQUESTED",
            }
        }
    )
    with pytest.raises(ScopeDenied):
        await guard.authorize_scope("folders/45")


async def test_project_response_must_match_requested_identity():
    guard, _ = policy({"projects/project-a": project(projectId="project-b", name="projects/20002")})
    with pytest.raises((CloudAPIError, ScopeDenied)):
        await guard.authorize_project("project-a")


@pytest.mark.parametrize(
    "name", ["10001", "folders/10001", "projects/10001/child", "projects/not-a-number"]
)
async def test_project_response_name_must_be_canonical(name):
    guard, _ = policy({"projects/project-a": project(name=name)})
    with pytest.raises((CloudAPIError, ScopeDenied)):
        await guard.authorize_project("project-a")


async def test_hierarchy_cycles_fail_closed():
    guard, _ = policy(
        {
            "projects/project-a": project("folders/45"),
            "folders/45": {"name": "folders/45", "parent": "folders/67", "state": "ACTIVE"},
            "folders/67": {"name": "folders/67", "parent": "folders/45", "state": "ACTIVE"},
        }
    )
    with pytest.raises(ScopeDenied, match="cycle"):
        await guard.authorize_project("project-a")


async def test_zero_ttl_rechecks_moved_project():
    guard, client = policy({"projects/project-a": project()}, scope_cache_seconds=0)
    await guard.authorize_project("project-a")
    client.resources["projects/project-a"] = project("organizations/999")
    with pytest.raises(ScopeDenied):
        await guard.authorize_project("project-a")


@pytest.mark.parametrize(
    "scope",
    [
        "organizations/999",
        "folders/../123",
        "folders/45:other",
        "projects/project-a/other",
        "organizations/123?x=1",
        "organizations/123\n",
    ],
)
async def test_invalid_or_disallowed_scope_rejected_without_cloud_access(scope):
    guard, client = policy({})
    with pytest.raises(ScopeDenied):
        await guard.authorize_scope(scope)
    assert client.calls == []


async def test_scopes_canonicalize_project_alias_and_accept_exact_org():
    guard, _ = policy({"projects/project-a": project()})
    assert await guard.authorize_scope("projects/project-a") == "projects/10001"
    assert await guard.authorize_scope("organizations/123") == "organizations/123"


@pytest.mark.parametrize(
    "target", ["project-a", "projects/project-a", "folders/45", "organizations/123"]
)
async def test_alibaba_only_deployment_never_attempts_google_identity_or_reads(target):
    class NeverCall:
        async def get(self, *args, **kwargs):
            raise AssertionError("Disabled Google provider attempted a cloud read")

    guard = ScopePolicy(Settings(allowed_alicloud_accounts=["1234567890123456"]), NeverCall())
    with pytest.raises(ScopeDenied, match="not enabled"):
        if "/" in target:
            await guard.authorize_scope(target)
        else:
            await guard.authorize_project(target)
