"""The connector publishes enough metadata to construct supported reads safely."""

from sec_auditor.providers.alicloud_catalog import capabilities as alicloud_capabilities
from sec_auditor.providers.capabilities import grouped_capabilities
from sec_auditor.providers.gcp_queries import query_capabilities


def test_alibaba_discovery_retains_selector_enums_and_exact_required_identifier_hints():
    capabilities = {
        item["kind"]: item for item in grouped_capabilities("alicloud", alicloud_capabilities())
    }
    policy = capabilities["alicloud.ram.policyVersions"]["queries"]["get"]
    assert policy["requires_parent"]
    assert policy["parent_format"] == "PolicyName"
    assert policy["requires_resource_id"]
    assert policy["resource_id_parameter"] == "VersionId"
    assert policy["selectors"]["policy_type"]["enum"] == ["Custom", "System"]
    assert policy["selectors"]["policy_type"]["required"]
    assert policy["selectors"]["policy_type"]["api_parameter"] == "PolicyType"
    assert policy["scope_types"] == ["accounts"]
    assert policy["method"] == "GET"

    listener = capabilities["alicloud.slb.httpsListeners"]["queries"]["get"]
    assert listener["selectors"]["port"]["minimum_value"] == 1
    assert listener["selectors"]["port"]["maximum_value"] == 65535

    events = capabilities["alicloud.actiontrail.events"]["queries"]["list"]
    for key in ("start_time", "end_time"):
        assert events["selectors"][key]["format"] == "date-time"
        assert events["selectors"][key]["timezone_required"]
        assert events["selectors"][key]["required"]

    vulnerabilities = capabilities["alicloud.sas.vulnerabilities"]["queries"]["list"]
    assert vulnerabilities["selectors"]["vulnerability_type"]["enum"] == [
        "cve",
        "sys",
        "cms",
        "app",
        "emg",
        "sca",
    ]


def test_legacy_gcp_lists_and_exact_queries_share_explicit_requirement_metadata():
    capabilities = {item["kind"]: item for item in query_capabilities()}
    for capability in capabilities.values():
        for operation in capability["operations"]:
            query = capability["queries"][operation]
            assert isinstance(query["requires_parent"], bool)
            assert isinstance(query["requires_resource_id"], bool)
            assert isinstance(query["requires_location"], bool)
            assert isinstance(query["selectors"], dict)
            assert query["method"] in {"GET", "POST"}
            assert query["scope_types"]

    assert capabilities["gcp.iam.policy"]["queries"]["list"]["method"] == "POST"
    assert capabilities["gcp.iam.policy"]["queries"]["get"]["method"] == "POST"
    instances = capabilities["gcp.compute.instances"]["queries"]
    assert not instances["list"]["requires_resource_id"]
    assert instances["get"]["requires_resource_id"]
