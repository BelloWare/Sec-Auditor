"""Adversarial cross-provider projection and scope contracts.

Malformed log schemas are treated as untrusted input: an allowed field name is
not permission to return a nested request, response or credential payload.
"""

import json
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from sec_auditor.alicloud_projection import project_config, project_event
from sec_auditor.config import Settings
from sec_auditor.models import ResourceRecord
from sec_auditor.projection import REDACTED, project_record
from sec_auditor.providers.alicloud_catalog import OPERATIONS, RESOURCE_SPECS
from sec_auditor.requests import AssessmentRequest, LogQuery, ResourceQuery

CANARY = "OPAQUE_VALUE_MUST_NOT_LEAVE_SECURITY_BOUNDARY"
ACCOUNT = "1234567890123456"


def projected_record(kind, data):
    return project_record(
        ResourceRecord(
            provider="alicloud", account_id=ACCOUNT, kind=kind, name="safe-reference", data=data
        )
    )


@pytest.mark.parametrize(
    "field", ["type", "principalId", "accountId", "userName", "arn", "identityType"]
)
@pytest.mark.parametrize(
    "payload", [{"requestParameters": {"value": CANARY}}, [{"responseElements": {"value": CANARY}}]]
)
def test_audit_identity_fields_cannot_hide_nested_payloads(field, payload):
    event = {"eventName": "DescribeInstances", "userIdentity": {field: payload}}
    result = project_event(event)
    assert CANARY not in json.dumps(result)
    assert result["eventName"] == "DescribeInstances"
    assert any("userIdentity" in path for path in result["redacted_paths"])


@pytest.mark.parametrize(
    "field", ["eventId", "eventName", "resourceName", "sourceIpAddress", "requestId"]
)
def test_audit_scalar_fields_cannot_hide_nested_request_objects(field):
    assert CANARY not in json.dumps(project_event({field: {"opaque": CANARY}}))


@pytest.mark.parametrize(
    "container,leaf",
    [
        ("objectRef", "name"),
        ("objectRef", "resourceVersion"),
        ("objectRef", "resource"),
        ("user", "username"),
        ("user", "uid"),
        ("responseStatus", "reason"),
        ("responseStatus", "status"),
        ("responseStatus", "code"),
    ],
)
def test_kubernetes_audit_nested_leaves_are_typed(container, leaf):
    result = project_event({container: {leaf: {"responseObject": {"value": CANARY}}}}, "kubernetes")
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize(
    "event",
    [
        {"user": {"groups": [{"requestObject": CANARY}]}},
        {"sourceIPs": [{"opaque": CANARY}]},
        {"sourceIPs": [CANARY]},
        {"referencedResources": {"requestParameters": [CANARY]}},
        {"referencedResources": {"ACS::ECS::Instance": [{"opaque": CANARY}]}},
    ],
)
def test_special_nested_log_collections_are_typed_and_scoped(event):
    category = "audit" if "referencedResources" in event else "kubernetes"
    assert CANARY not in json.dumps(project_event(event, category))


def test_valid_audit_identity_and_resource_references_remain_useful():
    event = {
        "eventName": "DescribeInstances",
        "eventRW": "Read",
        "userIdentity": {
            "type": "assumed-role",
            "principalId": "role:session",
            "accountId": ACCOUNT,
            "userName": "audit:session",
            "sessionContext": {"token": CANARY},
        },
        "referencedResources": {"ACS::ECS::Instance": ["i-security-audit"]},
        "requestParameters": {"AccessKeySecret": CANARY},
        "responseElements": {"opaque": CANARY},
    }
    result = project_event(event)
    assert result["userIdentity"]["principalId"] == "role:session"
    assert result["referencedResources"] == {"ACS::ECS::Instance": ["i-security-audit"]}
    assert CANARY not in json.dumps(result)


def test_valid_kubernetes_audit_metadata_excludes_payloads_and_url_queries():
    result = project_event(
        {
            "verb": "get",
            "requestURI": f"/api/v1/namespaces/prod/pods?token={CANARY}",
            "sourceIPs": ["10.0.0.1", "2001:db8::1"],
            "user": {
                "username": "system:serviceaccount:audit:reader",
                "groups": ["system:authenticated"],
                "extra": {"opaque": CANARY},
            },
            "objectRef": {"resource": "pods", "name": "web", "namespace": "prod"},
            "responseStatus": {"code": 200, "reason": "Success", "message": CANARY},
            "requestObject": {"spec": {"password": CANARY}},
            "responseObject": {"data": CANARY},
        },
        "kubernetes",
    )
    assert result["responseStatus"] == {"code": 200, "reason": "Success"}
    assert result["sourceIPs"] == ["10.0.0.1", "2001:db8::1"]
    assert result["objectRef"]["resource"] == "pods"
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize("category", ["vpc_flows", "firewall"])
def test_flow_and_firewall_projection_never_returns_opaque_log_messages(category):
    result = project_event(
        {
            "srcaddr": "10.0.0.1",
            "dstaddr": "10.0.0.2",
            "srcport": "443",
            "action": "ACCEPT",
            "bytes": "500",
            "message": CANARY,
            "request": CANARY,
            "response": CANARY,
            "packets": {"opaque": CANARY},
        },
        category,
    )
    assert result["srcaddr"] == "10.0.0.1"
    assert result["bytes"] == "500"
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize("wrapper", ["event", "eventData", "ActionTrailEvent"])
def test_encoded_audit_event_is_projected_before_evidence(wrapper):
    raw = {
        wrapper: json.dumps(
            {
                "eventName": "AssumeRole",
                "requestParameters": {"opaque": CANARY},
                "responseElements": {"AccessKeySecret": CANARY},
            }
        )
    }
    record = projected_record("alicloud.actiontrail.events", raw)
    assert record["data"]["eventName"] == "AssumeRole"
    assert CANARY not in json.dumps(record)


@pytest.mark.parametrize(
    "field",
    [
        "ServerKey",
        "server_key",
        "SECRET_DATA",
        "secret_data",
        "userData",
        "user_data",
        "configuration",
        "CONFIG_CONTENT",
        "EnvironmentVariables",
        "client_token",
        "securityToken",
        "bootstrap_script",
        "BootstrapData",
        "custom_config",
        "pre_user_data",
        "connectionString",
        "authInfo",
        "header_value",
        "password",
        "access_key_secret",
        "PrivateKey",
        "kube_config",
    ],
)
def test_explicit_credentials_and_opaque_configuration_are_normalized(field):
    result = projected_record("alicloud.cs.clusters", {field: CANARY, "cluster_id": "c-test"})
    assert CANARY not in json.dumps(result)
    assert result["data"]["cluster_id"] == "c-test"


def test_policy_projection_preserves_literal_percent_sequences_in_valid_json():
    policy = {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "oss:GetBucketInfo",
                "Resource": "acs:oss:*:*:bucket/name%2Fsegment",
            }
        ],
    }
    raw = json.dumps(policy)
    for encoded in [raw, quote(raw, safe="")]:
        result = projected_record("alicloud.ram.policyVersions", {"PolicyDocument": encoded})
        assert result["data"]["PolicyDocument"] == policy


def test_invalid_or_oversized_policy_documents_are_redacted():
    for payload in ["opaque:" + CANARY, "x" * 262145]:
        result = projected_record("alicloud.ram.policyVersions", {"PolicyDocument": payload})
        assert result["data"]["PolicyDocument"] == REDACTED
        assert "data.PolicyDocument" in result["redacted_paths"]


def test_truncated_configuration_lists_are_disclosed_in_evidence():
    omitted = []
    data = project_config({"Rules": [{"id": str(i)} for i in range(501)]}, omitted)
    assert len(data["Rules"]) <= 501
    assert any("Rules" in path for path in omitted)


def test_truncated_resource_reference_lists_are_disclosed():
    result = project_event(
        {"referencedResources": {"ACS::ECS::Instance": [f"i-{i}" for i in range(101)]}}
    )
    assert len(result["referencedResources"]["ACS::ECS::Instance"]) <= 100
    assert any("referencedResources" in path for path in result["redacted_paths"])


def test_omitted_field_paths_cannot_reflect_obvious_credential_strings():
    token = "TOKEN_CANARY_0123456789"
    result = project_event(
        {"eventName": "DescribeInstances", "Authorization: Bearer " + token: "ignored"}
    )
    assert token not in json.dumps(result)


def test_private_key_returning_rds_ssl_api_is_not_in_catalog():
    assert not any(operation.action == "DescribeDBInstanceSSL" for operation in OPERATIONS.values())
    assert "alicloud.rds.tls" not in RESOURCE_SPECS


@pytest.mark.parametrize(
    "query",
    [
        {"provider": "gcp", "kind": "alicloud.ecs.instances", "project": "project-a"},
        {"provider": "alicloud", "kind": "gcp.compute.instances", "account_id": ACCOUNT},
        {
            "provider": "alicloud",
            "kind": "alicloud.ecs.instances",
            "account_id": ACCOUNT,
            "project": "project-a",
        },
        {
            "provider": "gcp",
            "kind": "gcp.compute.instances",
            "project": "project-a",
            "account_id": ACCOUNT,
        },
        {
            "provider": "gcp",
            "kind": "gcp.compute.instances",
            "project": "project-a",
            "scope": "organizations/123",
        },
    ],
)
def test_resource_query_cannot_mix_provider_scopes(query):
    with pytest.raises(ValidationError):
        ResourceQuery(**query)


@pytest.mark.parametrize(
    "query",
    [
        {
            "provider": "alicloud",
            "account_id": ACCOUNT,
            "view": "projects/project-a/locations/global/buckets/a/views/all",
        },
        {"provider": "gcp", "project": "project-a", "logstore": "flows"},
        {"provider": "gcp", "project": "project-a", "location": "cn-hangzhou"},
    ],
)
def test_log_query_cannot_cross_provider_scope_models(query):
    with pytest.raises(ValidationError):
        LogQuery(**query)


def test_scope_configuration_rejects_wrong_account_or_region_for_log_destinations():
    for account, region in [("9876543210987654", "cn-hangzhou"), (ACCOUNT, "ap-southeast-1")]:
        with pytest.raises(ValidationError):
            Settings(
                allowed_alicloud_accounts=[ACCOUNT],
                allowed_alicloud_regions=["cn-hangzhou"],
                alicloud_logstores={
                    "flows": {
                        "account_id": account,
                        "region": region,
                        "project": "security-audit",
                        "logstore": "flows",
                    }
                },
            )


def test_assessment_explicit_queries_cannot_start_from_caller_cursor():
    query = ResourceQuery(
        provider="alicloud",
        kind="alicloud.ecs.instances",
        account_id=ACCOUNT,
        location="cn-hangzhou",
        cursor="opaque",
    )
    with pytest.raises(ValidationError):
        AssessmentRequest(queries=[query])
