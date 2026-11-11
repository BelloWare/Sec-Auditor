"""Bounded audit/flow reads must never become a raw event or config dump."""

import json
from collections import deque
from urllib.parse import quote

import pytest

from sec_auditor.alicloud_logs import read_logs
from sec_auditor.alicloud_projection import project_event
from sec_auditor.config import Settings
from sec_auditor.models import ResourceRecord
from sec_auditor.projection import project_record
from sec_auditor.providers.alicloud import AlibabaProvider
from sec_auditor.requests import LogQuery

ACCOUNT = "1234567890123456"
REGION = "ap-southeast-1"
START = "2026-01-01T10:00:00Z"
END = "2026-01-01T11:00:00Z"


class Client:
    def __init__(self, settings, *responses):
        self.settings = settings
        self.responses = deque(responses)
        self.calls = []

    async def execute(self, account_id, operation_id, *, region=None, parameters=None):
        self.calls.append(("execute", account_id, operation_id, region, parameters))
        return self.responses.popleft()

    async def query_logs(self, account_id, **kwargs):
        self.calls.append(("logs", account_id, kwargs))
        return self.responses.popleft()


def configuration(**changes):
    values = {
        "allowed_alicloud_accounts": [ACCOUNT],
        "allowed_alicloud_regions": [REGION],
        "alicloud_logstores": {
            "approved-flow": {
                "account_id": ACCOUNT,
                "region": REGION,
                "project": "security-logs",
                "logstore": "vpc-flow",
                "category": "vpc_flows",
            },
            "approved-k8s": {
                "account_id": ACCOUNT,
                "region": REGION,
                "project": "security-logs",
                "logstore": "ack-audit",
                "category": "kubernetes",
            },
        },
    }
    values.update(changes)
    return Settings(**values)


def query(**changes):
    values = {
        "provider": "alicloud",
        "account_id": ACCOUNT,
        "location": REGION,
        "start_time": START,
        "end_time": END,
    }
    values.update(changes)
    return LogQuery(**values)


async def test_actiontrail_uses_bounded_interval_and_projects_encoded_event_payloads():
    event = {
        "eventId": "e-1",
        "eventName": "UpdateRole",
        "eventTime": START,
        "eventSource": "ram.aliyuncs.com",
        "userIdentity": {
            "type": "ram-user",
            "principalId": "user-1",
            "accessKeyId": "IDENTITY-KEY-CONTENT",
            "sessionContext": {"payload": "SESSION-CONTENT"},
        },
        "requestParameters": {"PolicyDocument": "RAW-REQUEST-CONTENT"},
        "responseElements": {"value": "RAW-RESPONSE-CONTENT"},
    }
    settings = configuration()
    client = Client(
        settings, {"Events": [{"eventId": "e-1", "event": json.dumps(event)}], "NextToken": "next"}
    )
    result = await read_logs(settings, AlibabaProvider(client), client, query(page_size=200), {})
    assert client.calls[0][:4] == ("execute", ACCOUNT, "actiontrail.LookupEvents", REGION)
    parameters = client.calls[0][4]
    assert parameters["StartTime"] == START
    assert parameters["EndTime"] == END
    assert parameters["MaxResults"] == 50
    assert result.next_page_token == "next"
    assert result.items[0].data["eventName"] == "UpdateRole"
    combined = json.dumps(result.model_dump(mode="json"))
    for sentinel in (
        "IDENTITY-KEY-CONTENT",
        "SESSION-CONTENT",
        "RAW-REQUEST-CONTENT",
        "RAW-RESPONSE-CONTENT",
    ):
        assert sentinel not in combined
    assert result.metadata["content_projection"] == "security_metadata"


async def test_actiontrail_continuation_reuses_bound_window_in_state():
    settings = configuration()
    client = Client(settings, {"Events": [], "RequestId": "r"})
    state = {"start_time": START, "end_time": END, "token": "page-two"}
    await read_logs(
        settings, AlibabaProvider(client), client, query(start_time=None, end_time=None), state
    )
    assert client.calls[0][4]["StartTime"] == START
    assert client.calls[0][4]["EndTime"] == END
    assert client.calls[0][4]["NextToken"] == "page-two"


@pytest.mark.parametrize(
    "changes",
    [
        {"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-03T00:00:00Z"},
        {"start_time": END, "end_time": START},
        {"start_time": "2026-01-01T10:00:00"},
        {"filter": "eventName=Delete*"},
        {"location": None},
        {"category": "vpc_flows"},
    ],
)
async def test_invalid_or_unbounded_actiontrail_request_is_rejected_before_read(changes):
    settings = configuration()
    client = Client(settings)
    with pytest.raises(ValueError):
        await read_logs(settings, AlibabaProvider(client), client, query(**changes), {})
    assert client.calls == []


async def test_actiontrail_respects_operator_limit_stricter_than_provider_maximum():
    settings = configuration(max_log_hours=2)
    client = Client(settings)
    with pytest.raises(ValueError):
        await read_logs(
            settings,
            AlibabaProvider(client),
            client,
            query(start_time="2026-01-01T00:00:00Z", end_time="2026-01-01T03:00:00Z"),
            {},
        )
    assert not client.calls


async def test_sls_uses_only_registered_destination_and_security_fields():
    settings = configuration()
    client = Client(
        settings,
        {
            "logs": [
                {
                    "srcaddr": "10.0.0.2",
                    "dstaddr": "203.0.113.8",
                    "srcport": "40123",
                    "dstport": "443",
                    "protocol": "6",
                    "bytes": "200",
                    "action": "ACCEPT",
                    "__time__": "123",
                    "content": "RAW-LOG-CONTENT",
                    "request": {"opaque": "REQUEST-CONTENT"},
                }
            ],
            "progress": "Complete",
            "next_offset": 1,
        },
    )
    result = await read_logs(
        settings,
        AlibabaProvider(client),
        client,
        query(logstore="approved-flow", category="vpc_flows", page_size=200),
        {},
    )
    assert client.calls[0][0:2] == ("logs", ACCOUNT)
    arguments = client.calls[0][2]
    assert arguments["project"] == "security-logs"
    assert arguments["logstore"] == "vpc-flow"
    assert arguments["region"] == REGION
    assert arguments["line"] == 100
    assert arguments["offset"] == 0
    assert arguments["end_time"] - arguments["start_time"] == 3600
    assert result.items[0].kind == "alicloud.logs.vpc_flows"
    assert result.items[0].data["srcaddr"] == "10.0.0.2"
    assert result.next_page_token == "1"
    encoded = json.dumps(project_record(result.items[0]))
    assert "RAW-LOG-CONTENT" not in encoded
    assert "REQUEST-CONTENT" not in encoded
    assert result.metadata["effective_page_size"] == 100
    assert result.warnings


@pytest.mark.parametrize(
    "changes",
    [
        {"logstore": "unregistered"},
        {"logstore": "https://malicious.invalid"},
        {"account_id": "9999999999999999"},
        {"location": "cn-hangzhou"},
        {"category": "audit"},
        {"filter": "* | SELECT *"},
    ],
)
async def test_sls_rejects_alias_account_region_category_or_query_mismatch(changes):
    settings = configuration()
    client = Client(settings)
    values = {"logstore": "approved-flow", "category": "vpc_flows", **changes}
    with pytest.raises(ValueError):
        await read_logs(settings, AlibabaProvider(client), client, query(**values), {})
    assert client.calls == []


async def test_sls_incomplete_progress_remains_an_error_with_retryable_same_offset():
    settings = configuration()
    client = Client(settings, {"logs": [], "progress": "Incomplete", "next_offset": 0})
    result = await read_logs(
        settings,
        AlibabaProvider(client),
        client,
        query(logstore="approved-flow", category="vpc_flows"),
        {},
    )
    assert result.errors[0].code == "QUERY_INCOMPLETE"
    assert result.errors[0].retryable
    assert result.next_page_token == "0"
    assert result.metadata["observed_records_only"]


@pytest.mark.parametrize("state", [{"token": "no-integer"}, {"token": "-1"}, {"token": "100001"}])
async def test_sls_invalid_cursor_offset_never_reaches_client(state):
    settings = configuration()
    client = Client(settings)
    with pytest.raises(ValueError):
        await read_logs(
            settings,
            AlibabaProvider(client),
            client,
            query(logstore="approved-flow", category="vpc_flows"),
            state,
        )
    assert not client.calls


async def test_sls_malformed_page_cannot_exceed_effective_service_page_limit():
    settings = configuration()
    client = Client(settings, {"logs": [{"srcaddr": "10.0.0.1"}] * 101, "progress": "Complete"})
    with pytest.raises(ValueError, match="response"):
        await read_logs(
            settings,
            AlibabaProvider(client),
            client,
            query(logstore="approved-flow", category="vpc_flows", page_size=200),
            {},
        )


def test_kubernetes_audit_projection_preserves_attribution_and_drops_payloads():
    event = {
        "verb": "create",
        "requestURI": "/api/v1/namespaces/default/secrets?token=HIDDEN-QUERY",
        "user": {
            "username": "alice",
            "groups": ["developers"],
            "extra": {"credentials": "EXTRA-CONTENT"},
        },
        "objectRef": {"resource": "secrets", "name": "secret-a", "namespace": "default"},
        "responseStatus": {"code": 201, "status": "Success", "message": "RESPONSE-CONTENT"},
        "requestObject": {"data": {"secret": "SECRET-OBJECT-CONTENT"}},
        "responseObject": {"value": "SECRET-RESPONSE-CONTENT"},
    }
    result = project_event(event, "kubernetes")
    assert result["user"]["username"] == "alice"
    assert result["objectRef"]["resource"] == "secrets"
    assert result["responseStatus"]["code"] == 201
    encoded = json.dumps(result)
    for sentinel in (
        "EXTRA-CONTENT",
        "RESPONSE-CONTENT",
        "SECRET-OBJECT-CONTENT",
        "SECRET-RESPONSE-CONTENT",
        "HIDDEN-QUERY",
    ):
        assert sentinel not in encoded


def test_event_identity_metadata_rejects_nested_opaque_leaf_values():
    result = project_event(
        {
            "eventName": "UpdateRole",
            "userIdentity": {
                "type": "ram-user",
                "principalId": {"opaque": "NESTED-IDENTITY-PAYLOAD"},
                "userName": ["ARRAY-IDENTITY-PAYLOAD"],
            },
        }
    )
    assert result["userIdentity"]["type"] == "ram-user"
    assert "NESTED-IDENTITY-PAYLOAD" not in json.dumps(result)
    assert "ARRAY-IDENTITY-PAYLOAD" not in json.dumps(result)


def test_kubernetes_audit_metadata_rejects_objects_inside_allowed_leaf_arrays():
    event = {
        "verb": "get",
        "sourceIPs": ["203.0.113.7", {"opaque": "NESTED-IP-PAYLOAD"}],
        "user": {"username": "alice", "groups": ["developers", {"opaque": "NESTED-GROUP-PAYLOAD"}]},
        "objectRef": {"resource": "pods", "name": {"opaque": "NESTED-REFERENCE-PAYLOAD"}},
    }
    result = project_event(event, "kubernetes")
    assert result["user"]["username"] == "alice"
    encoded = json.dumps(result)
    for sentinel in ("NESTED-IP-PAYLOAD", "NESTED-GROUP-PAYLOAD", "NESTED-REFERENCE-PAYLOAD"):
        assert sentinel not in encoded


def test_encoded_ram_policy_and_inline_alibaba_configuration_are_projected():
    policy = {
        "Version": "1",
        "Statement": [{"Effect": "Allow", "Action": ["ecs:DescribeInstances"], "Resource": ["*"]}],
    }
    record = ResourceRecord(
        provider="alicloud",
        account_id=ACCOUNT,
        kind="alicloud.ram.roles",
        name="role",
        data={
            "AssumeRolePolicyDocument": quote(json.dumps(policy)),
            "UserData": "BOOTSTRAP-CONTENT",
            "EnvironmentVariables": {"opaque": "ENV-CONTENT"},
            "ConnectionString": "DB-CONTENT",
            "SecretData": "SECRET-CONTENT",
        },
    )
    result = project_record(record)
    assert result["data"]["AssumeRolePolicyDocument"]["Statement"][0]["Action"] == [
        "ecs:DescribeInstances"
    ]
    encoded = json.dumps(result)
    for sentinel in ("BOOTSTRAP-CONTENT", "ENV-CONTENT", "DB-CONTENT", "SECRET-CONTENT"):
        assert sentinel not in encoded


def test_unparseable_policy_payload_is_not_returned_as_an_opaque_string():
    record = ResourceRecord(
        provider="alicloud",
        account_id=ACCOUNT,
        kind="alicloud.ram.policies",
        name="policy",
        data={"PolicyDocument": "UNPARSEABLE-POLICY-CONTENT"},
    )
    result = project_record(record)
    assert "UNPARSEABLE-POLICY-CONTENT" not in json.dumps(result)


def test_reprojection_retains_omission_provenance_without_trusting_markers():
    projected = project_event(
        {
            "eventName": "DescribeInstances",
            "requestParameters": {"opaque": "PRIVATE-REQUEST"},
            "responseElements": {"opaque": "PRIVATE-RESPONSE"},
        }
    )
    # A marker must not authorize arbitrary fields on a subsequent projection.
    projected["responseElements"] = {"opaque": "PRIVATE-INJECTED"}
    output = project_record(
        ResourceRecord(
            provider="alicloud", kind="alicloud.actiontrail.events", name="event", data=projected
        )
    )
    assert "requestParameters" in output["data"]["omitted_payload_fields"]
    assert "responseElements" in output["data"]["omitted_payload_fields"]
    assert "PRIVATE-" not in json.dumps(output)
