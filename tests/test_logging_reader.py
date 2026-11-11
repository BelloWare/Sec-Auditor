"""Bounded log queries, incomplete pages, and content projection regressions."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from sec_auditor.config import Settings
from sec_auditor.logging_reader import LoggingReader, summarize_flows, time_window
from sec_auditor.models import ResourceRecord
from sec_auditor.transport import CloudAPIError

START = "2025-01-02T00:00:00Z"
END = "2025-01-02T01:00:00Z"


class FakeClient:
    def __init__(self, payload=None):
        self.payload = payload if payload is not None else {"entries": []}
        self.requests = []

    async def post_read(self, url, json):
        self.requests.append((url, json))
        return self.payload


def reader(payload=None, **settings):
    client = FakeClient(payload)
    return LoggingReader(client, Settings(allowed_projects=["project-a"], **settings)), client


async def query(logs, **kwargs):
    return await logs.query("project-a", start_time=START, end_time=END, **kwargs)


def test_time_offsets_normalized_and_default_interval_is_one_hour():
    start, end = time_window("2025-01-02T08:00:00+08:00", "2025-01-02T09:00:00+08:00", 24)
    assert start == "2025-01-02T00:00:00+00:00"
    assert end == "2025-01-02T01:00:00+00:00"
    start, end = time_window(None, END, 24)
    assert datetime.fromisoformat(end) - datetime.fromisoformat(start) == timedelta(hours=1)


@pytest.mark.parametrize(
    "start,end",
    [
        ("2025-01-02T00:00:00", END),
        (START, "2025-01-02T01:00:00"),
        ("not-a-time", END),
        (END, START),
        (START, START),
        ("2024-12-31T00:00:00Z", END),
    ],
)
def test_invalid_or_excessive_time_windows_rejected(start, end):
    with pytest.raises(ValueError):
        time_window(start, end, 24)


def test_future_log_window_rejected():
    future = datetime.now(UTC) + timedelta(minutes=20)
    with pytest.raises(ValueError, match="future"):
        time_window((future - timedelta(hours=1)).isoformat(), future.isoformat(), 24)


@pytest.mark.parametrize(
    "category,expected",
    [
        (
            "audit",
            [
                "cloudaudit.googleapis.com/activity",
                "cloudaudit.googleapis.com/system_event",
                "cloudaudit.googleapis.com/policy",
                "cloudaudit.googleapis.com/data_access",
            ],
        ),
        ("data_access", ["cloudaudit.googleapis.com/data_access"]),
        (
            "vpc_flows",
            ["compute.googleapis.com/vpc_flows", "networkmanagement.googleapis.com/vpc_flows"],
        ),
        ("firewall", ["compute.googleapis.com/firewall"]),
        ("gke", ["k8s_container", "k8s_cluster", "k8s_node", "k8s_pod"]),
    ],
)
async def test_log_category_filters_use_both_flow_sources_and_all_audit_kinds(category, expected):
    logs, client = reader()
    await query(logs, category=category)
    url, body = client.requests[0]
    assert url == "https://logging.googleapis.com/v2/entries:list"
    assert body["resourceNames"] == ["projects/project-a"]
    for item in expected:
        assert item in body["filter"]


async def test_caller_filter_is_added_to_scope_category_and_time_constraints():
    logs, client = reader()
    caller = 'severity>=ERROR OR protoPayload.methodName="example.operation"'
    result = await query(logs, category="audit", filter=caller, page_size=17)
    body = client.requests[0][1]
    assert body["resourceNames"] == ["projects/project-a"]
    assert 'timestamp >= "2025-01-02T00:00:00+00:00"' in body["filter"]
    assert 'timestamp < "2025-01-02T01:00:00+00:00"' in body["filter"]
    assert f"AND ({caller})" in body["filter"]
    assert "cloudaudit.googleapis.com/activity" in body["filter"]
    assert body["pageSize"] == 17
    assert result.metadata["start_time"].startswith("2025-01-02T00:00:00")


@pytest.mark.parametrize(
    "filter_",
    [
        'severity>=DEFAULT) OR timestamp>="1900-01-01T00:00:00Z" OR (severity>=DEFAULT',
        "(severity>=ERROR",
        'textPayload="unterminated',
        "severity>=ERROR\x00",
        "x" * 4001,
    ],
)
async def test_unbalanced_or_invalid_filter_rejected_without_api_call(filter_):
    logs, client = reader()
    with pytest.raises(ValueError):
        await query(logs, filter=filter_)
    assert client.requests == []


async def test_parentheses_inside_quoted_filter_literal_are_allowed():
    logs, client = reader()
    await query(logs, filter='protoPayload.methodName="a)b("')
    assert len(client.requests) == 1


async def test_log_view_requires_authorized_project_and_canonical_path():
    logs, client = reader()
    view = "projects/project-a/locations/global/buckets/_Default/views/security"
    await query(logs, view=view)
    assert client.requests[0][1]["resourceNames"] == [view]
    with pytest.raises(ValueError, match="authorized project"):
        await query(
            logs, view="projects/project-b/locations/global/buckets/_Default/views/security"
        )
    with pytest.raises(ValueError):
        await query(logs, view="projects/project-a/locations/global/buckets/../views/security")
    assert len(client.requests) == 1


@pytest.mark.parametrize("kwargs", [{"category": "unknown"}, {"page_size": 0}, {"page_size": 201}])
async def test_query_limits_rejected_before_api_access(kwargs):
    logs, client = reader()
    with pytest.raises(ValueError):
        await query(logs, **kwargs)
    assert client.requests == []


async def test_empty_page_with_token_preserves_continuation_and_warns_about_coverage():
    logs, client = reader({"entries": [], "nextPageToken": "native-next-token"})
    result = await query(logs, page_token="native-first-token")
    assert result.items == []
    assert result.next_page_token == "native-next-token"
    assert client.requests[0][1]["pageToken"] == "native-first-token"
    assert any("not proof" in warning for warning in result.warnings)
    assert result.metadata.get("complete") is not True


async def test_empty_final_page_still_does_not_assert_no_events_occurred():
    logs, _ = reader({"entries": []})
    result = await query(logs)
    assert result.next_page_token is None
    assert any("retention" in warning and "routing" in warning for warning in result.warnings)


async def test_audit_payload_omits_request_response_text_and_error_message():
    secret = "SENSITIVE_PAYLOAD_SHOULD_NOT_RETURN"
    entry = {
        "insertId": "entry-1",
        "timestamp": START,
        "logName": "projects/project-a/logs/cloudaudit.googleapis.com%2Fdata_access",
        "resource": {"type": "gcs_bucket", "labels": {"project_id": "project-a"}},
        "textPayload": secret,
        "jsonPayload": {"application": secret},
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.objects.get",
            "resourceName": "projects/_/buckets/example/objects/object-name",
            "request": {"contents": secret},
            "response": {"contents": secret},
            "metadata": {"contents": secret},
            "status": {"code": 7, "message": secret},
            "authenticationInfo": {
                "principalEmail": "auditor@example.test",
                "thirdPartyPrincipal": {"data": secret},
            },
            "requestMetadata": {"callerIp": "192.0.2.1", "requestAttributes": {"data": secret}},
        },
    }
    logs, _ = reader({"entries": [entry]})
    result = await query(logs)
    assert len(result.items) == 1
    encoded = result.items[0].model_dump_json()
    assert secret not in encoded
    payload = result.items[0].data["protoPayload"]
    assert payload["methodName"] == "storage.objects.get"
    assert payload["status"] == {"code": 7}
    assert payload["authenticationInfo"]["principalEmail"] == "auditor@example.test"
    assert "protoPayload.request" in result.items[0].data["omitted_payload_fields"]


async def test_all_metadata_and_gke_categories_do_not_expose_application_log_payloads():
    for category in ("all_metadata", "gke"):
        logs, _ = reader(
            {
                "entries": [
                    {
                        "insertId": "entry",
                        "textPayload": "PRIVATE APP DATA",
                        "jsonPayload": {"arbitrary": "PRIVATE APP DATA"},
                    }
                ]
            }
        )
        result = await query(logs, category=category)
        assert "PRIVATE APP DATA" not in result.items[0].model_dump_json()
        assert set(result.items[0].data["omitted_payload_fields"]) == {"textPayload", "jsonPayload"}


async def test_flow_projection_keeps_traffic_evidence_and_labels_sampling():
    entry = {
        "insertId": "flow-1",
        "jsonPayload": {
            "connection": {"dest_ip": "203.0.113.2", "dest_port": 443, "protocol": 6},
            "bytes_sent": "128",
            "packets_sent": "2",
            "application_data": "DO NOT COPY",
        },
    }
    logs, _ = reader({"entries": [entry]})
    result = await query(logs, category="vpc_flows")
    assert result.items[0].data["jsonPayload"]["bytes_sent"] == "128"
    assert "DO NOT COPY" not in result.items[0].model_dump_json()
    assert any("sampled" in warning for warning in result.warnings)
    summary = summarize_flows(result.items)
    assert summary["groups"][0]["observed_bytes_sent"] == 128
    assert summary["groups"][0]["observed_records"] == 1
    assert "not an exhaustive" in summary["basis"]


async def test_identifiers_are_deterministic_when_insert_id_is_absent():
    entry = {"timestamp": START, "severity": "NOTICE", "textPayload": "excluded"}
    logs, _ = reader({"entries": [entry]})
    first = await query(logs)
    second = await query(logs)
    assert first.items[0].name == second.items[0].name
    assert "excluded" not in first.items[0].name


async def test_invalid_entries_collection_is_reported():
    logs, _ = reader({"entries": {"not": "a list"}})
    with pytest.raises((ValueError, CloudAPIError)):
        await query(logs)


async def test_invalid_entry_is_not_silently_counted_as_complete():
    logs, _ = reader({"entries": [None, {"insertId": "valid-entry", "timestamp": START}]})
    try:
        result = await query(logs)
    except (ValueError, CloudAPIError):
        return
    assert result.errors or any(
        any(word in warning.lower() for word in ("invalid", "malformed", "skipped"))
        for warning in result.warnings
    )


async def test_invalid_proto_payload_does_not_raise_unclassified_type_error():
    logs, _ = reader(
        {"entries": [{"insertId": "entry", "protoPayload": None, "textPayload": "DO NOT COPY"}]}
    )
    try:
        result = await query(logs)
    except (ValueError, CloudAPIError):
        return
    assert "DO NOT COPY" not in json.dumps([item.model_dump(mode="json") for item in result.items])


def test_flow_summary_is_bounded_and_does_not_claim_full_traffic_totals():
    records = [
        ResourceRecord(
            kind="gcp.logging.entry",
            name=str(i),
            data={
                "jsonPayload": {
                    "connection": {"dest_ip": f"10.0.0.{i}", "dest_port": 443, "protocol": 6},
                    "bytes_sent": i,
                }
            },
        )
        for i in range(101)
    ]
    summary = summarize_flows(records)
    assert summary["records_examined"] == 101
    assert len(summary["groups"]) == 100
    assert summary["groups_truncated"] is True
    assert summary["groups"][0]["observed_bytes_sent"] == 100
    assert "Only records returned" in summary["basis"]
    empty = summarize_flows([])
    assert empty["groups"] == []
    assert "not an exhaustive" in empty["basis"]
