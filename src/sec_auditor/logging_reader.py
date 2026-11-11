"""Bounded audit/flow log queries. Never export logs or read log archive objects."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sec_auditor.config import Settings
from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.policy import validate_project
from sec_auditor.projection import project_log_entry
from sec_auditor.transport import GoogleRestClient

CATEGORIES = {
    "audit": '(log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/system_event") OR log_id("cloudaudit.googleapis.com/policy") OR log_id("cloudaudit.googleapis.com/data_access"))',
    "data_access": 'log_id("cloudaudit.googleapis.com/data_access")',
    "vpc_flows": '(log_id("compute.googleapis.com/vpc_flows") OR log_id("networkmanagement.googleapis.com/vpc_flows"))',
    "firewall": 'log_id("compute.googleapis.com/firewall")',
    "gke": '(resource.type="k8s_container" OR resource.type="k8s_cluster" OR resource.type="k8s_node" OR resource.type="k8s_pod")',
    "all_metadata": "",
}


def validate_filter(value: str) -> None:
    if len(value) > 4000 or any(ord(character) < 32 for character in value):
        raise ValueError("Log filter exceeds its size limit or contains control characters")
    quoted = False
    escaped = False
    depth = 0
    for index, character in enumerate(value):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character == "(":
            depth += 1
            if depth > 32:
                raise ValueError("Log filter nesting exceeds the supported limit")
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("Log filter has unbalanced parentheses")
        elif value[index : index + 2] in {"--", "/*", "*/"}:
            raise ValueError("Log filter comments are not permitted")
    if quoted or escaped or depth:
        raise ValueError("Log filter has an unterminated string or parentheses")


def time_window(start_time: str | None, end_time: str | None, max_hours: int) -> tuple[str, str]:
    now = datetime.now(UTC)
    try:
        end = datetime.fromisoformat(end_time.replace("Z", "+00:00")) if end_time else now
        start = (
            datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            if start_time
            else end - timedelta(hours=1)
        )
    except ValueError as exc:
        raise ValueError("Log times must be ISO 8601 timestamps") from exc
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("Log times must include a timezone")
    if start >= end or end - start > timedelta(hours=max_hours):
        raise ValueError(f"Log interval must be positive and at most {max_hours} hours")
    if end > now + timedelta(minutes=5):
        raise ValueError("Log interval ends in the future")
    return start.astimezone(UTC).isoformat(), end.astimezone(UTC).isoformat()


class LoggingReader:
    def __init__(self, client: GoogleRestClient, settings: Settings):
        self.client = client
        self.settings = settings

    async def query(
        self,
        project: str,
        *,
        category: str = "audit",
        start_time: str | None = None,
        end_time: str | None = None,
        filter: str = "",
        page_size: int = 100,
        page_token: str | None = None,
        view: str | None = None,
    ) -> CollectionResult:
        validate_project(project)
        if category not in CATEGORIES:
            raise ValueError("Unsupported log category")
        validate_filter(filter)
        if not 1 <= page_size <= self.settings.max_page_size:
            raise ValueError("Log page size is outside configured limits")
        start, end = time_window(start_time, end_time, self.settings.max_log_hours)
        filters = [f'timestamp >= "{start}"', f'timestamp < "{end}"']
        if CATEGORIES[category]:
            filters.append(CATEGORIES[category])
        if filter:
            filters.append(f"({filter})")
        resource = f"projects/{project}"
        if view is not None:
            import re

            if not re.fullmatch(
                r"projects/[a-z0-9-]+/locations/[a-z0-9-]+/buckets/[a-zA-Z0-9_.-]+/views/[a-zA-Z0-9_.-]+",
                view,
            ):
                raise ValueError("Invalid log view name")
            if any(segment in {".", ".."} for segment in view.split("/")):
                raise ValueError("Invalid log view path")
            if view.split("/")[1] != project:
                raise ValueError("Log view must belong to the authorized project")
            resource = view
        body: dict[str, Any] = {
            "resourceNames": [resource],
            "filter": " AND ".join(filters),
            "orderBy": "timestamp desc",
            "pageSize": page_size,
        }
        if page_token:
            body["pageToken"] = page_token
        payload = await self.client.post_read(
            "https://logging.googleapis.com/v2/entries:list", body
        )
        result = CollectionResult(
            next_page_token=payload.get("nextPageToken") or None,
            metadata={
                "project": project,
                "category": category,
                "start_time": start,
                "end_time": end,
                "payload_projection": "security_metadata",
                "resource": resource,
            },
            warnings=[
                "No records is not proof of no events: check logging enablement, retention, routing, permissions, and pagination."
            ],
        )
        if category == "vpc_flows":
            result.warnings.append(
                "VPC Flow Logs are sampled telemetry; returned records do not represent every packet or connection."
            )
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("Logging API returned an invalid entries collection")
        for entry in entries:
            if not isinstance(entry, dict):
                result.errors.append(
                    CollectionError(
                        target=resource,
                        code="INVALID_RESPONSE",
                        message="An invalid log entry was omitted",
                    )
                )
                continue
            identifier = str(
                entry.get("insertId")
                or hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()[:24]
            )
            result.items.append(
                ResourceRecord(
                    kind="gcp.logging.entry",
                    name=f"{resource}/entries/{identifier}",
                    project=project,
                    data=project_log_entry(entry, category),
                    source="https://logging.googleapis.com/v2/entries:list",
                )
            )
        return result


def summarize_flows(records: list[ResourceRecord]) -> dict[str, Any]:
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        payload = record.data.get("jsonPayload", {})
        connection = payload.get("connection", {})
        if not isinstance(connection, dict):
            continue
        key = (
            str(connection.get("dest_ip", "unknown")),
            str(connection.get("dest_port", "unknown")),
            str(connection.get("protocol", "unknown")),
        )
        row = groups.setdefault(
            key,
            {
                "destination_ip": key[0],
                "destination_port": key[1],
                "protocol": key[2],
                "observed_records": 0,
                "observed_bytes_sent": 0,
            },
        )
        row["observed_records"] += 1
        try:
            row["observed_bytes_sent"] += max(0, int(payload.get("bytes_sent", 0)))
        except (ValueError, TypeError):
            pass
    return {
        "basis": "Only records returned in this response; not an exhaustive traffic total",
        "records_examined": len(records),
        "groups": sorted(groups.values(), key=lambda row: row["observed_bytes_sent"], reverse=True)[
            :100
        ],
        "groups_truncated": len(groups) > 100,
    }
