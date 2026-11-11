"""Bounded ActionTrail and explicitly registered SLS security-log reads."""

import hashlib
import json
from datetime import datetime
from typing import Any

from sec_auditor.alicloud_projection import project_event
from sec_auditor.config import Settings
from sec_auditor.logging_reader import time_window
from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.requests import LogQuery


async def read_logs(
    settings: Settings, provider, client, query: LogQuery, state: dict[str, Any]
) -> CollectionResult:
    if query.filter:
        raise ValueError(
            "Alibaba log filters are not exposed; select the approved logstore and bounded time interval"
        )
    start, end = time_window(
        state.get("start_time", query.start_time),
        state.get("end_time", query.end_time),
        settings.max_log_hours,
    )
    metadata = {
        "start_time": start,
        "end_time": end,
        "category": query.category,
        "account_id": query.account_id,
        "content_projection": "security_metadata",
    }
    if query.logstore is None:
        if query.category != "audit":
            raise ValueError(
                "Alibaba flow, firewall and Kubernetes logs require an operator-registered SLS logstore"
            )
        if not query.location:
            raise ValueError("ActionTrail queries require a location (region)")
        result = await provider.query_resources(
            "alicloud.actiontrail.events",
            query.account_id,
            location=query.location,
            selectors={"start_time": start, "end_time": end},
            page_size=min(query.page_size, 50),
            page_token=state.get("token"),
        )
        # Project at the reader boundary as well as the common evidence boundary.
        result.items = [
            record.model_copy(update={"data": project_event(record.data)})
            for record in result.items
        ]
        result.metadata.update(metadata)
        result.metadata["effective_page_size"] = min(query.page_size, 50)
        return result
    target = settings.alicloud_logstores.get(query.logstore)
    if (
        target is None
        or target.account_id != query.account_id
        or (query.location is not None and target.region != query.location)
    ):
        raise ValueError("Logstore is not registered for this account and region")
    expected_category = "kubernetes" if query.category == "gke" else query.category
    if target.category != expected_category:
        raise ValueError("Log category must match the operator-registered logstore category")
    token = state.get("token")
    try:
        offset = int(token) if token is not None else 0
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid SLS continuation") from exc
    if offset < 0 or offset > 100000:
        raise ValueError("SLS offset exceeds the supported bound; narrow the time interval")
    response = await client.query_logs(
        query.account_id,
        region=target.region,
        project=target.project,
        logstore=target.logstore,
        start_time=int(datetime.fromisoformat(start).timestamp()),
        end_time=int(datetime.fromisoformat(end).timestamp()),
        offset=offset,
        line=min(query.page_size, 100),
    )
    logs = response.get("logs")
    if (
        not isinstance(logs, list)
        or len(logs) > min(query.page_size, 100)
        or any(not isinstance(row, dict) for row in logs)
    ):
        raise ValueError("Invalid SLS log response")
    records = []
    for index, entry in enumerate(logs):
        identifier = hashlib.sha256(
            json.dumps(entry, sort_keys=True, default=str).encode()
        ).hexdigest()[:24]
        records.append(
            ResourceRecord(
                provider="alicloud",
                account_id=query.account_id,
                kind=f"alicloud.logs.{target.category}",
                name=f"accounts/{query.account_id}/regions/{target.region}/logstores/{query.logstore}/entries/{identifier}-{offset + index}",
                location=target.region,
                data=project_event(entry, target.category),
                source="alicloud.sls.GetLogsV2",
            )
        )
    errors = []
    if response.get("progress") != "Complete":
        errors.append(
            CollectionError(
                target=query.logstore,
                code="QUERY_INCOMPLETE",
                message="SLS has not completed the query; retry the same time interval and page",
                retryable=True,
            )
        )
    next_offset = response.get("next_offset")
    if next_offset is not None and (
        type(next_offset) is not int
        or next_offset < offset
        or (next_offset == offset and response.get("progress") == "Complete")
    ):
        raise ValueError("Invalid SLS continuation offset")
    metadata.update(
        {
            "region": target.region,
            "logstore": query.logstore,
            "observed_records_only": True,
            "effective_page_size": min(query.page_size, 100),
        }
    )
    return CollectionResult(
        items=records,
        next_page_token=str(next_offset) if next_offset is not None else None,
        errors=errors,
        warnings=[
            "SLS offset pagination is not a snapshot; concurrent ingestion may change pages. Log records describe observed traffic only."
        ],
        metadata=metadata,
    )
