"""Scoped Alibaba Cloud configuration collectors and pagination normalization.

The client verifies the credential's real account ID before any request. This
adapter accepts only compiled queries and validated identifiers, and the shared
service applies the security projection before returning or persisting records.
"""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import unquote

from sec_auditor.models import CollectionError, CollectionResult, ResourceRecord
from sec_auditor.providers.alicloud_catalog import (
    OPERATIONS,
    QUERY_SPECS,
    AliResourceSpec,
    capabilities,
)
from sec_auditor.transport import CloudAPIError

_ACCOUNT = re.compile(r"[0-9]{6,32}\Z")
_REGION = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+){1,5}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9_.@:+-]{0,255}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
_MISSING = object()


class _Client(Protocol):
    async def execute(
        self,
        account_id: str,
        operation_id: str,
        *,
        region: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


def _get(value: Any, path: str, default: Any = None) -> Any:
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{name} must be one bare resource identifier")
    return value


def _page_value(value: Any, name: str) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int) or isinstance(value, str) and re.fullmatch(r"[0-9]{1,19}", value)
    ):
        raise CloudAPIError("INVALID_RESPONSE", f"Invalid Alibaba pagination field: {name}")
    result = int(value)
    if not 0 <= result <= 2**63 - 1:
        raise CloudAPIError("INVALID_RESPONSE", f"Invalid Alibaba pagination field: {name}")
    return result


def _token(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 for c in value):
        raise CloudAPIError("INVALID_RESPONSE", "Invalid Alibaba continuation token")
    return value


def _boolean(value: Any, name: str) -> bool:
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise CloudAPIError("INVALID_RESPONSE", f"Invalid Alibaba boolean field: {name}")


def _decode_policy_documents(value: Any, depth: int = 0) -> Any:
    """RAM returns policy JSON both plain and URL-encoded; never leave it opaque."""
    if depth > 40:
        raise CloudAPIError("INVALID_RESPONSE", "Alibaba metadata nesting exceeds the limit")
    if isinstance(value, list):
        return [_decode_policy_documents(item, depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"PolicyDocument", "AssumeRolePolicyDocument"} and isinstance(item, str):
            if len(item) > 1_000_000:
                raise CloudAPIError("INVALID_RESPONSE", "Alibaba policy document exceeds the limit")
            try:
                item = json.loads(item if item.lstrip().startswith("{") else unquote(item))
            except (ValueError, RecursionError) as exc:
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Alibaba policy document is not valid JSON"
                ) from exc
            if not isinstance(item, dict):
                raise CloudAPIError("INVALID_RESPONSE", "Alibaba policy document must be an object")
        result[key] = _decode_policy_documents(item, depth + 1)
    return result


def _security_summary(kind: str, data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Remove known opaque/bootstrap/report payloads before shared projection.

    Security Center reports can contain captured exploit evidence and weak
    passwords. ACK management responses can include bootstrap scripts or login
    passwords. These are never needed for the exposed configuration checks.
    """
    omitted: list[str] = []
    allowed = {
        "alicloud.sas.vulnerabilities": {
            "Status",
            "RaspDefend",
            "RaspStatus",
            "Type",
            "ModifyTs",
            "InternetIp",
            "PrimaryId",
            "K8sClusterId",
            "K8sNodeId",
            "InstanceName",
            "Online",
            "OsVersion",
            "Name",
            "Progress",
            "ResultCode",
            "InstanceId",
            "IntranetIp",
            "LastTs",
            "FirstTs",
            "RegionId",
            "Necessity",
            "RepairTs",
            "Uuid",
            "K8sPodName",
            "ContainerId",
            "GroupId",
            "K8sNamespace",
            "AliasName",
            "K8sNodeName",
            "Bind",
            "OsName",
            "AuthVersion",
            "RealRisk",
            "RuleTag",
            "Image",
            "Namespace",
        },
        "alicloud.sas.riskChecks": {
            "RiskLevel",
            "Status",
            "Type",
            "Sort",
            "RepairStatus",
            "RemainingTime",
            "ItemId",
            "StartStatus",
            "AffectedCount",
            "RiskAssertType",
            "Title",
            "TaskId",
            "CheckTime",
        },
        "alicloud.cr.vulnerabilities": {
            "Severity",
            "CveName",
            "Feature",
            "Version",
            "VersionFormat",
            "VersionFixed",
            "ScanType",
            "AliasName",
        },
    }.get(kind)
    if allowed is not None:
        # Do not let a schema change turn a nominal scalar into an opaque blob.
        selected = {
            key: value
            for key, value in data.items()
            if key in allowed and isinstance(value, (str, int, float, bool, type(None)))
        }
        omitted.extend(key for key in data if key not in selected)
        if kind == "alicloud.sas.vulnerabilities":
            cves = _get(data, "ExtendContentJson.cveList")
            if isinstance(cves, list):
                selected["CveIds"] = [
                    value
                    for value in cves[:1000]
                    if isinstance(value, str) and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,12}", value)
                ]
        data = selected
    blocked = set()
    if kind.startswith("alicloud.cs."):
        blocked = {
            "metadata",
            "parameters",
            "userdata",
            "preuserdata",
            "postuserdata",
            "customconfig",
            "loginpassword",
            "password",
            "privatekey",
            "serverkey",
            "secret",
            "credentials",
            "accesskeysecret",
            "securitytoken",
        }
    elif kind.startswith("alicloud.config."):
        blocked = {"inputparameters", "extendcontent", "annotation"}
    if not blocked:
        return data, omitted

    def walk(value: Any, path: str = "", depth: int = 0) -> Any:
        if depth > 40:
            raise CloudAPIError("INVALID_RESPONSE", "Alibaba metadata nesting exceeds the limit")
        if isinstance(value, list):
            return [walk(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            item_path = f"{path}.{key}" if path else key
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if (
                normalized in blocked
                or normalized == "kubeletconfiguration"
                and not isinstance(item, dict)
            ):
                omitted.append(item_path)
                continue
            result[key] = walk(item, item_path, depth + 1)
        return result

    return walk(data), omitted


class AlibabaProvider:
    name = "alicloud"

    def __init__(self, client: _Client):
        self.client = client

    def capabilities(self) -> list[dict[str, Any]]:
        return capabilities()

    async def list_resources(
        self,
        kind: str,
        account_id: str,
        *,
        location: str | None = None,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        return await self.query_resources(
            kind, account_id, location=location, page_size=page_size, page_token=page_token
        )

    async def query_resources(
        self,
        kind: str,
        account_id: str,
        *,
        location: str | None = None,
        parent: str | None = None,
        resource_id: str | None = None,
        selectors: dict[str, str] | None = None,
        operation: str = "list",
        page_size: int = 100,
        page_token: str | None = None,
    ) -> CollectionResult:
        if not isinstance(account_id, str) or not _ACCOUNT.fullmatch(account_id):
            raise ValueError("account_id must be the Alibaba Cloud account's numeric ID")
        spec = QUERY_SPECS.get((kind, operation))
        if spec is None:
            raise ValueError("Unsupported Alibaba Cloud resource kind or operation")
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 1000
        ):
            raise ValueError("page_size must be between 1 and 1000")
        if page_token is not None and (
            not isinstance(page_token, str)
            or len(page_token) > 16384
            or any(ord(c) < 32 for c in page_token)
        ):
            raise ValueError("Invalid page token")
        op = OPERATIONS[spec.operation_id]
        if op.region_required:
            if not isinstance(location, str) or not _REGION.fullmatch(location):
                raise ValueError(f"{kind} requires an explicit Alibaba Cloud region")
            if spec.allowed_regions and location not in spec.allowed_regions:
                raise ValueError(
                    f"{kind} requires one of these service home regions: {', '.join(spec.allowed_regions)}"
                )
        elif location is not None:
            raise ValueError(f"{kind} is account-global and does not accept location")
        params = self._parameters(
            spec, parent, resource_id, selectors if selectors is not None else {}
        )
        if spec.region_parameter:
            params[spec.region_parameter] = location
        effective_size = max(spec.min_page_size, min(page_size, spec.max_page_size))
        offset, page = self._pagination_parameters(spec, params, effective_size, page_token)
        target = f"alicloud/accounts/{account_id}/{location or 'global'}/{kind}"
        result = CollectionResult(
            metadata={
                "provider": "alicloud",
                "scope": f"accounts/{account_id}",
                "account_id": account_id,
                "kind": kind,
                "operation": operation,
                "location": location,
                "parent": parent,
                "resource_id": resource_id,
                "pagination": spec.pagination,
                "requested_page_size": page_size,
                "effective_page_size": effective_size,
                "freshness": spec.freshness,
                "api_action": op.action,
                "scope_notes": "Account is the cloud-resource boundary. Regions restrict API endpoints; home-region findings and inventory can describe assets in other regions.",
            }
        )
        if effective_size > page_size:
            result.warnings.append(
                "The upstream API has a minimum page size; all returned observations are retained subject to the shared output budget."
            )
        try:
            body = await self.client.execute(
                account_id, spec.operation_id, region=location, parameters=params
            )
            if not isinstance(body, dict) or not body:
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Alibaba response must be a nonempty object"
                )
            self._success(body)
            raw = self._items(spec, body)
            result.next_page_token = self._next_token(
                spec, body, len(raw), effective_size, page, page_token
            )
            if spec.pagination == "client":
                raw.sort(key=lambda item: self._item_identifier(spec, item))
                total = len(raw)
                raw = raw[offset : offset + effective_size]
                result.next_page_token = (
                    f"offset:{offset + effective_size}" if offset + effective_size < total else None
                )
                result.metadata.update(
                    {"upstream_items": total, "pagination_consistency": "best_effort"}
                )
                result.warnings.append(
                    "Upstream has no pagination. Continuation re-reads the collection; concurrent changes can shift pages."
                )
            if len(raw) > effective_size:
                result.warnings.append(
                    "Upstream exceeded the requested page size. Returned items are retained; output and evidence budgets still apply."
                )
            for item in raw:
                data, omitted = _security_summary(kind, _decode_policy_documents(item))
                if omitted:
                    result.metadata["provider_removed_fields"] = result.metadata.get(
                        "provider_removed_fields", 0
                    ) + len(omitted)
                    paths = result.metadata.setdefault("provider_removed_paths", [])
                    for path in omitted:
                        if path not in paths and len(paths) < 100:
                            paths.append(path[:512])
                if parent and spec.parent_parameter:
                    data.setdefault(spec.parent_parameter, parent)
                if resource_id and spec.resource_parameter:
                    data.setdefault(spec.resource_parameter, resource_id)
                if selectors:
                    data["queryContext"] = {"selectors": dict(selectors)}
                identifier = self._item_identifier(spec, data)
                context = parent or resource_id
                contexts = [context] if context and context != identifier else []
                contexts.extend(
                    (selectors or {})[key]
                    for key in ("policy_type", "repository_id", "tag", "port")
                    if key in (selectors or {})
                )
                if kind == "alicloud.config.resources":
                    contexts.extend(
                        str(data[key]) for key in ("ResourceType", "Region") if data.get(key)
                    )
                prefix = "/".join(contexts) + "/" if contexts else ""
                record_name = f"{target}/{prefix}{identifier}"
                result.items.append(
                    ResourceRecord(
                        provider="alicloud",
                        account_id=account_id,
                        kind=kind,
                        name=record_name,
                        location=location,
                        data=data,
                        freshness=spec.freshness,
                        source=f"{op.service}:{op.version}:{op.action}",
                    )
                )
            if result.metadata.get("provider_removed_fields"):
                result.warnings.append(
                    "Known bootstrap credentials, opaque configuration, or captured report payloads were omitted by the Alibaba security projection."
                )
            if kind == "alicloud.actiontrail.events":
                result.metadata.update(
                    {
                        "start_time": params["StartTime"],
                        "end_time": params["EndTime"],
                        "category": "audit",
                    }
                )
                result.warnings.append(
                    "ActionTrail events and resource metadata are untrusted evidence. Request/response payloads are removed before model access."
                )
            return result
        except CloudAPIError as exc:
            result.items = []
            result.next_page_token = None
            result.errors.append(
                CollectionError(
                    target=target, code=exc.code, message=exc.message, retryable=exc.retryable
                )
            )
            return result

    def _parameters(
        self,
        spec: AliResourceSpec,
        parent: str | None,
        resource_id: str | None,
        selectors: dict[str, str],
    ) -> dict[str, Any]:
        if not isinstance(selectors, dict):
            raise ValueError("selectors must be an object")
        allowed = dict(spec.selectors)
        if set(selectors) - set(allowed):
            raise ValueError("Query contains an unsupported Alibaba selector")
        if set(spec.required_selectors) - set(selectors):
            raise ValueError(f"Required selectors: {', '.join(spec.required_selectors)}")
        params = dict(spec.fixed_parameters)
        for value, api_name, name in (
            (parent, spec.parent_parameter, "parent"),
            (resource_id, spec.resource_parameter, "resource_id"),
        ):
            if api_name:
                params[api_name] = _identifier(value, name)
                if api_name == "BucketName" and not _BUCKET.fullmatch(value):
                    raise ValueError("resource_id must be one OSS bucket name")
            elif value is not None:
                raise ValueError(f"{spec.kind} does not accept {name}")
        for key, value in selectors.items():
            if key in {"start_time", "end_time"}:
                if not isinstance(value, str) or len(value) > 40:
                    raise ValueError("Audit timestamps must be ISO 8601 strings")
            else:
                _identifier(value, key)
            if key == "policy_type" and value not in {"Custom", "System"}:
                raise ValueError("policy_type must be Custom or System")
            if key == "port":
                if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
                    raise ValueError("port must be between 1 and 65535")
                params[allowed[key]] = int(value)
            elif key == "vulnerability_type" and value not in {
                "cve",
                "sys",
                "cms",
                "app",
                "emg",
                "sca",
            }:
                raise ValueError("Unsupported Security Center vulnerability_type")
            else:
                params[allowed[key]] = value
        if spec.kind == "alicloud.actiontrail.events":
            settings = getattr(self.client, "settings", None)
            max_hours = min(getattr(settings, "max_log_hours", 24), 24)
            parsed = {}
            for key in ("StartTime", "EndTime"):
                try:
                    value = datetime.fromisoformat(params[key].replace("Z", "+00:00"))
                except (ValueError, TypeError) as exc:
                    raise ValueError("Audit timestamps must be valid ISO 8601 timestamps") from exc
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("Audit timestamps must include a timezone")
                parsed[key] = value.astimezone(UTC)
            if (
                not timedelta(0)
                < parsed["EndTime"] - parsed["StartTime"]
                <= timedelta(hours=max_hours)
            ):
                raise ValueError(
                    f"Audit queries require a positive interval of at most {max_hours} hours"
                )
            if parsed["EndTime"] > datetime.now(UTC) + timedelta(minutes=5):
                raise ValueError("Audit query end_time cannot be in the future")
            for key, value in parsed.items():
                params[key] = value.isoformat(timespec="seconds").replace("+00:00", "Z")
        return params

    @staticmethod
    def _pagination_parameters(
        spec: AliResourceSpec, params: dict[str, Any], size: int, token: str | None
    ) -> tuple[int, int]:
        page, offset = 1, 0
        if spec.pagination == "token" or spec.pagination == "marker":
            params[spec.size_parameter] = size
            if token:
                params[spec.token_parameter] = token
        elif spec.pagination == "page":
            if token:
                match = re.fullmatch(r"page:([1-9][0-9]{0,6})", token)
                if not match:
                    raise ValueError("Invalid page-number continuation")
                page = int(match[1])
            params[spec.page_parameter] = page
            params[spec.size_parameter] = size
        elif spec.pagination == "client":
            if token:
                match = re.fullmatch(r"offset:([0-9]{1,9})", token)
                if not match:
                    raise ValueError("Invalid local continuation")
                offset = int(match[1])
        elif token:
            raise ValueError("Singleton queries do not accept a continuation")
        return offset, page

    @staticmethod
    def _success(body: dict[str, Any]) -> None:
        for key in ("Success", "IsSuccess"):
            if key in body and not _boolean(body[key], key):
                raise CloudAPIError("UPSTREAM_FAILURE", "Alibaba API reported an unsuccessful read")

    @staticmethod
    def _items(spec: AliResourceSpec, body: dict[str, Any]) -> list[dict[str, Any]]:
        if spec.items_path is None:
            return [dict(body)]
        value = _get(body, spec.items_path, _MISSING)
        if spec.pagination == "singleton":
            if not isinstance(value, dict):
                raise CloudAPIError("INVALID_RESPONSE", "Expected an Alibaba resource object")
            return [dict(value)]
        if value is _MISSING:
            # Empty collection containers may be omitted by RPC serializers. A
            # successful response still needs recognizable protocol metadata.
            if any(
                key in body
                for key in ("RequestId", "IsTruncated", "TotalCount", "NextToken", "page_info")
            ):
                return []
            raise CloudAPIError("INVALID_RESPONSE", "Missing Alibaba resource collection")
        if value is None:
            return []
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise CloudAPIError("INVALID_RESPONSE", "Expected an Alibaba resource array")
        return [dict(item) for item in value]

    @staticmethod
    def _next_token(
        spec: AliResourceSpec,
        body: dict[str, Any],
        count: int,
        size: int,
        page: int,
        previous: str | None,
    ) -> str | None:
        if spec.pagination == "token":
            result = _token(_get(body, spec.token_path))
        elif spec.pagination == "marker":
            truncated = _boolean(_get(body, spec.truncated_path, False), spec.truncated_path)
            result = _token(_get(body, spec.token_path)) if truncated else None
            if truncated and not result:
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Truncated Alibaba response omitted its continuation"
                )
        elif spec.pagination == "page":
            total_raw = _get(body, spec.total_path, _MISSING)
            if total_raw is _MISSING:
                raise CloudAPIError(
                    "INVALID_RESPONSE", "Alibaba page response omitted its total count"
                )
            total = _page_value(total_raw, spec.total_path)
            prefix = spec.total_path.rsplit(".", 1)[0] + "." if "." in spec.total_path else ""
            size_path = prefix + spec.size_parameter
            reported_size = _get(body, size_path, size)
            effective_size = _page_value(reported_size, size_path)
            if effective_size < 1:
                raise CloudAPIError("INVALID_RESPONSE", "Alibaba response has a zero page size")
            number_path = prefix + spec.page_parameter
            reported_page = _get(body, number_path, page)
            if _page_value(reported_page, number_path) != page:
                raise CloudAPIError(
                    "PAGINATION_STALLED", "Alibaba API returned a different page number"
                )
            result = f"page:{page + 1}" if page * effective_size < total else None
            if count == 0 and result:
                raise CloudAPIError(
                    "INCOMPLETE_RESPONSE",
                    "Alibaba page is empty before the reported collection end",
                )
        else:
            result = None
        if result and result == previous:
            raise CloudAPIError("PAGINATION_STALLED", "Alibaba API repeated its continuation token")
        return result

    @staticmethod
    def _item_identifier(spec: AliResourceSpec, data: dict[str, Any]) -> str:
        if spec.kind == "alicloud.cr.vulnerabilities" and data.get("CveName"):
            return ":".join(str(data.get(key, "")) for key in ("CveName", "Feature", "Version"))[
                :1024
            ]
        for path in spec.name_fields:
            value = _get(data, path)
            if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
                # Upstream names are evidence only; never feed them to a URL.
                return str(value)[:1024]
        digest = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()[:24]
        return f"observation-{digest}"
