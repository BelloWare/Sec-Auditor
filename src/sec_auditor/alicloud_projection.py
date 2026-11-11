"""Alibaba security projections, including encoded policy documents and log events."""

import ipaddress
import json
import re
from typing import Any
from urllib.parse import unquote

from sec_auditor.projection import (
    REDACTED,
    _normalized,
    _projection_metadata,
    _selected,
    safe_text,
    sanitize,
)

_POLICY_FIELDS = {
    "PolicyDocument",
    "AssumeRolePolicyDocument",
    "policy_document",
    "assume_role_policy_document",
    "BucketPolicy",
}
_OPAQUE_FIELDS = {
    "UserData",
    "user_data",
    "userData",
    "Kubeconfig",
    "kubeconfig",
    "Configuration",
    "ConfigContent",
    "EnvironmentVariables",
    "environment_variables",
    "ConnectionString",
    "connection_string",
    "ClientToken",
    "SecurityToken",
    "Secret",
    "SecretData",
    "Password",
    "AuthInfo",
    "HeaderValue",
}
_OPAQUE_FIELDS |= {
    "ServerKey",
    "PreUserData",
    "BootstrapData",
    "BootstrapScript",
    "CustomConfig",
    "MetaData",
    "Parameters",
    "ExtendContentJson",
    "ResultMessage",
    "ContentResource",
    "InputParameters",
    "FixCmd",
    "AddedBy",
    "CveLocation",
}
_OPAQUE_NORMALIZED = frozenset(_normalized(key) for key in _OPAQUE_FIELDS)
_POLICY_NORMALIZED = frozenset(_normalized(key) for key in _POLICY_FIELDS)
_AUDIT_FIELDS = {
    "eventId",
    "eventVersion",
    "eventTime",
    "eventName",
    "eventSource",
    "eventType",
    "eventRW",
    "eventCategory",
    "acsRegion",
    "sourceIpAddress",
    "sourceIPAddress",
    "recipientAccountId",
    "errorCode",
    "serviceName",
    "resourceName",
    "requestId",
    "userIdentity",
    "referencedResources",
}
_IDENTITY_FIELDS = {"type", "principalId", "accountId", "userName", "arn", "identityType"}
_FLOW_FIELDS = {
    "version",
    "account-id",
    "account_id",
    "interface-id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
    "log_status",
    "src_addr",
    "dst_addr",
    "src_port",
    "dst_port",
    "packet_count",
    "byte_count",
    "start_time",
    "end_time",
    "vpc_id",
    "vswitch_id",
    "eni_id",
    "instance_id",
    "region_id",
    "traffic_path",
    "direction",
    "flow_direction",
    "flow_direction_type",
    "__time__",
}
_FIREWALL_FIELDS = _FLOW_FIELDS | {
    "rule_id",
    "acl_id",
    "policy_id",
    "rule_action",
    "hit_rule_id",
    "internet_ip",
    "intranet_ip",
}
_KUBERNETES_FIELDS = {
    "apiVersion",
    "kind",
    "auditID",
    "stage",
    "requestURI",
    "verb",
    "sourceIPs",
    "userAgent",
    "requestReceivedTimestamp",
    "stageTimestamp",
    "objectRef",
    "user",
    "responseStatus",
    "__time__",
}


def _typed_fields(
    source: dict[str, Any],
    fields: set[str],
    path: str,
    omitted: list[str],
    *,
    lists: set[str] = frozenset(),
    integers: set[str] = frozenset(),
) -> dict[str, Any]:
    selected = _selected(source, fields, path, omitted)
    for key, value in list(selected.items()):
        if key in lists:
            valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
        elif key in integers:
            valid = type(value) is int
        else:
            valid = isinstance(value, str)
        if not valid:
            selected.pop(key)
            omitted.append(f"{path}.{key}".strip("."))
    return selected


def project_event(entry: dict[str, Any], category: str = "audit") -> dict[str, Any]:
    omitted: list[str] = []
    # Reprojection remains mandatory; preserve only bounded, path-shaped omission
    # provenance, never trust a supplied marker to skip field validation.
    prior_omissions = entry.get("omitted_payload_fields")
    if isinstance(prior_omissions, list):
        omitted.extend(
            path
            for path in prior_omissions[:500]
            if isinstance(path, str) and re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,512}", path)
        )
    source = entry
    if category == "audit":
        # SLS may encapsulate an ActionTrail event as JSON. Never emit the raw string.
        for key in ("event", "eventData", "ActionTrailEvent"):
            nested = entry.get(key)
            if isinstance(nested, str) and len(nested) <= 262144:
                try:
                    parsed = json.loads(nested)
                except (ValueError, RecursionError):
                    continue
                if isinstance(parsed, dict):
                    source = parsed
                    omitted.extend(str(k) for k in entry if k != key)
                    break
        selected = _selected(source, _AUDIT_FIELDS, "", omitted)
        identity = selected.get("userIdentity")
        if isinstance(identity, dict):
            selected["userIdentity"] = _typed_fields(
                identity, _IDENTITY_FIELDS, "userIdentity", omitted
            )
        elif identity is not None:
            selected.pop("userIdentity")
            omitted.append("userIdentity")
        resources = selected.get("referencedResources")
        if isinstance(resources, dict):
            # Resource references are structured identifiers, never API response objects.
            selected["referencedResources"] = {}
            for key, values in list(resources.items())[:100]:
                if (
                    not isinstance(key, str)
                    or not re.fullmatch(r"ACS::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*", key)
                    or not isinstance(values, list)
                    or not all(isinstance(item, str) for item in values)
                ):
                    omitted.append("referencedResources.invalid_entry")
                    continue
                selected["referencedResources"][key] = values[:100]
                if len(values) > 100:
                    omitted.append("referencedResources." + key + "[100:]")
            if len(resources) > 100:
                omitted.append("referencedResources[100:]")
        elif resources is not None:
            selected.pop("referencedResources")
            omitted.append("referencedResources")
    elif category == "kubernetes":
        selected = _selected(source, _KUBERNETES_FIELDS, "", omitted)
        for key, fields in {
            "objectRef": {
                "resource",
                "namespace",
                "name",
                "uid",
                "apiGroup",
                "apiVersion",
                "resourceVersion",
                "subresource",
            },
            "user": {"username", "uid", "groups"},
            "responseStatus": {"code", "status", "reason"},
        }.items():
            value = selected.get(key)
            if isinstance(value, dict):
                selected[key] = _typed_fields(
                    value,
                    fields,
                    key,
                    omitted,
                    lists={"groups"} if key == "user" else set(),
                    integers={"code"} if key == "responseStatus" else set(),
                )
            elif value is not None:
                selected.pop(key)
                omitted.append(key)
        if "sourceIPs" in selected:
            addresses = selected["sourceIPs"]
            try:
                if not isinstance(addresses, list) or any(
                    not isinstance(value, str) for value in addresses
                ):
                    raise ValueError
                for value in addresses:
                    ipaddress.ip_address(value)
            except ValueError:
                selected.pop("sourceIPs")
                omitted.append("sourceIPs")
    else:
        selected = _selected(
            source, _FLOW_FIELDS if category == "vpc_flows" else _FIREWALL_FIELDS, "", omitted
        )
    # Even allowed fields have primitive types: malformed nested payloads are removed.
    for key in list(selected):
        if key not in {
            "userIdentity",
            "referencedResources",
            "objectRef",
            "user",
            "responseStatus",
            "sourceIPs",
        } and isinstance(selected[key], (list, dict)):
            selected.pop(key)
            omitted.append(key)
    result = sanitize(selected, redactions=omitted, resource_kind="alicloud.log." + category)
    result["omitted_payload_fields"] = sorted({safe_text(path, 4096) for path in omitted})
    return _projection_metadata(result, omitted)


def project_config(data: Any, omitted: list[str], path: str = "data", depth: int = 0) -> Any:
    if depth > 25:
        omitted.append(path)
        return REDACTED
    if isinstance(data, list):
        if len(data) > 500:
            omitted.append(path + "[500:]")
        return [
            project_config(value, omitted, f"{path}[{index}]", depth + 1)
            for index, value in enumerate(data[:500])
        ]
    if not isinstance(data, dict):
        return data
    output = {}
    for key, value in data.items():
        child = f"{path}.{key}"
        if _normalized(str(key)) in _OPAQUE_NORMALIZED:
            output[key] = REDACTED
            omitted.append(child)
        elif _normalized(str(key)) in _POLICY_NORMALIZED and isinstance(value, str):
            try:
                decoded = None
                if len(value) <= 262144:
                    try:
                        decoded = json.loads(value)
                    except (ValueError, RecursionError):
                        decoded = json.loads(unquote(value))
            except (ValueError, RecursionError):
                decoded = None
            if isinstance(decoded, dict):
                output[key] = project_config(decoded, omitted, child, depth + 1)
            else:
                output[key] = REDACTED
                omitted.append(child)
        else:
            output[key] = project_config(value, omitted, child, depth + 1)
    return output
