"""Minimize content before evidence leaves the service or enters its state store.

Field exclusions are deterministic; they cannot recognize every secret someone
places in a legitimate resource name, label, or other configuration string.
"""

import base64
import binascii
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sec_auditor.models import ResourceRecord

REDACTED = "[REDACTED]"
_SENSITIVE = frozenset(
    {
        "password",
        "passwd",
        "privatekey",
        "privatekeydata",
        "publickeydata",
        "clientsecret",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authorization",
        "proxyauthorization",
        "credentials",
        "credential",
        "connectionstring",
        "sourcecontents",
        "sourcearchiveurl",
        "sourcerepository",
        "buildconfig",
        "clientkey",
        "serviceaccountkey",
        "sshkeys",
        "sshkey",
        "certificateauthoritydata",
        "clustercacertificate",
        "clientcertificate",
        "clientkeydata",
        "passworddata",
        "encryptedprivatekey",
        "rawkey",
        "signingkey",
        "secretvalue",
        "binarydata",
        "stringdata",
        "apikey",
        "apikeys",
        "xapikey",
        "xgoogapikey",
        "apitoken",
        "bearertoken",
        "token",
        "secretaccesskey",
        "accesskeysecret",
        "securitytoken",
        "sessiontoken",
        "connectiontoken",
        "userdata",
        "kubeconfig",
        "serverkey",
        "secretdata",
        "authenticationtoken",
        "cookiedata",
        "cookie",
        "cookies",
        "setcookie",
        "keyring",
    }
)
_DROP = frozenset(
    {
        "annotations",
        "managedfields",
        "command",
        "args",
        "startupscript",
        "shutdownscript",
    }
)
_SAFE_VM_METADATA = frozenset(
    {
        "enable-oslogin",
        "enable-oslogin-2fa",
        "block-project-ssh-keys",
        "disable-legacy-endpoints",
        "serial-port-enable",
    }
)
_SAFE_STORAGE_PARAMETERS = frozenset(
    {
        "type",
        "replication-type",
        "availability-type",
        "fstype",
        "csi.storage.k8s.io/fstype",
        "disk-encryption-kms-key",
        "kmsKeyName",
        "provisioned-iops-on-create",
        "provisioned-throughput-on-create",
    }
)
_STORAGE_SECRET_REFERENCE = re.compile(
    r"csi\.storage\.k8s\.io/(?:provisioner|controller-publish|node-stage|node-publish|controller-expand|node-expand)-secret-(?:name|namespace)\Z"
)
_TOKEN = re.compile(
    r"(?i)(?:bearer\s+[a-z0-9._~+/=-]{4,}|AIza[a-z0-9_-]{30,}|eyJ[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,})"
)
_BASIC_AUTH = re.compile(r"(?i)\bbasic\s+([a-z0-9+/]{8,}={0,2})")
_PEM = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", re.DOTALL
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|access_token|refresh_token|api[_-]?key|token)[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)


def safe_text(value: str, max_length: int = 2000) -> str:
    """Best-effort patterns plus removal of credentials, query, and fragment in URLs."""
    text = _PEM.sub(REDACTED, value)
    text = _TOKEN.sub(REDACTED, text)

    def redact_basic(match: re.Match[str]) -> str:
        try:
            decoded = base64.b64decode(match.group(1), validate=True)
        except (ValueError, binascii.Error):
            return match.group(0)
        return REDACTED if b":" in decoded else match.group(0)

    text = _BASIC_AUTH.sub(redact_basic, text)
    text = _ASSIGNMENT.sub(lambda match: match.group(1) + "=" + REDACTED, text)
    absolute_url = text.lower().startswith(("https://", "http://"))
    relative_url = not any(char.isspace() for char in text) and (
        text.startswith(("/", "./", "../")) or "?" in text or "#" in text
    )
    if absolute_url or relative_url:
        try:
            parsed = urlsplit(text)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                hostname = parsed.hostname or ""
                if ":" in hostname:
                    hostname = f"[{hostname}]"
                if parsed.port:
                    hostname += f":{parsed.port}"
                # Also strip fragments, which can contain OAuth tokens.
                text = urlunsplit(
                    (
                        parsed.scheme,
                        hostname,
                        parsed.path,
                        REDACTED if parsed.query else "",
                        REDACTED if parsed.fragment else "",
                    )
                )
        except ValueError:
            text = REDACTED
    return text if len(text) <= max_length else text[:max_length] + "[TRUNCATED]"


def _normalized(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _path(parent: str, key: str) -> str:
    return f"{parent}.{key}" if parent else key


def _selected(
    source: dict[str, Any], fields: set[str], path: str, omitted: list[str]
) -> dict[str, Any]:
    """Track omitted branches at every explicitly projected object boundary."""
    omitted.extend(_path(path, str(key)) for key in source if key not in fields)
    return {key: value for key, value in source.items() if key in fields}


def sanitize(
    value: Any,
    *,
    path: str = "",
    redactions: list[str] | None = None,
    depth: int = 0,
    resource_kind: str | None = None,
) -> Any:
    redactions = redactions if redactions is not None else []
    if depth > 30:
        redactions.append(path)
        return "[DEPTH_LIMIT]"
    if isinstance(value, str):
        cleaned = safe_text(value)
        if cleaned != value:
            redactions.append(path)
        return cleaned
    if isinstance(value, list):
        result = [
            sanitize(
                item,
                path=f"{path}[{index}]",
                redactions=redactions,
                depth=depth + 1,
                resource_kind=resource_kind,
            )
            for index, item in enumerate(value[:500])
        ]
        if len(value) > 500:
            redactions.append(path + "[500:]")
            result.append({"omitted_items": len(value) - 500})
        return result
    if not isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for original_key, item in value.items():
        key = str(original_key)
        child = _path(path, key)
        normalized = _normalized(key)
        # Map keys are untrusted strings too. Report the original path but avoid
        # reflecting recognizable credentials in the returned key itself.
        output_key = safe_text(key, 512)
        if output_key != key:
            redactions.append(child)
        is_resource_message = resource_kind is not None and normalized.endswith("message")
        is_opaque_options = normalized == "volumeattributes" or (
            normalized == "options" and _normalized(path.rsplit(".", 1)[-1]) == "flexvolume"
        )
        if (
            normalized in _SENSITIVE
            or normalized in _DROP
            or normalized.endswith("password")
            or is_resource_message
            or is_opaque_options
            or normalized in {"environmentvariables", "secretenvironmentvariables", "data"}
        ):
            result[output_key] = REDACTED
            redactions.append(child)
        elif normalized in {"httpheaders", "headers"}:
            if isinstance(item, list):
                headers = []
                for index, header in enumerate(item[:500]):
                    header_path = f"{child}[{index}]"
                    if not isinstance(header, dict):
                        headers.append(REDACTED)
                        redactions.append(header_path)
                        continue
                    selected = _selected(header, {"name", "value"}, header_path, redactions)
                    if "value" in selected:
                        selected["value"] = REDACTED
                        redactions.append(f"{header_path}.value")
                    headers.append(
                        sanitize(
                            selected,
                            path=header_path,
                            redactions=redactions,
                            depth=depth + 1,
                            resource_kind=resource_kind,
                        )
                    )
                result[output_key] = headers
                if len(item) > 500:
                    redactions.append(child + "[500:]")
            elif isinstance(item, dict):
                result[output_key] = {safe_text(str(name), 512): REDACTED for name in item}
                redactions.extend(_path(child, str(name)) for name in item)
            else:
                result[output_key] = REDACTED
                redactions.append(child)
        elif normalized == "env" and isinstance(item, list):
            result[output_key] = []
            for index, env in enumerate(item[:500]):
                env_path = f"{child}[{index}]"
                if not isinstance(env, dict):
                    result[output_key].append(REDACTED)
                    redactions.append(env_path)
                    continue
                # Both Kubernetes valueFrom and Cloud Run valueSource are references.
                entry = _selected(
                    env, {"name", "value", "valueFrom", "valueSource"}, env_path, redactions
                )
                if "value" in entry:
                    entry["value"] = REDACTED
                    redactions.append(f"{env_path}.value")
                result[output_key].append(
                    sanitize(
                        entry,
                        path=env_path,
                        redactions=redactions,
                        depth=depth + 1,
                        resource_kind=resource_kind,
                    )
                )
            if len(item) > 500:
                redactions.append(child + "[500:]")
        elif (
            normalized == "metadata"
            and isinstance(item, dict)
            and isinstance(item.get("items"), list)
        ):
            metadata = {k: v for k, v in item.items() if k != "items"}
            metadata["items"] = []
            for index, pair in enumerate(item["items"][:500]):
                pair_path = f"{child}.items[{index}]"
                if not isinstance(pair, dict):
                    metadata["items"].append(REDACTED)
                    redactions.append(pair_path)
                    continue
                name = str(pair.get("key", ""))
                raw_value = pair.get("value")
                allowed = name in _SAFE_VM_METADATA and str(raw_value).lower() in {
                    "true",
                    "false",
                    "0",
                    "1",
                }
                selected = _selected(pair, {"key", "value"}, pair_path, redactions)
                selected["key"] = name
                selected["value"] = raw_value if allowed else REDACTED
                if not allowed:
                    redactions.append(f"{pair_path}.value")
                metadata["items"].append(selected)
            if len(item["items"]) > 500:
                redactions.append(f"{child}.items[500:]")
            result[output_key] = sanitize(
                metadata,
                path=child,
                redactions=redactions,
                depth=depth + 1,
                resource_kind=resource_kind,
            )
        elif (
            normalized == "parameters"
            and resource_kind == "k8s.StorageClass"
            and isinstance(item, dict)
        ):
            parameters = {}
            for name, parameter in item.items():
                parameter_path = _path(child, str(name))
                if name in _SAFE_STORAGE_PARAMETERS or _STORAGE_SECRET_REFERENCE.fullmatch(
                    str(name)
                ):
                    parameters[name] = sanitize(
                        parameter,
                        path=parameter_path,
                        redactions=redactions,
                        depth=depth + 1,
                        resource_kind=resource_kind,
                    )
                else:
                    parameters[safe_text(str(name), 512)] = REDACTED
                    redactions.append(parameter_path)
            result[output_key] = parameters
        else:
            result[output_key] = sanitize(
                item,
                path=child,
                redactions=redactions,
                depth=depth + 1,
                resource_kind=resource_kind,
            )
    return result


def _projection_metadata(result: dict[str, Any], redactions: list[str]) -> dict[str, Any]:
    # Do not silently drop paths after the first 200: response budgets are enforced
    # by the service, and an omitted branch represents its entire omitted subtree.
    paths = sorted({safe_text(path, 4096) for path in redactions})
    result["projection"] = "security"
    result["redacted_paths"] = paths
    result["redacted_path_count"] = len(paths)
    result["content_is_untrusted"] = True
    return result


def project_record(record: ResourceRecord) -> dict[str, Any]:
    redactions: list[str] = []
    result = sanitize(record.model_dump(mode="json", exclude={"data"}), redactions=redactions)
    data = record.data
    if record.provider == "alicloud":
        from sec_auditor.alicloud_projection import project_config, project_event

        if record.kind == "alicloud.actiontrail.events":
            data = project_event(data)
        elif record.kind.startswith("alicloud.logs."):
            data = project_event(data, record.kind.rsplit(".", 1)[-1])
        else:
            data = project_config(data, redactions)
    result["data"] = sanitize(data, path="data", redactions=redactions, resource_kind=record.kind)
    return _projection_metadata(result, redactions)


_AUDIT_FIELDS = {
    "serviceName",
    "methodName",
    "resourceName",
    "authorizationInfo",
    "status",
    "numResponseItems",
}
_AUTH_FIELDS = {"principalEmail", "principalSubject", "serviceAccountDelegationInfo"}
_LOG_FIELDS = {
    "logName",
    "resource",
    "timestamp",
    "receiveTimestamp",
    "severity",
    "insertId",
    "trace",
    "spanId",
}
_FLOW_FIELDS = {
    "connection",
    "bytes_sent",
    "packets_sent",
    "start_time",
    "end_time",
    "reporter",
    "src_instance",
    "dest_instance",
    "src_vpc",
    "dest_vpc",
    "src_location",
    "dest_location",
    "rtt_msec",
    "src_gke_details",
    "dest_gke_details",
    "internet_routing_details",
}
_FIREWALL_FIELDS = {"connection", "disposition", "rule_details", "instance", "vpc"}


def _project_authentication(
    source: dict[str, Any], path: str, omitted: list[str]
) -> dict[str, Any]:
    selected = _selected(source, _AUTH_FIELDS, path, omitted)
    delegation = selected.get("serviceAccountDelegationInfo")
    if isinstance(delegation, list):
        identities = []
        for index, info in enumerate(delegation[:500]):
            item_path = f"{path}.serviceAccountDelegationInfo[{index}]"
            if not isinstance(info, dict):
                omitted.append(item_path)
                continue
            # Opaque third-party claims and serviceMetadata can include payload data.
            identity = _selected(
                info, {"principalSubject", "firstPartyPrincipal"}, item_path, omitted
            )
            principal = identity.get("firstPartyPrincipal")
            if isinstance(principal, dict):
                identity["firstPartyPrincipal"] = _selected(
                    principal, {"principalEmail"}, item_path + ".firstPartyPrincipal", omitted
                )
            elif principal is not None:
                identity.pop("firstPartyPrincipal")
                omitted.append(item_path + ".firstPartyPrincipal")
            identities.append(identity)
        selected["serviceAccountDelegationInfo"] = identities
        if len(delegation) > 500:
            omitted.append(path + ".serviceAccountDelegationInfo[500:]")
    elif delegation is not None:
        selected.pop("serviceAccountDelegationInfo")
        omitted.append(path + ".serviceAccountDelegationInfo")
    return selected


def project_log_entry(entry: dict[str, Any], category: str) -> dict[str, Any]:
    omitted: list[str] = []
    allowed_top = _LOG_FIELDS | {"protoPayload"}
    if category in {"vpc_flows", "firewall"}:
        allowed_top.add("jsonPayload")
    selected = _selected(entry, allowed_top, "", omitted)
    payload = selected.get("protoPayload")
    if isinstance(payload, dict):
        selected_payload = _selected(
            payload,
            _AUDIT_FIELDS | {"authenticationInfo", "requestMetadata"},
            "protoPayload",
            omitted,
        )
        authentication = selected_payload.get("authenticationInfo")
        if isinstance(authentication, dict):
            selected_payload["authenticationInfo"] = _project_authentication(
                authentication, "protoPayload.authenticationInfo", omitted
            )
        elif authentication is not None:
            selected_payload.pop("authenticationInfo")
            omitted.append("protoPayload.authenticationInfo")
        request_metadata = selected_payload.get("requestMetadata")
        if isinstance(request_metadata, dict):
            selected_payload["requestMetadata"] = _selected(
                request_metadata,
                {"callerIp", "callerSuppliedUserAgent"},
                "protoPayload.requestMetadata",
                omitted,
            )
        elif request_metadata is not None:
            selected_payload.pop("requestMetadata")
            omitted.append("protoPayload.requestMetadata")
        status = selected_payload.get("status")
        if isinstance(status, dict):
            selected_payload["status"] = _selected(status, {"code"}, "protoPayload.status", omitted)
        elif status is not None:
            selected_payload.pop("status")
            omitted.append("protoPayload.status")
        authorization = selected_payload.get("authorizationInfo")
        if isinstance(authorization, list):
            selected_authz = []
            for index, info in enumerate(authorization[:500]):
                item_path = f"protoPayload.authorizationInfo[{index}]"
                if not isinstance(info, dict):
                    omitted.append(item_path)
                    continue
                item = _selected(
                    info,
                    {"resource", "permission", "granted", "resourceAttributes"},
                    item_path,
                    omitted,
                )
                attributes = item.get("resourceAttributes")
                if isinstance(attributes, dict):
                    item["resourceAttributes"] = _selected(
                        attributes,
                        {"service", "name", "type"},
                        item_path + ".resourceAttributes",
                        omitted,
                    )
                elif attributes is not None:
                    item.pop("resourceAttributes")
                    omitted.append(item_path + ".resourceAttributes")
                selected_authz.append(item)
            selected_payload["authorizationInfo"] = selected_authz
            if len(authorization) > 500:
                omitted.append("protoPayload.authorizationInfo[500:]")
        elif authorization is not None:
            selected_payload.pop("authorizationInfo")
            omitted.append("protoPayload.authorizationInfo")
        selected["protoPayload"] = selected_payload
    elif "protoPayload" in selected:
        selected.pop("protoPayload")
        omitted.append("protoPayload")
    json_payload = selected.get("jsonPayload")
    if isinstance(json_payload, dict):
        fields = _FLOW_FIELDS if category == "vpc_flows" else _FIREWALL_FIELDS
        selected["jsonPayload"] = _selected(json_payload, fields, "jsonPayload", omitted)
    elif "jsonPayload" in selected:
        selected.pop("jsonPayload")
        omitted.append("jsonPayload")
    redactions = list(omitted)
    result = sanitize(selected, redactions=redactions)
    result["omitted_payload_fields"] = sorted({safe_text(path, 4096) for path in omitted})
    return _projection_metadata(result, redactions)
