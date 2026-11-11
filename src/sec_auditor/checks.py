"""Deterministic configuration observations, independent of cloud transport and MCP.

Checks deliberately do not determine effective IAM permissions, packet reachability,
guest state, or compliance certification. All text emitted by a predicate is fixed
application text; arbitrary values from resource documents are never copied into
findings. Resource identifiers and field paths provide the evidence linkage.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal
from functools import partial
from types import MappingProxyType
from typing import Any, Literal

from sec_auditor.checks_alicloud import build_rules as build_alicloud_rules
from sec_auditor.models import CheckDefinition, CheckResult, ResourceRecord

Status = Literal["pass", "fail", "unknown", "not_applicable"]
Severity = Literal["info", "low", "medium", "high", "critical"]
RULE_VERSION = "1"
_MISSING = object()


class _Unavailable(Exception):
    """A required observation is absent or is not in its native API shape."""


@dataclass(frozen=True)
class _Outcome:
    status: Status
    summary: str
    paths: tuple[str, ...] = ()
    examined: int | None = None
    violations: int | None = None


@dataclass(frozen=True)
class _Rule:
    definition: CheckDefinition
    predicate: Callable[[dict[str, Any]], _Outcome]
    policy_specific: bool = False


def _get(data: dict[str, Any], path: str, default: Any = _MISSING) -> Any:
    current: Any = data
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Unavailable
    return value


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise _Unavailable
    return value


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _Unavailable
    return value


def _unknown(
    *paths: str, summary: str = "Required configuration evidence is unavailable."
) -> _Outcome:
    return _Outcome("unknown", summary, tuple(paths))


def _verdict(
    ok: bool,
    success: str,
    failure: str,
    *paths: str,
    examined: int | None = None,
    violations: int | None = None,
) -> _Outcome:
    return _Outcome(
        "pass" if ok else "fail", success if ok else failure, tuple(paths), examined, violations
    )


def _bool_field(data: dict[str, Any], path: str, wanted: bool) -> _Outcome:
    value = _get(data, path)
    if type(value) is not bool:
        return _unknown(path)
    return _verdict(
        value is wanted,
        "The observed setting matches this check's configuration requirement.",
        "The observed setting does not match this check's configuration requirement.",
        path,
    )


def _enum_field(
    data: dict[str, Any], path: str, allowed: frozenset[str], denied: frozenset[str]
) -> _Outcome:
    value = _get(data, path)
    if value not in allowed | denied:
        return _unknown(path)
    return _verdict(
        value in allowed,
        "The observed configuration is one of the permitted modes for this check.",
        "The observed configuration is a mode this check flags for review.",
        path,
    )


def _nonempty_field(data: dict[str, Any], path: str) -> _Outcome:
    value = _get(data, path)
    if value is _MISSING or value is None:
        return _unknown(path)
    if not isinstance(value, (str, list, dict)):
        return _unknown(path)
    return _verdict(
        bool(value),
        "The required configuration is present.",
        "The required configuration is explicitly empty.",
        path,
    )


def _external_ip(data: dict[str, Any]) -> _Outcome:
    interfaces = _objects(_get(data, "networkInterfaces"))
    public = 0
    for interface in interfaces:
        access = _objects(interface.get("accessConfigs", []))
        access6 = _objects(interface.get("ipv6AccessConfigs", []))
        public += int(bool(access or access6))
    return _verdict(
        public == 0,
        "No external IP access configuration was observed on this VM.",
        "The VM has an external IP access configuration; reachability is not established.",
        "networkInterfaces[].accessConfigs",
        "networkInterfaces[].ipv6AccessConfigs",
        examined=len(interfaces),
        violations=public,
    )


def _default_service_account(data: dict[str, Any], *, cloud_run: bool = False) -> _Outcome:
    if cloud_run:
        email = _get(data, "template.serviceAccount")
        if not isinstance(email, str) or not email:
            return _unknown("template.serviceAccount")
        emails = [email]
        path = "template.serviceAccount"
    else:
        accounts = _objects(_get(data, "serviceAccounts"))
        emails = []
        for account in accounts:
            email = account.get("email")
            if not isinstance(email, str):
                return _unknown("serviceAccounts[].email")
            emails.append(email)
        path = "serviceAccounts[].email"
    count = sum(
        bool(re.fullmatch(r"\d+-compute@developer\.gserviceaccount\.com", e)) for e in emails
    )
    return _verdict(
        count == 0,
        "No default Compute Engine service account was observed.",
        "A default Compute Engine service account is attached; review its purpose and IAM grants.",
        path,
        examined=len(emails),
        violations=count,
    )


def _metadata_value(data: dict[str, Any], key: str) -> Any:
    items = _objects(_get(data, "metadata.items"))
    values = [item.get("value", _MISSING) for item in items if item.get("key") == key]
    if len(values) > 1:
        raise _Unavailable
    return values[0] if values else _MISSING


def _instance_metadata_bool(data: dict[str, Any], key: str) -> _Outcome:
    value = _metadata_value(data, key)
    path = f"metadata.items[key={key}].value"
    if value is _MISSING:
        return _unknown(
            path,
            summary="The instance setting is absent; project-level inheritance was not evaluated.",
        )
    if not isinstance(value, str) or value.lower() not in {"true", "false"}:
        return _unknown(path)
    return _verdict(
        value.lower() == "true",
        "The instance explicitly enables the required metadata control.",
        "The instance explicitly disables the required metadata control.",
        path,
    )


def _block_project_keys(data: dict[str, Any]) -> _Outcome:
    oslogin = _metadata_value(data, "enable-oslogin")
    if isinstance(oslogin, str) and oslogin.lower() == "true":
        return _Outcome(
            "not_applicable",
            "OS Login is explicitly enabled on this instance.",
            ("metadata.items[key=enable-oslogin].value",),
        )
    return _instance_metadata_bool(data, "block-project-ssh-keys")


def _public_cidrs(values: Any) -> bool:
    networks = _strings(values)
    return any(ipaddress.ip_network(item, strict=False).prefixlen == 0 for item in networks)


def _covers_all_ports(ranges: list[tuple[int, int]]) -> bool:
    """Combine overlapping/adjacent ranges without mixing different protocols."""
    next_port = 1
    for low, high in sorted(ranges):
        if low > next_port:
            return False
        next_port = max(next_port, high + 1)
        if next_port > 65535:
            return True
    return False


def _firewall_allows(data: dict[str, Any], *, port: int | None) -> _Outcome:
    if not data or "name" not in data:
        return _unknown("name", "allowed", "sourceRanges")
    if data.get("disabled") is True:
        return _Outcome("not_applicable", "The firewall rule is disabled.", ("disabled",))
    direction = data.get("direction", "INGRESS")
    if direction == "EGRESS":
        return _Outcome("not_applicable", "This check evaluates ingress rules.", ("direction",))
    if direction != "INGRESS":
        return _unknown("direction")
    if data.get("denied") and not data.get("allowed"):
        return _Outcome("not_applicable", "This is a deny rule.", ("denied",))
    allowed = _objects(_get(data, "allowed"))
    sources = data.get("sourceRanges", [])
    has_selectors = bool(data.get("sourceTags") or data.get("sourceServiceAccounts"))
    public = _public_cidrs(sources) if sources else not has_selectors
    violations = 0
    protocol_ranges: dict[str, list[tuple[int, int]]] = {}
    for rule in allowed:
        protocol = rule.get("IPProtocol")
        if not isinstance(protocol, str):
            raise _Unavailable
        ports = _strings(rule.get("ports", []))
        matches = protocol == "all"
        if protocol in {"tcp", "6"} or (port is None and protocol in {"udp", "17"}):
            ranges: list[tuple[int, int]] = []
            for item in ports:
                parts = item.split("-")
                if len(parts) not in {1, 2} or not all(p.isdigit() for p in parts):
                    raise _Unavailable
                low, high = int(parts[0]), int(parts[-1])
                if not 0 <= low <= high <= 65535:
                    raise _Unavailable
                ranges.append((low, high))
            if port is None:
                matches |= not ranges or _covers_all_ports(ranges)
                normalized_protocol = "tcp" if protocol in {"tcp", "6"} else "udp"
                protocol_ranges.setdefault(normalized_protocol, []).extend(ranges)
            else:
                matches |= not ranges or any(low <= port <= high for low, high in ranges)
        violations += int(public and matches)
    if port is None and public and violations == 0:
        # Equivalent rules can split one full TCP/UDP range across ALLOW entries.
        violations = int(any(_covers_all_ports(ranges) for ranges in protocol_ranges.values()))
    return _verdict(
        violations == 0,
        "This rule contains no unrestricted-source allow entry matching the checked ports.",
        "This rule permits the checked traffic from an unrestricted source range; effective reachability was not evaluated.",
        "sourceRanges",
        "sourceTags",
        "sourceServiceAccounts",
        "allowed",
        "direction",
        "disabled",
        examined=len(allowed),
        violations=violations,
    )


def _firewall_logging(data: dict[str, Any]) -> _Outcome:
    if data.get("disabled") is True:
        return _Outcome("not_applicable", "The firewall rule is disabled.", ("disabled",))
    return _bool_field(data, "logConfig.enable", True)


def _flow_logs(data: dict[str, Any]) -> _Outcome:
    if type(_get(data, "logConfig.enable")) is bool:
        result = _bool_field(data, "logConfig.enable", True)
    else:
        result = _bool_field(data, "enableFlowLogs", True)
    if result.status == "fail":
        return _Outcome(
            "fail",
            "Subnet-local flow logging is explicitly disabled; separate Network Management flow-log configurations were not evaluated.",
            result.paths,
        )
    return result


def _gke_network_policy(data: dict[str, Any]) -> _Outcome:
    if _get(data, "networkConfig.datapathProvider") == "ADVANCED_DATAPATH":
        return _Outcome(
            "pass",
            "GKE Dataplane V2 is configured, which provides network-policy enforcement.",
            ("networkConfig.datapathProvider",),
        )
    return _bool_field(data, "networkPolicy.enabled", True)


def _gke_authorized_networks(data: dict[str, Any]) -> _Outcome:
    ip_config = _get(data, "controlPlaneEndpointsConfig.ipEndpointsConfig")
    if isinstance(ip_config, dict):
        if ip_config.get("enabled") is False:
            return _Outcome(
                "not_applicable",
                "IP-based control-plane endpoints are disabled.",
                ("controlPlaneEndpointsConfig.ipEndpointsConfig.enabled",),
            )
        return _bool_field(
            data,
            "controlPlaneEndpointsConfig.ipEndpointsConfig.authorizedNetworksConfig.enabled",
            True,
        )
    return _bool_field(data, "masterAuthorizedNetworksConfig.enabled", True)


def _gke_binauthz(data: dict[str, Any]) -> _Outcome:
    mode = _get(data, "binaryAuthorization.evaluationMode")
    if mode in {
        "PROJECT_SINGLETON_POLICY_ENFORCE",
        "POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE",
    }:
        return _Outcome(
            "pass",
            "Binary Authorization admission enforcement is configured.",
            ("binaryAuthorization.evaluationMode",),
        )
    if mode in {"DISABLED", "POLICY_BINDINGS"}:
        return _Outcome(
            "fail",
            "Binary Authorization admission enforcement is not configured in the observed mode.",
            ("binaryAuthorization.evaluationMode",),
        )
    if mode not in {_MISSING, None, "EVALUATION_MODE_UNSPECIFIED"}:
        return _unknown("binaryAuthorization.evaluationMode")
    return _bool_field(data, "binaryAuthorization.enabled", True)


def _gke_node_management(data: dict[str, Any], setting: str) -> _Outcome:
    if _get(data, "autopilot.enabled") is True:
        return _Outcome(
            "not_applicable",
            "Node maintenance is managed by GKE Autopilot.",
            ("autopilot.enabled",),
        )
    pools = _objects(_get(data, "nodePools"))
    if not pools:
        return _unknown("nodePools")
    values = [_get(pool, f"management.{setting}") for pool in pools]
    if any(type(value) is not bool for value in values):
        return _unknown(f"nodePools[].management.{setting}")
    count = sum(value is False for value in values)
    return _verdict(
        count == 0,
        "All observed node pools enable the maintenance control.",
        "At least one observed node pool disables the maintenance control.",
        f"nodePools[].management.{setting}",
        examined=len(pools),
        violations=count,
    )


def _public_access_prevention(data: dict[str, Any]) -> _Outcome:
    value = _get(data, "iamConfiguration.publicAccessPrevention")
    if value == "enforced":
        return _Outcome(
            "pass",
            "Public access prevention is explicitly enforced on the bucket.",
            ("iamConfiguration.publicAccessPrevention",),
        )
    if value == "inherited":
        return _unknown(
            "iamConfiguration.publicAccessPrevention",
            summary="The bucket inherits public access prevention; effective organization policy was not collected by this check.",
        )
    return _unknown("iamConfiguration.publicAccessPrevention")


def _iam_binding_review(data: dict[str, Any], *, basic_roles: bool = False) -> _Outcome:
    bindings = _objects(_get(data, "bindings"))
    violations = 0
    for binding in bindings:
        members = _strings(_get(binding, "members"))
        role = binding.get("role")
        if not isinstance(role, str):
            raise _Unavailable
        flagged = (
            role in {"roles/owner", "roles/editor", "roles/viewer"}
            if basic_roles
            else any(member in {"allUsers", "allAuthenticatedUsers"} for member in members)
        )
        violations += int(flagged and bool(members))
    return _verdict(
        violations == 0,
        "No binding matching this review criterion was found in the observed policy.",
        "A binding matching this review criterion exists; conditions, deny policies, and effective access require separate analysis.",
        "bindings[].role",
        "bindings[].members",
        "bindings[].condition",
        examined=len(bindings),
        violations=violations,
    )


def _sql_authorized_ranges(data: dict[str, Any]) -> _Outcome:
    entries = _objects(_get(data, "settings.ipConfiguration.authorizedNetworks"))
    public = 0
    for entry in entries:
        value = entry.get("value")
        if not isinstance(value, str):
            raise _Unavailable
        public += int(ipaddress.ip_network(value, strict=False).prefixlen == 0)
    return _verdict(
        public == 0,
        "No unrestricted CIDR is present in the observed authorized networks.",
        "An unrestricted CIDR is present in authorized networks; this does not establish database authentication or reachability.",
        "settings.ipConfiguration.authorizedNetworks[].value",
        examined=len(entries),
        violations=public,
    )


def _sql_tls(data: dict[str, Any]) -> _Outcome:
    path = "settings.ipConfiguration.sslMode"
    mode = _get(data, path)
    if mode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}:
        return _Outcome("pass", "The observed SSL mode requires encrypted connections.", (path,))
    if mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
        return _Outcome("fail", "The observed SSL mode permits unencrypted connections.", (path,))
    if mode not in {_MISSING, None, "SSL_MODE_UNSPECIFIED"}:
        return _unknown(path)
    return _bool_field(data, "settings.ipConfiguration.requireSsl", True)


def _sql_backup(data: dict[str, Any], *, pitr: bool = False) -> _Outcome:
    if data.get("instanceType") == "READ_REPLICA_INSTANCE":
        return _Outcome(
            "not_applicable",
            "Review backup and recovery controls on the primary instance.",
            ("instanceType",),
        )
    path = "settings.backupConfiguration.enabled"
    if pitr:
        version = data.get("databaseVersion")
        if not isinstance(version, str):
            return _unknown("databaseVersion")
        if version.startswith("MYSQL_"):
            path = "settings.backupConfiguration.binaryLogEnabled"
        elif version.startswith(("POSTGRES_", "SQLSERVER_")):
            path = "settings.backupConfiguration.pointInTimeRecoveryEnabled"
        else:
            return _unknown("databaseVersion")
    return _bool_field(data, path, True)


def _run_binauthz(data: dict[str, Any]) -> _Outcome:
    justification = _get(data, "binaryAuthorization.breakglassJustification")
    if isinstance(justification, str) and justification:
        return _Outcome(
            "fail",
            "A Binary Authorization break-glass justification is configured; its content is not included.",
            ("binaryAuthorization.breakglassJustification",),
        )
    return _bool_field(data, "binaryAuthorization.useDefault", True)


def _immutable_tags(data: dict[str, Any]) -> _Outcome:
    format_ = data.get("format")
    if not isinstance(format_, str):
        return _unknown("format")
    if format_ != "DOCKER":
        return _Outcome("not_applicable", "The repository format is not Docker.", ("format",))
    mode = data.get("mode")
    if mode in {"REMOTE_REPOSITORY", "VIRTUAL_REPOSITORY"}:
        return _Outcome(
            "not_applicable", "This check applies to standard Docker repositories.", ("mode",)
        )
    return _bool_field(data, "dockerConfig.immutableTags", True)


def _push_auth(data: dict[str, Any]) -> _Outcome:
    config = _get(data, "pushConfig")
    if config is _MISSING:
        return _unknown("pushConfig")
    config = _mapping(config)
    endpoint = config.get("pushEndpoint", "")
    if not isinstance(endpoint, str):
        return _unknown("pushConfig.pushEndpoint")
    if not endpoint:
        return _Outcome(
            "not_applicable", "No push endpoint is configured.", ("pushConfig.pushEndpoint",)
        )
    account = _get(config, "oidcToken.serviceAccountEmail")
    return _verdict(
        isinstance(account, str) and bool(account),
        "The push subscription is configured to attach an OIDC identity token.",
        "The push subscription has no configured OIDC service-account identity.",
        "pushConfig.oidcToken.serviceAccountEmail",
    )


def _bigquery_public(data: dict[str, Any]) -> _Outcome:
    entries = _objects(_get(data, "access"))
    violations = sum(
        entry.get("specialGroup") == "allAuthenticatedUsers"
        or entry.get("iamMember") in {"allUsers", "allAuthenticatedUsers"}
        for entry in entries
    )
    return _verdict(
        violations == 0,
        "No public principal was observed in the dataset access entries.",
        "A public principal appears in the dataset access entries; effective access was not evaluated.",
        "access[].specialGroup",
        "access[].iamMember",
        examined=len(entries),
        violations=violations,
    )


def _pod_spec(data: dict[str, Any], kind: str) -> tuple[dict[str, Any], str]:
    if kind == "Pod":
        path = "spec"
    elif kind == "CronJob":
        path = "spec.jobTemplate.spec.template.spec"
    else:
        path = "spec.template.spec"
    return _mapping(_get(data, path)), path


def _containers(
    spec: dict[str, Any], *, ephemeral: bool = True
) -> list[tuple[dict[str, Any], str]]:
    regular = _objects(_get(spec, "containers"))
    if not regular:
        raise _Unavailable
    result = [(item, f"containers[{i}]") for i, item in enumerate(regular)]
    for field in ("initContainers", "ephemeralContainers") if ephemeral else ("initContainers",):
        result.extend(
            (item, f"{field}[{i}]") for i, item in enumerate(_objects(spec.get(field, [])))
        )
    return result


def _effective(spec: dict[str, Any], container: dict[str, Any], field: str) -> Any:
    value = _get(container, f"securityContext.{field}")
    return _get(spec, f"securityContext.{field}") if value is _MISSING else value


def _positive_quantity(value: Any) -> bool:
    """Check a native Kubernetes Quantity's sign without coercing arbitrary text."""
    if type(value) not in {str, int, float}:
        raise _Unavailable
    # DecimalSI, BinarySI, and decimal exponent forms from the Quantity grammar.
    match = re.fullmatch(
        r"([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))(?:[eE][+-]?[0-9]+|[numkMGTPE]|[KMGTPE]i)?",
        str(value),
    )
    if match is None:
        raise _Unavailable
    return Decimal(match.group(1)) > 0


def _container_check(data: dict[str, Any], kind: str, control: str) -> _Outcome:
    spec, path = _pod_spec(data, kind)
    linux_only = control in {
        "privileged",
        "privilege_escalation",
        "non_root",
        "root_uid",
        "seccomp",
        "drop_capabilities",
        "added_capabilities",
        "read_only_root",
    }
    if linux_only and _get(spec, "os.name") == "windows":
        return _Outcome(
            "not_applicable", "This control applies to Linux workloads.", (f"{path}.os.name",)
        )
    containers = _containers(spec, ephemeral=control != "resource_limits")
    failures: list[str] = []
    missing: list[str] = []
    examined_paths: list[str] = []
    for container, relative in containers:
        prefix = f"{path}.{relative}"
        security = _mapping(container.get("securityContext", {}))
        if control == "privileged":
            value = security.get("privileged", False)
            ok = value is False
            known = type(value) is bool
            leaf = "securityContext.privileged"
        elif control == "privilege_escalation":
            value = security.get("allowPrivilegeEscalation", True)
            added = _strings(_get(security, "capabilities.add", []))
            ok = (
                value is False
                and security.get("privileged") is not True
                and "SYS_ADMIN" not in added
            )
            known = type(value) is bool
            leaf = "securityContext.allowPrivilegeEscalation"
        elif control == "non_root":
            value = _effective(spec, container, "runAsNonRoot")
            uid = _effective(spec, container, "runAsUser")
            ok = value is True and uid != 0
            known = type(value) is bool or uid == 0
            leaf = "securityContext.runAsNonRoot"
        elif control == "root_uid":
            value = _effective(spec, container, "runAsUser")
            ok = value is _MISSING or value is None or (type(value) is int and value != 0)
            known = value is _MISSING or value is None or type(value) is int
            leaf = "securityContext.runAsUser"
        elif control == "seccomp":
            value = _effective(spec, container, "seccompProfile.type")
            ok = value in {"RuntimeDefault", "Localhost"}
            known = value in {"RuntimeDefault", "Localhost", "Unconfined"}
            leaf = "securityContext.seccompProfile.type"
        elif control == "drop_capabilities":
            value = _strings(_get(security, "capabilities.drop", []))
            ok, known = "ALL" in value, True
            leaf = "securityContext.capabilities.drop"
        elif control == "added_capabilities":
            value = _strings(_get(security, "capabilities.add", []))
            ok, known = set(value) <= {"NET_BIND_SERVICE"}, True
            leaf = "securityContext.capabilities.add"
        elif control == "read_only_root":
            value = security.get("readOnlyRootFilesystem", False)
            ok, known = value is True, type(value) is bool
            leaf = "securityContext.readOnlyRootFilesystem"
        elif control == "host_ports":
            ports = _objects(container.get("ports", []))
            values = [port.get("hostPort", 0) for port in ports]
            ok = all(value == 0 for value in values)
            known = all(type(value) is int for value in values)
            leaf = "ports[].hostPort"
        elif control == "resource_limits":
            limits = _mapping(_get(container, "resources.limits", {}))
            quantities = [
                _positive_quantity(limits[field]) if field in limits else False
                for field in ("cpu", "memory")
            ]
            ok = all(quantities)
            known = True
            leaf = "resources.limits"
        elif control == "image_digest":
            value = container.get("image")
            known = isinstance(value, str) and bool(value)
            ok = known and bool(re.fullmatch(r"[^\s@]+@sha256:[0-9a-fA-F]{64}", value))
            leaf = "image"
        elif control == "host_process":
            value = _effective(spec, container, "windowsOptions.hostProcess")
            if value is _MISSING:
                value = False
            ok, known = value is False, type(value) is bool
            leaf = "securityContext.windowsOptions.hostProcess"
        else:
            raise ValueError("Unknown internal container control")
        evidence = f"{prefix}.{leaf}"
        examined_paths.append(evidence)
        if not known:
            missing.append(evidence)
        elif not ok:
            failures.append(evidence)
    inherited = control in {"non_root", "root_uid", "seccomp", "host_process"}
    context_paths = [f"{path}.securityContext"] if inherited else []
    if failures:
        return _Outcome(
            "fail",
            "At least one container does not meet this configuration requirement.",
            tuple(failures + context_paths),
            len(containers),
            len(failures),
        )
    if missing:
        return _Outcome(
            "unknown",
            "Some container settings are unresolved; image, node, or inherited defaults may apply.",
            tuple(missing + context_paths),
            len(containers),
            0,
        )
    return _Outcome(
        "pass",
        "All observed containers meet this configuration requirement.",
        tuple(examined_paths + context_paths),
        len(containers),
        0,
    )


def _pod_flag(data: dict[str, Any], kind: str, field: str) -> _Outcome:
    spec, path = _pod_spec(data, kind)
    _containers(spec)
    value = spec.get(field, False)
    if type(value) is not bool:
        return _unknown(f"{path}.{field}")
    return _verdict(
        not value,
        "The workload does not request this host namespace.",
        "The workload requests a host namespace.",
        f"{path}.{field}",
    )


def _host_path(data: dict[str, Any], kind: str) -> _Outcome:
    spec, path = _pod_spec(data, kind)
    _containers(spec)
    volumes = _objects(spec.get("volumes", []))
    count = sum("hostPath" in volume for volume in volumes)
    return _verdict(
        count == 0,
        "No hostPath volume is declared.",
        "The workload declares a hostPath volume; host path values are not included.",
        f"{path}.volumes[].hostPath",
        examined=len(volumes),
        violations=count,
    )


def _automount(data: dict[str, Any], kind: str) -> _Outcome:
    spec, path = _pod_spec(data, kind)
    _containers(spec)
    value = spec.get("automountServiceAccountToken", _MISSING)
    if type(value) is not bool:
        return _unknown(
            f"{path}.automountServiceAccountToken",
            summary="Token automount is not set on this workload; its service account's setting was not evaluated.",
        )
    return _verdict(
        value is False,
        "Automatic service-account token mounting is explicitly disabled.",
        "Automatic service-account token mounting is explicitly enabled; confirm the workload requires Kubernetes API access.",
        f"{path}.automountServiceAccountToken",
    )


def _default_ksa(data: dict[str, Any], kind: str) -> _Outcome:
    spec, path = _pod_spec(data, kind)
    _containers(spec)
    value = spec.get("serviceAccountName", "default") or "default"
    if not isinstance(value, str):
        return _unknown(f"{path}.serviceAccountName")
    return _verdict(
        value != "default",
        "A non-default Kubernetes service account is selected.",
        "The workload selects the default Kubernetes service account.",
        f"{path}.serviceAccountName",
    )


def _rbac_rules(data: dict[str, Any], *, secret_reads: bool = False) -> _Outcome:
    rules = _objects(_get(data, "rules"))
    if not rules and data.get("aggregationRule"):
        return _unknown(
            "rules",
            "aggregationRule",
            summary="The aggregated role has no observed rules; aggregation may not have completed.",
        )
    count = 0
    for rule in rules:
        if secret_reads:
            verbs = _strings(_get(rule, "verbs"))
            resources = _strings(rule.get("resources", []))
            groups = _strings(rule.get("apiGroups", []))
            flags = (
                bool(set(verbs) & {"get", "list", "watch", "*"})
                and bool(set(resources) & {"secrets", "*"})
                and bool(set(groups) & {"", "*"})
            )
        else:
            flags = any(
                "*" in value
                for key in ("verbs", "apiGroups", "resources", "nonResourceURLs")
                for value in _strings(rule.get(key, []))
            )
        count += int(flags)
    return _verdict(
        count == 0,
        "No matching permission grant was found in the observed role rules.",
        "The role includes permissions matching this review criterion; bindings and effective access were not evaluated.",
        "rules",
        examined=len(rules),
        violations=count,
    )


def _rbac_binding(data: dict[str, Any], *, public_groups: bool = False) -> _Outcome:
    role = _mapping(_get(data, "roleRef"))
    subjects = _objects(_get(data, "subjects"))
    if public_groups:
        count = sum(
            subject.get("kind") == "Group"
            and subject.get("name")
            in {"system:anonymous", "system:unauthenticated", "system:authenticated"}
            or subject.get("kind") == "User"
            and subject.get("name") == "system:anonymous"
            for subject in subjects
        )
    else:
        count = int(
            bool(subjects)
            and role.get("kind") == "ClusterRole"
            and role.get("name") == "cluster-admin"
        )
    return _verdict(
        count == 0,
        "The observed binding does not match this review criterion.",
        "The binding matches this review criterion; namespace scope and the referenced role determine its impact.",
        "roleRef",
        "subjects",
        examined=len(subjects),
        violations=count,
    )


def _namespace_pss(data: dict[str, Any]) -> _Outcome:
    labels = _get(data, "metadata.labels")
    if not isinstance(labels, dict) or "pod-security.kubernetes.io/enforce" not in labels:
        return _unknown(
            "metadata.labels[pod-security.kubernetes.io/enforce]",
            summary="No namespace enforcement label was observed; cluster admission defaults were not evaluated.",
        )
    mode = labels["pod-security.kubernetes.io/enforce"]
    if mode not in {"baseline", "restricted", "privileged"}:
        return _unknown("metadata.labels[pod-security.kubernetes.io/enforce]")
    return _verdict(
        mode in {"baseline", "restricted"},
        "The namespace explicitly enforces baseline or restricted Pod Security.",
        "The namespace explicitly selects privileged Pod Security enforcement.",
        "metadata.labels[pod-security.kubernetes.io/enforce]",
    )


def _rule(
    id_: str,
    kind: str,
    title: str,
    description: str,
    predicate: Callable[[dict[str, Any]], _Outcome],
    *,
    severity: Severity = "medium",
    remediation: str = "Review the cited configuration against your organization's requirements.",
    policy: bool = False,
) -> _Rule:
    return _Rule(
        CheckDefinition(
            id=id_,
            title=title,
            description=description,
            resource_kind=kind,
            severity=severity,
            remediation=remediation,
        ),
        predicate,
        policy,
    )


def _bool_rule(
    id_: str,
    kind: str,
    title: str,
    path: str,
    wanted: bool,
    *,
    description: str = "",
    severity: Severity = "medium",
    policy: bool = False,
) -> _Rule:
    return _rule(
        id_,
        kind,
        title,
        description
        or f"Checks the explicitly observed {path} setting; missing values remain unknown.",
        partial(_bool_field, path=path, wanted=wanted),
        severity=severity,
        policy=policy,
    )


def _build_rules() -> tuple[_Rule, ...]:
    rules: list[_Rule] = []
    add = rules.append
    instance = "gcp.compute.instances"
    add(
        _rule(
            "gcp.compute.instance.no_external_ip",
            instance,
            "VM external IP configuration",
            "Flags an external IPv4 or IPv6 access configuration. This is an observation, not an internet-reachability assessment. Public workloads can have approved exceptions.",
            _external_ip,
            policy=True,
        )
    )
    for suffix, title, field in (
        ("secure_boot", "Shielded VM Secure Boot", "enableSecureBoot"),
        ("vtpm", "Shielded VM virtual TPM", "enableVtpm"),
        ("integrity_monitoring", "Shielded VM integrity monitoring", "enableIntegrityMonitoring"),
    ):
        add(
            _bool_rule(
                f"gcp.compute.instance.{suffix}",
                instance,
                title,
                f"shieldedInstanceConfig.{field}",
                True,
            )
        )
    add(
        _bool_rule(
            "gcp.compute.instance.no_ip_forwarding",
            instance,
            "VM IP forwarding disabled",
            "canIpForward",
            False,
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.compute.instance.dedicated_service_account",
            instance,
            "VM dedicated service account",
            "Flags the default Compute Engine service account; it does not infer the account's privileges.",
            _default_service_account,
        )
    )
    add(
        _rule(
            "gcp.compute.instance.os_login",
            instance,
            "Instance OS Login setting",
            "Checks an explicit instance metadata setting. Absent configuration is unknown because project metadata can apply.",
            partial(_instance_metadata_bool, key="enable-oslogin"),
        )
    )
    add(
        _rule(
            "gcp.compute.instance.block_project_ssh_keys",
            instance,
            "Instance project SSH key restriction",
            "Checks instance metadata; explicitly enabled OS Login makes this key control inapplicable.",
            _block_project_keys,
        )
    )
    add(
        _bool_rule(
            "gcp.compute.instance.deletion_protection",
            instance,
            "VM deletion protection",
            "deletionProtection",
            True,
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.compute.disk.cmek",
            "gcp.compute.disks",
            "Disk customer-managed encryption key",
            "Policy-specific check for an observed KMS key reference; absence is unknown and does not mean data is unencrypted.",
            partial(_nonempty_field, path="diskEncryptionKey.kmsKeyName"),
            severity="low",
            policy=True,
        )
    )
    for suffix, title, port in (
        ("no_public_ssh", "Unrestricted-source SSH firewall rule", 22),
        ("no_public_rdp", "Unrestricted-source RDP firewall rule", 3389),
        ("no_public_all_ports", "Unrestricted-source broad firewall rule", None),
    ):
        add(
            _rule(
                f"gcp.compute.firewall.{suffix}",
                "gcp.compute.firewalls",
                title,
                "Examines the local ingress allow rule, IPv4 and IPv6 CIDRs, and port ranges. Priorities, hierarchical policies, targets, and actual reachability are not evaluated.",
                partial(_firewall_allows, port=port),
                severity="high",
            )
        )
    add(
        _rule(
            "gcp.compute.firewall.logging",
            "gcp.compute.firewalls",
            "Firewall rule logging",
            "Requires the observed enabled rule to have logging explicitly enabled; disabled rules are inapplicable.",
            _firewall_logging,
            severity="low",
            policy=True,
        )
    )
    add(
        _bool_rule(
            "gcp.compute.network.custom_subnets",
            "gcp.compute.networks",
            "Custom subnet mode",
            "autoCreateSubnetworks",
            False,
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.compute.subnet.flow_logs",
            "gcp.compute.subnetworks",
            "Subnet-local VPC Flow Logs",
            "Evaluates only the subnet's local flow-log setting. Separate centralized Network Management configurations may also collect flows.",
            _flow_logs,
            severity="low",
            policy=True,
        )
    )
    add(
        _bool_rule(
            "gcp.compute.subnet.private_google_access",
            "gcp.compute.subnetworks",
            "Private Google Access",
            "privateIpGoogleAccess",
            True,
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.compute.ssl.minimum_tls",
            "gcp.compute.sslPolicies",
            "TLS 1.2 or later minimum",
            "Checks the observed TLS policy minimum version.",
            partial(
                _enum_field,
                path="minTlsVersion",
                allowed=frozenset({"TLS_1_2", "TLS_1_3"}),
                denied=frozenset({"TLS_1_0", "TLS_1_1"}),
            ),
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.compute.ssl.modern_profile",
            "gcp.compute.sslPolicies",
            "Modern TLS profile",
            "MODERN and RESTRICTED pass; COMPATIBLE requires review. CUSTOM remains unknown because its cipher configuration needs separate evaluation.",
            partial(
                _enum_field,
                path="profile",
                allowed=frozenset({"MODERN", "RESTRICTED"}),
                denied=frozenset({"COMPATIBLE"}),
            ),
            policy=True,
        )
    )

    cluster = "gcp.container.clusters"
    add(
        _bool_rule(
            "gcp.gke.legacy_abac_disabled",
            cluster,
            "Legacy ABAC disabled",
            "legacyAbac.enabled",
            False,
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.gke.workload_identity",
            cluster,
            "Workload Identity Federation configured",
            "Checks the configured workload identity pool. It does not prove that each node pool or workload uses the intended identity.",
            partial(_nonempty_field, path="workloadIdentityConfig.workloadPool"),
        )
    )
    add(
        _rule(
            "gcp.gke.release_channel",
            cluster,
            "GKE release channel",
            "Checks explicit release-channel enrollment; it is not a patch-age or support-lifecycle assessment.",
            partial(
                _enum_field,
                path="releaseChannel.channel",
                allowed=frozenset({"RAPID", "REGULAR", "STABLE", "EXTENDED"}),
                denied=frozenset({"UNSPECIFIED"}),
            ),
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.gke.network_policy",
            cluster,
            "Network policy enforcement capability",
            "Checks NetworkPolicy enablement or Dataplane V2. Individual workload isolation policies are not evaluated by this check.",
            _gke_network_policy,
        )
    )
    add(
        _bool_rule(
            "gcp.gke.shielded_nodes", cluster, "GKE Shielded Nodes", "shieldedNodes.enabled", True
        )
    )
    add(
        _rule(
            "gcp.gke.authorized_networks",
            cluster,
            "Control-plane IP authorized networks",
            "Evaluates IP endpoint authorized networks; DNS-only control planes are inapplicable. VPC Service Controls and effective endpoint reachability are not inferred.",
            _gke_authorized_networks,
        )
    )
    add(
        _bool_rule(
            "gcp.gke.no_client_certificate",
            cluster,
            "Legacy cluster client certificate issuance",
            "masterAuth.clientCertificateConfig.issueClientCertificate",
            False,
        )
    )
    add(
        _rule(
            "gcp.gke.binary_authorization",
            cluster,
            "Binary Authorization admission enforcement",
            "Policy-specific admission enforcement check. Continuous-validation-only mode is not admission enforcement.",
            _gke_binauthz,
            policy=True,
        )
    )
    for setting, suffix, title in (
        ("autoUpgrade", "node_auto_upgrade", "Node pool automatic upgrades"),
        ("autoRepair", "node_auto_repair", "Node pool automatic repair"),
    ):
        add(
            _rule(
                f"gcp.gke.{suffix}",
                cluster,
                title,
                "Evaluates every node pool embedded in the collected cluster. Autopilot is managed and inapplicable; missing node-pool evidence is unknown.",
                partial(_gke_node_management, setting=setting),
                severity="low",
            )
        )

    bucket = "gcp.storage.buckets"
    add(
        _bool_rule(
            "gcp.storage.uniform_access",
            bucket,
            "Uniform bucket-level access",
            "iamConfiguration.uniformBucketLevelAccess.enabled",
            True,
        )
    )
    add(
        _rule(
            "gcp.storage.public_access_prevention",
            bucket,
            "Bucket public access prevention",
            "An enforced bucket setting passes. Inherited settings remain unknown until effective organization policy is evaluated.",
            _public_access_prevention,
            severity="high",
        )
    )
    add(
        _bool_rule(
            "gcp.storage.versioning",
            bucket,
            "Bucket object versioning",
            "versioning.enabled",
            True,
            description="Policy-specific durability check for versioning; soft delete, backups, and retention requirements are separate controls.",
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.storage.cmek",
            bucket,
            "Bucket default customer-managed key",
            "Policy-specific default KMS reference check. It does not inspect existing objects or imply unencrypted storage when unknown.",
            partial(_nonempty_field, path="encryption.defaultKmsKeyName"),
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.iam.no_public_principal",
            "gcp.iam.policy",
            "IAM public-principal bindings",
            "Flags bindings to allUsers or allAuthenticatedUsers. Conditional bindings are included as observations; effective access is not evaluated.",
            _iam_binding_review,
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.iam.no_basic_roles",
            "gcp.iam.policy",
            "IAM basic-role bindings",
            "Flags Owner, Editor, or Viewer in the observed policy, including conditional bindings. Approved administrative grants can be excepted.",
            partial(_iam_binding_review, basic_roles=True),
            policy=True,
        )
    )

    sql = "gcp.sql.instances"
    add(
        _bool_rule(
            "gcp.sql.no_public_ipv4",
            sql,
            "Cloud SQL public IPv4 disabled",
            "settings.ipConfiguration.ipv4Enabled",
            False,
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.sql.no_unrestricted_networks",
            sql,
            "Cloud SQL authorized network scope",
            "Flags IPv4 or IPv6 /0 CIDRs in the observed authorized networks; authentication and effective reachability are not inferred.",
            _sql_authorized_ranges,
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.sql.require_tls",
            sql,
            "Cloud SQL encrypted connections",
            "Checks sslMode and, when appropriate, the legacy requireSsl flag. Unknown modes remain unknown.",
            _sql_tls,
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.sql.automated_backups",
            sql,
            "Cloud SQL automated backups",
            "Reads the primary-instance backup setting; replicas require assessment of their primary.",
            _sql_backup,
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.sql.point_in_time_recovery",
            sql,
            "Cloud SQL recovery log setting",
            "For MySQL, checks binary logging; for PostgreSQL and SQL Server, checks PITR enablement. Backup completeness and successful restoration are not proven.",
            partial(_sql_backup, pitr=True),
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.sql.high_availability",
            sql,
            "Cloud SQL regional availability",
            "Policy-specific availability requirement; zonal deployments may have approved exceptions.",
            partial(
                _enum_field,
                path="settings.availabilityType",
                allowed=frozenset({"REGIONAL"}),
                denied=frozenset({"ZONAL"}),
            ),
            severity="low",
            policy=True,
        )
    )
    add(
        _bool_rule(
            "gcp.sql.deletion_protection",
            sql,
            "Cloud SQL deletion protection",
            "settings.deletionProtectionEnabled",
            True,
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.sql.cmek",
            sql,
            "Cloud SQL customer-managed key",
            "Policy-specific KMS reference check; missing key metadata is unknown and does not imply missing default encryption.",
            partial(_nonempty_field, path="diskEncryptionConfiguration.kmsKeyName"),
            severity="low",
            policy=True,
        )
    )

    run = "gcp.run.services"
    add(
        _rule(
            "gcp.run.restricted_ingress",
            run,
            "Cloud Run restricted ingress",
            "Policy-specific ingress check. Public web services may legitimately accept all ingress; this does not evaluate authentication or load balancer reachability.",
            partial(
                _enum_field,
                path="ingress",
                allowed=frozenset(
                    {"INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"}
                ),
                denied=frozenset({"INGRESS_TRAFFIC_ALL"}),
            ),
            policy=True,
        )
    )
    add(
        _bool_rule(
            "gcp.run.invoker_iam",
            run,
            "Cloud Run invoker IAM check",
            "invokerIamDisabled",
            False,
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.run.dedicated_service_account",
            run,
            "Cloud Run dedicated service account",
            "Flags an explicitly observed default Compute Engine service account; missing account evidence is unknown.",
            partial(_default_service_account, cloud_run=True),
        )
    )
    add(
        _rule(
            "gcp.run.binary_authorization",
            run,
            "Cloud Run Binary Authorization",
            "Policy-specific default-policy enforcement check. A break-glass configuration is flagged without returning its justification text.",
            _run_binauthz,
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.artifactregistry.immutable_tags",
            "gcp.artifactregistry.repositories",
            "Artifact Registry immutable Docker tags",
            "Policy-specific check for standard Docker repositories; remote, virtual, and non-Docker repositories are inapplicable.",
            _immutable_tags,
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.artifactregistry.cmek",
            "gcp.artifactregistry.repositories",
            "Artifact Registry customer-managed key",
            "Policy-specific observed KMS reference check; it does not inspect artifact content.",
            partial(_nonempty_field, path="kmsKeyName"),
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.secretmanager.rotation_schedule",
            "gcp.secretmanager.secrets",
            "Secret Manager rotation notification schedule",
            "Checks rotationPeriod metadata. A notification schedule is not proof that secret material is rotated. Secret versions and values are never read.",
            partial(_nonempty_field, path="rotation.rotationPeriod"),
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.pubsub.topic_cmek",
            "gcp.pubsub.topics",
            "Pub/Sub topic customer-managed key",
            "Policy-specific KMS reference check; no messages are read.",
            partial(_nonempty_field, path="kmsKeyName"),
            severity="low",
            policy=True,
        )
    )
    add(
        _rule(
            "gcp.pubsub.authenticated_push",
            "gcp.pubsub.subscriptions",
            "Pub/Sub authenticated push configuration",
            "Checks that a push endpoint has an OIDC service-account identity. Pull and export subscriptions are not push endpoints.",
            _push_auth,
        )
    )
    add(
        _rule(
            "gcp.bigquery.no_public_access_entry",
            "gcp.bigquery.datasets",
            "BigQuery dataset public access entries",
            "Requires dataset access metadata; list-only summaries without access entries remain unknown. IAM inheritance and authorized-view behavior require separate analysis.",
            _bigquery_public,
            severity="high",
        )
    )
    add(
        _rule(
            "gcp.bigquery.cmek",
            "gcp.bigquery.datasets",
            "BigQuery dataset default customer-managed key",
            "Policy-specific default KMS reference check; existing tables and data are not inspected.",
            partial(_nonempty_field, path="defaultEncryptionConfiguration.kmsKeyName"),
            severity="low",
            policy=True,
        )
    )

    controls = (
        (
            "privileged",
            "No privileged Linux containers",
            "Flags privileged containers; an omitted privileged flag uses the API's false default.",
            "high",
            False,
        ),
        (
            "privilege_escalation",
            "Privilege escalation disabled",
            "Requires allowPrivilegeEscalation=false. Privileged execution and SYS_ADMIN also permit escalation.",
            "high",
            False,
        ),
        (
            "non_root",
            "Non-root execution required",
            "Checks effective pod/container runAsNonRoot and explicit UID conflicts. Unresolved image defaults remain unknown.",
            "medium",
            False,
        ),
        (
            "root_uid",
            "No explicit root UID",
            "Flags effective runAsUser=0. A pass only means no explicit root UID; image identity is not established.",
            "medium",
            False,
        ),
        (
            "seccomp",
            "Restricted seccomp profile",
            "Checks container overrides then pod inheritance. RuntimeDefault and Localhost pass; missing node defaults are unknown.",
            "medium",
            False,
        ),
        (
            "drop_capabilities",
            "Drop all Linux capabilities",
            "Requires an explicit drop list containing ALL, consistent with the Restricted Pod Security capability control.",
            "medium",
            False,
        ),
        (
            "added_capabilities",
            "Restricted added Linux capabilities",
            "Only NET_BIND_SERVICE may be explicitly added under this control.",
            "medium",
            False,
        ),
        (
            "read_only_root",
            "Read-only container root filesystem",
            "Policy-specific check; writable mounted volumes are not covered and some applications need writable root filesystems.",
            "low",
            True,
        ),
        (
            "host_ports",
            "No container host ports",
            "Flags nonzero hostPort requests; service exposure and network reachability are not inferred.",
            "medium",
            True,
        ),
        (
            "resource_limits",
            "CPU and memory limits declared",
            "Policy-specific resource-isolation check on ordinary and init containers. Ephemeral containers cannot set these limits.",
            "low",
            True,
        ),
        (
            "image_digest",
            "Images pinned by SHA-256 digest",
            "Policy-specific reproducibility check; an immutable digest does not prove an image is trusted or vulnerability-free.",
            "low",
            True,
        ),
        (
            "host_process",
            "No Windows HostProcess containers",
            "Checks effective container/pod Windows HostProcess settings without reading host contents.",
            "high",
            False,
        ),
    )
    for kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"):
        canonical = f"k8s.{kind}"
        prefix = f"k8s.{kind.lower()}"
        for control, title, description, severity, policy in controls:
            add(
                _rule(
                    f"{prefix}.{control}",
                    canonical,
                    title,
                    description,
                    partial(_container_check, kind=kind, control=control),
                    severity=severity,
                    policy=policy,
                )
            )
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            add(
                _rule(
                    f"{prefix}.no_{field.lower()}",
                    canonical,
                    f"No {field} namespace",
                    "Evaluates the declared pod-spec flag using its false default; templates may be changed by admission before Pods are created.",
                    partial(_pod_flag, kind=kind, field=field),
                    severity="high",
                )
            )
        add(
            _rule(
                f"{prefix}.no_hostpath",
                canonical,
                "No hostPath volumes",
                "Flags hostPath declarations; host path strings and mounted content are not returned.",
                partial(_host_path, kind=kind),
                severity="high",
            )
        )
        add(
            _rule(
                f"{prefix}.token_automount",
                canonical,
                "Service-account token automount disabled",
                "Checks only the workload flag. An omitted flag is unknown because the Kubernetes service account can supply the setting; explicit projected tokens are separate.",
                partial(_automount, kind=kind),
                policy=True,
            )
        )
        add(
            _rule(
                f"{prefix}.dedicated_service_account",
                canonical,
                "Dedicated Kubernetes service account",
                "Policy-specific separation of workload identity. The default service account is selected when the field is omitted.",
                partial(_default_ksa, kind=kind),
                severity="low",
                policy=True,
            )
        )

    for kind in ("Role", "ClusterRole"):
        add(
            _rule(
                f"k8s.{kind.lower()}.no_wildcards",
                f"k8s.{kind}",
                "RBAC wildcard permissions",
                "Flags wildcard grants in observed rules. A role without bindings grants no access by itself.",
                _rbac_rules,
                severity="high",
            )
        )
        add(
            _rule(
                f"k8s.{kind.lower()}.no_secret_reads",
                f"k8s.{kind}",
                "RBAC Secret read permissions",
                "Identifies get/list/watch grants for core Secret resources, including wildcards, without reading Secrets. resourceNames restrictions remain relevant to impact.",
                partial(_rbac_rules, secret_reads=True),
                severity="high",
                policy=True,
            )
        )
    for kind in ("RoleBinding", "ClusterRoleBinding"):
        add(
            _rule(
                f"k8s.{kind.lower()}.no_cluster_admin",
                f"k8s.{kind}",
                "cluster-admin role reference",
                "Flags a nonempty binding to ClusterRole/cluster-admin. RoleBindings remain limited to their namespace; approved administrative bindings can be excepted.",
                _rbac_binding,
                severity="high",
                policy=True,
            )
        )
        add(
            _rule(
                f"k8s.{kind.lower()}.no_broad_groups",
                f"k8s.{kind}",
                "Broad authentication-group binding",
                "Flags bindings for all authenticated/unauthenticated identities or the anonymous user; referenced permissions and scope determine impact.",
                partial(_rbac_binding, public_groups=True),
                severity="high",
                policy=True,
            )
        )
    add(
        _rule(
            "k8s.namespace.pod_security",
            "k8s.Namespace",
            "Namespace Pod Security enforcement",
            "Checks explicit baseline/restricted namespace enforcement; absence is unknown because cluster defaults can apply.",
            _namespace_pss,
        )
    )
    add(
        _bool_rule(
            "k8s.serviceaccount.token_automount",
            "k8s.ServiceAccount",
            "Service-account token automount default",
            "automountServiceAccountToken",
            False,
            description="Policy-specific check of an explicit service-account default. Workload overrides and projected tokens are separate; omitted evidence remains unknown.",
            policy=True,
        )
    )
    return tuple(rules)


_RULES = _build_rules() + build_alicloud_rules()
_RULES_BY_ID = MappingProxyType({rule.definition.id: rule for rule in _RULES})
if len(_RULES_BY_ID) != len(_RULES):  # pragma: no cover - invariant at import time
    raise RuntimeError("Duplicate check identifiers")


def list_checks() -> list[CheckDefinition]:
    """Return independent copies so callers cannot mutate the registry."""
    return [rule.definition.model_copy(deep=True) for rule in _RULES]


def evaluate(
    records: Iterable[ResourceRecord], check_ids: list[str] | None = None
) -> list[CheckResult]:
    """Evaluate selected rules on matching kinds, with no network or filesystem I/O.

    Unknown identifiers are rejected even for empty input. Explicit [] evaluates
    no checks. Nonmatching kinds generate no result; caller coverage must account
    for missing resources. Runtime/API shape errors become unknown rather than a
    pass, and their arbitrary error text is never included in findings.
    """
    if check_ids is None:
        selected = _RULES
    else:
        unknown = sorted(set(check_ids) - _RULES_BY_ID.keys())
        if unknown:
            raise ValueError("Unknown check IDs: " + ", ".join(unknown))
        selected = tuple(_RULES_BY_ID[id_] for id_ in dict.fromkeys(check_ids))
    by_kind: dict[str, list[_Rule]] = {}
    for rule in selected:
        by_kind.setdefault(rule.definition.resource_kind, []).append(rule)
    results: list[CheckResult] = []
    for record in records:
        for rule in by_kind.get(record.kind, []):
            try:
                outcome = rule.predicate(record.data)
            except (_Unavailable, TypeError, ValueError, AttributeError, KeyError, OverflowError):
                outcome = _unknown(
                    summary="Required fields are missing or do not have the expected native API shape."
                )
            definition = rule.definition
            details: dict[str, Any] = {
                "rule_version": RULE_VERSION,
                "policy_specific": rule.policy_specific,
            }
            if outcome.examined is not None:
                details["examined"] = outcome.examined
            if outcome.violations is not None:
                details["violations"] = outcome.violations
            results.append(
                CheckResult(
                    check_id=definition.id,
                    resource=record.name,
                    status=outcome.status,
                    severity=definition.severity,
                    title=definition.title,
                    summary=outcome.summary,
                    evidence_paths=list(outcome.paths),
                    details=details,
                    remediation=definition.remediation,
                )
            )
    return results
