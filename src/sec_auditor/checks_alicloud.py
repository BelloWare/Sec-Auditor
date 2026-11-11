"""Alibaba configuration predicates over native metadata, with no API or runtime I/O."""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any

from sec_auditor.models import CheckDefinition


@dataclass(frozen=True)
class Outcome:
    status: str
    summary: str
    paths: tuple[str, ...] = ()
    examined: int | None = None
    violations: int | None = None


@dataclass(frozen=True)
class Rule:
    definition: CheckDefinition
    predicate: Callable[[dict[str, Any]], Outcome]
    policy_specific: bool = False


def get(data: dict, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def result(ok: bool | None, *paths: str) -> Outcome:
    if ok is None:
        return Outcome(
            "unknown",
            "Required native configuration evidence is missing, malformed, or uses an unsupported mode.",
            paths,
        )
    return Outcome(
        "pass" if ok else "fail",
        "The observed configuration meets this check's criterion."
        if ok
        else "The observed configuration requires review against this check's criterion.",
        paths,
    )


def boolean(data: dict, path: str, *, xml: bool = False) -> Outcome:
    value = get(data, path)
    if xml and isinstance(value, str) and value.lower() in {"true", "false"}:
        value = value.lower() == "true"
    return result(value if type(value) is bool else None, path)


def enum(data: dict, path: str, good: tuple[str, ...], bad: tuple[str, ...]) -> Outcome:
    value = get(data, path)
    return result(value in good if isinstance(value, str) and value in good + bad else None, path)


def minimum(data: dict, path: str, threshold: int) -> Outcome:
    value = get(data, path)
    return result(value >= threshold if type(value) is int and value >= 0 else None, path)


def nonempty(data: dict, path: str) -> Outcome:
    value = get(data, path)
    return result(bool(value) if isinstance(value, str) else None, path)


def metadata_mode(data: dict) -> Outcome:
    paths = ("MetadataOptions.HttpEndpoint", "MetadataOptions.HttpTokens", "OSType")
    endpoint = get(data, paths[0])
    if endpoint == "disabled":
        return result(True, *paths)
    if get(data, "OSType") == "windows":
        return Outcome(
            "not_applicable",
            "Alibaba documents hardened metadata mode as unsupported for Windows; evaluate exposure separately.",
            paths,
        )
    if endpoint != "enabled" or get(data, "OSType") != "linux":
        return result(None, *paths)
    return enum(data, paths[1], ("required",), ("optional",))


def public_ip(data: dict) -> Outcome:
    paths = ("PublicIpAddress.IpAddress", "EipAddress.IpAddress")
    public, elastic = (get(data, path) for path in paths)
    if isinstance(public, list) and any(isinstance(ip, str) and ip for ip in public):
        return result(False, *paths)
    if isinstance(elastic, str) and elastic:
        return result(False, *paths)
    if (
        not isinstance(public, list)
        or any(not isinstance(ip, str) for ip in public)
        or elastic != ""
    ):
        return result(None, *paths)
    return result(True, *paths)


def ingress_rule(data: dict, port: int) -> Outcome:
    paths = ("Direction", "Policy", "IpProtocol", "SourceCidrIp", "Ipv6SourceCidrIp", "PortRange")
    if data.get("Direction") == "egress" or data.get("Policy") == "Drop":
        return Outcome(
            "not_applicable", "This observation is not an accepting ingress rule.", paths
        )
    if data.get("Direction") != "ingress" or data.get("Policy") != "Accept":
        return result(None, *paths)
    protocol = data.get("IpProtocol")
    if protocol in {"udp", "icmp", "icmpv6", "gre"}:
        return Outcome(
            "not_applicable", "This rule does not permit the TCP protocol checked here.", paths
        )
    if protocol not in {"tcp", "all"}:
        return result(None, *paths)
    public = False
    has_source = False
    for field in paths[3:5]:
        value = data.get(field)
        if value not in (None, ""):
            if not isinstance(value, str):
                return result(None, *paths)
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return result(None, *paths)
            has_source = True
            public |= network.prefixlen == 0
    if not has_source:
        return result(None, *paths)
    if not public:
        return result(True, *paths)
    if protocol == "all":
        return result(False, *paths)
    ports = data.get("PortRange")
    if ports == "-1/-1":
        return result(False, *paths)
    if not isinstance(ports, str) or not re.fullmatch(r"[0-9]{1,5}/[0-9]{1,5}", ports):
        return result(None, *paths)
    lower, upper = (int(value) for value in ports.split("/"))
    if not 1 <= lower <= upper <= 65535:
        return result(None, *paths)
    return result(not lower <= port <= upper, *paths)


def database_allowlist(data: dict) -> Outcome:
    path = "SecurityIPList"
    value = data.get(path)
    if not isinstance(value, str):
        return result(None, path)
    for entry in value.split(","):
        if not entry.strip():
            continue
        try:
            network = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            return result(None, path)
        if network.prefixlen == 0:
            return result(False, path)
    return result(True, path)


def backup_retention(data: dict) -> Outcome:
    if data.get("AdvancedBackupPolicyEnabled") is True:
        return result(None, "AdvancedBackupPolicyEnabled", "AdvancedDataPolicies")
    return minimum(data, "BackupRetentionPeriod", 7)


def rotation(data: dict) -> Outcome:
    spec = data.get("KeySpec")
    if isinstance(spec, str) and spec.startswith(("RSA_", "EC_", "SM2_")):
        return Outcome(
            "not_applicable",
            "Automatic rotation applies to supported symmetric KMS keys.",
            ("KeySpec",),
        )
    if data.get("Origin") == "EXTERNAL":
        return Outcome(
            "not_applicable",
            "Imported key material requires a separate rotation procedure.",
            ("Origin",),
        )
    return enum(data, "AutomaticRotation", ("Enabled",), ("Disabled", "Suspended"))


def build_rules() -> tuple[Rule, ...]:
    rules = []

    def add(
        identifier: str,
        kind: str,
        title: str,
        description: str,
        predicate,
        *,
        policy: bool = False,
        severity: str = "medium",
    ):
        rules.append(
            Rule(
                CheckDefinition(
                    id="alicloud." + identifier,
                    resource_kind="alicloud." + kind,
                    title=title,
                    description=description,
                    severity=severity,
                    remediation="Review the cited native configuration and apply your approved security policy using a separate change workflow.",
                ),
                predicate,
                policy,
            )
        )

    add(
        "ecs.instance.metadata_tokens",
        "ecs.instances",
        "Hardened instance metadata",
        "Checks explicit endpoint/token settings on Linux ECS instances; disabled endpoints pass, Windows is inapplicable, missing OS/settings remain unknown.",
        metadata_mode,
    )
    add(
        "ecs.instance.no_public_ip",
        "ecs.instances",
        "ECS public-IP configuration",
        "Flags a configured public or elastic IP. It does not establish internet reachability or include every independent ENI/NAT association.",
        public_ip,
        policy=True,
    )
    add(
        "ecs.instance.deletion_protection",
        "ecs.instances",
        "ECS deletion protection",
        "Requires explicit deletion protection; use approved lifecycle exceptions for ephemeral instances.",
        partial(boolean, path="DeletionProtection"),
        policy=True,
    )
    add(
        "ecs.instance.secure_boot",
        "ecs.instances",
        "ECS Secure Boot",
        "Inspects explicit SecurityOptions.EnableSecureBoot. Unsupported or omitted capabilities remain unknown.",
        partial(boolean, path="SecurityOptions.EnableSecureBoot"),
        policy=True,
    )
    add(
        "ecs.disk.encryption",
        "ecs.disks",
        "ECS disk encryption",
        "Requires the native Encrypted flag; does not access block data or prove key custody.",
        partial(boolean, path="Encrypted"),
    )
    for name, port in (("ssh", 22), ("rdp", 3389)):
        add(
            "ecs.rule.no_public_" + name,
            "ecs.securityGroupRules",
            "Security-group public " + name.upper(),
            "Flags an individual accepting ingress rule exposing the TCP port to all IPv4 or IPv6 addresses. Other rules, priorities, targets and reachability are not evaluated.",
            partial(ingress_rule, port=port),
            severity="high",
            policy=True,
        )
    add(
        "ram.password.minimum_length",
        "ram.passwordPolicy",
        "RAM password minimum length",
        "Policy-specific minimum of 14 characters. This is a local account configuration observation, not a complete authentication policy.",
        partial(minimum, path="MinimumPasswordLength", threshold=14),
        policy=True,
    )
    add(
        "ram.login.mfa_binding",
        "ram.loginProfiles",
        "RAM login MFA binding",
        "Requires explicit MFABindRequired for this login profile. Binding requirement does not prove every session was challenged.",
        partial(boolean, path="MFABindRequired"),
        severity="high",
    )
    add(
        "oss.bucket.private_acl",
        "oss.bucketAcl",
        "OSS private bucket ACL",
        "Checks this bucket ACL only. A private ACL does not resolve RAM policies, bucket policies, object ACLs or inherited public-access controls.",
        partial(
            enum,
            path="AccessControlList.Grant",
            good=("private",),
            bad=("public-read", "public-read-write"),
        ),
        severity="high",
    )
    add(
        "oss.bucket.public_access_block",
        "oss.bucketPublicAccessBlock",
        "OSS bucket public-access block",
        "Inspects explicit local BlockPublicAccess; missing/account-level inherited settings remain unknown.",
        partial(boolean, path="BlockPublicAccess", xml=True),
        severity="high",
    )
    add(
        "oss.bucket.default_encryption",
        "oss.bucketEncryption",
        "OSS bucket default encryption",
        "Accepts AES256, KMS or SM4 as the configured default algorithm; does not inspect any existing object or prove that it was encrypted by this setting.",
        partial(
            enum,
            path="Rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm",
            good=("AES256", "KMS", "SM4"),
            bad=("",),
        ),
    )
    add(
        "oss.bucket.versioning",
        "oss.bucketVersioning",
        "OSS bucket versioning",
        "Policy-specific requirement for Enabled versioning; no object versions are read.",
        partial(enum, path="Status", good=("Enabled",), bad=("Suspended", "")),
        policy=True,
    )
    add(
        "oss.bucket.access_logging",
        "oss.bucketLogging",
        "OSS bucket access logging",
        "Checks an explicitly present log destination, without reading delivered log objects. Missing settings remain unknown.",
        partial(nonempty, path="LoggingEnabled.TargetBucket"),
        policy=True,
    )
    add(
        "vpc.flow_log.active",
        "vpc.flowLogs",
        "VPC flow-log activation",
        "Checks the state of this existing flow-log configuration; does not prove every VPC/ENI has a flow log.",
        partial(enum, path="Status", good=("Active",), bad=("Inactive",)),
    )
    add(
        "vpc.flow_log.delivery",
        "vpc.flowLogs",
        "VPC flow-log delivery",
        "Checks an explicitly reported delivery status; absent status or transitional states remain unknown.",
        partial(enum, path="FlowLogDeliverStatus", good=("SUCCESS",), bad=("FAILED",)),
    )
    add(
        "rds.allowlist.no_public_cidr",
        "rds.ipAllowlists",
        "RDS unrestricted IP range",
        "Flags all-address IPv4 or IPv6 CIDRs in one IP array. Network endpoints and additional access controls affect actual reachability.",
        database_allowlist,
        severity="high",
    )
    add(
        "rds.encryption.tde",
        "rds.encryption",
        "RDS instance TDE",
        "Checks instance-level TDEStatus; engine/database-specific behavior and other encryption layers need separate evidence.",
        partial(enum, path="TDEStatus", good=("Enabled",), bad=("Disabled",)),
        policy=True,
    )
    add(
        "rds.backup.retention",
        "rds.backupPolicy",
        "RDS backup retention",
        "Policy-specific minimum seven-day basic backup retention. Advanced policies remain unknown; this does not perform a restore or prove recovery.",
        backup_retention,
        policy=True,
    )
    add(
        "kms.key.deletion_protection",
        "kms.keys",
        "KMS deletion protection",
        "Inspects explicit key metadata; ListKeys summaries need a subsequent DescribeKey query.",
        partial(enum, path="DeletionProtection", good=("Enabled",), bad=("Disabled",)),
        policy=True,
    )
    add(
        "kms.key.rotation",
        "kms.keys",
        "KMS automatic rotation",
        "Checks explicit automatic rotation state for supported keys. Asymmetric or imported material uses separate rotation procedures.",
        rotation,
        policy=True,
    )
    return tuple(rules)
