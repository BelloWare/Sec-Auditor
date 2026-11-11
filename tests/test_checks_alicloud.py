"""Security meanings and conservative failure modes of Alibaba predicates."""

import pytest

from sec_auditor.checks import evaluate, list_checks
from sec_auditor.models import ResourceRecord

CASES = [
    (
        "ecs.instance.metadata_tokens",
        "ecs.instances",
        {
            "OSType": "linux",
            "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"},
        },
        {
            "OSType": "linux",
            "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "optional"},
        },
    ),
    (
        "ecs.instance.no_public_ip",
        "ecs.instances",
        {"PublicIpAddress": {"IpAddress": []}, "EipAddress": {"IpAddress": ""}},
        {"PublicIpAddress": {"IpAddress": ["203.0.113.5"]}},
    ),
    (
        "ecs.instance.deletion_protection",
        "ecs.instances",
        {"DeletionProtection": True},
        {"DeletionProtection": False},
    ),
    (
        "ecs.instance.secure_boot",
        "ecs.instances",
        {"SecurityOptions": {"EnableSecureBoot": True}},
        {"SecurityOptions": {"EnableSecureBoot": False}},
    ),
    ("ecs.disk.encryption", "ecs.disks", {"Encrypted": True}, {"Encrypted": False}),
    (
        "ram.password.minimum_length",
        "ram.passwordPolicy",
        {"MinimumPasswordLength": 14},
        {"MinimumPasswordLength": 8},
    ),
    (
        "ram.login.mfa_binding",
        "ram.loginProfiles",
        {"MFABindRequired": True},
        {"MFABindRequired": False},
    ),
    (
        "oss.bucket.private_acl",
        "oss.bucketAcl",
        {"AccessControlList": {"Grant": "private"}},
        {"AccessControlList": {"Grant": "public-read"}},
    ),
    (
        "oss.bucket.public_access_block",
        "oss.bucketPublicAccessBlock",
        {"BlockPublicAccess": "true"},
        {"BlockPublicAccess": "false"},
    ),
    (
        "oss.bucket.default_encryption",
        "oss.bucketEncryption",
        {"Rule": {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "KMS"}}},
        {"Rule": {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": ""}}},
    ),
    (
        "oss.bucket.versioning",
        "oss.bucketVersioning",
        {"Status": "Enabled"},
        {"Status": "Suspended"},
    ),
    (
        "oss.bucket.access_logging",
        "oss.bucketLogging",
        {"LoggingEnabled": {"TargetBucket": "audit"}},
        {"LoggingEnabled": {"TargetBucket": ""}},
    ),
    ("vpc.flow_log.active", "vpc.flowLogs", {"Status": "Active"}, {"Status": "Inactive"}),
    (
        "vpc.flow_log.delivery",
        "vpc.flowLogs",
        {"FlowLogDeliverStatus": "SUCCESS"},
        {"FlowLogDeliverStatus": "FAILED"},
    ),
    (
        "rds.allowlist.no_public_cidr",
        "rds.ipAllowlists",
        {"SecurityIPList": "10.0.0.0/8,192.0.2.5"},
        {"SecurityIPList": "10.0.0.0/8,::/0"},
    ),
    ("rds.encryption.tde", "rds.encryption", {"TDEStatus": "Enabled"}, {"TDEStatus": "Disabled"}),
    (
        "rds.backup.retention",
        "rds.backupPolicy",
        {"BackupRetentionPeriod": 7},
        {"BackupRetentionPeriod": 1},
    ),
    (
        "kms.key.deletion_protection",
        "kms.keys",
        {"DeletionProtection": "Enabled"},
        {"DeletionProtection": "Disabled"},
    ),
    (
        "kms.key.rotation",
        "kms.keys",
        {"AutomaticRotation": "Enabled"},
        {"AutomaticRotation": "Disabled"},
    ),
]


def check(identifier, kind, data):
    record = ResourceRecord(
        provider="alicloud",
        account_id="1234567890123456",
        kind="alicloud." + kind,
        name="safe-reference",
        data=data,
    )
    return evaluate([record], ["alicloud." + identifier])[0]


@pytest.mark.parametrize("identifier,kind,good,bad", CASES)
def test_documented_configuration_criteria(identifier, kind, good, bad):
    assert check(identifier, kind, good).status == "pass"
    assert check(identifier, kind, bad).status == "fail"
    assert check(identifier, kind, {}).status == "unknown"


@pytest.mark.parametrize(
    "protocol,ports,source,expected",
    [
        ("tcp", "1/65535", "0.0.0.0/0", "fail"),
        ("tcp", "22/22", "::/0", "fail"),
        ("tcp", "23/65535", "0.0.0.0/0", "pass"),
        ("all", "-1/-1", "::/0", "fail"),
        ("tcp", "22/22", "10.0.0.0/8", "pass"),
        ("udp", "22/22", "0.0.0.0/0", "not_applicable"),
        ("tcp", "65536/65537", "0.0.0.0/0", "unknown"),
        ("tcp", "22/22", "not-a-cidr", "unknown"),
    ],
)
def test_sg_rules_are_protocol_and_range_aware(protocol, ports, source, expected):
    data = {
        "Direction": "ingress",
        "Policy": "Accept",
        "IpProtocol": protocol,
        "PortRange": ports,
        "SourceCidrIp": source,
    }
    assert check("ecs.rule.no_public_ssh", "ecs.securityGroupRules", data).status == expected
    data["Direction"] = "egress"
    assert (
        check("ecs.rule.no_public_ssh", "ecs.securityGroupRules", data).status == "not_applicable"
    )


def test_rdp_has_its_own_port_and_never_inferrs_effective_reachability():
    data = {
        "Direction": "ingress",
        "Policy": "Accept",
        "IpProtocol": "tcp",
        "PortRange": "3389/3389",
        "SourceCidrIp": "0.0.0.0/0",
    }
    assert check("ecs.rule.no_public_rdp", "ecs.securityGroupRules", data).status == "fail"
    assert check("ecs.rule.no_public_ssh", "ecs.securityGroupRules", data).status == "pass"
    data["Policy"] = "Drop"
    assert (
        check("ecs.rule.no_public_rdp", "ecs.securityGroupRules", data).status == "not_applicable"
    )


def test_provider_modes_do_not_create_false_passes():
    assert (
        check("ecs.instance.metadata_tokens", "ecs.instances", {"OSType": "windows"}).status
        == "not_applicable"
    )
    assert (
        check(
            "ecs.instance.metadata_tokens",
            "ecs.instances",
            {"MetadataOptions": {"HttpEndpoint": "disabled"}},
        ).status
        == "pass"
    )
    assert (
        check(
            "ecs.instance.no_public_ip", "ecs.instances", {"PublicIpAddress": {"IpAddress": []}}
        ).status
        == "unknown"
    )
    assert (
        check(
            "rds.backup.retention",
            "rds.backupPolicy",
            {"AdvancedBackupPolicyEnabled": True, "BackupRetentionPeriod": 7},
        ).status
        == "unknown"
    )
    assert check("kms.key.rotation", "kms.keys", {"KeySpec": "RSA_2048"}).status == "not_applicable"
    assert check("kms.key.rotation", "kms.keys", {"Origin": "EXTERNAL"}).status == "not_applicable"
    assert check("ecs.disk.encryption", "ecs.disks", {"Encrypted": "true"}).status == "unknown"


def test_every_alibaba_rule_is_covered_and_emits_only_fixed_explanations():
    definitions = [row for row in list_checks() if row.id.startswith("alicloud.")]
    identifiers = {"alicloud." + row[0] for row in CASES} | {
        "alicloud.ecs.rule.no_public_ssh",
        "alicloud.ecs.rule.no_public_rdp",
    }
    assert {row.id for row in definitions} == identifiers
    for definition in definitions:
        record = ResourceRecord(
            provider="alicloud",
            kind=definition.resource_kind,
            name="safe-reference",
            data={"Password": "PRIVATE-SECRET-FIXTURE"},
        )
        result = evaluate([record], [definition.id])[0]
        assert result.status == "unknown"
        assert "PRIVATE-" not in result.model_dump_json()
