from collections import deque
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from sec_auditor.providers.alicloud import AlibabaProvider
from sec_auditor.providers.alicloud_catalog import OPERATIONS, QUERY_SPECS, required_ram_actions
from sec_auditor.transport import CloudAPIError

ACCOUNT = "1234567890123456"
REGION = "cn-hangzhou"


class FakeClient:
    def __init__(self, *responses, max_log_hours=24):
        self.responses = deque(responses)
        self.calls = []
        self.settings = SimpleNamespace(max_log_hours=max_log_hours)

    async def execute(self, account_id, operation_id, *, region=None, parameters=None):
        self.calls.append((account_id, operation_id, region, parameters))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


async def test_compute_explicit_imds_attribute_and_native_token():
    client = FakeClient(
        {
            "Instances": {
                "Instance": [{"InstanceId": "i-123", "MetadataOptions": {"HttpTokens": "required"}}]
            },
            "NextToken": "next",
            "RequestId": "request",
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.ecs.instances", ACCOUNT, location=REGION, page_size=20
    )
    assert not result.errors
    assert result.next_page_token == "next"
    record = result.items[0]
    assert record.provider == "alicloud" and record.account_id == ACCOUNT and record.project is None
    assert record.data["MetadataOptions"]["HttpTokens"] == "required"
    assert client.calls == [
        (
            ACCOUNT,
            "ecs.DescribeInstances",
            REGION,
            {
                "RegionId": REGION,
                "AdditionalAttributes.1": "META_OPTIONS",
                "MaxResults": 20,
            },
        )
    ]


async def test_native_empty_page_preserves_continuation():
    client = FakeClient({"RequestId": "request", "NextToken": "later"})
    result = await AlibabaProvider(client).list_resources(
        "alicloud.ecs.disks", ACCOUNT, location=REGION, page_token="previous"
    )
    assert not result.errors and not result.items
    assert result.next_page_token == "later"
    assert client.calls[0][3]["NextToken"] == "previous"


async def test_nested_security_rules_keep_group_context():
    client = FakeClient(
        {
            "Permissions": {
                "Permission": [
                    {
                        "SecurityGroupRuleId": "sgr-123",
                        "Direction": "ingress",
                        "SourceCidrIp": "0.0.0.0/0",
                        "PortRange": "22/22",
                    }
                ]
            },
            "NextToken": "more",
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.ecs.securityGroupRules", ACCOUNT, location=REGION, parent="sg-123"
    )
    assert result.items[0].data["SecurityGroupId"] == "sg-123"
    assert "/sg-123/" in result.items[0].name
    assert client.calls[0][3]["SecurityGroupId"] == "sg-123"
    assert result.next_page_token == "more"


async def test_page_number_flow_logs_accept_documented_string_counts():
    client = FakeClient(
        {
            "PageNumber": "1",
            "PageSize": "20",
            "TotalCount": "21",
            "Success": "true",
            "FlowLogs": {"FlowLog": [{"FlowLogId": "fl-1", "Status": "Active"}]},
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.vpc.flowLogs", ACCOUNT, location=REGION, page_size=20
    )
    assert result.next_page_token == "page:2"
    assert client.calls[0][3] == {"RegionId": REGION, "PageNumber": 1, "PageSize": 20}


async def test_numeric_pagination_uses_upstream_reported_size_when_clamped():
    client = FakeClient(
        {"Vpcs": {"Vpc": [{"VpcId": "vpc-1"}]}, "PageSize": 10, "PageNumber": 1, "TotalCount": 15}
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.vpc.vpcs", ACCOUNT, location=REGION, page_size=20
    )
    assert result.next_page_token == "page:2"


async def test_numeric_pagination_detects_ignored_page_number():
    client = FakeClient(
        {"Vpcs": {"Vpc": [{"VpcId": "vpc-1"}]}, "PageSize": 10, "PageNumber": 1, "TotalCount": 15}
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.vpc.vpcs", ACCOUNT, location=REGION, page_size=10, page_token="page:2"
    )
    assert result.errors[0].code == "PAGINATION_STALLED"


async def test_marker_requires_explicit_truncation_and_preserves_page():
    client = FakeClient(
        {"Roles": {"Role": [{"RoleName": "auditor"}]}, "IsTruncated": True, "Marker": "m2"}
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.ram.roles", ACCOUNT, page_size=20, page_token="m1"
    )
    assert result.next_page_token == "m2"
    assert client.calls[0][3] == {"MaxItems": 20, "Marker": "m1"}


@pytest.mark.parametrize(
    "body",
    [
        {"Users": {"User": []}, "IsTruncated": True},
        {"Users": {"User": []}, "IsTruncated": "yes", "Marker": "m2"},
    ],
)
async def test_invalid_marker_metadata_is_incomplete(body):
    result = await AlibabaProvider(FakeClient(body)).list_resources("alicloud.ram.users", ACCOUNT)
    assert result.errors[0].code == "INVALID_RESPONSE"


async def test_ack_roa_and_nested_page_info():
    client = FakeClient(
        {
            "clusters": [{"cluster_id": "c123", "region_id": REGION}],
            "page_info": {"page_number": 2, "page_size": 20, "total_count": 41},
        }
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.cs.clusters", ACCOUNT, location=REGION, page_size=20, page_token="page:2"
    )
    assert result.next_page_token == "page:3"
    assert client.calls[0][3] == {"region_id": REGION, "page_number": 2, "page_size": 20}
    op = OPERATIONS["cs.DescribeClustersV1"]
    assert op.style == "ROA" and op.path == "/api/v1/clusters"


async def test_exact_ack_cluster_and_unpaged_nodepools():
    client = FakeClient(
        {"cluster_id": "c123", "deletion_protection": True},
        {
            "nodepools": [
                {"nodepool_info": {"nodepool_id": "np2"}},
                {"nodepool_info": {"nodepool_id": "np1"}},
            ]
        },
    )
    provider = AlibabaProvider(client)
    result = await provider.query_resources(
        "alicloud.cs.clusters", ACCOUNT, location=REGION, resource_id="c123", operation="get"
    )
    assert result.items[0].data["deletion_protection"] is True
    result = await provider.query_resources(
        "alicloud.cs.nodePools", ACCOUNT, location=REGION, parent="c123", page_size=1
    )
    assert result.items[0].data["nodepool_info"]["nodepool_id"] == "np1"
    assert result.next_page_token == "offset:1"
    assert result.metadata["pagination_consistency"] == "best_effort"


async def test_policy_decodes_url_encoded_json_and_preserves_plain_percent_values():
    document = '{"Statement":[{"Effect":"Allow","Action":"ecs:Describe*","Condition":{"StringEquals":{"key":"foo%2Fbar"}}}]}'
    client = FakeClient(
        {"Role": {"RoleName": "a", "AssumeRolePolicyDocument": quote(document)}},
        {"Role": {"RoleName": "a", "AssumeRolePolicyDocument": document}},
    )
    provider = AlibabaProvider(client)
    for _ in range(2):
        result = await provider.query_resources(
            "alicloud.ram.roles", ACCOUNT, resource_id="a", operation="get"
        )
        assert (
            result.items[0].data["AssumeRolePolicyDocument"]["Statement"][0]["Condition"][
                "StringEquals"
            ]["key"]
            == "foo%2Fbar"
        )


async def test_policy_get_preserves_default_version_and_requires_type():
    client = FakeClient(
        {
            "Policy": {"PolicyName": "audit"},
            "DefaultPolicyVersion": {"PolicyDocument": '{"Statement":[]}'},
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.ram.policies",
        ACCOUNT,
        operation="get",
        resource_id="audit",
        selectors={"policy_type": "Custom"},
    )
    assert result.items[0].data["DefaultPolicyVersion"]["PolicyDocument"] == {"Statement": []}
    assert client.calls[0][3] == {"PolicyName": "audit", "PolicyType": "Custom"}


async def test_login_profile_has_only_metadata_api():
    client = FakeClient(
        {
            "LoginProfile": {
                "UserName": "auditor",
                "MFABindRequired": True,
                "PasswordResetRequired": False,
            }
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.ram.loginProfiles", ACCOUNT, operation="get", resource_id="auditor"
    )
    assert result.items[0].data["MFABindRequired"] is True
    assert client.calls[0][1] == "ram.GetLoginProfile"


async def test_oss_empty_regional_page_retains_account_marker():
    client = FakeClient({"Buckets": [], "IsTruncated": True, "NextMarker": "bucket-before-next"})
    result = await AlibabaProvider(client).list_resources(
        "alicloud.oss.buckets", ACCOUNT, location=REGION
    )
    assert result.items == [] and result.next_page_token == "bucket-before-next"
    assert client.calls[0][3] == {"MaxKeys": 100}


async def test_oss_bucket_get_uses_only_named_metadata_operation():
    client = FakeClient({"AccessControlList": {"Grant": "private"}})
    result = await AlibabaProvider(client).query_resources(
        "alicloud.oss.bucketAcl",
        ACCOUNT,
        location=REGION,
        resource_id="audit-bucket",
        operation="get",
    )
    assert result.items[0].data["AccessControlList"]["Grant"] == "private"
    assert client.calls[0][1:] == ("oss.GetBucketAcl", REGION, {"BucketName": "audit-bucket"})
    assert "oss:GetBucketInfo" in QUERY_SPECS[("alicloud.oss.bucketAcl", "get")].permissions


async def test_cloud_config_nested_native_token_and_inventory_freshness():
    client = FakeClient(
        {
            "DiscoveredResourceProfiles": {
                "DiscoveredResourceProfileList": [{"ResourceId": "i-1"}],
                "NextToken": "next",
            }
        }
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.config.resources", ACCOUNT, location="cn-shanghai"
    )
    assert result.next_page_token == "next"
    assert result.items[0].freshness == "inventory"


async def test_cloud_config_nested_total_count():
    client = FakeClient(
        {
            "ConfigRules": {
                "ConfigRuleList": [{"ConfigRuleId": "cr-1"}],
                "PageNumber": 1,
                "PageSize": 10,
                "TotalCount": 11,
            }
        }
    )
    result = await AlibabaProvider(client).list_resources(
        "alicloud.config.rules", ACCOUNT, location="ap-southeast-1", page_size=10
    )
    assert result.next_page_token == "page:2"


async def test_rds_database_allowlist_is_configuration():
    client = FakeClient(
        {
            "Items": {
                "DBInstanceIPArray": [
                    {"DBInstanceIPArrayName": "default", "SecurityIPList": "0.0.0.0/0"}
                ]
            }
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.rds.ipAllowlists", ACCOUNT, location=REGION, resource_id="rm-123", operation="get"
    )
    assert result.items[0].data["DBInstanceId"] == "rm-123"
    assert result.items[0].data["SecurityIPList"] == "0.0.0.0/0"


async def test_actiontrail_bounded_window_normalized_to_utc():
    client = FakeClient(
        {"Events": [{"eventId": "e-1", "eventName": "DescribeInstances"}], "NextToken": "later"}
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.actiontrail.events",
        ACCOUNT,
        location=REGION,
        selectors={
            "start_time": "2026-01-01T08:00:00+08:00",
            "end_time": "2026-01-01T09:00:00+08:00",
        },
    )
    assert result.next_page_token == "later"
    assert client.calls[0][3] == {
        "Direction": "BACKWARD",
        "StartTime": "2026-01-01T00:00:00Z",
        "EndTime": "2026-01-01T01:00:00Z",
        "MaxResults": 50,
    }
    assert result.metadata["category"] == "audit"


@pytest.mark.parametrize(
    "selectors",
    [
        {},
        {"start_time": "2026-01-01T00:00:00Z"},
        {"start_time": "2026-01-01T00:00:00", "end_time": "2026-01-01T01:00:00"},
        {"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-03T01:00:00Z"},
        {"start_time": "2026-01-01T01:00:00Z", "end_time": "2026-01-01T00:00:00Z"},
        {"start_time": "9999-01-01T00:00:00Z", "end_time": "9999-01-01T01:00:00Z"},
        {"start_time": "invalid", "end_time": "2026-01-01T01:00:00Z"},
    ],
)
async def test_actiontrail_rejects_missing_invalid_or_unbounded_window(selectors):
    client = FakeClient()
    with pytest.raises(ValueError):
        await AlibabaProvider(client).query_resources(
            "alicloud.actiontrail.events", ACCOUNT, location=REGION, selectors=selectors
        )
    assert not client.calls


async def test_collect_resources_cannot_bypass_configured_log_window():
    client = FakeClient(max_log_hours=1)
    with pytest.raises(ValueError, match="at most 1 hours"):
        await AlibabaProvider(client).query_resources(
            "alicloud.actiontrail.events",
            ACCOUNT,
            location=REGION,
            selectors={"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T02:00:00Z"},
        )
    assert not client.calls


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kind": "alicloud.ecs.DeleteInstance"},
        {"kind": "alicloud.oss.objects"},
        {"operation": "delete"},
        {"account_id": "../../123456"},
        {"location": "cn-hangzhou.attacker.example"},
        {"location": None},
        {"selectors": {"OwnerId": "1234567890123457"}},
        {"selectors": {"endpoint": "https://attacker.example"}},
        {"selectors": {"vpc_id": "../other"}},
        {"parent": "sg-1"},
        {"resource_id": "i-1"},
        {"page_size": 0},
        {"page_size": True},
        {"page_token": "bad\nnext"},
    ],
)
async def test_invalid_query_is_rejected_before_any_call(kwargs):
    client = FakeClient()
    request = {"kind": "alicloud.ecs.instances", "account_id": ACCOUNT, "location": REGION}
    request.update(kwargs)
    with pytest.raises(ValueError):
        await AlibabaProvider(client).query_resources(**request)
    assert not client.calls


@pytest.mark.parametrize(
    "kind,operation,kwargs",
    [
        ("alicloud.ram.roles", "get", {"resource_id": "../../other"}),
        ("alicloud.ram.roles", "list", {"location": REGION}),
        (
            "alicloud.ram.policies",
            "get",
            {"resource_id": "a", "selectors": {"policy_type": "Administrator"}},
        ),
        ("alicloud.cs.nodePools", "list", {"parent": "c123/exec", "location": REGION}),
        ("alicloud.config.rules", "list", {"location": "us-east-1"}),
        (
            "alicloud.slb.httpsListeners",
            "get",
            {"location": REGION, "parent": "lb-1", "selectors": {"port": "65536"}},
        ),
        ("alicloud.oss.bucketAcl", "get", {"location": REGION, "resource_id": "Bucket-UPPER"}),
    ],
)
async def test_specific_selector_contracts(kind, operation, kwargs):
    client = FakeClient()
    with pytest.raises(ValueError):
        await AlibabaProvider(client).query_resources(kind, ACCOUNT, operation=operation, **kwargs)
    assert not client.calls


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"Instances": {"Instance": "bad"}},
        {"Instances": {"Instance": ["bad"]}},
        {"Instances": {"Instance": []}, "NextToken": 123},
        {"Instances": {"Instance": []}, "NextToken": "previous"},
        {"Success": False, "Message": "sensitive upstream explanation"},
    ],
)
async def test_invalid_or_failed_upstream_response_is_explicit(body):
    result = await AlibabaProvider(FakeClient(body)).list_resources(
        "alicloud.ecs.instances", ACCOUNT, location=REGION, page_token="previous"
    )
    assert result.errors and not result.items and not result.next_page_token
    assert "sensitive upstream" not in result.errors[0].message


@pytest.mark.parametrize(
    "body",
    [
        {"Vpcs": {"Vpc": []}, "TotalCount": 11},
        {"Vpcs": {"Vpc": []}, "TotalCount": "bad"},
        {"Vpcs": {"Vpc": []}, "TotalCount": True},
        {"Vpcs": {"Vpc": []}},
    ],
)
async def test_invalid_page_metadata_cannot_claim_complete(body):
    result = await AlibabaProvider(FakeClient(body)).list_resources(
        "alicloud.vpc.vpcs", ACCOUNT, location=REGION, page_size=10
    )
    assert result.errors


async def test_permission_denied_retains_target_and_retryability():
    result = await AlibabaProvider(
        FakeClient(CloudAPIError("PERMISSION_DENIED", "Read denied", retryable=False))
    ).list_resources("alicloud.ecs.instances", ACCOUNT, location=REGION)
    assert result.errors[0].code == "PERMISSION_DENIED"
    assert ACCOUNT in result.errors[0].target and REGION in result.errors[0].target
    assert not result.errors[0].retryable


def test_capabilities_describe_query_requirements_and_precise_ram_actions():
    caps = AlibabaProvider(FakeClient()).capabilities()
    rules = next(c for c in caps if c["kind"] == "alicloud.ecs.securityGroupRules")
    assert rules["parent_required"] and rules["location_required"] and not rules["default_scan"]
    events = next(c for c in caps if c["kind"] == "alicloud.actiontrail.events")
    assert events["required_selectors"] == ["start_time", "end_time"]
    assert "cr:ListRepositoryTag" in required_ram_actions()
    assert "cr:GetScan" in required_ram_actions()
    assert "cs:DescribeClusterDetail" in required_ram_actions()
    assert not any(
        any(
            verb in action
            for verb in (
                "GetObject",
                "GetSecretValue",
                "Decrypt",
                "Create",
                "Update",
                "Delete",
                "Kubeconfig",
            )
        )
        for action in required_ram_actions()
    )


def test_catalog_does_not_allow_owner_credentials_or_mutation_parameters():
    prohibited = {
        "OwnerId",
        "ResourceOwnerId",
        "OwnerAccount",
        "ResourceOwnerAccount",
        "Password",
        "Secret",
        "AccessKeySecret",
        "Command",
        "UserData",
        "DryRun",
    }
    for op in OPERATIONS.values():
        assert not prohibited.intersection(op.parameters)
        assert op.action.startswith(("List", "Get", "Describe", "Lookup"))
        assert op.method == "GET"
    with pytest.raises(TypeError):
        OPERATIONS["ecs.DeleteInstance"] = None


def test_native_tls_action_that_returns_postgresql_private_key_is_excluded():
    assert "rds.DescribeDBInstanceSSL" not in OPERATIONS
    assert "rds:DescribeDBInstanceSSL" not in required_ram_actions()
    assert ("alicloud.rds.tls", "get") not in QUERY_SPECS


async def test_ack_bootstrap_passwords_and_opaque_config_are_removed_before_output():
    client = FakeClient(
        {
            "nodepools": [
                {
                    "nodepool_info": {"nodepool_id": "np1"},
                    "scaling_group": {
                        "login_password": "secret-password",
                        "system_disk_encrypted": True,
                    },
                    "kubernetes_config": {
                        "user_data": "secret-script",
                        "pre_user_data": "secret-before",
                        "runtime": "containerd",
                    },
                    "node_components": [{"config": {"custom_config": {"hidden": "secret-custom"}}}],
                    "node_config": {"kubelet_configuration": "opaque-secret-config"},
                }
            ]
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.cs.nodePools", ACCOUNT, location=REGION, parent="c1"
    )
    serialized = result.model_dump_json()
    for value in (
        "secret-password",
        "secret-script",
        "secret-before",
        "secret-custom",
        "opaque-secret-config",
    ):
        assert value not in serialized
    assert result.items[0].data["scaling_group"]["system_disk_encrypted"] is True
    assert result.items[0].data["kubernetes_config"]["runtime"] == "containerd"
    assert result.metadata["provider_removed_fields"] == 5


async def test_ack_cluster_encoded_metadata_and_ros_parameters_removed():
    client = FakeClient(
        {
            "cluster_id": "c1",
            "meta_data": '{"password":"secret"}',
            "parameters": {"something": "secret"},
            "rrsa_config": {"enabled": True},
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.cs.clusters", ACCOUNT, location=REGION, operation="get", resource_id="c1"
    )
    assert "secret" not in result.model_dump_json()
    assert result.items[0].data["rrsa_config"]["enabled"] is True


async def test_security_center_findings_strip_captured_payloads_but_keep_cves():
    client = FakeClient(
        {
            "TotalCount": 1,
            "VulRecords": [
                {
                    "Name": "openssl-vulnerability",
                    "InstanceId": "i-1",
                    "Necessity": "asap",
                    "ResultMessage": "captured-secret",
                    "ExtendContentJson": {
                        "EmgProof": "exploit-secret",
                        "cveList": ["CVE-2026-12345", "secret-token"],
                    },
                    "UnexpectedPayload": {"credential": "unknown-secret"},
                }
            ],
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.sas.vulnerabilities",
        ACCOUNT,
        location="cn-shanghai",
        selectors={"vulnerability_type": "cve"},
    )
    assert "secret" not in result.model_dump_json()
    assert result.items[0].data["CveIds"] == ["CVE-2026-12345"]
    assert result.items[0].data["InstanceId"] == "i-1"


async def test_registry_vulnerability_evidence_does_not_return_fix_command_or_opaque_locations():
    client = FakeClient(
        {
            "TotalCount": 1,
            "IsSuccess": True,
            "Vulnerabilities": [
                {
                    "CveName": "CVE-2026-12345",
                    "Severity": "High",
                    "Feature": "openssl",
                    "VersionFixed": "4.0",
                    "FixCmd": "command-with-secret",
                    "CveLocation": "file-contents-secret",
                    "AddedBy": "dockerfile-secret",
                }
            ],
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.cr.vulnerabilities",
        ACCOUNT,
        location=REGION,
        parent="cri-1",
        selectors={"repository_id": "crr-1", "tag": "latest"},
    )
    assert "secret" not in result.model_dump_json()
    assert result.items[0].data["VersionFixed"] == "4.0"


async def test_cloud_config_annotation_is_omitted_but_status_and_resource_retained():
    client = FakeClient(
        {
            "EvaluationResults": {
                "EvaluationResultList": [
                    {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "captured-secret",
                        "EvaluationResultIdentifier": {
                            "EvaluationResultQualifier": {"ResourceId": "i-1"}
                        },
                    }
                ]
            }
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.config.evaluations", ACCOUNT, location="cn-shanghai", parent="cr-1"
    )
    assert "captured-secret" not in result.model_dump_json()
    assert result.items[0].data["ComplianceType"] == "NON_COMPLIANT"


async def test_multiple_rds_ip_arrays_have_distinct_evidence_names():
    client = FakeClient(
        {
            "Items": {
                "DBInstanceIPArray": [
                    {"DBInstanceIPArrayName": "default", "SecurityIPList": "0.0.0.0/0"},
                    {"DBInstanceIPArrayName": "office", "SecurityIPList": "192.0.2.0/24"},
                ]
            }
        }
    )
    result = await AlibabaProvider(client).query_resources(
        "alicloud.rds.ipAllowlists", ACCOUNT, location=REGION, operation="get", resource_id="rm-1"
    )
    assert len({record.name for record in result.items}) == 2


async def test_nested_registry_report_names_include_repository_tag_and_package():
    body = {
        "TotalCount": 2,
        "Vulnerabilities": [
            {"CveName": "CVE-2026-12345", "Feature": "package-a", "Version": "1"},
            {"CveName": "CVE-2026-12345", "Feature": "package-b", "Version": "1"},
        ],
    }
    provider = AlibabaProvider(FakeClient(body, body))
    first = await provider.query_resources(
        "alicloud.cr.vulnerabilities",
        ACCOUNT,
        location=REGION,
        parent="cri-1",
        selectors={"repository_id": "repo-a", "tag": "stable"},
    )
    second = await provider.query_resources(
        "alicloud.cr.vulnerabilities",
        ACCOUNT,
        location=REGION,
        parent="cri-1",
        selectors={"repository_id": "repo-b", "tag": "stable"},
    )
    assert len({record.name for record in first.items + second.items}) == 4
    assert first.items[0].data["queryContext"]["selectors"]["repository_id"] == "repo-a"
