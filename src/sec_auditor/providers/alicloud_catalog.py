"""Reviewed Alibaba Cloud configuration reads, never a general OpenAPI proxy.

Action versions, parameter spellings, response paths and RAM actions were checked
against Alibaba Cloud's published OpenAPI schemas. The registry is compiled into
the service; caller input cannot add an action, endpoint or request parameter.
"""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal


@dataclass(frozen=True)
class AliOperation:
    id: str
    service: str
    version: str
    action: str
    endpoint: str
    parameters: tuple[str, ...] = ()
    region_required: bool = True
    style: str = "RPC"
    method: str = "GET"
    path: str = "/"
    path_parameters: tuple[str, ...] = ()
    endpoint_overrides: dict[str, str] = field(default_factory=dict)
    oss_method: str | None = None


@dataclass(frozen=True)
class AliResourceSpec:
    kind: str
    operation_id: str
    items_path: str | None
    name_fields: tuple[str, ...]
    permissions: tuple[str, ...]
    operation: Literal["list", "get"] = "list"
    pagination: Literal["token", "page", "marker", "client", "singleton"] = "token"
    max_page_size: int = 100
    min_page_size: int = 1
    page_parameter: str = "PageNumber"
    size_parameter: str = "MaxResults"
    token_parameter: str = "NextToken"
    token_path: str = "NextToken"
    total_path: str = "TotalCount"
    truncated_path: str = "IsTruncated"
    region_parameter: str | None = None
    selectors: tuple[tuple[str, str], ...] = ()
    required_selectors: tuple[str, ...] = ()
    resource_parameter: str | None = None
    parent_parameter: str | None = None
    fixed_parameters: tuple[tuple[str, Any], ...] = ()
    allowed_regions: tuple[str, ...] = ()
    freshness: Literal["live", "inventory"] = "live"
    default_scan: bool = True
    notes: str = ""

    def capability(self) -> dict[str, Any]:
        op = OPERATIONS[self.operation_id]
        return {
            "provider": "alicloud",
            "kind": self.kind,
            "operation": self.operation,
            "operations": [self.operation],
            "description": self.notes or f"Read {self.kind} security configuration.",
            "api_action": op.action,
            "api_version": op.version,
            "endpoint": op.endpoint,
            "permissions": list(self.permissions),
            "scope_type": "account",
            "scope_notes": "Account is the cloud-resource boundary. Regions restrict API endpoints; home-region security/inventory services may describe assets in other regions.",
            "location_required": op.region_required,
            "requires_location": op.region_required,
            "location_mode": "required" if op.region_required else "none",
            "allowed_locations": list(self.allowed_regions),
            "selectors": [key for key, _ in self.selectors],
            "required_selectors": list(self.required_selectors),
            "parent_required": self.parent_parameter is not None,
            "resource_id_required": self.resource_parameter is not None,
            "pagination": self.pagination,
            "max_page_size": self.max_page_size,
            "min_page_size": self.min_page_size,
            "freshness": self.freshness,
            "default_scan": self.default_scan
            and self.operation == "list"
            and not self.required_selectors
            and not self.parent_parameter
            and not self.resource_parameter,
            "notes": self.notes,
        }


_SERVICES = {
    "ecs": ("2014-05-26", "ecs.{region}.aliyuncs.com", True),
    "vpc": ("2016-04-28", "vpc.{region}.aliyuncs.com", True),
    "ram": ("2015-05-01", "ram.aliyuncs.com", False),
    "cs": ("2015-12-15", "cs.{region}.aliyuncs.com", True),
    "rds": ("2014-08-15", "rds.{region}.aliyuncs.com", True),
    "kms": ("2016-01-20", "kms.{region}.aliyuncs.com", True),
    "actiontrail": ("2020-07-06", "actiontrail.{region}.aliyuncs.com", True),
    "config": ("2020-09-07", "config.{region}.aliyuncs.com", True),
    "resourcemanager": ("2020-03-31", "resourcemanager.aliyuncs.com", False),
    "slb": ("2014-05-15", "slb.{region}.aliyuncs.com", True),
    "sas": ("2018-12-03", "tds.{region}.aliyuncs.com", True),
    "cr": ("2018-12-01", "cr.{region}.aliyuncs.com", True),
    "oss": ("2006-03-01", "oss-{region}.aliyuncs.com", True),
}
_operations: dict[str, AliOperation] = {
    "sts.identity": AliOperation(
        "sts.identity",
        "sts",
        "2015-04-01",
        "GetCallerIdentity",
        "sts.aliyuncs.com",
        region_required=False,
    )
}
_specs: list[AliResourceSpec] = []


def _add(
    service: str,
    collection: str,
    action: str,
    items: str | None,
    names: tuple[str, ...],
    *,
    permission: str | None = None,
    operation: Literal["list", "get"] = "list",
    pagination: Literal["token", "page", "marker", "client", "singleton"] = "token",
    region_parameter: str | None = None,
    selectors: tuple[tuple[str, str], ...] = (),
    required: tuple[str, ...] = (),
    resource: str | None = None,
    parent: str | None = None,
    fixed: tuple[tuple[str, Any], ...] = (),
    max_page_size: int = 100,
    min_page_size: int = 1,
    size: str | None = None,
    page: str = "PageNumber",
    token: str = "NextToken",
    token_path: str = "NextToken",
    total: str = "TotalCount",
    truncated: str = "IsTruncated",
    path: str = "/",
    allowed_regions: tuple[str, ...] = (),
    freshness: Literal["live", "inventory"] = "live",
    default_scan: bool = True,
    notes: str = "",
    oss_method: str | None = None,
) -> None:
    version, endpoint, regional = _SERVICES[service]
    operation_id = f"{service}.{action}"
    style = "OSS" if service == "oss" else "ROA" if service == "cs" else "RPC"
    size = size or {"page": "PageSize", "marker": "MaxItems"}.get(pagination, "MaxResults")
    params = [value for _, value in selectors]
    params += [key for key, _ in fixed]
    params += [value for value in (resource, parent, region_parameter) if value]
    if pagination == "token":
        params += [token, size]
    elif pagination == "page":
        params += [page, size]
    elif pagination == "marker":
        params += [token, size]
    overrides = {"cn-hangzhou": "rds.aliyuncs.com"} if service == "rds" else {}
    op = AliOperation(
        operation_id,
        service,
        version,
        action,
        endpoint,
        tuple(sorted(set(params))),
        regional,
        style=style,
        path=path,
        path_parameters=("ClusterId",) if "{ClusterId}" in path else (),
        endpoint_overrides=overrides,
        oss_method=oss_method,
    )
    if operation_id in _operations and _operations[operation_id] != op:
        raise RuntimeError(f"Conflicting compiled Alibaba operation: {operation_id}")
    _operations[operation_id] = op
    _specs.append(
        AliResourceSpec(
            kind=f"alicloud.{service}.{collection}",
            operation_id=operation_id,
            items_path=items,
            name_fields=names,
            permissions=(permission or f"{service}:{action}",)
            + (
                ("oss:GetBucketInfo",)
                if service == "oss" and resource and action != "GetBucketInfo"
                else ()
            ),
            operation=operation,
            pagination=pagination,
            max_page_size=max_page_size,
            min_page_size=min_page_size,
            page_parameter=page,
            size_parameter=size,
            token_parameter=token,
            token_path=token_path,
            total_path=total,
            truncated_path=truncated,
            region_parameter=region_parameter,
            selectors=selectors,
            required_selectors=required,
            resource_parameter=resource,
            parent_parameter=parent,
            fixed_parameters=fixed,
            allowed_regions=allowed_regions,
            freshness=freshness,
            default_scan=default_scan,
            notes=notes,
        )
    )


# Compute: no user data, console output, guest execution or instance credentials.
for _collection, _action, _items, _id in (
    ("instances", "DescribeInstances", "Instances.Instance", "InstanceId"),
    ("disks", "DescribeDisks", "Disks.Disk", "DiskId"),
    ("securityGroups", "DescribeSecurityGroups", "SecurityGroups.SecurityGroup", "SecurityGroupId"),
    (
        "networkInterfaces",
        "DescribeNetworkInterfaces",
        "NetworkInterfaceSets.NetworkInterfaceSet",
        "NetworkInterfaceId",
    ),
):
    _add(
        "ecs",
        _collection,
        _action,
        _items,
        (_id,),
        region_parameter="RegionId",
        selectors=(("instance_id", "InstanceId"),)
        if _collection == "disks"
        else (("vpc_id", "VpcId"),),
        min_page_size=10,
        fixed=(("AdditionalAttributes.1", "META_OPTIONS"),) if _collection == "instances" else (),
        notes="One region. Native token pagination; VM/disk/network configuration only. Instance queries request IMDS security metadata explicitly.",
    )
_add(
    "ecs",
    "securityGroupRules",
    "DescribeSecurityGroupAttribute",
    "Permissions.Permission",
    ("SecurityGroupRuleId",),
    parent="SecurityGroupId",
    region_parameter="RegionId",
    min_page_size=10,
    max_page_size=1000,
    notes="One security group's inbound and outbound rules; parent is its SecurityGroupId. All pages must be read before judging rule absence.",
)

# Networking and flow-log configuration. Captured flow records use the log tool.
for _collection, _action, _items, _id in (
    ("vpcs", "DescribeVpcs", "Vpcs.Vpc", "VpcId"),
    ("vswitches", "DescribeVSwitches", "VSwitches.VSwitch", "VSwitchId"),
    (
        "routeTables",
        "DescribeRouteTableList",
        "RouterTableList.RouterTableListType",
        "RouteTableId",
    ),
    ("natGateways", "DescribeNatGateways", "NatGateways.NatGateway", "NatGatewayId"),
    ("eipAddresses", "DescribeEipAddresses", "EipAddresses.EipAddress", "AllocationId"),
    ("flowLogs", "DescribeFlowLogs", "FlowLogs.FlowLog", "FlowLogId"),
    ("networkAcls", "DescribeNetworkAcls", "NetworkAcls.NetworkAcl", "NetworkAclId"),
):
    _add(
        "vpc",
        _collection,
        _action,
        _items,
        (_id,),
        pagination="page",
        region_parameter="RegionId",
        max_page_size=50,
    )
_add(
    "vpc",
    "routeEntries",
    "DescribeRouteEntryList",
    "RouteEntrys.RouteEntry",
    ("RouteEntryId",),
    parent="RouteTableId",
    region_parameter="RegionId",
    size="MaxResult",
    max_page_size=100,
)
_add(
    "vpc",
    "networkAcls",
    "DescribeNetworkAclAttributes",
    "NetworkAclAttribute",
    ("NetworkAclId",),
    operation="get",
    pagination="singleton",
    resource="NetworkAclId",
    region_parameter="RegionId",
)

# Identity: policy contents are configuration, key metadata is not key material.
for _collection, _action, _items, _id in (
    ("users", "ListUsers", "Users.User", "UserName"),
    ("roles", "ListRoles", "Roles.Role", "RoleName"),
    ("groups", "ListGroups", "Groups.Group", "GroupName"),
    ("policies", "ListPolicies", "Policies.Policy", "PolicyName"),
):
    _add(
        "ram",
        _collection,
        _action,
        _items,
        (_id,),
        pagination="marker",
        token="Marker",
        token_path="Marker",
        max_page_size=100 if _collection == "groups" else 1000,
        selectors=(("policy_type", "PolicyType"),) if _collection == "policies" else (),
    )
for _collection, _action, _items, _id, _param in (
    ("users", "GetUser", "User", "UserName", "UserName"),
    ("roles", "GetRole", "Role", "RoleName", "RoleName"),
    ("loginProfiles", "GetLoginProfile", "LoginProfile", "UserName", "UserName"),
    ("mfaDevices", "GetUserMFAInfo", "MFADevice", "SerialNumber", "UserName"),
):
    _add(
        "ram",
        _collection,
        _action,
        _items,
        (_id,),
        operation="get",
        pagination="singleton",
        resource=_param,
        notes="Explicit RAM identity required; no password, MFA seed or session credential is retrieved.",
    )
_add(
    "ram",
    "policies",
    "GetPolicy",
    None,
    ("PolicyName",),
    operation="get",
    pagination="singleton",
    resource="PolicyName",
    selectors=(("policy_type", "PolicyType"),),
    required=("policy_type",),
    notes="Policy metadata and current default policy version. policy_type must be Custom or System.",
)
_add(
    "ram",
    "policyVersions",
    "GetPolicyVersion",
    "PolicyVersion",
    ("VersionId",),
    operation="get",
    pagination="singleton",
    parent="PolicyName",
    resource="VersionId",
    selectors=(("policy_type", "PolicyType"),),
    required=("policy_type",),
)
for _collection, _action, _items, _id, _parent in (
    ("userPolicies", "ListPoliciesForUser", "Policies.Policy", "PolicyName", "UserName"),
    ("rolePolicies", "ListPoliciesForRole", "Policies.Policy", "PolicyName", "RoleName"),
    ("groupPolicies", "ListPoliciesForGroup", "Policies.Policy", "PolicyName", "GroupName"),
    ("userGroups", "ListGroupsForUser", "Groups.Group", "GroupName", "UserName"),
    ("accessKeys", "ListAccessKeys", "AccessKeys.AccessKey", "AccessKeyId", "UserName"),
):
    _add(
        "ram",
        _collection,
        _action,
        _items,
        (_id,),
        pagination="client",
        parent=_parent,
        notes="Explicit parent identity. Access-key results contain ID/status/creation metadata only; never a secret key.",
    )
_add(
    "ram",
    "groupUsers",
    "ListUsersForGroup",
    "Users.User",
    ("UserName",),
    pagination="marker",
    parent="GroupName",
    token="Marker",
    token_path="Marker",
    max_page_size=1000,
)
for _collection, _action, _items in (
    ("securityPreference", "GetSecurityPreference", "SecurityPreference"),
    ("passwordPolicy", "GetPasswordPolicy", "PasswordPolicy"),
):
    _add("ram", _collection, _action, _items, (), pagination="singleton")

# OSS metadata only; transport proves bucket ownership and region before reads.
_add(
    "oss",
    "buckets",
    "ListBuckets",
    "Buckets",
    ("Name",),
    pagination="marker",
    token="Marker",
    token_path="NextMarker",
    size="MaxKeys",
    max_page_size=1000,
    permission="oss:ListBuckets",
    oss_method="list_buckets",
    notes="Bucket metadata in the selected region. Account-wide upstream pages are filtered; an empty page can still have a continuation.",
)
for _collection, _action, _method in (
    ("buckets", "GetBucketInfo", "get_bucket_info"),
    ("bucketAcl", "GetBucketAcl", "get_bucket_acl"),
    ("bucketPolicy", "GetBucketPolicy", "get_bucket_policy"),
    ("bucketEncryption", "GetBucketEncryption", "get_bucket_encryption"),
    ("bucketVersioning", "GetBucketVersioning", "get_bucket_versioning"),
    ("bucketLogging", "GetBucketLogging", "get_bucket_logging"),
    ("bucketPublicAccessBlock", "GetBucketPublicAccessBlock", "get_bucket_public_access_block"),
):
    _add(
        "oss",
        _collection,
        _action,
        None,
        ("Name",),
        operation="get",
        pagination="singleton",
        resource="BucketName",
        oss_method=_method,
        notes="Bucket configuration only. GetBucketInfo verifies owner and region. No object listing, body, metadata, signed download URL or export.",
    )

# ACK control-plane configuration; Kubernetes objects use separately scoped RBAC.
_add(
    "cs",
    "clusters",
    "DescribeClustersV1",
    "clusters",
    ("cluster_id",),
    permission="cs:GetClusters",
    pagination="page",
    region_parameter="region_id",
    path="/api/v1/clusters",
    size="page_size",
    page="page_number",
    total="page_info.total_count",
    max_page_size=50,
    notes="ACK management-plane inventory in one region. Does not acquire kubeconfig or grant Kubernetes access.",
)
_add(
    "cs",
    "clusters",
    "DescribeClusterDetail",
    None,
    ("cluster_id",),
    permission="cs:DescribeClusterDetail",
    operation="get",
    pagination="singleton",
    resource="ClusterId",
    path="/clusters/{ClusterId}",
)
_add(
    "cs",
    "nodePools",
    "DescribeClusterNodePools",
    "nodepools",
    ("nodepool_info.nodepool_id",),
    permission="cs:DescribeClusterNodePools",
    pagination="client",
    parent="ClusterId",
    path="/clusters/{ClusterId}/nodepools",
    notes="Node-pool configuration. Bootstrap data, credentials and inline scripts are removed by the security projection.",
)

# Managed databases: configuration and protection settings, never SQL or backups.
_add(
    "rds",
    "instances",
    "DescribeDBInstances",
    "Items.DBInstance",
    ("DBInstanceId",),
    region_parameter="RegionId",
)
_add(
    "rds",
    "instances",
    "DescribeDBInstanceAttribute",
    "Items.DBInstanceAttribute",
    ("DBInstanceId",),
    operation="get",
    pagination="client",
    resource="DBInstanceId",
)
for _collection, _action, _items in (
    ("ipAllowlists", "DescribeDBInstanceIPArrayList", "Items.DBInstanceIPArray"),
    ("networkEndpoints", "DescribeDBInstanceNetInfo", "DBInstanceNetInfos.DBInstanceNetInfo"),
    ("backupPolicy", "DescribeBackupPolicy", None),
    ("encryption", "DescribeDBInstanceTDE", None),
    ("auditPolicy", "DescribeSQLCollectorPolicy", None),
):
    _names = {
        "ipAllowlists": ("DBInstanceIPArrayName",),
        "networkEndpoints": ("ConnectionString",),
    }.get(_collection, ("DBInstanceId",))
    _add(
        "rds",
        _collection,
        _action,
        _items,
        _names,
        operation="get",
        pagination="client" if _items else "singleton",
        resource="DBInstanceId",
        notes="Engine support varies. Unsupported/denied reads remain explicit coverage errors, not passes.",
    )

# KMS metadata only: key IDs, state, rotation, versions and secret metadata.
_add("kms", "keys", "ListKeys", "Keys.Key", ("KeyId",), pagination="page", max_page_size=100)
_add(
    "kms",
    "keys",
    "DescribeKey",
    "KeyMetadata",
    ("KeyId",),
    operation="get",
    pagination="singleton",
    resource="KeyId",
)
_add(
    "kms",
    "keyVersions",
    "ListKeyVersions",
    "KeyVersions.KeyVersion",
    ("KeyVersionId",),
    pagination="page",
    parent="KeyId",
    max_page_size=100,
)
_add(
    "kms",
    "secretMetadata",
    "ListSecrets",
    "SecretList.Secret",
    ("SecretName",),
    pagination="page",
    max_page_size=100,
    notes="Secret names, type and rotation metadata only; GetSecretValue is never allowed.",
)

# Audit trails and bounded management events. No create/start/stop operations.
_add(
    "actiontrail",
    "trails",
    "DescribeTrails",
    "TrailList",
    ("Name",),
    pagination="client",
    fixed=(("IncludeShadowTrails", False),),
    notes="Trail configuration in one region; combine with trailStatus for current delivery state.",
)
_add(
    "actiontrail",
    "trailStatus",
    "GetTrailStatus",
    None,
    (),
    operation="get",
    pagination="singleton",
    resource="Name",
)
_add(
    "actiontrail",
    "events",
    "LookupEvents",
    "Events",
    ("eventId",),
    max_page_size=50,
    selectors=(("start_time", "StartTime"), ("end_time", "EndTime")),
    required=("start_time", "end_time"),
    fixed=(("Direction", "BACKWARD"),),
    default_scan=False,
    notes="Explicit UTC interval of at most 24 hours. Management event attribution only; request/response bodies and opaque additional event data are removed.",
)

# Existing Cloud Config observations and evaluations; does not trigger evaluation.
_CONFIG_REGIONS = ("cn-shanghai", "ap-southeast-1")
_add(
    "config",
    "rules",
    "ListConfigRules",
    "ConfigRules.ConfigRuleList",
    ("ConfigRuleId",),
    pagination="page",
    total="ConfigRules.TotalCount",
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
    notes="Cloud Config home region is China Shanghai or international Singapore; evaluation freshness is upstream-defined.",
)
_add(
    "config",
    "rules",
    "GetConfigRule",
    "ConfigRule",
    ("ConfigRuleId",),
    operation="get",
    pagination="singleton",
    resource="ConfigRuleId",
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
)
_add(
    "config",
    "evaluations",
    "ListConfigRuleEvaluationResults",
    "EvaluationResults.EvaluationResultList",
    ("EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId",),
    parent="ConfigRuleId",
    token_path="EvaluationResults.NextToken",
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
    notes="Existing results for one rule. Does not start scans or invoke a custom function.",
)
_add(
    "config",
    "resources",
    "ListDiscoveredResources",
    "DiscoveredResourceProfiles.DiscoveredResourceProfileList",
    ("ResourceId",),
    token_path="DiscoveredResourceProfiles.NextToken",
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
    notes="Cross-service inventory metadata only; resource bodies and historical configuration snapshots are not retrieved.",
)

# Account/resource-group discovery is metadata, not authority to enter members.
_add(
    "resourcemanager",
    "resourceGroups",
    "ListResourceGroups",
    "ResourceGroups.ResourceGroup",
    ("Id",),
    pagination="page",
    max_page_size=100,
)
_add(
    "resourcemanager",
    "accounts",
    "ListAccounts",
    "Accounts.Account",
    ("AccountId",),
    pagination="page",
    max_page_size=100,
    notes="Resource Directory metadata only. Each target account still needs a separately verified credential connection.",
)

# Classic load balancer inventory and exact listener protection configuration.
_add(
    "slb",
    "loadBalancers",
    "DescribeLoadBalancers",
    "LoadBalancers.LoadBalancer",
    ("LoadBalancerId",),
    pagination="page",
    region_parameter="RegionId",
    max_page_size=100,
)
_add(
    "slb",
    "loadBalancers",
    "DescribeLoadBalancerAttribute",
    None,
    ("LoadBalancerId",),
    operation="get",
    pagination="singleton",
    resource="LoadBalancerId",
)
for _protocol in ("HTTP", "HTTPS", "TCP", "UDP"):
    _add(
        "slb",
        f"{_protocol.lower()}Listeners",
        f"DescribeLoadBalancer{_protocol}ListenerAttribute",
        None,
        (),
        operation="get",
        pagination="singleton",
        parent="LoadBalancerId",
        selectors=(("port", "ListenerPort"),),
        required=("port",),
        notes="One classic load balancer listener; reads protocol, TLS/ACL and health-check settings, never private certificate material.",
    )

# Security Center existing findings; never run commands, remediation or scans.
_add(
    "sas",
    "vulnerabilities",
    "DescribeVulList",
    "VulRecords",
    ("PrimaryId",),
    permission="yundun-sas:DescribeVulList",
    pagination="page",
    page="CurrentPage",
    max_page_size=100,
    selectors=(("vulnerability_type", "Type"),),
    required=("vulnerability_type",),
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
    default_scan=False,
    notes="Existing Security Center results. vulnerability_type must be cve, sys, cms, app, emg or sca. Use the account's Security Center home region, not an ECS instance region.",
)
_add(
    "sas",
    "riskChecks",
    "DescribeRiskCheckResult",
    "List",
    ("ItemId",),
    permission="yundun-sas:DescribeRiskCheckResult",
    pagination="page",
    page="CurrentPage",
    allowed_regions=_CONFIG_REGIONS,
    freshness="inventory",
    notes="Existing Security Center posture results only. Findings are observations, not proof that every host was scanned.",
)

# Enterprise Container Registry metadata and existing image vulnerability reports.
_add(
    "cr",
    "instances",
    "ListInstance",
    "Instances",
    ("InstanceId",),
    pagination="page",
    page="PageNo",
    max_page_size=100,
)
_add(
    "cr",
    "repositories",
    "ListRepository",
    "Repositories",
    ("RepoId",),
    parent="InstanceId",
    max_page_size=100,
)
_add(
    "cr",
    "tags",
    "ListRepoTag",
    "Images",
    ("Tag", "Digest"),
    parent="InstanceId",
    permission="cr:ListRepositoryTag",
    selectors=(("repository_id", "RepoId"),),
    required=("repository_id",),
    max_page_size=100,
    notes="Tag/digest/security metadata only; image layers and manifests are not downloaded.",
)
_add(
    "cr",
    "vulnerabilities",
    "ListRepoTagScanResult",
    "Vulnerabilities",
    ("CveName", "VulnName"),
    permission="cr:GetScan",
    pagination="page",
    page="PageNo",
    parent="InstanceId",
    selectors=(("repository_id", "RepoId"), ("tag", "Tag")),
    required=("repository_id", "tag"),
    max_page_size=100,
    freshness="inventory",
    notes="Existing scan results for one repository tag; does not start a scan.",
)

OPERATIONS = MappingProxyType(_operations)
QUERY_SPECS = MappingProxyType({(spec.kind, spec.operation): spec for spec in _specs})
RESOURCE_SPECS = MappingProxyType({spec.kind: spec for spec in _specs if spec.operation == "list"})


def capabilities() -> list[dict[str, Any]]:
    return [QUERY_SPECS[key].capability() for key in sorted(QUERY_SPECS)]


def required_ram_actions() -> list[str]:
    """Exact reviewed permissions, useful for generating a custom RAM policy."""
    return sorted({permission for spec in _specs for permission in spec.permissions})
