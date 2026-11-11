# Alibaba Cloud query coverage

Alibaba Cloud is an implemented provider, selected with `provider: "alicloud"`.
The catalog currently contains **75 configuration/report query operations across
65 resource kinds and 13 services**. `capabilities` is the runtime authority for
the exact operations, required identifiers, selectors, page limits and RAM
permissions. A resource kind can offer both `list` and `get`; those are distinct
query contracts, not additional arbitrary API access.

The adapter uses official Alibaba credential and signing SDKs through the bounded
transport. It does not invoke a shell, `aliyun`, `gcloud`, a Kubernetes credential
plugin, or a caller-supplied OpenAPI action. No cloud mutation is registered.

## Scope and identity

Every read supplies one explicitly allowed numeric `account_id`. The transport
obtains the real credential account with STS `GetCallerIdentity`, and rejects a
requested account that differs from that identity. The proof is tied to the
credential generation, so a rotated credential is verified again. Listing
Resource Directory members does **not** grant access to those accounts. The
current default credential connection targets its own account; deploy another
connection/instance with an explicitly configured identity for another account.

`allowed_alicloud_regions` restricts the **API endpoint regions** that the server
may contact. The account is the cloud-resource boundary. Some security services
operate from a home region and report on assets elsewhere: Cloud Config and
Security Center use `cn-shanghai` for the China site or `ap-southeast-1` for the
international site. A finding returned through those endpoints may refer to a
resource in another region. The setting is not a promise to filter every
cross-region inventory/finding record by the asset's physical location.

RAM and Resource Manager reads are account-global and reject `location`.
Other query families require an explicit `location`; the catalog adds the API's
`RegionId`/`region_id` parameter only where that action accepts it. OSS lists use
account-wide native pagination and filter bucket metadata to the selected
region. Consequently, an empty OSS page can still have a continuation.

See [Alibaba authentication](alicloud-authentication.md) for temporary
credentials, ECS RAM roles, ACK RRSA, cross-cloud identity considerations and
the generated [custom RAM policy](../deploy/alicloud/read-policy.json). A broad
system read-only role can include reads of application data; the custom policy
enumerates only reviewed actions. Bucket-specific operations also require
`oss:GetBucketInfo` because the transport proves the bucket owner and region
before reading further metadata.

## Security questions and actual evidence

| Question family | Supported evidence | Interpretation and limits |
| --- | --- | --- |
| What accounts and resource groups exist? | Resource Manager account/resource-group lists; Cloud Config discovered resource metadata | Account listing is discovery only. Cloud Config is an existing inventory observation, not a live scan of every service. |
| Who can assume roles or hold permissions? | RAM users, roles, groups, group membership, attached policy references, exact role trust policy, current and explicit policy versions | List role metadata first, then `get` the role for its trust document. No claim to calculate all effective permissions, session policies or every cross-account condition. |
| Are human identities protected? | RAM password policy, security preferences, explicit login-profile MFA/reset flags, MFA-device metadata, access-key ID/status/creation metadata | No password, MFA seed, access-key secret or credential is returned. A missing/denied login profile is not automatically interpreted as a failure. |
| Are VMs hardened and encrypted? | ECS instance configuration including requested `META_OPTIONS`, disks, network interfaces and security groups | IMDS token enforcement, security options, disk encryption and network context are available. No guest execution, guest filesystem access, console output or VM user data. |
| What network paths and ingress rules exist? | VPCs, vSwitches, route tables and nested route entries, EIPs, NAT gateways, network ACL configuration, nested security-group rules | All pages of the relevant rules/collections are needed. An address or permissive rule alone does not prove end-to-end reachability. |
| Are load balancer listeners protected? | Classic SLB inventory/details and explicit HTTP, HTTPS, TCP and UDP listener attributes | Classic SLB is implemented. ALB/NLB and WAF/CDN-specific configuration require future reviewed adapters. Certificate private-key APIs are excluded. |
| Are buckets public, encrypted and logged? | OSS bucket metadata, ACL, policy, default encryption, versioning, access logging and public-access-block settings | Owner/region are verified before a bucket read. No object list, body, object metadata, signed download link or content export. Missing optional configuration can return an explicit upstream error; it is not silently treated as private. |
| Are ACK clusters and nodes configured securely? | Regional ACK clusters, exact cluster details and node pools | Management-plane configuration is separate from Kubernetes API access. No user kubeconfig/certificate is fetched. Bootstrap scripts, passwords and opaque configuration are removed before evidence leaves the provider. |
| Are RDS instances protected? | Instance inventory/details, IP allowlists, network endpoints, backup policy, TDE configuration and SQL-audit policy | No SQL execution, row reads, backup download or database password API. Direct TLS configuration is deliberately excluded; see below. Engine-specific unsupported reads remain coverage errors. |
| Are keys and secrets configured safely? | KMS key inventory, exact key metadata, key-version metadata and secret inventory metadata | Key state/rotation requires exact `get` after key discovery. No decrypt, cryptographic operation, private-key retrieval or secret-value read. |
| Are audit trails enabled and delivering? | ActionTrail trail configuration and exact trail status | A configured trail is different from active delivery. Query both when assessing collection health. No start/stop/create trail calls. |
| What audit events occurred? | Time-bounded ActionTrail `LookupEvents`, maximum 50 native entries per page | Management-event metadata is projected before return. The query requires explicit UTC-aware bounds, at most the configured limit and never more than 24 hours. Historical availability and event delivery are upstream constraints. |
| Are VPC flow logs configured and available? | VPC `DescribeFlowLogs` configuration/status/destination; registered SLS logstores through `query_logs` | Configuration does not prove all traffic is captured. SLS queries use operator-registered sources and bounded windows; raw SQL is not exposed. |
| What compliance and vulnerability evidence already exists? | Cloud Config rules and evaluation results, Security Center existing vulnerability/risk reports, Enterprise Container Registry repositories/tags and existing tag-scan reports | No scans or remediation are started. Captured exploit payloads, report commands and opaque result content are excluded. Findings retain upstream freshness and never prove that unobserved assets passed. |

### A deliberately excluded native API

Alibaba's `rds:DescribeDBInstanceSSL` action can return **`ServerKey`, the
PostgreSQL server certificate private key**. The catalog does not include that
action and the generated RAM policy does not grant it. The server does not fetch
a private key and then attempt to hide it. RDS TLS posture can be considered from
existing Cloud Config evaluation evidence when an appropriate rule is deployed;
this adapter does not claim a direct live TLS check for every RDS engine.

This distinction matters when extending the catalog: a method called
`Describe...` is not sufficient evidence that its response contains configuration
only. Review the full response schema and permission behavior before adding it.

## Query examples

These are arguments for `collect_resources`. They can be submitted in one batch
up to the configured batch limit; each target has its own result, cursor,
coverage and error status.

```json
{
  "queries": [
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "location": "cn-hangzhou",
      "kind": "alicloud.ecs.instances"
    },
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "location": "cn-hangzhou",
      "kind": "alicloud.ecs.securityGroupRules",
      "parent": "sg-example"
    },
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "kind": "alicloud.ram.roles",
      "operation": "get",
      "resource_id": "security-auditor"
    },
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "location": "cn-hangzhou",
      "kind": "alicloud.oss.bucketPublicAccessBlock",
      "operation": "get",
      "resource_id": "example-audit-bucket"
    },
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "location": "cn-hangzhou",
      "kind": "alicloud.slb.httpsListeners",
      "operation": "get",
      "parent": "lb-example",
      "selectors": {"port": "443"}
    }
  ]
}
```

Policy versions require the policy name as `parent`, the version as `resource_id`
and `selectors.policy_type` as `Custom` or `System`. Container Registry tag
queries require an instance ID as `parent` and
`selectors.repository_id`. Existing image vulnerability results additionally
require `selectors.tag`. These inputs are identifiers for compiled reads, not
arbitrary Alibaba API parameters.

The log tool supplies default bounds when omitted and retains the exact bounds
inside its continuation. Direct resource access to ActionTrail events requires
explicit bounds:

```json
{
  "queries": [
    {
      "provider": "alicloud",
      "account_id": "1234567890123456",
      "location": "cn-hangzhou",
      "kind": "alicloud.actiontrail.events",
      "selectors": {
        "start_time": "2026-11-10T00:00:00Z",
        "end_time": "2026-11-10T01:00:00Z"
      },
      "page_size": 50
    }
  ]
}
```

## Pagination, evidence and assessments

Native `NextToken`/`MaxResults`, RAM marker/truncation, numeric pages and ACK's
nested `page_info` are normalized to the shared opaque MCP cursor. Native tokens
never become agent-editable cloud request parameters. Cursor ownership and query
binding are enforced by the shared service. Empty native-token pages retain the
next token; repeated tokens, invalid counters and missing continuation markers
are errors. Numeric totals are observations of a changing collection, not a
transactional snapshot.

Some read APIs have no pagination, including several RAM attachments, ACK node
pools and exact RDS subresources. Those responses are bounded by the transport's
byte cap, sorted and locally paged. Continuations reread the source and explicitly
report best-effort consistency. A default assessment reads only top-level
queries marked `default_scan`; it does not pretend that exact/nested queries have
run. Supply explicit assessment `queries` for discovered security groups, roles,
buckets, keys, RDS instances, rule evaluations and registry tags.

Evidence is observed through the service's projection, byte limits, caller
ownership and retention policy. The Alibaba adapter additionally removes known
ACK bootstrap/password/opaque fields, arbitrary Cloud Config annotations and
input parameters, Security Center exploit/report payloads, and Container
Registry report commands. Policy JSON is decoded before projection so an encoded
document cannot bypass filtering. Configuration names, labels, policy conditions
and log metadata can still contain sensitive or misleading user-authored text;
the service marks evidence as untrusted and does not promise to recognize every
secret embedded in arbitrary metadata.

## Scope of this implementation

The implemented catalog is a maintained set of security questions, not every
Alibaba Cloud OpenAPI. Native adapters for ALB/NLB, PolarDB, MongoDB, Tair/Redis,
Function Compute, CDN/WAF/DDoS, message queues, DNS and other product-specific
security settings are not included. Cloud Config can expose inventory metadata
and existing compliance results for additional supported services, but those
observations must not be represented as equivalent to native live configuration
reads. Regional availability, editions, API enablement and actual RAM grants are
validated only when an operator runs a query against their account.

This code has offline contract and security-boundary tests. No live Alibaba
account credentials were supplied during implementation, so it has not been
validated against the user's production accounts, subscriptions or policies.

## Primary references

The published OpenAPI metadata was used to validate API versions, parameter
names, paging contracts, response shapes and action-specific RAM permission
names. Relevant references:

- [Alibaba OpenAPI Explorer](https://api.alibabacloud.com/)
- [ECS DescribeInstances](https://api.alibabacloud.com/document/Ecs/2014-05-26/DescribeInstances)
- [ECS DescribeSecurityGroupAttribute](https://api.alibabacloud.com/document/Ecs/2014-05-26/DescribeSecurityGroupAttribute)
- [VPC DescribeFlowLogs](https://www.alibabacloud.com/help/en/vpc/developer-reference/api-vpc-2016-04-28-describeflowlogs)
- [RAM ListRoles](https://www.alibabacloud.com/help/en/ram/developer-reference/api-ram-2015-05-01-listroles)
- [ACK DescribeClustersV1](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/developer-reference/api-cs-2015-12-15-describeclustersv1)
- [RDS DescribeDBInstanceSSL response](https://www.alibabacloud.com/help/en/rds/developer-reference/api-rds-2014-08-15-describedbinstancessl)
- [KMS DescribeKey](https://api.alibabacloud.com/document/Kms/2016-01-20/DescribeKey)
- [ActionTrail LookupEvents](https://www.alibabacloud.com/help/en/actiontrail/developer-reference/api-actiontrail-2020-07-06-lookupevents)
- [Cloud Config integration and home-region endpoints](https://www.alibabacloud.com/help/en/cloud-config/latest/using-openapi)
- [Container Registry ListRepoTagScanResult](https://api.alibabacloud.com/document/cr/2018-12-01/ListRepoTagScanResult)
- [Security Center DescribeVulList](https://api.alibabacloud.com/document/Sas/2018-12-03/DescribeVulList)

## Complete registered query table

This table is generated from the checked-in catalog. All selectors and identifiers
must satisfy the runtime schema; `capabilities` also supplies paging limits,
freshness and required RAM actions.

| Resource kind | Operation | Native action | Required inputs beyond account |
| --- | --- | --- | --- |
| `alicloud.actiontrail.events` | `list` | `LookupEvents` | location; selectors: start_time, end_time |
| `alicloud.actiontrail.trailStatus` | `get` | `GetTrailStatus` | location; resource_id: Name |
| `alicloud.actiontrail.trails` | `list` | `DescribeTrails` | location |
| `alicloud.config.evaluations` | `list` | `ListConfigRuleEvaluationResults` | location (cn-shanghai, ap-southeast-1); parent: ConfigRuleId |
| `alicloud.config.resources` | `list` | `ListDiscoveredResources` | location (cn-shanghai, ap-southeast-1) |
| `alicloud.config.rules` | `get` | `GetConfigRule` | location (cn-shanghai, ap-southeast-1); resource_id: ConfigRuleId |
| `alicloud.config.rules` | `list` | `ListConfigRules` | location (cn-shanghai, ap-southeast-1) |
| `alicloud.cr.instances` | `list` | `ListInstance` | location |
| `alicloud.cr.repositories` | `list` | `ListRepository` | location; parent: InstanceId |
| `alicloud.cr.tags` | `list` | `ListRepoTag` | location; parent: InstanceId; selectors: repository_id |
| `alicloud.cr.vulnerabilities` | `list` | `ListRepoTagScanResult` | location; parent: InstanceId; selectors: repository_id, tag |
| `alicloud.cs.clusters` | `get` | `DescribeClusterDetail` | location; resource_id: ClusterId |
| `alicloud.cs.clusters` | `list` | `DescribeClustersV1` | location |
| `alicloud.cs.nodePools` | `list` | `DescribeClusterNodePools` | location; parent: ClusterId |
| `alicloud.ecs.disks` | `list` | `DescribeDisks` | location |
| `alicloud.ecs.instances` | `list` | `DescribeInstances` | location |
| `alicloud.ecs.networkInterfaces` | `list` | `DescribeNetworkInterfaces` | location |
| `alicloud.ecs.securityGroupRules` | `list` | `DescribeSecurityGroupAttribute` | location; parent: SecurityGroupId |
| `alicloud.ecs.securityGroups` | `list` | `DescribeSecurityGroups` | location |
| `alicloud.kms.keyVersions` | `list` | `ListKeyVersions` | location; parent: KeyId |
| `alicloud.kms.keys` | `get` | `DescribeKey` | location; resource_id: KeyId |
| `alicloud.kms.keys` | `list` | `ListKeys` | location |
| `alicloud.kms.secretMetadata` | `list` | `ListSecrets` | location |
| `alicloud.oss.bucketAcl` | `get` | `GetBucketAcl` | location; resource_id: BucketName |
| `alicloud.oss.bucketEncryption` | `get` | `GetBucketEncryption` | location; resource_id: BucketName |
| `alicloud.oss.bucketLogging` | `get` | `GetBucketLogging` | location; resource_id: BucketName |
| `alicloud.oss.bucketPolicy` | `get` | `GetBucketPolicy` | location; resource_id: BucketName |
| `alicloud.oss.bucketPublicAccessBlock` | `get` | `GetBucketPublicAccessBlock` | location; resource_id: BucketName |
| `alicloud.oss.bucketVersioning` | `get` | `GetBucketVersioning` | location; resource_id: BucketName |
| `alicloud.oss.buckets` | `get` | `GetBucketInfo` | location; resource_id: BucketName |
| `alicloud.oss.buckets` | `list` | `ListBuckets` | location |
| `alicloud.ram.accessKeys` | `list` | `ListAccessKeys` | parent: UserName |
| `alicloud.ram.groupPolicies` | `list` | `ListPoliciesForGroup` | parent: GroupName |
| `alicloud.ram.groupUsers` | `list` | `ListUsersForGroup` | parent: GroupName |
| `alicloud.ram.groups` | `list` | `ListGroups` | None |
| `alicloud.ram.loginProfiles` | `get` | `GetLoginProfile` | resource_id: UserName |
| `alicloud.ram.mfaDevices` | `get` | `GetUserMFAInfo` | resource_id: UserName |
| `alicloud.ram.passwordPolicy` | `list` | `GetPasswordPolicy` | None |
| `alicloud.ram.policies` | `get` | `GetPolicy` | resource_id: PolicyName; selectors: policy_type |
| `alicloud.ram.policies` | `list` | `ListPolicies` | None |
| `alicloud.ram.policyVersions` | `get` | `GetPolicyVersion` | parent: PolicyName; resource_id: VersionId; selectors: policy_type |
| `alicloud.ram.rolePolicies` | `list` | `ListPoliciesForRole` | parent: RoleName |
| `alicloud.ram.roles` | `get` | `GetRole` | resource_id: RoleName |
| `alicloud.ram.roles` | `list` | `ListRoles` | None |
| `alicloud.ram.securityPreference` | `list` | `GetSecurityPreference` | None |
| `alicloud.ram.userGroups` | `list` | `ListGroupsForUser` | parent: UserName |
| `alicloud.ram.userPolicies` | `list` | `ListPoliciesForUser` | parent: UserName |
| `alicloud.ram.users` | `get` | `GetUser` | resource_id: UserName |
| `alicloud.ram.users` | `list` | `ListUsers` | None |
| `alicloud.rds.auditPolicy` | `get` | `DescribeSQLCollectorPolicy` | location; resource_id: DBInstanceId |
| `alicloud.rds.backupPolicy` | `get` | `DescribeBackupPolicy` | location; resource_id: DBInstanceId |
| `alicloud.rds.encryption` | `get` | `DescribeDBInstanceTDE` | location; resource_id: DBInstanceId |
| `alicloud.rds.instances` | `get` | `DescribeDBInstanceAttribute` | location; resource_id: DBInstanceId |
| `alicloud.rds.instances` | `list` | `DescribeDBInstances` | location |
| `alicloud.rds.ipAllowlists` | `get` | `DescribeDBInstanceIPArrayList` | location; resource_id: DBInstanceId |
| `alicloud.rds.networkEndpoints` | `get` | `DescribeDBInstanceNetInfo` | location; resource_id: DBInstanceId |
| `alicloud.resourcemanager.accounts` | `list` | `ListAccounts` | None |
| `alicloud.resourcemanager.resourceGroups` | `list` | `ListResourceGroups` | None |
| `alicloud.sas.riskChecks` | `list` | `DescribeRiskCheckResult` | location (cn-shanghai, ap-southeast-1) |
| `alicloud.sas.vulnerabilities` | `list` | `DescribeVulList` | location (cn-shanghai, ap-southeast-1); selectors: vulnerability_type |
| `alicloud.slb.httpListeners` | `get` | `DescribeLoadBalancerHTTPListenerAttribute` | location; parent: LoadBalancerId; selectors: port |
| `alicloud.slb.httpsListeners` | `get` | `DescribeLoadBalancerHTTPSListenerAttribute` | location; parent: LoadBalancerId; selectors: port |
| `alicloud.slb.loadBalancers` | `get` | `DescribeLoadBalancerAttribute` | location; resource_id: LoadBalancerId |
| `alicloud.slb.loadBalancers` | `list` | `DescribeLoadBalancers` | location |
| `alicloud.slb.tcpListeners` | `get` | `DescribeLoadBalancerTCPListenerAttribute` | location; parent: LoadBalancerId; selectors: port |
| `alicloud.slb.udpListeners` | `get` | `DescribeLoadBalancerUDPListenerAttribute` | location; parent: LoadBalancerId; selectors: port |
| `alicloud.vpc.eipAddresses` | `list` | `DescribeEipAddresses` | location |
| `alicloud.vpc.flowLogs` | `list` | `DescribeFlowLogs` | location |
| `alicloud.vpc.natGateways` | `list` | `DescribeNatGateways` | location |
| `alicloud.vpc.networkAcls` | `get` | `DescribeNetworkAclAttributes` | location; resource_id: NetworkAclId |
| `alicloud.vpc.networkAcls` | `list` | `DescribeNetworkAcls` | location |
| `alicloud.vpc.routeEntries` | `list` | `DescribeRouteEntryList` | location; parent: RouteTableId |
| `alicloud.vpc.routeTables` | `list` | `DescribeRouteTableList` | location |
| `alicloud.vpc.vpcs` | `list` | `DescribeVpcs` | location |
| `alicloud.vpc.vswitches` | `list` | `DescribeVSwitches` | location |
