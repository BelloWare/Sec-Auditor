# Alibaba Cloud security metadata role

Use [alicloud_security_auditor.tf](alicloud_security_auditor.tf) for an account-wide
security configuration reader that excludes first-class content and credentials
at the RAM permission layer. It is a standalone Terraform file: the Python
connector, MCP server, this README and the review manifest are not runtime
dependencies.

The reviewed profile contains **202 exact RAM actions across 34 service
namespaces**, as of **2026-11-16**. It creates two custom policies and attaches
them to an **existing dedicated ordinary RAM role**. It creates no credentials,
trust relationships, cloud scanners, log pipelines, data stores or background
jobs. Terraform is only the provisioning mechanism; the resulting role's
permissions are read-only.

This implements the intended separation between security configuration and
workload data. It is not an Alibaba managed policy, a byte-for-byte equivalent
of a GCP role, or a promise of complete visibility into every Alibaba product.
`Resource = "*"` means all applicable resources for the enumerated actions;
it does not mean that every API is permitted or that member accounts are
automatically accessible.

## What the role can and cannot read

Allowed information includes resource identifiers, locations, ownership,
network topology, public exposure, access policies, encryption settings, key
identifiers, backup/retention controls, identity/MFA metadata and selected
aggregate security statistics. References such as a snapshot ID, key ID,
certificate ID, secret name or image digest are metadata, not retrieval
permissions for the referenced content.

The profile deliberately excludes:

- Object bodies, object-level listing/metadata, object versions and downloads.
- Secret values, access-key secrets, MFA provisioning seeds, private keys,
  decryption, signed downloads and credential issuance.
- Database rows, SQL, queue messages, file contents, backed-up files, image
  layers, function code and executable VM/bootstrap configuration.
- Raw audit events, flow records, application logs and security finding evidence
  that may contain request bodies, captured files or application content.
- Pod/VM execution, arbitrary API proxies, role chaining and cloud mutations.
- Generic configuration bodies and opaque strings whose response contract
  cannot establish a useful configuration-only boundary.

**Configuration strings are still visible.** Someone can put a secret into a
tag, resource name, description, DNS TXT record, policy condition or endpoint
string. RAM has no mechanism to recognize and redact such a value. The honest
boundary is absence of the reviewed native operations that retrieve first-class
data, credentials or mixed sensitive responses, not a guarantee that every
returned string is intrinsically non-sensitive.

## Why there are two policies

The allow document grants the exact reviewed action union. The guard document
uses `Effect = "Deny"`, `NotAction = <the same entire union>` and
`Resource = "*"`. Thus every action outside the union receives an explicit deny
when RAM evaluates this role's policies. `NotAction` is an exception to the deny,
not a grant; the allow policy supplies the grant.

Alibaba documents both [NotAction semantics](https://www.alibabacloud.com/help/en/ram/policy-elements)
and [explicit-deny precedence](https://www.alibabacloud.com/help/en/ram/policy-evaluation-process).
This makes an accidental later broad read-only grant insufficient to reopen an
excluded action. Other Resource Directory controls, session policies and
resource policies can still restrict allowed actions further.

There are no action wildcards, including `Get*`, `Describe*`, `List*` or
`service:*`. New API actions remain outside the exception list. Existing APIs
can still acquire new response fields, so this snapshot requires review when
their contracts change.

Each RAM custom policy is limited to
[6,144 characters](https://www.alibabacloud.com/help/en/ram/product-overview/limits/).
The two compact ASCII documents are **5,618 bytes** (allow) and **5,620 bytes**
(guard). Terraform checks both limits. Duplicating the union inside one combined
document would exceed that quota.

**Never partition the guard into disjoint `Deny`/`NotAction` statements or
policies.** Multiple such statements intersect their exception sets: an action
excepted by one guard is still denied by another. If future reviewed actions
exceed the quota, reduce the action set or redesign the boundary explicitly;
do not automatically introduce wildcards.

## Coverage by service family

The count is of distinct permission names, not API operations. Some permissions
authorize multiple APIs, which must all be safe before the permission is added.
The complete names are grouped in the HCL. Each approved action and each reviewed
exclusion has its rationale and primary-source URLs in
[policy-review.json](policy-review.json).

| Service family | Namespaces / actions | Included | Deliberate limits |
| --- | --- | --- | --- |
| Identity and access | `ram` 27, `sts` 1 | Users/groups/roles, trusts, policy documents and attachments, SSO metadata, login/MFA settings, access-key IDs/status/last use, caller identity | No passwords, MFA seeds, secret access keys, token issuance or outgoing role assumption |
| Account structure and inventory | `resourcemanager` 12, `resourcecenter` 2, `config` 2 | Accounts, directory/folders, resource groups, control policies, supported summary inventory and Config rule listings | No generic resource-configuration body or per-resource Config evaluation; no automatic member-account authority |
| Virtual machines and scaling | `ecs` 11, `ess` 3 | Instances, disks, images, snapshots, security groups, NICs, attached RAM roles, launch-template summaries, scaling groups/membership/rules | No user data, launch-template versions, scaling configurations, console/session data or in-guest filesystem/package inspection |
| Networking | `vpc` 13, `cen` 6 | VPCs/subnets, route tables/entries, ACLs, NAT/EIP, CEN/transit routing, VPN gateway and SSL server summaries, flow-log configuration | No IPsec connection pre-shared keys, customer-gateway auth keys, VPN client bundles or traffic records |
| Load balancing | `slb` 8, `alb` 8, `nlb` 5 | Load balancers, listener settings, ACLs, TLS/certificate metadata and reviewed server groups | CLB UDP/NLB server-group health payloads and ALB literal response/header rules excluded |
| Object storage | `oss` 19 | Buckets/access points, ACL/policies, encryption, public-access blocks, versioning, retention/WORM, lifecycle, replication, logging, CORS and HTTPS settings | No objects or object versions; website/origin-header configuration excluded |
| Filesystems and backups | `nas` 4, `hbr` 2 | NAS permission groups/rules, access points and recycle-bin settings; backup-vault encryption/immutability and retention policies | NAS filesystem/mount-target reads can include CPFS login passwords; no backup-plan opaque details, file browsing or restore/download |
| Databases | `rds` 8, `polardb` 7, `kvstore` 6, `dds` 6, `adb` 4 | Reviewed inventory and dedicated network, backup, TLS, TDE and audit-configuration reads, varying by engine | RDS SSL/private-key and instance recovery fields excluded; Redis instance opaque `Config` and MongoDB detailed recovery fields excluded; no database data |
| TableStore | `ots` 3 | Instance metadata, instance policy/network settings and VPC binding information | No rows, range scans, SQL or data-plane access |
| Keys and secrets | `kms` 8 | Key metadata/states/aliases/versions/policies, secret names/version IDs/policies | No secret payload, opaque secret extended configuration, private key or cryptographic operations |
| Audit and logging | `actiontrail` 2, `log` 7 | Trail destination/configuration/delivery status; SLS project/logstore/index/shard configuration | No ActionTrail event payloads, SLS records, histograms or arbitrary SQL queries |
| Registry | `cr` 6 | Instance/endpoint, repository and tag/digest metadata | No pull tokens, image layers, manifests or unbounded/shared scan contracts |
| DNS, CDN and API Gateway | `alidns` 4, `cdn` 2, `apigateway` 2 | DNS/domain configuration and records; CDN/API/group summaries | CDN feature values can include signing keys; detailed API mocks/constants excluded |
| Messaging | `alikafka` 2, `mq` 3, `rocketmq` 3 | Kafka ACL/group configuration; legacy ONS and RocketMQ instance/topic/group summaries | Kafka instance/topic opaque configuration excluded; no message contents, consumer pulls or credential-bearing detail APIs |
| Security products | `yundun-sas` 2, `yundun-waf` 1, `yundun-ddoscoo` 3 | Security Center assets/aggregate counts, WAF domain summaries and DDoS protection inventory | No raw vulnerability proof, captured requests, origin-auth header values or opaque WAF rules |
| ACK, Function Compute, Elasticsearch and other services | Supported summary inventory, where independently authorized | Resource Center / existing Cloud Config may provide identifiers and summary metadata | No claim of safe direct detail access; ACK/FC/ES mixed responses are excluded; Kubernetes uses separate RBAC |

Inventory is conditional. Resource Center requires supported/enabled resource
discovery and can perform underlying service authorization checks; Cloud Config
reflects an existing recorder's inventory. These permissions do not enable
recording or repair discovery gaps. A denied or missing resource is an explicit
coverage gap, not evidence of a secure configuration.

## Non-obvious exclusions reviewed

Read-only describes whether an API changes state. It does not establish whether
its response contains secrets or application data. These examples explain why
a blanket read policy cannot meet this profile:

| API / permission | Native response concern | Decision |
| --- | --- | --- |
| [ACK DescribeClusterNodePools](https://www.alibabacloud.com/help/en/ack/ack-edge/developer-reference/api-cs-2015-12-15-describeclusternodepools-edge) | `user_data` and bootstrap configuration | Exclude the permission, even if the MCP would redact these fields |
| [VPN DescribeVpnConnections](https://www.alibabacloud.com/help/en/vpn/sub-product-ipsec-vpn/developer-reference/api-vpc-2016-04-28-describevpnconnections-vpns) | `IkeConfig.Psk`, tunnel PSKs and BGP authentication keys | Permit gateway summaries, not connection details |
| [NAS DescribeFileSystems](https://www.alibabacloud.com/help/en/nas/developer-reference/api-nas-2017-06-26-describefilesystems) / DescribeMountTargets | CPFS `ClientMasterNodes...DefaultPasswd` | Permit separate access-control APIs; do not grant these inventory/detail calls |
| [Function Compute ListFunctions](https://www.alibabacloud.com/help/en/functioncompute/api-fc-2023-03-30-listfunctions) / GetFunction | Environment-variable values and executable bootstrap/container settings | Exclude both list and detail |
| [RDS DescribeDBInstanceSSL](https://www.alibabacloud.com/help/en/rds/developer-reference/api-rds-2014-08-15-describedbinstancessl) | `ServerKey` is a server private key | Exclude; dedicated SSL reads for other database products were reviewed separately |
| [RDS DescribeDBInstanceAttribute](https://www.alibabacloud.com/help/en/rds/developer-reference/api-rds-2014-08-15-describedbinstanceattribute) | Opaque `DisasterRecoveryInfo` has documented `replicatorPassword`; the example is masked, but an enforced masking contract was not established | Conservative exclusion; no claim that plaintext was observed in a live tenant |
| [CLB UDP listener detail](https://www.alibabacloud.com/help/en/slb/classic-load-balancer/developer-reference/api-slb-2014-05-15-describeloadbalancerudplistenerattribute) / NLB ListServerGroups | Literal health-check request/expected-response payloads | Keep reviewed listener/configuration alternatives |
| [OSS GetBucketWebsite](https://www.alibabacloud.com/help/en/oss/developer-reference/getbucketwebsite) | Origin/mirror request header values can carry credentials | Exclude the whole action |
| [CDN feature configuration](https://www.alibabacloud.com/help/en/cdn/developer-reference/parameters-for-configuring-features-for-domain-names) | Feature arguments include `auth_key1` / `auth_key2`; custom header values may also be sensitive | Permit domain summaries only |
| ActionTrail LookupEvents, SLS content reads, SAS vulnerability/risk details | Request/response payloads, log bodies or captured application evidence | Configuration and selected aggregates only |
| Cloud Config / Resource Center generic detail and some engine settings | Opaque configuration/evaluation bodies cannot be constrained by RAM to selected fields | Summary inventory or dedicated typed configuration reads |
| Elasticsearch ListAllNode | Its response is a safe summary, but its authorization is `elasticsearch:DescribeInstance`, which also grants excluded opaque instance details | Exclude the shared permission, not merely the unsafe endpoint |

All **43 reviewed exclusions** and their exact source URLs are in the manifest.
They are examples evaluated during this review, not an exhaustive blacklist:
the guard denies *every* action not present in the allow union, including future
actions and known data-plane reads that did not require detailed review.

## Apply to a dedicated role

Requirements:

- Terraform **1.7 or newer, below 2.0**. Tested with Terraform 1.17.2.
- Alibaba provider **2.2.x** (`aliyun/alicloud`, constrained by this file and the
  committed dependency lock). Tested with 2.2.0.
- An existing ordinary dedicated RAM role in the target provider account.
- Your normal provisioning identity with permission to create/version custom
  policies and attach them to that role. Do not run this operation as the
  restricted auditor itself.

Run from this directory, or copy just `alicloud_security_auditor.tf` into an
empty Terraform directory. Configure the provider using your normal environment
or credential setup; no credentials belong in this file.

```sh
terraform init
terraform plan -var='auditor_role_name=sec-auditor' -out=auditor.tfplan
terraform apply auditor.tfplan
```

The plan creates two policies, `SecAuditorMetadata-Allow` and
`SecAuditorMetadata-Guardrail`, and two account-scope attachments. Set
`auditor_policy_name_prefix` when separate deployments need distinct policy
names. Existing resources with those names must be imported/managed deliberately;
this file does not take ownership of arbitrary existing policies.

Keep the role's trust narrowly bound to the workload. For ACK RRSA, the existing
OIDC trust should constrain the provider, audience and Kubernetes service-account
subject. This Terraform intentionally requires the already configured role
instead of inventing a permissive trust policy. The incoming OIDC exchange is
separate from the permissions of the assumed role. Outgoing `sts:AssumeRole` is
denied, so the connector cannot use this role to chain into a broader role.

For multiple accounts, provision a dedicated reviewed role in each target
account and authenticate directly into the appropriate role. A directory account
list or `SearchMultiAccountResources` grant does not establish cross-account
trust or data access. The current connector validates its actual credential
account and does not create cross-account sessions automatically.

Terraform attaches the guard before the allow policy. RAM uses
[eventual consistency](https://www.alibabacloud.com/help/en/ram/support/faq-about-ram-users),
so completion is not an atomic global enforcement guarantee. Use a new dedicated
role for initial rollout and verify expected permissions before placing it into
service. No account was accessed or policy applied during development of this
file.

## Logs and Kubernetes are separate boundaries

**Logs:** This profile allows inspection of ActionTrail/SLS/flow-log setup, not
the collected events. An audit event can contain request parameters, and a flow
or security logstore may mix telemetry with application fields. Query projections
or SQL column selections do not constrain what the same RAM credentials can
retrieve through another request. If telemetry is needed under a content-free
contract, prepare a separately sanitized source and explicitly review a narrowly
scoped reader for that source. An extra SLS allow policy will not override this
profile's guard. Do not simply remove the guard to make `query_logs` work.

**Kubernetes:** RAM/RRSA authenticates Alibaba cloud requests. Reading Pods and
RBAC objects uses a separate Kubernetes identity and ClusterRole. The repository's
[ACK RBAC example](../kubernetes/15-rbac.yaml) grants `get`/`list` for named
resource kinds and omits Secrets, ConfigMaps, logs, exec, attach, proxy, token
creation, impersonation and write verbs. It is not created by this Terraform.

Permission to read a Pod definition also permits literal `env.value`, command,
argument and annotation fields inside that Pod. Kubernetes RBAC cannot redact
those fields. The connector projects known sensitive fields before returning
definitions to the agent, but the underlying Kubernetes identity still receives
the native object. Strictly preventing that identity from ever fetching such
content requires an already sanitized intermediary or a configuration discipline
that keeps sensitive material out of readable definitions. Denying `secrets`
alone does not establish that stronger property.

## Relationship to the Sec-Auditor connector

This profile is independent of the MCP catalog and spans more service families.
Granting a permission does not add a new MCP operation. The connector continues
to advertise and enforce its own fixed query catalog, authentication, scope
checks, pagination limits and output projections.

The older [read-policy.json](../read-policy.json), regenerated by
`sec-auditor ram-policy`, is the complete permission contract for the current
compiled catalog. It includes operations whose native responses mix useful
metadata with fields the connector removes. It is **not** an equivalent strict
RAM metadata-only boundary.

Compared with that 75-action catalog contract, this strict profile allows 64 and
explicitly denies these 11:

```text
actiontrail:LookupEvents
config:GetConfigRule
config:ListConfigRuleEvaluationResults
cr:GetScan
cs:DescribeClusterDetail
cs:DescribeClusterNodePools
cs:GetClusters
rds:DescribeDBInstanceAttribute
slb:DescribeLoadBalancerUDPListenerAttribute
yundun-sas:DescribeRiskCheckResult
yundun-sas:DescribeVulList
```

Catalog discovery remains a description of connector capabilities, not proof of
the active role's authorization. A query using one of these actions will return
an upstream permission error/coverage gap. The connector must not escalate
permissions, switch credentials or treat that gap as a passing assessment.

The review also identified two concrete projection gaps in those broader
catalog paths: JSON-encoded RDS recovery details and CLB UDP health-check bodies.
The connector now excludes `DisasterRecoveryInfo`, `HealthCheckReq` and
`HealthCheckExp` as opaque fields. This is defense in depth for deployments using
the broader catalog policy; the strict Terraform profile denies their underlying
actions entirely.

## Updates, removal and verification

The Terraform uses `create_before_destroy` for replacements and `force = false`
for policy deletion. A prefix/name change can create new policies before old ones
are detached. Forcing replacement while retaining the same unique name can
collide. In-place policy-document updates are version changes, not atomic
replacement of both documents. Old and new deny guards, when simultaneously
attached, enforce the intersection of their exceptions and can temporarily
block newly introduced reads. Leave spare policy/attachment quota for rotation.

`force = false` prevents policy deletion from forcibly detaching unexpected
external users of that policy. It is not `prevent_destroy`. Destroying or moving
the managed attachments removes the restriction from the previous role, which
can reactivate other attached grants. Stop/retire the role before removing its
guard. Administrators can still alter permissions; this is not an immutable
organization control policy.

The scope is requests authenticated as this role for which RAM enforces these
policies. It does not govern public/anonymous HTTP access, a URL signed by another
identity, other credentials, a Kubernetes token or a service that does not use
RAM authorization.

Local verification commands:

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
```

The tests use a mocked Alibaba provider and plans only. They check the exact
allow set, complete unconditional deny exception set, excluded/synthetic future
actions, policy limits, provenance and role/name input validation. They do not
prove live service authorization, response behavior or tenant-specific feature
availability. Production rollout should check representative safe reads and
expected denials using the dedicated role. New action requests require reviewing
native responses and every API sharing the RAM action; a `Get`/`List`/`Describe`
prefix is not sufficient evidence.
