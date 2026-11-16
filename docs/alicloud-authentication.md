# Alibaba Cloud authentication and scope

Alibaba Cloud access uses a separate cloud credential binding from Google ADC.
Running the MCP on GKE does not by itself grant an Alibaba RAM identity. Each
deployment must have Alibaba credentials whose actual account is explicitly
allowed in `SEC_AUDITOR_ALLOWED_ALICLOUD_ACCOUNTS`.

The HTTP MCP caller's JWT or static token authenticates the agent to this service.
It is never forwarded to Alibaba APIs. Cloud credentials are obtained only by the
server and are never included in tool results. The connector stores no collected
records or job state.

## Keyless credentials

The implementation uses the official `alibabacloud-credentials` default provider
chain. A single long-lived SDK credential client obtains and refreshes temporary
credentials. The supported SDK sources include environment STS credentials,
OIDC role federation, an operator-managed Alibaba CLI profile, ECS instance RAM
roles, and an operator-configured credentials URI. The MCP does not accept a
credential source, token path, profile, role ARN or endpoint as tool input.

For ACK, use RAM Roles for Service Accounts (RRSA). An OIDC binding supplies:

```sh
ALIBABA_CLOUD_ROLE_ARN=acs:ram::1234567890123456:role/sec-auditor
ALIBABA_CLOUD_OIDC_PROVIDER_ARN=acs:ram::1234567890123456:oidc-provider/ack-rrsa-example
ALIBABA_CLOUD_OIDC_TOKEN_FILE=/var/run/secrets/ack.alibabacloud.com/rrsa-tokens/token
```

These are examples of SDK environment variable names. Use the actual values and
token path provisioned by your RRSA configuration. The SDK exchanges the OIDC
token for STS credentials and refreshes them. For a federated deployment outside
ACK, configure the corresponding Alibaba RAM OIDC trust and projected workload
token. Google Workload Identity and Alibaba federation are separate bindings.

For ECS instance RAM roles, prefer hardened metadata access and configure
`ALIBABA_CLOUD_IMDSV1_DISABLED=true`. Where instance metadata should not be used,
configure `ALIBABA_CLOUD_ECS_METADATA_DISABLED=true`. The official chain checks
environment AccessKeys before OIDC; remove unintended static credential variables
from a keyless deployment so they do not select another identity.

The server loads Alibaba credentials lazily: a GCP-only deployment does not need
an Alibaba profile, token file or metadata server.

Primary references:

- [Python credential provider chain and automatic refresh](https://www.alibabacloud.com/help/en/sdk/developer-reference/v2-manage-python-access-credentials)
- [Use RRSA for pod-level cloud access](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services)
- [Official Alibaba Python credentials implementation](https://github.com/aliyun/credentials-python)

## Account and region isolation

Example deployment scope:

```sh
SEC_AUDITOR_ALLOWED_ALICLOUD_ACCOUNTS='["1234567890123456"]'
SEC_AUDITOR_ALLOWED_ALICLOUD_REGIONS='["cn-hangzhou","ap-southeast-1"]'
```

Before a resource read, the transport calls STS `GetCallerIdentity` using the same
credential snapshot that will sign the target request. `AccountId` must exactly
match the requested allowed account. The identity proof is cached for the
configured scope cache lifetime, keyed by a hash of the complete credential
generation. Refreshed credentials therefore require a new identity proof even
if the earlier cache entry is still valid. No credential values are persisted.

Regional operations require an explicit configured region. An empty regional
allowlist permits only global operations such as RAM queries. Neither API
endpoint URLs nor owner-account overrides can be supplied by an agent.

This release has one default Alibaba credential binding per server process.
Listing several allowed account IDs does not create cross-account credentials.
For several actual member accounts, run separately scoped credential bindings
and connect the agent to those MCP deployments. Resource Directory membership
does not imply that a management-account identity can read a member account.
An operator-managed SDK profile can assume an auditing role, but that resulting
role's account must still pass the STS check. The MCP never chooses or assumes a
RAM role from an agent's query arguments.

STS documents `GetCallerIdentity` as requiring no RAM authorization. It is used
to prove identity, not to infer the permissions of that identity.

Reference: [STS GetCallerIdentity response and authorization](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity).

## RAM permissions

Use the recommended [strict metadata IAM profile](../deploy/alicloud/terraform/README.md)
when the RAM identity itself must be unable to read cloud content. The standalone
[`alicloud_security_auditor.tf`](../deploy/alicloud/terraform/alicloud_security_auditor.tf)
attaches two custom policies to an existing dedicated RAM role: an exact allowlist
of 202 reviewed actions across 34 RAM namespaces and a `Deny`/`NotAction` guardrail
covering everything outside the same list. `Resource: "*"` applies those actions
across the provider's account; it does not create organization-wide credentials.
The role's narrow RRSA/OIDC trust is configured separately.

The strict profile denies ActionTrail `LookupEvents`, SLS log-record reads,
ACK cluster/node-pool calls with mixed responses, RDS instance detail, selected
Cloud Config/finding queries and other content-bearing calls. An additional
allow policy cannot override its explicit deny. Metadata names, descriptions,
tags and policy text can still contain administrator-supplied secrets; RAM has
no field-level guarantee for arbitrary text.

[`read-policy.json`](../deploy/alicloud/read-policy.json), regenerated by
`sec-auditor ram-policy`, remains the connector catalog's 75-action permission
contract. It includes 11 mixed-content or opaque-response actions excluded by
the strict profile and relies on the connector to project their responses.
It is useful for a separately reviewed broader deployment, but is not a
metadata-only native RAM guarantee. Adding either policy does not add connector
adapters: the strict IAM list covers more service families than the current
query catalog.

A broad managed read-only policy is not a metadata-only policy. For example,
[AliyunOSSReadOnlyAccess](https://www.alibabacloud.com/help/en/ram/developer-reference/aliyunossreadonlyaccess)
grants `oss:Get*` and `oss:List*`, which includes object-content reads.
[AliyunYundunSASReadOnlyAccess](https://www.alibabacloud.com/help/en/ram/developer-reference/aliyunyundunsasreadonlyaccess)
is a Security Center policy, not an infrastructure-wide policy; its current
published actions also include `secllm:ToolInvoke`. Use exact reviewed actions
for a fetch-only connector instead of inferring behavior from a policy name.

`capabilities` advertises query requirements, not effective grants. Under the
strict profile, keep excluded queries denied and treat their errors as coverage
gaps. For a separate broader profile, review the exact catalog actions and their
response projections alongside service-specific resource scopes. The query
catalog deliberately excludes object download, Secret Manager
value retrieval, KMS decryption, instance user-data/console reads, cluster
kubeconfig retrieval and cloud mutations.

The application allowlist and response projection remain separate controls.
They restrict connector output; they do not prevent direct use of the RAM
identity to retrieve every field authorized by a broader cloud policy.

OSS bucket-specific reads also require `oss:GetBucketInfo`. The transport checks
the returned bucket name, `Owner.ID` and `Location` against the requested
account/region before returning metadata or reading another bucket setting.
Endpoint values in a response are never followed. Bucket listing is filtered to
the requested configured region while preserving pagination; a filtered empty
page can still have a continuation cursor.

Reference: [OSS GetBucketInfo ownership and location fields](https://www.alibabacloud.com/help/en/oss/developer-reference/getbucketinfo).

## Audit and VPC flow logs: separate broader profile

The following log-reading configuration is optional and requires a separate
deployment/role authorized to receive log contents. It does not work around the
strict metadata guardrail. For that broader role, scope the
[SLS example](../deploy/alicloud/sls-read-policy.example.json) to approved
security logstores. The strict profile permits reviewed logging configuration
reads, not SLS log records or ActionTrail event bodies.

SLS log destinations are registered by the operator. An agent selects a registry
key, never a project/logstore URL or arbitrary SLS expression. For example:

```sh
SEC_AUDITOR_ALICLOUD_LOGSTORES='{"production-flows":{"account_id":"1234567890123456","region":"cn-hangzhou","project":"security-audit","logstore":"vpc_flows","category":"vpc_flows"}}'
```

The transport independently rechecks the entire account, region, project and
logstore tuple against this registry. Reads use the current GetLogsV2 fixed
`POST /logstores/{logstore}/logs` route with a JSON request, a fixed `*` search,
a bounded time window, and at most 100 records per upstream page. SQL and arbitrary search
expressions are rejected. The service projects log entries to the selected
security telemetry fields before returning them. The transport requests
gzip compression and separately caps compressed and decompressed response bytes.

SLS can return an incomplete result while its search is still processing. Those
results are explicitly marked incomplete and the continuation retains the same
offset. A full page conservatively returns another offset; a subsequent empty
complete page ends the scan. These are bounded evidence pages, not proof that all
historical traffic or audit events have been collected.

ActionTrail `LookupEvents` is supported through the query catalog only when the
separate broader identity is authorized for it.
Its transport also requires an explicit timezone-aware time interval within the
configured log-window limit, so generic resource collection cannot bypass the
log-query bounds.

Reference: [Current GetLogsV2 API, response and RAM permission](https://www.alibabacloud.com/help/en/sls/developer-reference/api-sls-2020-12-30-getlogsv2).

## ACK Kubernetes authorization

RAM/RRSA authorizes Alibaba cloud API calls. Kubernetes API reads still need
Kubernetes RBAC. Native ACK workload reads use operator-registered cluster
connections with a trusted CA and a rotating read-only Kubernetes service-account
token file. The server does not fetch administrator kubeconfigs or certificates
from ACK. Grant only the documented `get`/`list` workload and security resource
permissions; Secrets, ConfigMaps, logs, exec, attach and proxy operations remain
outside the MCP's Kubernetes allowlist.

This is independent of the strict RAM profile. RBAC can deny Secret objects,
but an allowed Pod/workload read still returns literal environment values,
commands and other embedded content to the connector. The mandatory Kubernetes
projection removes those fields before returning results. If the identity must
not receive them at all, omit native workload access; RBAC cannot selectively
hide fields in a Pod response.

## Transport details and deployment limits

The official Tea OpenAPI SDK signs RPC and ROA requests using ACS3; the official
OSS and SLS SDK signers sign their fixed metadata and log routes. No custom
cryptographic signing implementation is used. The application sends those
signed requests with its bounded HTTP client because the SDKs' generic HTTP
paths do not expose all required response-size and redirect controls.

HTTPS certificate verification is enabled, redirects are not followed, and
ambient proxy settings are not used by the resource HTTP transport. The SDK's
credential acquisition is its own credential-provider workflow; configure that
workflow through trusted deployment settings only. Cloud API response bodies
have byte limits, and calls have concurrency, rate, retry and deadline bounds.
Upstream error bodies are not returned because they can contain credential or
request details. A permission error stays an explicit gap in coverage.

Only the compiled public Alibaba API endpoints are supported by this release.
PrivateLink, Cloud Box, sovereign/special endpoints and arbitrary gateway URLs
require a reviewed provider extension. This implementation has been verified
with offline fixtures and the real SDK signers; deployment-specific RAM policy,
network reachability and live service response behavior require a read-only
smoke test in your own account.

SDK protocol reference: [Python generic OpenAPI requests](https://www.alibabacloud.com/help/en/sdk/developer-reference/generalized-call-python).
