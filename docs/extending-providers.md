# Extending query coverage

GCP and Alibaba Cloud implement the same `CloudProvider.query_resources` contract.
The MCP accepts explicit `provider`, `kind`, a GCP project/scope or Alibaba account,
operation, location, parent, resource ID, declared selectors, page size and cursor.
Existing GCP requests without `provider` remain valid and default to `gcp`.

## Shared contract

`capabilities()` describes compiled query operations. The MCP groups them by
resource kind with an `operations` list and a `queries` map containing the exact
requirements for each operation. `sec-auditor catalog` exposes the same discovery
shape offline, without cloud credentials. A `CollectionResult` includes:

- Native-shaped `ResourceRecord` observations with provider, canonical name,
  project or account, location, source, observation time and freshness.
- A native continuation token; the service replaces it with an authenticated,
  expiring cursor bound to the caller, operation and complete query.
- Safe source errors, partial-result warnings and relevant API metadata.

GCP verifies project identity and organization ancestry. Alibaba verifies the
actual credential account with STS before signing resource requests. These are
separate authorization implementations. Alibaba's region allowlist restricts
API endpoints and service home regions; inventory/findings can reference other
resource regions within the same verified account. Account-global and regional
operations are explicit in capabilities.

## Adding a cloud query

1. Review the primary API schema, authorization reference, native pagination,
   locations, required inputs and every returned field. A method named `Get` or
   `Describe` can return passwords or key material. This review excluded Alibaba
   `DescribeDBInstanceSSL` because it can return a private key.
2. Add a fixed spec in `providers/catalog.py` / `providers/gcp_queries.py` for GCP,
   or `providers/alicloud_catalog.py` for Alibaba. Declare exact permissions and
   selector requirements. Never accept arbitrary methods, actions, URLs, fields,
   response paths or request bodies from the agent.
3. Enforce scope at the resource boundary. A global bucket name is insufficient:
   prove its owning project/account before reading its settings. A nested parent
   must belong to the authorized root. Do not trust endpoint URLs returned in data.
4. Preserve native continuation, partial failures and freshness. Empty pages can
   still have a continuation. Observe service-specific minimum/maximum page sizes.
5. Add deterministic content projection before persistence or MCP output. Prefer
   excluding an unsafe API entirely when it intrinsically returns secret payloads.
6. Add realistic positive, denial, malformed-response, pagination, scope-escape,
   credential/data minimization and relevant transport tests. Update the question
   matrix and coverage reference. Validate the deployed identity in a test account.

Google POST reads and Alibaba's signed read routes are individually constrained.
Do not broaden transport rules from `GET`/`list` naming alone. CAI RESOURCE reads
also have an asset-type allowlist; inventory must not bypass the content boundary.

## Adding a check

`checks.py` and `checks_alicloud.py` are pure metadata evaluators. Predicates make
no network or filesystem calls. Define a stable ID, native resource kind, fixed
summary, evidence paths, rule version, severity and policy assumptions. Missing,
inherited or malformed evidence yields `unknown`. Inspect all relevant resources
before claiming effective IAM access, routing or admission behavior; an isolated
configuration flag does not establish those properties.

Return fixed explanations and paths, not arbitrary values copied from resource
documents. Test meaningful pass/fail cases, missing evidence, defaults, malformed
shapes and provider-specific exceptions. New check registrations automatically
appear in `list_security_checks` and `sec-auditor checks`.

## Deployment-specific extensions

This release has one default Alibaba credential binding per process. Multi-account
role routing would require an operator-controlled role map, separate immutable
credential sessions and STS verification for each target account. Resource
Directory membership alone must never authorize a member account query.

Private Alibaba endpoints, additional service-specific log formats and custom
Kubernetes resources require reviewed adapters. The registered ACK reader accepts
only operator-configured endpoint/CA/token bindings and reuses the same explicit
Kubernetes kind allowlist as GKE. Agent-supplied kubeconfigs and executable auth
plugins are outside this extension boundary.
