# Extending read coverage

The connector exposes reviewed queries, not arbitrary CLI or HTTP execution.
GCP and Alibaba implement the `CloudProvider.query_resources` contract. Query
inputs select the provider/kind, project or canonical scope/account, operation,
location, parent, resource ID, declared selectors, page size and continuation.
Kubernetes has a fixed kind-to-route mapping for list and exact get.

## Shared contract

`capabilities()` groups cloud kinds with `operations` and a `queries` map containing
exact requirements for each operation. Offline `sec-auditor catalog` exposes the
catalog without credentials. A provider `CollectionResult` contains:

- Native-shaped `ResourceRecord` observations with provider, canonical identity,
  project/account, location, source and observation/freshness metadata.
- A native continuation token, replaced at the connector boundary with a signed,
  expiring caller/query-bound cursor.
- Source errors, warnings and relevant API metadata.

Provider observations are internal. `CloudConnector` is the reusable public
boundary because it applies scope validation, mandatory projection and budgets.
Do not expose a raw provider as an alternative agent tool.

## Adding a query

1. Review the primary API schema, authorization reference, locations, required
   inputs, every returned field and native pagination. A Get or Describe method
   can return passwords or private keys. For example, Alibaba
   `DescribeDBInstanceSSL` is excluded because its response can contain a private
   server key.
2. Add a fixed specification in `providers/catalog.py` / `providers/gcp_queries.py`
   for GCP, or `providers/alicloud_catalog.py` for Alibaba. Declare exact required
   permissions, parent/resource identifiers, selector validation and operation
   semantics. Never accept caller-defined actions, URLs or native request bodies.
3. Prove scope at the resource boundary. Verify globally named bucket ownership;
   constrain nested parents to the authorized root; prove the Alibaba credential
   account independently of query arguments. Never follow an endpoint URL found
   inside an untrusted resource record.
4. Preserve native continuation, freshness and partial errors. An empty page may
   still have a next token. Respect API-specific minimum/maximum page sizes and
   page-number versus token semantics.
5. Define content projection before returning data. Prefer excluding an API that
   intrinsically retrieves forbidden content, even if output redaction seems
   possible. Optional output fields operate only after this mandatory projection.
6. Add meaningful positive, denial, malformed-response, pagination, ownership,
   projection and transport tests. Update the coverage table and capability
   metadata. Validate representative reads with the deployed identity separately.

Google POST reads and Alibaba signed actions are constrained independently at the
transport. CAI resource snapshots also have an explicit asset-type allowlist.
Do not widen these boundaries based only on HTTP method or an API name.

## Extending Kubernetes reads

Add only reviewed kinds with a fixed group/version/plural, namespaced flag and
safe output projection. Lists and gets must share the allowlist. An exact get
requires one object name and a namespace for namespaced kinds; no caller path or
subresource is accepted. Validate returned kind/name/namespace before exposing it.
Update explicit read-only RBAC examples for the same resources and `get`/`list`
verbs. Do not add Secrets, ConfigMaps, arbitrary CRDs, execution or log subresources
as a shortcut to broader coverage.

## Deployment-specific integrations

One process currently has one Alibaba credential binding. Multi-account role
routing requires an operator-controlled role map, separate immutable credential
sessions and independent STS proof for each account. Listing Resource Directory
accounts does not create access to them.

Additional private endpoints, service-specific log formats and custom Kubernetes
resources require reviewed adapters. ACK accepts operator-configured endpoint,
CA and token bindings; it never accepts agent-supplied kubeconfigs or executable
authentication plugins.

Policy evaluation, findings persistence and inspection workflows belong in the
calling agent/application. A new read query does not need a built-in assessment
rule or background job to become available.
