# MCP query guide

## Discovery before collection

Call `capabilities` with `{"provider":"gcp","kind_prefix":"gcp.iam."}` or
`{"provider":"alicloud","kind_prefix":"alicloud.oss."}`. The result groups each
kind's operations in `queries.list` and `queries.get`. Those entries describe
permissions, locations, scope types, parent/resource IDs, selectors and pagination.
Use these compiled names; the service is not a general cloud-API proxy.

The same catalog is available offline:

```bash
sec-auditor catalog --provider gcp
sec-auditor catalog --provider alicloud
sec-auditor checks
```

## GCP precise and inherited queries

Example `collect_resources` arguments:

```json
{
  "queries": [
    {"project":"prod-a","kind":"gcp.compute.instances","operation":"get","resource_id":"web-01","location":"us-central1-a"},
    {"scope":"organizations/123456789012","kind":"gcp.iam.denyPolicies"},
    {"project":"prod-a","kind":"gcp.storage.bucketIamPolicy","operation":"get","resource_id":"example-bucket"}
  ]
}
```

Some exact Compute gets also require a `location_type` selector to distinguish
regional and zonal collections; the particular query's capability specifies it.
Use `get_iam_context` for direct/inherited GCP allow policies. Deny/PAB/role
queries supply additional evidence; this service does not calculate effective
principal permissions. Use `search_inventory` for GCP-wide discovery and clearly
marked eventually consistent configuration/IAM snapshots.

## Alibaba nested queries

Example `collect_resources` arguments:

```json
{
  "queries": [
    {"provider":"alicloud","account_id":"1234567890123456","kind":"alicloud.ram.roles","operation":"get","resource_id":"application-role"},
    {"provider":"alicloud","account_id":"1234567890123456","kind":"alicloud.ram.rolePolicies","parent":"application-role"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.securityGroupRules","parent":"sg-example"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.oss.bucketAcl","operation":"get","resource_id":"example-bucket"}
  ]
}
```

Account-global RAM operations omit `location`. Regional operations require an
allowed endpoint region. Resource Directory and inventory results cannot grant
access to another account. Each cloud resource request uses credentials whose
actual account is verified independently of query arguments.

## GKE and ACK Pod definitions

Example `inspect_kubernetes` arguments:

```json
{
  "queries": [
    {"provider":"gcp","cluster":"projects/prod-a/locations/us-central1/clusters/apps","kind":"Pod","namespace":"production"},
    {"provider":"alicloud","cluster":"accounts/1234567890123456/regions/cn-hangzhou/clusters/your-cluster-id","kind":"Pod","namespace":"production"}
  ]
}
```

The ACK cluster must already be registered by the operator. Both readers expose
the same safe kinds and projection. Inline environment values, annotations,
commands and sensitive volume/probe fields are removed; Secret references and
security contexts remain useful evidence. Secret and ConfigMap objects, exec,
logs, attach and arbitrary resources cannot be requested through this tool.

## Audit and flow telemetry

Example `query_logs` arguments, defaulting to the last hour:

```json
{
  "queries": [
    {"project":"prod-a","category":"audit","page_size":100},
    {"project":"prod-a","category":"vpc_flows","page_size":100},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","category":"audit","page_size":50},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","category":"vpc_flows","logstore":"production-flows","page_size":100}
  ]
}
```

Use timezone-aware ISO timestamps for explicit `start_time` / `end_time`. GCP
supports constrained Logging filters and authorized log views. Alibaba uses bounded
ActionTrail or exact operator-registered SLS destinations with fixed search; SQL
and arbitrary search expressions are not exposed. Request/response bodies and
opaque log payloads are removed. Flow records and summaries describe observed
traffic; absence does not prove isolation or complete log collection.

## Durable mixed-provider assessments

Use `start_assessment` with explicit `queries` when the question needs nested or
exact reads. Example:

```json
{
  "request": {
    "queries": [
      {"project":"prod-a","kind":"gcp.compute.instances"},
      {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.instances"},
      {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.oss.bucketPublicAccessBlock","operation":"get","resource_id":"example-bucket"}
    ],
    "include_kubernetes": false,
    "include_passes": false
  }
}
```

For discovery, use `scope`/`projects` for GCP or `accounts` plus explicit
`locations` for Alibaba. `resource_kinds` selects top-level discovery collections;
queries requiring parents/IDs must use `queries`. Default scans collect kinds with
applicable checks and available top-level operations. They are not automatic
recursive collection of every possible setting. Budgets apply across all targets.

Poll `get_assessment`, then `list_assessment_results`. Findings reference sanitized
evidence. `evidence_pages` in the summary also preserves observations when no local
check applies, with explicit expiry. `cancel_assessment` stops further reads and
retains already collected results. It changes only the service's job state.

## Reading the response

Each target has its own `items`, `errors`, `warnings`, `coverage`, `next_cursor`,
`evidence_id` and `response_truncated`. `next_cursor` continues upstream collection;
`next_evidence_cursor` pages through already collected sanitized evidence. These
are distinct. Resume with identical original query arguments and the returned
cursor. Never copy a cursor between providers, targets, tools or callers.

Use `get_evidence` to retrieve caller-owned evidence, optionally selecting simple
dot paths such as `data.spec.securityContext`. No unfiltered original payload is
stored. A page can be complete while an entire organization assessment is not.
An empty list, no local check for a kind, an unknown predicate, or a denied API is
never an overall passing security result.
