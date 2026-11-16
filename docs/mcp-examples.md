# MCP read guide

The connector exposes six tools. Your agent chooses resources and follows
continuations; the connector does not turn a request into an assessment plan.
Every example below is tool argument JSON, not a shell command or free-form
provider request. Replace example scopes, locations, accounts and names.

## 1. Discover available operations

Call `capabilities`:

```json
{"provider":"gcp","kind_prefix":"gcp.iam.","page_size":20}
```

Follow `next_cursor` with the same discovery filters/page size when present. The
result groups cloud operations in each kind's `queries.list` and `queries.get`.
Entries declare permissions, locations, scope types, parent/resource ID formats,
selectors and pagination. Kubernetes entries declare namespaced versus
cluster-scoped resources and exact-get requirements. Unsupported operations are
not reachable through another generic proxy tool.

Offline discovery exposes the same compiled catalog:

```bash
sec-auditor catalog --provider gcp
sec-auditor catalog --provider alicloud
sec-auditor catalog --provider kubernetes
```

## 2. Discover GCP inventory

Call `search_inventory` for one authorized organization/folder/project page:

```json
{
  "scope":"organizations/123456789012",
  "mode":"search",
  "query":"",
  "asset_types":["compute.googleapis.com/Instance"],
  "page_size":50
}
```

`mode=configurations` reads approved configuration snapshots; it does not accept
a search expression. `mode=iam` searches indexed IAM policies. Inventory is
eventually consistent, and IAM search may return only matching bindings. Traverse
all pages and required child scopes explicitly. Native resource gets can provide
fresher detail than an inventory snapshot.

## 3. Read explicit cloud resources

Call `collect_resources` for native GCP exact/nested reads:

```json
{
  "queries":[
    {"project":"prod-a","kind":"gcp.compute.instances","operation":"get","resource_id":"web-01","location":"us-central1-a"},
    {"scope":"organizations/123456789012","kind":"gcp.iam.denyPolicies"},
    {"project":"prod-a","kind":"gcp.storage.bucketIamPolicy","operation":"get","resource_id":"example-bucket"}
  ]
}
```

GCP accepts exactly one `project` or canonical `scope`. Some Compute gets require
a `location_type` selector in addition to `location`; inspect the exact capability.
Bucket ownership is proved before globally addressed settings are read. Neither
bucket listing nor bucket settings grant object content access through this tool.

Alibaba examples using the same tool:

```json
{
  "queries":[
    {"provider":"alicloud","account_id":"1234567890123456","kind":"alicloud.ram.roles","operation":"get","resource_id":"application-role"},
    {"provider":"alicloud","account_id":"1234567890123456","kind":"alicloud.ram.rolePolicies","parent":"application-role"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.securityGroupRules","parent":"sg-example"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.oss.bucketAcl","operation":"get","resource_id":"example-bucket"}
  ]
}
```

Account-global RAM operations omit `location`. Regional operations require an
allowed endpoint region. Resource Directory discovery does not authorize another
account. Each Alibaba read uses credentials whose actual account is independently
verified.

GCP and Alibaba queries can share one batch:

```json
{
  "queries":[
    {"project":"prod-a","kind":"gcp.compute.instances","page_size":25},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.instances","page_size":25}
  ]
}
```

Results stay in query order. One denied target does not turn successful targets
into failures; inspect each result's `errors` and `next_cursor` independently.
Batching is bounded concurrency, not a persisted job.

## 4. Read Kubernetes definitions

Call `inspect_kubernetes` to list GKE Pods and fetch one registered ACK Deployment:

```json
{
  "queries":[
    {"provider":"gcp","cluster":"projects/prod-a/locations/us-central1/clusters/apps","kind":"Pod","namespace":"production","page_size":50},
    {"provider":"alicloud","cluster":"accounts/1234567890123456/regions/cn-hangzhou/clusters/your-cluster-id","kind":"Deployment","operation":"get","resource_id":"api","namespace":"production"}
  ]
}
```

The same `operation=get` works for a named GKE Pod or any of the other approved
kinds. `resource_id` is one Kubernetes object name, never a path or subresource.
Namespaced gets require `namespace`; cluster-scoped kinds reject it. List
operations can span namespaces when authorized. The ACK cluster must be
registered by the operator.

Both providers preserve the same projection and allowlist. Secret references and
security contexts can be returned, while inline environment values, commands,
annotations and sensitive probe/volume fields are removed. Secret and ConfigMap
objects, pod logs, exec, attach and arbitrary resources are excluded.

## 5. Read IAM context

Call `get_iam_context`:

```json
{"scope":"projects/prod-a","include_ancestors":true}
```

The connector reads direct allow policies and any authorized ancestors. It does
not calculate effective principal permissions. Inspect conditions, deny policies,
principal access boundaries and role definitions using their explicit catalog
queries. A service account's own IAM policy describes access to that account;
it is not the list of all resource grants made to that account.

## 6. Read audit and flow telemetry

Call `query_logs`, defaulting to the last hour:

```json
{
  "queries":[
    {"project":"prod-a","category":"audit","page_size":100},
    {"project":"prod-a","category":"vpc_flows","page_size":100},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","category":"audit","page_size":50},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","category":"vpc_flows","logstore":"production-flows","page_size":100}
  ]
}
```

Use timezone-aware ISO timestamps for explicit `start_time` / `end_time`. The
first page fixes a default time interval for subsequent continuations. GCP
supports constrained Logging filters and authorized log views. Alibaba uses
bounded ActionTrail or operator-registered SLS destinations with fixed search;
no caller SQL is exposed. Request/response bodies and opaque payloads are removed.
An empty interval does not prove an absence of events or complete log collection.

## Paging and oversized responses

Each target contains `items`, `errors`, `warnings`, `coverage`, `next_cursor` and
`response_truncated`. Continue with the returned cursor and the same original
query. Do not share cursors between callers, providers, tools or targets. A native
empty page can still have a continuation; keep following it. Time-window and
sampling metadata remain relevant to every conclusion.

The connector retains no resource data for later lookup. If a projected response
does not fit its budget, it returns `RESPONSE_TOO_LARGE`, no partial rows and no
advancing cursor. Retry the original input cursor with fewer batched queries or
selected output fields. For example, narrow a resource request:

```json
{
  "queries":[
    {
      "project":"prod-a",
      "kind":"gcp.compute.instances",
      "page_size":50,
      "fields":["data.name","data.shieldedInstanceConfig","data.networkInterfaces"]
    }
  ]
}
```

Field selection happens after mandatory projection. Asking for removed fields
cannot retrieve them. `fields` may change while resuming the original cursor;
other query arguments, including `page_size`, are bound. To reduce `page_size`,
restart without a cursor. `search_inventory` and `get_iam_context` also accept
`fields`; batch tools put it inside each query.

There is no evidence ID, assessment ID, polling endpoint or stored-result tool.
If your agent needs a durable record, save the returned projected data in its own
application with the associated timestamps, errors and coverage qualifications.
