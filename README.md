# Sec-Auditor

Sec-Auditor is a Python MCP server for **GCP and Alibaba Cloud security evidence**:
cloud configuration, identity policies, Kubernetes workload definitions, audit
logs, VPC flow logs and existing vulnerability/posture findings. It supports
mixed-provider parallel reads and durable assessments with explicit coverage.

The runtime calls a compiled catalog of cloud and Kubernetes APIs using official
credential/signing libraries. On GKE, Google ADC uses Workload Identity Federation
to the GSA with your organization-level `roles/iam.securityAuditor` grant. Alibaba
uses its own credential chain, including RRSA/OIDC and short-lived STS credentials,
and verifies the actual account before resource reads. No cloud CLI subprocess is
involved. See [architecture](docs/architecture.md) for the boundaries.

## Current coverage

| Area | Implemented surface |
| --- | --- |
| MCP | 13 typed tools; stdio and authenticated Streamable HTTP; one consistent provider-aware query shape |
| GCP | 91 resource/query kinds and 160 reviewed list/get operations, plus scoped Cloud Asset inventory and bounded log reads |
| Alibaba Cloud | 65 kinds and 75 reviewed configuration/query operations across 13 services, plus registered SLS log queries |
| Kubernetes | 29 allowed kinds shared by GKE and registered ACK clusters: Pods/controllers, RBAC, networking, admission, nodes and storage configuration |
| Checks | 211 resource-kind-specific definitions: 54 GCP, 21 Alibaba, and 136 Kubernetes registrations (18 workload controls across seven kinds plus ten other checks) |
| Execution | Independent target errors/cursors, bounded concurrency/retries, sanitized evidence, expiring caller-owned cursors, durable cancellable jobs |

The [security-question matrix](docs/query-coverage.md) explains which questions
require lists, exact gets, nested reads, inherited settings or existing reports.
[GCP coverage](docs/gcp-coverage.md), [Alibaba coverage](docs/alicloud-coverage.md),
and [Kubernetes coverage](docs/kubernetes.md) document exact support and gaps.
The runtime `capabilities` and `list_security_checks` tools are authoritative;
`sec-auditor catalog` and `sec-auditor checks` provide offline discovery.

These counts describe implemented queries and rule registrations, not universal
cloud coverage or a compliance certification. A completed assessment can still
have denied APIs, unavailable telemetry, partial pages or unknown findings.

The API boundary excludes GCS/OSS object listing and contents, Kubernetes Secrets
and ConfigMaps, secret payloads, key material, database rows, message bodies,
pod/VM execution, arbitrary HTTP and cloud mutations. Allowed metadata/logs can
still contain application text; deterministic projection removes sensitive known
fields before output or persistence. All remaining text is untrusted evidence.

## Install

The source supports Python 3.11 or later. The container and production dependency
lock target Python 3.12; use that version for the locked installation below.
Dependencies are locked with hashes. The MCP SDK dependency is `mcp>=2.3,<3`.

```bash
git clone https://github.com/BelloWare/Sec-Auditor.git
cd Sec-Auditor
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
```

For development and the offline test suite:

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check src tests
```

The `sec-auditor` executable and `python -m sec_auditor` are equivalent entry
points. Inspect the check catalog without cloud credentials:

```bash
sec-auditor checks
```

## Identity and authorized scope

The MCP caller and the cloud reader are separate identities. An HTTP caller's
token authenticates it to this service; that token is never forwarded to Google.
Google and target-cluster requests use the server's ADC identity. All approved
callers of one deployment share its configured cloud scope; separate deployments
are appropriate when reader groups need different cloud access.

Configure at least one explicit organization or project allowlist. Organization
values are numeric organization IDs, not names:

```bash
export SEC_AUDITOR_ALLOWED_ORGANIZATIONS='["123456789012"]'
export SEC_AUDITOR_STATE_PATH='.state/sec-auditor.sqlite3'
```

Replace the example organization ID. A project-only deployment can instead set
`SEC_AUDITOR_ALLOWED_PROJECTS='["your-project-id"]'`. Every target in a batch is
authorized independently. Organization membership and ancestor policy reads also
depend on the reader's Resource Manager access.

For GKE, follow the complete [deployment guide](docs/deployment.md). The linked
service-account setup requires both `roles/iam.workloadIdentityUser` on the GSA
for the selected KSA identity and the KSA's
`iam.gke.io/gcp-service-account` annotation. Grant the GSA
`roles/iam.securityAuditor` on the intended organization. The supplied manifests
use the metadata server, disable the pod's Kubernetes API token mount, and do not
require a downloadable service-account key or a cluster-admin binding.

For development outside GKE, configure an approved
[ADC source](https://docs.cloud.google.com/docs/authentication/application-default-credentials),
such as your organization's service-account impersonation or external workload
identity setup. Cloud authentication alone does not grant target-cluster network
connectivity or authorization.

`roles/iam.securityAuditor` is the chosen starting grant, not a guarantee that
every optional API call succeeds. For example, VM Manager inventory/report reads,
particular log views, and a quota project can have additional permission or
configuration requirements. Review the exact denied operation and the catalog's
permission column before granting a narrowly scoped additional permission.
Missing permissions, disabled APIs, network failures, and unavailable telemetry
are reported as incomplete coverage. The server never expands IAM or enables an
API itself. Also review other inherited/direct grants on the GSA: this service's
restricted routes do not remove privileges the identity holds elsewhere.

## Connect over stdio

Stdio is suitable when the MCP client launches the server as a trusted local
process. It uses the local process identity and does not require HTTP caller
tokens. Protocol output goes to stdout; diagnostics go to stderr.

A client using the common `mcpServers` configuration format can use:

```json
{
  "mcpServers": {
    "sec-auditor": {
      "command": "/absolute/path/Sec-Auditor/.venv/bin/sec-auditor",
      "args": ["serve", "--transport", "stdio"],
      "env": {
        "SEC_AUDITOR_ALLOWED_ORGANIZATIONS": "[\"123456789012\"]",
        "SEC_AUDITOR_STATE_PATH": "/absolute/path/sec-auditor-state/sec-auditor.sqlite3"
      }
    }
  }
}
```

Replace paths and the organization ID, and ensure that process can obtain ADC.
Use a distinct state database for independent deployments.

## Serve authenticated HTTP

For a shared agent service, use JWT authentication with your existing issuer.
Configure the exact issuer, dedicated audience, HTTPS JWKS endpoint, approved
subjects, and required scopes:

```bash
export SEC_AUDITOR_AUTH_MODE='jwt'
export SEC_AUDITOR_JWT_ISSUER='https://issuer.example.com/'
export SEC_AUDITOR_JWT_AUDIENCE='sec-auditor'
export SEC_AUDITOR_JWKS_URL='https://issuer.example.com/.well-known/jwks.json'
export SEC_AUDITOR_ALLOWED_SUBJECTS='["your-security-agent-subject"]'
export SEC_AUDITOR_REQUIRED_SCOPES='["security:read"]'
export SEC_AUDITOR_PUBLIC_URL='https://sec-auditor.example.com/mcp'
export SEC_AUDITOR_ALLOWED_HOSTS='["sec-auditor.example.com"]'
sec-auditor serve --transport http --host 0.0.0.0 --port 8000
```

These are placeholders for your issuer and TLS gateway. JWTs must have valid
signatures and the required `iss`, `aud`, `sub`, `iat`, and `exp` claims, with
approved subjects and scopes. Only explicitly configured asymmetric signing
algorithms are accepted. The server verifies tokens issued by your issuer; it
does not issue agent credentials.

The public MCP URL is `/mcp`. Put remote access behind HTTPS, preserve the
Authorization and MCP headers, and match the allowed Host headers to your actual
gateway. Plain HTTP public URLs are accepted only for local loopback development.
`/healthz` and `/readyz` are process probes; they do not establish successful cloud
authentication or assessment coverage. There is no unauthenticated HTTP MCP mode.

Machine clients that support a configured bearer header can use static mode:

```bash
sec-auditor hash-token
```

Enter a cryptographically random token of at least 32 characters through the
prompt, or supply it on stdin from your secret-management workflow. This command
prints its SHA-256 digest. Set `SEC_AUDITOR_AUTH_MODE=static` and
`SEC_AUDITOR_STATIC_TOKENS` to a JSON object mapping caller names to those digests.
The client sends the original token as `Authorization: Bearer ...`. Configure no
raw tokens in the repository. Static mode is a preconfigured machine-token mode,
not an OAuth issuer or an OAuth discovery/consent implementation.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `capabilities` | Discover kinds, location requirements, scopes, exclusions, and budgets |
| `list_security_checks` | List versioned check definitions and assumptions, optionally for one kind |
| `search_inventory` | Search resource metadata, configuration snapshots, or IAM bindings at an authorized scope |
| `collect_resources` | Collect a parallel batch of bounded native GCP configuration pages |
| `inspect_kubernetes` | Collect a parallel batch of allowed Kubernetes objects |
| `get_iam_context` | Read a direct allow policy, optionally including ancestor policies |
| `query_logs` | Read bounded, projected log evidence and flow summaries |
| `run_security_checks` | Collect one page per requested query and evaluate applicable checks |
| `get_evidence` | Retrieve caller-owned sanitized evidence, optionally selecting fields |
| `start_assessment` | Queue a durable assessment with project, cluster, location, and check selection |
| `get_assessment` | Poll job status and its coverage/check summary |
| `list_assessment_results` | Page through stored assessment findings |
| `cancel_assessment` | Request cancellation of a caller-owned job |

Jobs and evidence write only the service's local state. Audited cloud resources
remain unchanged. Agent inputs are typed and bounded; no generic command or
arbitrary REST-request tool is exposed.

### Parallel configuration collection

The following blocks show MCP tool names and their JSON arguments. Replace
project IDs and cluster names with authorized targets.

`collect_resources`:

```json
{
  "queries": [
    {"kind": "gcp.compute.instances", "project": "your-project-id", "page_size": 100},
    {"kind": "gcp.storage.buckets", "project": "your-project-id", "page_size": 100},
    {"kind": "gcp.run.services", "project": "your-project-id", "location": "us-central1", "page_size": 100}
  ]
}
```

Each batch item has its own records, errors, and continuation. Compute aggregated
collections include their supported zones/regions; some other APIs require an
explicit region or zone. Missing a required location is an error, not an implicit
request for every location.

### Read pod definitions and cluster policy

`inspect_kubernetes`:

```json
{
  "queries": [
    {"cluster": "projects/your-project-id/locations/us-central1/clusters/your-cluster", "kind": "Pod", "namespace": "apps", "page_size": 100},
    {"cluster": "projects/your-project-id/locations/us-central1/clusters/your-cluster", "kind": "NetworkPolicy", "namespace": "apps", "page_size": 100},
    {"cluster": "projects/your-project-id/locations/us-central1/clusters/your-cluster", "kind": "ClusterRole", "page_size": 100}
  ]
}
```

Omit `namespace` to list a namespaced kind across namespaces. Cluster-wide kinds
must not include a namespace. Requests for Secrets, ConfigMaps, or unsupported
custom kinds are rejected.

### Audit and VPC flow evidence

`query_logs`:

```json
{
  "queries": [
    {"project": "your-project-id", "category": "audit", "page_size": 100},
    {"project": "your-project-id", "category": "vpc_flows", "page_size": 100}
  ]
}
```

Supported categories are `audit`, `data_access`, `vpc_flows`, `firewall`, `gke`,
and `all_metadata`. Optional `start_time` and `end_time` are RFC 3339 timestamps;
queries are bounded by the configured maximum window. `filter` adds a Logging
filter within the enforced project/time/category constraint. `view` can select
an authorized project log view. Flow summaries describe only the returned page,
not every packet or the complete time window. Flow logging and relevant audit
logging must already be configured; the service does not turn them on.

### Evaluate selected resources now

`run_security_checks`:

```json
{
  "queries": [
    {"kind": "gcp.compute.instances", "project": "your-project-id", "page_size": 100},
    {"kind": "gcp.compute.subnetworks", "project": "your-project-id", "page_size": 100}
  ],
  "kubernetes_queries": [
    {"cluster": "projects/your-project-id/locations/us-central1/clusters/your-cluster", "kind": "Pod", "namespace": "apps", "page_size": 100}
  ],
  "include_passes": false
}
```

This evaluates one collected page per query. Follow its continuations or use an
assessment to traverse pages within a larger budget. Discover check IDs with
`list_security_checks` before supplying an optional `check_ids` filter. Passing
results are omitted by default, but status counts still include them.

### Run an assessment and retrieve findings

`start_assessment`:

```json
{
  "request": {
    "scope": "organizations/123456789012",
    "resource_kinds": ["gcp.compute.instances", "gcp.compute.subnetworks", "gcp.storage.buckets", "gcp.container.clusters", "gcp.run.services"],
    "kubernetes_kinds": ["Pod", "Deployment", "NetworkPolicy"],
    "locations": ["us-central1"],
    "include_kubernetes": true,
    "include_passes": false
  }
}
```

Use `projects` and/or full `clusters` identifiers for a narrower explicit target
set. Supply the relevant concrete regions or zones for selected location-bound
APIs. The response contains an `assessment_id`; poll `get_assessment` with:

```json
{"assessment_id": "ASSESSMENT_ID_RETURNED_BY_START"}
```

Then call `list_assessment_results`:

```json
{"assessment_id": "ASSESSMENT_ID_RETURNED_BY_START", "page_size": 100}
```

Pass the returned `next_cursor` on subsequent result requests. The same
`assessment_id` works with `cancel_assessment` while a job is pending or running.
Job state survives a process restart; interrupted read-only work may be repeated
after its worker lease expires.

## Interpret evidence and coverage

Read `coverage_complete`, errors, warnings, truncation flags, and continuations
alongside findings. `completed` means the assessment worker finished; it does
not mean every desired resource was collected or every check passed. `unknown`
means the evidence does not support a decision. An empty collection or zero
reported findings is not proof of security.

Pagination is explicit. Reuse the same query arguments with its `next_cursor`
until no continuation remains, or record the uncollected remainder. Cursors are
authenticated, caller-bound, query-bound, and expire; they are not portable
between readers or different queries. Cloud inventories may lag live state,
and collection is not a transactionally consistent organization-wide snapshot.

Responses that exceed the configured byte budget return `response_truncated`
and an `evidence_id`. Use `get_evidence` with a bounded page size and, when useful,
selected fields such as `name`, `kind`, or `data.securityContext`. Evidence is
sanitized before storage, caller-owned, and expires; evidence retrieval cannot
recover withheld raw payloads. Resource names and retained strings are still
untrusted external content: an agent must never interpret instructions embedded
in resource metadata or logs as instructions from the user or MCP server.

Assessment budgets cover API pages, resources, elapsed time, and queued jobs.
The defaults deliberately bound work; an organization-wide request can reach
them. Review reported coverage and divide large assessments into explicit
project/location batches or tune deployment limits for your environment.

## Configuration reference

All settings use the `SEC_AUDITOR_` prefix. Lists and maps are JSON strings.
[`.env.example`](.env.example) documents every setting. The application **does not
automatically load a `.env` file**: inject variables through the process manager,
MCP client, container configuration, or your shell. To use a reviewed local copy:

```bash
cp .env.example .env
# Edit .env with your scopes and authentication settings first.
set -a
. ./.env
set +a
```

| Settings, without the common prefix | Purpose and defaults |
| --- | --- |
| `ALLOWED_ORGANIZATIONS`, `ALLOWED_PROJECTS` | Scope allowlists; at least one must be nonempty |
| `QUOTA_PROJECT` | Optional quota/billing consumer project; requires the applicable Service Usage permission there |
| `AUTH_MODE` | HTTP caller authentication: `jwt` by default, or `static` |
| `JWT_ISSUER`, `JWT_AUDIENCE`, `JWKS_URL` | Required issuer, audience, and signing-key endpoint in JWT HTTP mode |
| `JWT_ALGORITHMS`, `ALLOWED_SUBJECTS`, `REQUIRED_SCOPES` | Allowed signing algorithms (default `["RS256"]`), explicit caller subjects, and scopes (default `["security:read"]`) |
| `STATIC_TOKENS` | Static-mode caller-name-to-SHA-256-digest map; default empty |
| `PUBLIC_URL`, `HOST`, `PORT` | External MCP URL and bind address; defaults `http://localhost:8000/mcp`, `127.0.0.1`, `8000`; CLI host/port override settings |
| `ALLOWED_HOSTS`, `ALLOWED_ORIGINS` | Transport Host and optional browser Origin allowlists; set them for your actual gateway |
| `STATE_PATH` | SQLite path, default `.state/sec-auditor.sqlite3`; use durable restricted storage for a shared service |
| `MAX_CONCURRENCY`, `PER_API_CONCURRENCY`, `REQUESTS_PER_SECOND` | Per-process request bounds, default `12`, `4`, `5` |
| `REQUEST_TIMEOUT`, `REQUEST_RETRIES` | Per-request timeout seconds and bounded retry count, default `30`, `2` |
| `MAX_API_RESPONSE_BYTES`, `MAX_RESPONSE_BYTES` | Upstream Google-response and MCP-response byte budgets, default `16000000`, `500000`; Kubernetes also enforces its own response bound |
| `MAX_BATCH_SIZE`, `MAX_PAGE_SIZE` | Service-wide batch and page limits, default `20`, `200`; stricter native limits also apply |
| `MAX_LOG_HOURS` | Maximum log-query time window, default `24` |
| `MAX_SCAN_PAGES`, `MAX_SCAN_RESOURCES`, `MAX_SCAN_SECONDS` | Total per-assessment budgets, default `20`, `5000`, `600` |
| `MAX_PENDING_JOBS` | Queue bound, default `20` |
| `EVIDENCE_TTL_SECONDS`, `RETENTION_SECONDS` | Evidence/cursor lifetime and retained job lifetime, default `3600`, `86400` |
| `SCOPE_CACHE_SECONDS` | Authorization ancestry cache lifetime, default `60`; use `0` to disable caching |
| `KUBERNETES_ENDPOINT` | GKE control-plane choice: `auto` by default, or `dns`, `private`, `public` |

## Deploy and operate

[The GKE deployment guide](docs/deployment.md) includes the exact identity
bindings, configuration, image build, and deployment steps. The
[manifests](deploy/kubernetes) provide a restricted nonroot pod, ClusterIP Service,
ingress NetworkPolicy, and an RWO volume. The Dockerfile installs the hash-locked
production dependencies. Replace the example image reference with your built
image digest.

Use **one replica with the Recreate strategy** for this SQLite-backed version.
Persist `/data/sec-auditor.sqlite3`; do not share it between independent processes
or scale replicas as a substitute for distributed job/limit coordination. The
database contains sanitized security observations and caller ownership metadata,
so restrict access and backups accordingly. Metadata-server access, DNS, Google
APIs, your JWKS endpoint, and target control-plane connectivity must be available.

## Validation and extension

The test suite exercises fixed API routes, request validation, pagination,
partial failures, scoped access, caller authentication, projection, Kubernetes
collection, check outcomes, and durable job/evidence behavior using mocked cloud
responses. **Live GCP/Alibaba permissions, service availability, target-cluster connectivity,
and deployment still require validation in your environment.** The repository does
not claim that passing offline tests establishes live access or complete audit
coverage.

GCP and Alibaba use the shared service, evidence, checks and job contracts while
retaining separate identity, scope and API implementations. See
[Extending coverage](docs/extending-providers.md) before adding a query or provider.
Alibaba has one credential binding per deployment; auditing another member
account requires a credential binding for that account. No member-account access
is inferred from Resource Directory membership.

### Primary references

- [Google IAM Security Auditor role](https://docs.cloud.google.com/iam/docs/roles-permissions/iam#iam.securityAuditor)
- [Application Default Credentials](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- [Workload Identity Federation for GKE](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [GKE IAM and Kubernetes RBAC](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control)
- [Cloud Audit Logs access control](https://docs.cloud.google.com/logging/docs/audit)
- [VPC Flow Logs](https://docs.cloud.google.com/vpc/docs/flow-logs)
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

See the collector guides for endpoint-specific primary references and limitations.

## Alibaba and mixed-provider usage

Configure Alibaba scopes and the official SDK credential source. A GCP-only
installation leaves these allowlists empty; an Alibaba-only installation can
leave Google scopes empty.

```bash
export SEC_AUDITOR_ALLOWED_ALICLOUD_ACCOUNTS='["1234567890123456"]'
export SEC_AUDITOR_ALLOWED_ALICLOUD_REGIONS='["cn-hangzhou","ap-southeast-1"]'
sec-auditor catalog --provider alicloud
sec-auditor ram-policy > reviewed-ram-policy.json
```

Review the generated policy's exact actions and scope before granting it. It
contains the catalog's metadata actions, with no object downloads, KMS decryption
or secret payload reads. Registered SLS log access has a separate exact-logstore
policy example. See [Alibaba identity](docs/alicloud-authentication.md) and
[ACK deployment](docs/alicloud-deployment.md) for RRSA, projected tokens and RBAC.

One `collect_resources` call can contain both providers:

```json
{
  "queries": [
    {"provider":"gcp","project":"prod-a","kind":"gcp.compute.instances"},
    {"provider":"gcp","scope":"organizations/123456789012","kind":"gcp.iam.denyPolicies"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.instances"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.ecs.securityGroupRules","parent":"sg-example"},
    {"provider":"alicloud","account_id":"1234567890123456","location":"cn-hangzhou","kind":"alicloud.oss.bucketPublicAccessBlock","operation":"get","resource_id":"example-bucket"}
  ]
}
```

The `parent`, `resource_id` and `selectors` fields are operation-specific. First
call `capabilities` with `provider` and optional `kind_prefix`; read that kind's
`queries.list` or `queries.get` requirements. Unsupported actions, selectors and
resources fail closed. Global RAM queries omit `location`. Cloud Config and
Security Center use documented service home regions; they can report resources
in other regions of the same verified account. The region allowlist limits API
endpoints, not those findings' resource locations.

For `query_logs`, Alibaba audit queries use `provider=alicloud`, `account_id`,
`location`, and `category=audit`. VPC flow, firewall or Kubernetes audit queries
also name an operator-registered `logstore` alias. `category=kubernetes` is the
provider-neutral Kubernetes log category. Both providers enforce time windows;
SLS has no agent-supplied search expression or SQL. Returned fields are projected
security metadata, including when ActionTrail is read through `collect_resources`.

For `start_assessment`, use `accounts` and `locations` for top-level Alibaba
checks. Use explicit `queries` for nested lists, exact gets, organization-level
queries, or a mixed-provider assessment. Every observed page has a sanitized
`evidence_pages` reference even if no local check applies. Account default scans
do not silently recurse into every identity, bucket, database or service.
Discover parents, then supply the required queries; absent evidence is not a pass.

See [MCP examples](docs/mcp-examples.md) for complete requests and response semantics.
