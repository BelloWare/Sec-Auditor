# Sec-Auditor

Sec-Auditor is a **lightweight, read-only cloud connector** for GCP, Alibaba
Cloud, GKE and registered ACK clusters. Your AI agent decides what to inspect;
the connector validates the request, reads the permitted API, removes sensitive
content and returns the result.

Use the Python `CloudConnector` directly inside your own connector, or run the
optional MCP server. Neither path creates a database, stores collected resources,
starts background assessments or evaluates security controls. Requests are
independent, bounded reads. The cloud query catalog and safety controls are shared
by both entry points.

## Use it as a Python library

Python 3.11 or later is supported. The core install includes the cloud clients;
it does not install the MCP server or its HTTP authentication dependencies.

```bash
git clone https://github.com/BelloWare/Sec-Auditor.git
cd Sec-Auditor
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

```python
import asyncio

from sec_auditor.config import Settings
from sec_auditor.connector import CloudConnector
from sec_auditor.requests import ResourceQuery


async def main():
    settings = Settings(allowed_projects=["your-project-id"])
    query = ResourceQuery(
        project="your-project-id",
        kind="gcp.compute.instances",
        page_size=50,
    )
    async with CloudConnector(settings) as connector:
        while True:
            response = await connector.collect_resources("trusted-agent", [query])
            page = response["results"][0]
            if page["errors"]:
                raise RuntimeError(page["errors"])
            for resource in page["items"]:
                print(resource)
            if not page["next_cursor"]:
                break
            query = query.model_copy(update={"cursor": page["next_cursor"]})


asyncio.run(main())
```

Configure your approved Google ADC source before reading GCP, or the Alibaba
credential chain before reading Alibaba. Cloud credentials are separate from the
`actor` argument. In library mode, your application must authenticate its caller
and pass a stable, trusted actor identifier; the connector uses it to bind
continuation cursors. Exposing an unauthenticated wrapper that lets callers choose
someone else's actor identifier would defeat that isolation.

The public methods are `capabilities`, `inventory`, `collect_resources`,
`inspect_kubernetes`, `iam_context` and `query_logs`. Use these methods instead of
exposing raw provider adapters: the connector applies scope checks, response
projection and budgets. See [embedding and architecture](docs/architecture.md).

## Run the MCP server

Install the MCP extra when you want the supplied server:

```bash
python -m pip install -e '.[mcp]'
export SEC_AUDITOR_ALLOWED_PROJECTS='["your-project-id"]'
sec-auditor serve --transport stdio
```

`sec-auditor` and `python -m sec_auditor` are equivalent entry points. Stdio trusts
the local launching process; diagnostics go to stderr, not protocol stdout.
An MCP client using the common configuration format can launch:

```json
{
  "mcpServers": {
    "sec-auditor": {
      "command": "/absolute/path/Sec-Auditor/.venv/bin/sec-auditor",
      "args": ["serve", "--transport", "stdio"],
      "env": {
        "SEC_AUDITOR_ALLOWED_PROJECTS": "[\"your-project-id\"]"
      }
    }
  }
}
```

For authenticated Streamable HTTP, configure your existing JWT issuer:

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

Terminate TLS at your gateway and preserve the Authorization and MCP headers.
HTTP requires either an audience/issuer/subject/scope-validated JWT or configured
static bearer authentication. Static mode stores SHA-256 token digests; use
`sec-auditor hash-token` to hash a strong token privately. There is no anonymous
HTTP mode. All authenticated callers share the deployment's configured cloud
scope. Use separately scoped deployments for reader groups requiring different
resource visibility.

## Six read tools

| Tool | Purpose |
| --- | --- |
| `capabilities` | Discover supported kinds, exact operations, required inputs, permissions, scope and limits. Filter by provider/kind prefix and follow discovery pagination. |
| `search_inventory` | Read GCP organization/folder/project inventory, configuration snapshots or indexed IAM policy search. |
| `collect_resources` | Read a batch of explicit GCP/Alibaba list/get queries with independent results and cursors. |
| `inspect_kubernetes` | List approved object kinds or get a named Pod, workload, policy or other approved object from GKE/registered ACK. |
| `get_iam_context` | Read GCP direct IAM allow policies, optionally including authorized ancestors. |
| `query_logs` | Read bounded, projected audit, flow, firewall and Kubernetes security telemetry. |

Bulk tools execute independent queries concurrently within shared process limits.
They do not schedule a scan or infer what to inspect next. The caller traverses
parents, selects regional locations and follows each result's continuation.

Offline catalog discovery needs no cloud credentials:

```bash
sec-auditor catalog --provider gcp
sec-auditor catalog --provider alicloud
sec-auditor catalog --provider kubernetes
sec-auditor ram-policy
```

See [MCP request examples](docs/mcp-examples.md) for every tool and common query
families, including mixed-provider batches and named Kubernetes reads.

## Query coverage

| Provider | Implemented surface |
| --- | --- |
| GCP | 91 resource kinds and 160 reviewed list/get variants, plus Cloud Asset Inventory and bounded log reads. Hierarchy, IAM/organization policies, VMs, networking/firewalls, GKE, storage configuration, databases, serverless, KMS/secret metadata, logging and existing security reports. |
| Alibaba Cloud | 65 resource kinds and 75 configuration/query variants across 13 services, plus registered SLS log reads. ECS, VPC, OSS, RAM, Resource Directory, ACK, RDS, SLB, KMS, ActionTrail, Cloud Config, Security Center and Container Registry. |
| Kubernetes | 29 approved kinds, each with list and exact get, shared by GKE and registered ACK. Pods/controllers, RBAC, networking/admission, nodes and storage configuration. |

All existing cloud reads are available independently of the removed auditor.
These are maintained allowlists, not every cloud API or command. The connector
does not accept arbitrary `gcloud`, `aliyun`, `kubectl`, URLs or HTTP bodies.
Runtime `capabilities` and the [GCP](docs/gcp-coverage.md),
[Alibaba](docs/alicloud-coverage.md) and [Kubernetes](docs/kubernetes.md) references
state the exact supported operations. The [question matrix](docs/query-coverage.md)
explains where live configuration, existing reports or additional sensors are
needed. Add new operations through the [reviewed catalog extension](docs/extending-providers.md)
path; an API being named Get or Describe is not sufficient to make it safe.

Query support and IAM permission are separate. The recommended Alibaba
[strict metadata IAM profile](deploy/alicloud/terraform/README.md) grants 202
reviewed actions across 34 RAM namespaces, including services without a connector
adapter yet. It also denies some registered queries whose native responses mix
metadata with content. `capabilities` describes implemented queries and their
required permissions; it does not establish that the deployed identity holds
those permissions. Denied reads remain explicit coverage gaps.

## Authentication and read-only boundaries

The MCP caller authenticates to the connector. Cloud requests use the deployment's
own provider-specific identity; the caller's bearer token is never forwarded.
On GKE, Google ADC can use Workload Identity Federation to the linked GSA with your
organization-level `roles/iam.securityAuditor` grant. Alibaba uses its own official
credential chain, including RRSA/OIDC or STS, and verifies the credential account.
ACK native Kubernetes reads use a separately registered endpoint, CA and rotating
read-only Kubernetes token. Cloud IAM and cluster connectivity remain separate.

Configure explicit organization/project or Alibaba account/region allowlists.
The connector verifies project ancestry, nested-parent ownership, account identity
and bucket ownership where applicable. `roles/iam.securityAuditor` is the chosen
GCP starting grant; particular APIs, log views or inventory products can require
additional permissions or configuration. Denials are returned to the caller.
Nothing grants permissions or enables cloud services automatically.

For Alibaba, use the standalone
[`alicloud_security_auditor.tf`](deploy/alicloud/terraform/alicloud_security_auditor.tf)
to attach an exact metadata allowlist and a matching `Deny`/`NotAction` guardrail
to an existing dedicated RAM role. The guardrail rejects actions outside that
allowlist even if another policy grants them. The generated
[`read-policy.json`](deploy/alicloud/read-policy.json) is the 75-action connector
catalog permission contract, including 11 mixed-content or opaque-response
actions excluded by the strict profile. Those queries rely on application
projection; that policy alone does not enforce a metadata-only boundary in RAM.
ActionTrail event bodies and SLS log payloads require a separate, deliberately
broader deployment. An additional log-read allow cannot override the strict guard.

The routes exclude GCS/OSS object listing and downloads, Kubernetes Secrets and
ConfigMaps, secret payloads, private key material, database rows, message bodies,
pod/VM execution and cloud mutations. Known sensitive fields in allowed metadata
are projected out, including literal environment values, commands, annotations,
startup content and opaque log request/response payloads. `fields` selects only
from that already projected result; it cannot recover removed content. Remaining
names, labels and policy text are untrusted data and can contain user-authored
values. Projection is not a guarantee that arbitrary metadata never contains a
secret.

The supplied Kubernetes RBAC grants no Secret-object access but cannot hide
literal environment values or commands inside an allowed Pod definition. Native
workload reads use the connector's projection as well as a separate Kubernetes
identity; the Alibaba RAM profile does not impose field restrictions on
Kubernetes responses.

## Pagination, response limits and replicas

Each read returns one complete bounded source page, per-target errors and an
expiring signed `next_cursor` when another page exists. An empty page can still
have a cursor. An error or an empty collection does not establish good security
posture; the AI agent must interpret source coverage and freshness.

The connector does not retain oversized responses. `RESPONSE_TOO_LARGE` returns
no partial items and no advancing cursor, so it cannot silently skip rows. Retry
with fewer batched queries or a narrower `fields` selection. You can change only
`fields` while reusing the original input cursor; other query arguments,
including `page_size`, remain bound. To reduce `page_size`, restart the query
without a cursor. A single record can also require field selection. No evidence
ID or later evidence-retrieval call is needed.

By default, the cursor signing key exists only in process memory. Cursors stop
working after restart or on a different replica. To preserve them across replicas
and restarts, inject the same secret `SEC_AUDITOR_CURSOR_SIGNING_KEY` as 64 hex
characters and the same scope/authentication configuration. Rotate that key to
invalidate existing cursors. `SEC_AUDITOR_CURSOR_TTL_SECONDS` defaults to 3600.
No persistent volume is needed. Rate/concurrency budgets remain per process,
so size the replica count against shared cloud quotas.

## Deploy and develop

Use the [GKE deployment guide](docs/deployment.md) or the
[Alibaba/ACK deployment guide](docs/alicloud-deployment.md). The container supports
a read-only root filesystem; manifests contain no state volume or PVC.
`.env.example` lists supported settings and must be injected by your launcher;
the application does not automatically load it.

The full MCP container installation is pinned for Python 3.12 in
`requirements.lock` and uses hash verification. For local development:

```bash
python -m pip install -e '.[mcp,dev]'
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

Offline tests exercise mocked cloud responses, real SDK signing, authorization,
projection, pagination, budget handling and MCP transports. They do not establish
live permissions, private-cluster connectivity or telemetry availability in your
accounts. See [validation](docs/validation.md) for the verification scope.

## Migrating from 0.2

Version 0.3 keeps the six read-tool names and removes `list_security_checks`,
`run_security_checks`, `get_evidence`, `start_assessment`, `get_assessment`,
`list_assessment_results` and `cancel_assessment`. `CloudConnector` replaces the
old `SecurityService` embedding API. Assessment request types, check predicates,
SQLite storage and worker code are removed from the package.

Remove state-path, assessment-budget, evidence-TTL and retention settings from
your deployment; use the cursor settings above instead. Remove the old PVC from
your installation only after handling any historical data under your own retention
policy. Applying the new manifests does not delete an existing PVC. Old cursors
and evidence/job identifiers do not carry forward. Read responses contain returned
data directly, with no stored-evidence references. Your agent owns any persistence,
planning, policy evaluation or workflow that it needs.
