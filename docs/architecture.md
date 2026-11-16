# Connector architecture

Sec-Auditor has one read implementation, `CloudConnector`, and an optional MCP
transport adapter. The connector accepts typed queries, authorizes their targets,
executes reviewed API reads, projects sensitive fields and returns bounded data.
The agent supplies the inspection plan and decides what the observations mean.
There is no assessment engine, background worker, database or result repository.

## Embedding boundary

```python
from sec_auditor.config import Settings
from sec_auditor.connector import CloudConnector
from sec_auditor.requests import KubernetesQuery, ResourceQuery


async def inspect_for_authenticated_actor(actor: str):
    settings = Settings(allowed_projects=["your-project-id"])
    async with CloudConnector(settings) as connector:
        return await connector.collect_resources(
            actor,
            [ResourceQuery(project="your-project-id", kind="gcp.compute.instances")],
        )
```

The host application authenticates `actor` before calling this function. It must
not derive the actor from an unverified query field. Keep a connector instance for
the lifecycle of a long-running host when connection reuse and stable ephemeral
cursors matter; the context manager closes its clients on exit. The constructor
accepts provider/client injection for testing. Use the public connector methods,
not raw adapters, as the application-facing API.

A core-only installation (`pip install .`) has no MCP or HTTP server dependency.
`pip install '.[mcp]'` adds the supplied stdio/Streamable HTTP adapter. Both use
exactly the same authorization, read catalog, projection and output budgets.

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `connector.py` | Public `CloudConnector`, lifecycle, target authorization, bounded bulk dispatch, resource projection and response envelopes. |
| `requests.py` / `models.py` | Typed provider-aware queries, observations and source errors. |
| `config.py` | Explicit cloud scopes, caller authentication, request/response budgets and cursor settings. |
| `cursors.py` | Canonical serialization and signed, expiring, caller/query-bound continuation tokens. No database. |
| `server.py` | Six MCP tools and authenticated HTTP application. Optional runtime. |
| `auth.py` | JWT issuer/audience/subject/scope verification or comparison against configured bearer-token hashes. |
| `policy.py` | GCP identity/ancestry authorization with a bounded short-lived cache. |
| `transport.py` | Google ADC, fixed host/method rules, concurrency/rate limits, retries and response caps. |
| `providers/catalog.py` / `providers/gcp_queries.py` | Compiled GCP route/permission/input and pagination contracts. |
| `providers/gcp.py` | Native GCP resource, IAM and inventory adapters. |
| `providers/alicloud_catalog.py` | Fixed Alibaba actions, versions, parameters, permissions and native pagination. |
| `providers/alicloud_transport.py` | Official credentials/signing, same-session account proof, response limits and OSS/SLS request boundaries. |
| `providers/alicloud.py` | Alibaba collectors and their native response normalization. |
| `providers/kubernetes.py` | GKE endpoint discovery, TLS, explicit kind allowlist, list/get requests and bounded retry behavior. |
| `providers/kubernetes_registered.py` | Operator-registered ACK endpoint/CA and rotating read-only Kubernetes token. |
| `logging_reader.py` / `alicloud_logs.py` | Bounded security telemetry queries. |
| `projection.py` / `alicloud_projection.py` | Known sensitive field exclusions and typed log projections before data leaves the connector. |

## Request execution

A request follows five steps:

1. The MCP adapter verifies the caller, or the embedding application supplies its
   already authenticated actor. Typed query validation rejects unsupported input.
2. Cloud scope policy verifies the requested project/organization, account,
   location and nested resource ownership as applicable.
3. A fixed provider adapter performs one bounded read with the runtime cloud
   identity. Batch items share process limits and retain independent errors.
4. The connector applies mandatory content projection, then any caller-selected
   output fields. Selection cannot recover data removed by projection.
5. A bounded response contains observations, errors, warnings, timestamps and an
   authenticated continuation when needed. The connector retains no observations
   after the request for later retrieval.

Connection pools, credential caches, short-lived identity/endpoint caches and the
cursor signing key may exist in memory. Stateless means no stored observations,
job records or persistent pagination database; it does not mean a new TLS or
credential session is constructed for every read.

## Separate caller and cloud identities

HTTP callers authenticate to this application. Their tokens never become backend
cloud credentials. All approved callers share one deployment's configured cloud
scope. Use separate scope/identity deployments for different visibility groups;
actor-bound cursors alone are not per-user cloud authorization.

GCP uses ADC. The documented GKE deployment links a Kubernetes service account to
the intended organization-auditor Google service account using Workload Identity
Federation. The same Google identity authenticates GKE native API reads. It does
not fall back to the pod's mounted Kubernetes token. See [GKE deployment](deployment.md)
and [Kubernetes access](kubernetes.md).

Alibaba uses the official credential chain and checks STS GetCallerIdentity with
the same immutable credential generation that signs the resource request. One
process has one default Alibaba credential binding. Resource Directory membership
never establishes access to member accounts. The region allowlist controls API
endpoints/home regions; inventory and findings may describe resources elsewhere
in the same verified account. See [Alibaba authentication](alicloud-authentication.md).

ACK native reads have a separate operator-registered endpoint, trusted CA and
projected Kubernetes service-account token. RRSA cloud credentials are not native
Kubernetes credentials. The operator binding establishes cluster attribution;
TLS and Kubernetes RBAC enforce the target connection and reads.

## Read-only and content controls

Caller input never becomes a shell command, executable kubeconfig, arbitrary URL,
API action or request body. POST routes are allowed only for fixed read RPCs.
The native catalogs exclude objects/secret payloads, VM diagnostics and execution,
SQL/message contents, key material and mutations. Kubernetes excludes Secrets,
ConfigMaps, arbitrary custom resources and all subresources including logs,
exec, attach, proxy and port-forward. Exact gets use the same allowlist as lists.

Projection removes known sensitive content embedded in otherwise allowed records:
inline environment values, commands, annotations, arbitrary VM metadata values,
bootstrap content and opaque log request/response payloads. The application must
treat returned resource strings as untrusted data, never instructions. Metadata
can contain unexpected user-authored secrets; deterministic projection is not a
universal secret detector.

## Pagination without storage

Signed cursors contain continuation state, not retained resource records. They
are bound to actor, operation and query, with expiration. Native pagination can
be token-, marker-, offset- or page-number-based, so changing `page_size` requires
restarting without a cursor. Output `fields` is the exception: it can narrow the
already projected response while retrying the same input cursor. It never changes
the underlying read authorization.

If a response exceeds its budget, `RESPONSE_TOO_LARGE` returns no partial rows and
no advancing cursor. Retry using fewer batch items or narrower fields. Restart
with smaller `page_size` if needed. There is no evidence store, replay job or
hidden continuation that skips omitted records. Provider errors and incomplete
upstream responses remain explicit. A native API may return an empty page with
another continuation, and a source can change between reads.

An unset `cursor_signing_key` generates an in-memory key per connector instance.
For replica/restart continuity, configure one shared 64-hex secret and identical
scope/auth policy across replicas. Key rotation invalidates previous cursors.
Cursors expire after `cursor_ttl_seconds` (default 3600). Process request and rate
budgets are independent across replicas; shared cloud quota coordination belongs
to the deployment architecture.

## Coverage limits

The catalogs contain 91 GCP kinds/160 operations, 65 Alibaba kinds/75 operations
and 29 Kubernetes kinds with list/get. Inventory and logging add their own bounded
read surfaces. These are implemented operations, not a guarantee of permissions,
service enablement, scanner freshness, complete telemetry or every cloud product.
See the [question matrix](query-coverage.md) and provider coverage references.
