# Validation of version 0.3

The connector is verified with offline tests and mocked upstream responses.
No live GCP organization, Alibaba account or Kubernetes cluster is accessed or
modified by the test suite. Live identity, permissions, private routing and data
availability require deployment acceptance in your environment.

The version 0.3 validation run on 2026-11-12 passed **753 tests** on Python 3.12.
The 66 warnings came from deprecated datetime usage in upstream Alibaba signing
SDKs. Ruff lint and formatting, dependency compatibility, and source whitespace
checks also passed. Tests include real MCP HTTP/stdio protocol exchanges with
mocked cloud APIs and a fresh-process import test that blocks MCP, its HTTP/auth
stack and SQLite while using the core connector.

## Automated verification gates

Run the full MCP test environment and package build:

```bash
python -m pip install -e '.[mcp,dev]'
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

The relevant contracts are:

| Area | Verified behavior |
| --- | --- |
| Core embedding | Direct connector reads without assessments, workers, SQLite or stored observations. |
| Packaging | The base library can be imported without MCP; the MCP extra supplies server dependencies. |
| Cloud identity/scope | GCP identity and ancestry, nested ownership, Alibaba account proof and credential rotation, and bucket ownership. |
| Pagination | Native token/marker/number handling, per-query cursors, caller/query binding, tamper rejection and expiration. |
| Output budgets | Whole-page success or explicit oversized-response failure; field selection after mandatory security projection. |
| Provider routing | Mixed-provider bulk reads preserve per-target results and failures. |
| Kubernetes | The 29-kind allowlist, exact gets, list pagination, TLS/endpoint controls, projected token rotation and no forbidden subresources. |
| Content controls | Resource/log projection, encoded policy handling, malformed payloads and decompression limits. |
| MCP | Six advertised read tools, real stdio handshake and authenticated HTTP dispatch. |
| Deployment files | No state PVC or state mount; explicit identity projections, narrow RBAC, probes and hardened pod settings. |

Official Alibaba SDK signing is exercised with mocked HTTP rather than replaced
with a handwritten signer. The compiled catalogs preserve 91 GCP kinds/160 cloud
operations, 65 Alibaba kinds/75 cloud operations, and 29 Kubernetes kinds with
list/get. CAI has 45 approved asset types. Counts describe tested implementation
contracts, not a security certification or universal product coverage.

## Remaining live acceptance

Build the container in your trusted pipeline, replace all manifest placeholders
and test representative reads under the deployment's identity. Check API
enablement, exact permissions, service home regions, quotas, network routes,
cluster RBAC, log routing/indexing/retention and existing scanner freshness.
A healthy process probe does not prove access to every cloud target.

Exercise cursor continuation and projected output across a replica/restart when
using a shared cursor signing key. An unset signing key intentionally invalidates
cursors when the process changes. Request/rate limits are per process, so adding
replicas changes total API pressure.

The connector does not grant permissions, enable APIs, start scanners or alter
cloud resources. All approved callers share configured resource scopes; actor
binding isolates continuations, not independent per-user cloud permissions.
