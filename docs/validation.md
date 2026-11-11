# Validation of version 0.2.0

This implementation was validated in the local Python 3.12 environment. No live
GCP organization, Alibaba account or Kubernetes cluster was accessed or modified.

| Gate | Result |
| --- | --- |
| Offline pytest suite | 822 tests passed |
| Ruff lint | Passed |
| Ruff formatting | Passed |
| Dependency consistency | Installed packages compatible; production dependencies installed from hashed lockfile |
| Python packaging | Wheel and source distribution built successfully |
| Package contents | Provider modules present; runtime databases, credentials and environment files excluded |
| Documented requests | 16 JSON query examples validated against schemas/capability requirements |
| ACK manifests | Nine YAML documents parse; settings, namespace, bindings, selectors, mounts and probes align |
| ACK RBAC | Exactly the 29 allowlisted kinds; get/list only, no Secrets, ConfigMaps or subresources |
| Alibaba RAM policy | Matches generated catalog actions; unsafe data/key/SSL actions excluded |
| SLS policy | Separate exact-logstore ARN example |

Tests cover native-shaped pagination and malformed responses, project ancestry,
Alibaba credential/account proof and rotation, bucket ownership, nested parents,
provider/actor/query-bound cursors, mixed-provider partial failures, MCP stdio and
HTTP, typed log projection, decompression bounds, token rotation, assessment
budgets/cancellation/persistence, and deterministic check semantics. Official
Alibaba SDK signers are exercised with mocked HTTP, not replaced with hand-written
cryptography. A repeated-projection regression preserves redaction provenance.

The catalog exposes 91 GCP kinds/160 list-get variants, 65 Alibaba kinds/75 query
variants and 29 native Kubernetes kinds. Existing CAI inventory has 45 approved
asset types. There are 211 rule registrations, including 21 Alibaba rules and
136 Kubernetes registrations of shared workload and policy checks. A kind or
rule count is not a compliance-coverage score.

## Remaining deployment validation

Docker image building and GKE/ACK deployment were not performed in this workspace.
Use your trusted image build pipeline, replace all deployment placeholders and
validate representative read calls under the deployed identity. Check enabled
APIs, exact permissions, service home regions, quotas, private-cluster routing,
log collection/indexing and existing scanner availability. Denials and missing
reports remain coverage gaps; the code does not grant itself permissions, enable
services, generate traffic, run vulnerability scans or modify cloud resources.

One process has one default Alibaba credential binding and one SQLite job worker.
Use separately scoped deployments for independent account credentials; distributed
queue/storage/quota coordination is not implemented. The scope allowlists apply
to all authorized MCP callers; caller ownership separates their saved jobs and
evidence, not their available cloud resource scopes.
