# Deploying Sec-Auditor on GKE

The MCP server uses native Google REST APIs and the official `google-auth`
Application Default Credentials (ADC) implementation. It does not launch
`gcloud` or `kubectl`. Commands below are administrator setup steps, not runtime
tools available to the AI agent.

There are two independent identities:

1. The AI agent authenticates to the MCP endpoint with an audience-bound JWT or
   a preconfigured bearer token.
2. The MCP pod uses its Kubernetes service account (KSA), linked through GKE
   Workload Identity Federation to the Google service account (GSA) that holds
   `roles/iam.securityAuditor` on the organization.

The supplied manifests configure one replica, a private ClusterIP Service,
restricted pod settings, and a persistent volume for SQLite assessment and
evidence state. They contain placeholders and must be configured before use.
They do not create a public ingress or grant Kubernetes cluster-admin.

## 1. Configure Workload Identity

Follow Google's [Workload Identity Federation for GKE guide](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).
Autopilot enables it by default. On Standard, enable the workload pool and use a
node pool configured with the GKE metadata server. For an existing Standard
cluster and the selected node pool, the administrative commands are:

```bash
gcloud container clusters update CLUSTER_NAME \
  --project=CLUSTER_PROJECT_ID --location=CLUSTER_LOCATION \
  --workload-pool=CLUSTER_PROJECT_ID.svc.id.goog

gcloud container node-pools update NODE_POOL_NAME \
  --cluster=CLUSTER_NAME --project=CLUSTER_PROJECT_ID \
  --location=CLUSTER_LOCATION --workload-metadata=GKE_METADATA
```

Use the intended existing GSA, or create it in your security project:

```bash
gcloud iam service-accounts create sec-auditor --project=SA_PROJECT_ID

gcloud organizations add-iam-policy-binding ORG_ID \
  --member=serviceAccount:sec-auditor@SA_PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/iam.securityAuditor

gcloud iam service-accounts add-iam-policy-binding \
  sec-auditor@SA_PROJECT_ID.iam.gserviceaccount.com \
  --project=SA_PROJECT_ID \
  --role=roles/iam.workloadIdentityUser \
  --member='serviceAccount:CLUSTER_PROJECT_ID.svc.id.goog[sec-auditor/sec-auditor]'
```

The last binding is on the GSA itself. Replace `CLUSTER_PROJECT_ID` with the
project hosting the workload identity pool, even when the GSA lives in a
different project. Both that binding and the KSA annotation in
`10-service-account.yaml` are required. Do not create a downloadable GSA key or
mount a credentials JSON file.

The pod's `serviceAccountName` selects the KSA. Google client authentication
obtains credentials from the GKE metadata server. This application does not use
the mounted Kubernetes API token, so the manifests disable automatic token
mounting. Native target-cluster reads use the GSA's Google access token and the
cluster's verified TLS endpoint.

On Standard GKE, uncomment the metadata-server node selector in
`40-deployment.yaml` after configuring the intended node pool. Leave it absent
on Autopilot. Restrict who can create or modify pods using this KSA: a workload
that can run as it can use its cloud permissions. Namespaces and KSA names in
clusters sharing one workload identity pool also need appropriate governance.

## 2. Configure MCP caller authentication

The default Kubernetes manifest uses JWT verification. Set these values in
`20-config-map.yaml` to match the issuer that issues tokens to your AI agent:

| Setting | Meaning |
| --- | --- |
| `SEC_AUDITOR_AUTH_MODE` | `jwt` |
| `SEC_AUDITOR_JWT_ISSUER` | Exact expected issuer, including any trailing slash |
| `SEC_AUDITOR_JWT_AUDIENCE` | Audience dedicated to this MCP service |
| `SEC_AUDITOR_JWKS_URL` | HTTPS signing-key endpoint controlled by your issuer |
| `SEC_AUDITOR_JWT_ALGORITHMS` | Explicit supported asymmetric algorithms, for example `["RS256"]` |
| `SEC_AUDITOR_ALLOWED_SUBJECTS` | JSON array of approved agent subject identifiers |
| `SEC_AUDITOR_REQUIRED_SCOPES` | JSON array, default `["security:read"]` |
| `SEC_AUDITOR_PUBLIC_URL` | Externally reachable HTTPS MCP URL, ending in `/mcp` |
| `SEC_AUDITOR_ALLOWED_HOSTS` | Expected external and internal Host headers |
| `SEC_AUDITOR_ALLOWED_ORIGINS` | Add explicit browser origins only when needed |

The MCP service verifies caller credentials. It does not forward the caller's
token to Google APIs; Google requests use the runtime GSA's ADC credentials.

All approved callers in one deployment share its configured cloud scope. They
do not receive automatic per-user cloud permission delegation. Deploy separate
instances with separate scope policy/identities when distinct reader groups
need different resource access. Assessment and evidence identifiers remain
bound to their initiating caller.

For a machine client with preconfigured headers, static mode is available:

```text
SEC_AUDITOR_AUTH_MODE=static
SEC_AUDITOR_STATIC_TOKENS={"security-agent":"SHA256_HEX_DIGEST_OF_A_RANDOM_TOKEN"}
```

Generate a strong random token in your secret-management workflow. Give the
agent the raw token and configure only its SHA-256 digest in the server. Send
`Authorization: Bearer TOKEN` on requests. Store configuration through your
normal secret/configuration deployment process; do not commit a real bearer
token. Static mode is intended for clients that can supply a configured header,
not an interactive OAuth consent flow.

## 3. Configure cloud scope and query budgets

Replace `ORG_ID` with the numeric organization ID. The value must remain a JSON
array, such as `["123456789012"]`. A narrower deployment can use
`SEC_AUDITOR_ALLOWED_PROJECTS` with explicit project IDs instead. Every request
and each batch item is checked against this policy independently of the GSA's
IAM grants.

If you configure `SEC_AUDITOR_QUOTA_PROJECT`, enable the relevant APIs there and
ensure the GSA has `serviceusage.services.use` on that quota project; the
project-scoped Service Usage Consumer role is one option. The service does not
enable APIs or expand IAM automatically. Disabled APIs, quota errors, missing
permissions, and inaccessible resources appear as incomplete coverage.

Tune concurrency, requests per second, page limits, time windows, assessment
budgets, and retention in the ConfigMap. Limits currently apply within one
process. Do not raise the replica count expecting distributed quota coordination.
Some APIs have organization-wide quotas shared with other tools.

## 4. Network access

Workload Identity requires access to the GKE metadata server. Depending on GKE
dataplane/version, the relevant destination is `169.254.169.254:80` or
`169.254.169.252:988`; use Google's current
[network-policy guidance](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy)
for your cluster. DNS, HTTPS Google API endpoints, and the configured JWKS
endpoint must also be reachable. The sample NetworkPolicy restricts ingress
only; it intentionally does not impose a universally incorrect egress policy.

To permit a caller, label both its namespace and its pods with
`sec-auditor-client=true`. If a gateway forwards requests, permit the gateway's
actual namespace/pod labels. NetworkPolicy enforcement must be enabled in the
cluster. NetworkPolicy labels supplement the application authentication; they
do not replace it.

Target GKE clusters also need a reachable control-plane endpoint. The collector
can use configured DNS, internal IP, or external IP endpoints and validates TLS.
DNS endpoints and private IP endpoints have different network requirements.
See [GKE network isolation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation)
and [the Kubernetes collector guide](kubernetes.md). Authorization does not
establish private network connectivity. Set `SEC_AUDITOR_KUBERNETES_ENDPOINT`
to `auto`, `dns`, `private`, or `public` according to your topology.

For access from outside the cluster, put the service behind your authenticated
TLS gateway or internal load-balancing architecture. Configure HTTPS, the
allowed Host header, and a dedicated audience before exposing `/mcp`. Preserve
the Authorization header and the MCP transport headers. The example manifests
deliberately do not assume an ingress controller, certificate system, or domain.

## 5. Build and apply

Build the image using your normal trusted CI/build service and deploy its
immutable digest:

```bash
docker build -t REGION-docker.pkg.dev/IMAGE_PROJECT/REPOSITORY/sec-auditor:0.2.0 .
docker push REGION-docker.pkg.dev/IMAGE_PROJECT/REPOSITORY/sec-auditor:0.2.0
```

Replace the image placeholder with the resulting `@sha256:...` reference.
The build installs the pinned production dependencies from `requirements.lock`
with hash verification, then installs this package without resolving additional
runtime dependencies. Retain the resulting image digest/SBOM and pin the Python
base image digest in your release process. Replace all organization, identity, issuer, subject, and host
placeholders. Review the storage class and resource limits, then apply:

```bash
kubectl apply -f deploy/kubernetes/
kubectl rollout status deployment/sec-auditor -n sec-auditor
kubectl get pods,svc,pvc -n sec-auditor
```

The deployment uses a single replica with `Recreate` and a ReadWriteOnce PVC.
State belongs on the persistent `/data` volume, not `/tmp`. Back up the volume
according to your operational policy. SQLite is intentionally a single-service
starting point; scaling this deployment requires a shared job/evidence store
and a shared quota scheduler before adding replicas.

`/healthz` and `/readyz` are process/readiness endpoints for probes. A healthy
pod does not establish that every target API or cluster can be accessed. Use
the MCP capability listing and representative collection requests to validate
actual coverage.

## 6. Validate the intended boundary

Before enabling broad agent assessments, run representative tool requests for
inventory, VM configuration, bucket configuration, project IAM, one target
cluster's Pods, and a short audit/flow-log window using the deployed identity.
Verify that pagination and any denials are reported. Do not infer complete
organization coverage from an empty findings array.

The service never adds RBAC bindings, changes workloads, downloads bucket
objects, retrieves Kubernetes Secrets, executes guest commands, pulls Pub/Sub
messages, or queries database rows. It reads existing configuration and reports.
API endpoint access, service activation, networking, and optional security
products determine which observations are actually available. See the exact
[GCP collector coverage](gcp-coverage.md).

## References

- [GKE Workload Identity, including KSA-to-GSA linking](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [ADC with an attached service account](https://docs.cloud.google.com/docs/authentication/set-up-adc-attached-service-account)
- [GKE control-plane endpoints and networking](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation)
- [Cloud Asset Inventory quotas](https://docs.cloud.google.com/asset-inventory/docs/quota)
- [Setting a quota project](https://docs.cloud.google.com/docs/quotas/set-quota-project)

## Alibaba Cloud deployment

The image also includes Alibaba collectors and native ACK readers. Use the separate
[Alibaba deployment guide](alicloud-deployment.md) for an ACK/RRSA deployment or
to add a separate Alibaba credential binding to a GKE-hosted server. Google
Workload Identity alone does not grant Alibaba permissions.
