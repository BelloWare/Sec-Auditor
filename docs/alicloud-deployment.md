# Deploying Alibaba and ACK collection

The Python package and container support either cloud independently or both in
one server. Google ADC and Alibaba credentials are separate. On ACK, use RRSA
for Alibaba API calls and a second projected Kubernetes service-account token
for native Pod/policy reads. On GKE, keep Workload Identity for Google and supply
an independently configured Alibaba OIDC trust/credential binding.

## Account permissions

Start from `deploy/alicloud/read-policy.json`, generated from the exact compiled
catalog with `sec-auditor ram-policy`. Review its read actions and reduce the
resource scope where supported. Attach it to the dedicated RAM auditing role.
No `oss:GetObject`, `oss:ListObjects`, `kms:GetSecretValue`, decryption, cluster
kubeconfig retrieval, instance user-data reads or resource mutations are granted.
The RDS TLS-description permission is deliberately absent because its response
can contain server private-key material. Existing Cloud Config findings may supply
TLS evidence instead; the service must not infer missing TLS settings as passing.

SLS access is separate: edit `deploy/alicloud/sls-read-policy.example.json` to the
exact permitted project/logstore ARN. Grant `log:GetLogStoreLogs` only on the stores
you register. Logs must already be collected and indexed. The MCP does not enable
logging, create indexes or change retention.

Read [authentication and account boundaries](alicloud-authentication.md) for the
STS identity proof and official credential chain. The runtime verifies the
credential's actual account; a list of allowed accounts does not create cross-
account sessions. Use a separately bound server for each account when needed.

## ACK deployment example

`deploy/alicloud/kubernetes/` contains a complete deployment example: namespace,
service account, explicit read-only RBAC, configuration, PVC, hardened single-
replica deployment, ClusterIP Service and ingress NetworkPolicy.

Before applying it:

1. Enable ACK RRSA and obtain the cluster OIDC provider ARN and issuer.
2. Create a RAM role whose OIDC trust restricts issuer, `oidc:aud=sts.aliyuncs.com`,
   and `oidc:sub=system:serviceaccount:sec-auditor:sec-auditor`.
3. Grant the reviewed metadata policy and, if used, the exact SLS policy.
4. Replace account, region, cluster ID, RAM role and OIDC provider placeholders.
   Set an immutable image digest built from this repository. Review the storage
   class, service resource limits and network rules.
5. Configure the MCP caller JWT issuer/JWKS/audience/allowed subjects and HTTPS
   gateway as described in [deployment](deployment.md). These caller credentials
   do not become the cloud identity.
6. Review the RBAC resource list. It grants `get`/`list` for exactly the native
   Kubernetes kinds advertised by the service; it grants no Secrets, ConfigMaps,
   pod logs, exec, impersonation or writes. For narrower namespace access, adapt
   the binding to your selected namespaces and keep ungranted reads as explicit
   coverage errors.

The example manually configures the RRSA token projection, so it does not depend
on the optional pod identity webhook. There are two volumes:

| Projection | Purpose |
| --- | --- |
| `/var/run/sec-auditor/rrsa/token`, audience `sts.aliyuncs.com` | Official Alibaba credential SDK exchanges it for RAM-role STS credentials. |
| `/var/run/sec-auditor/kubernetes/token`, API-server default audience | Native ACK Kubernetes authentication under the narrow RBAC binding. |
| `/var/run/sec-auditor/kubernetes/ca.crt` | Projected `kube-root-ca.crt` CA used to verify the Kubernetes endpoint. |

Tokens rotate through Kubernetes projection. The SDK refreshes Alibaba STS
credentials, and the native reader reopens the Kubernetes token for requests.
`automountServiceAccountToken: false` prevents an extra implicit token volume;
the two explicit projections still work. The service does not call the Kubernetes
ConfigMap API to obtain the mounted CA; the kubelet supplies the projected file.

```bash
kubectl apply -f deploy/alicloud/kubernetes/
kubectl rollout status deployment/sec-auditor -n sec-auditor
```

These are administrator deployment commands. The MCP runtime does not run them.
Only one deployment in this example should manage the named SQLite PVC; the GKE
and ACK manifests are alternative starting points, not concurrent installations
in the same namespace.

## Registered cluster connection

The deployment registers its own ACK cluster as:

```json
{
  "accounts/1234567890123456/regions/cn-hangzhou/clusters/your-cluster-id": {
    "server": "https://kubernetes.default.svc",
    "ca_file": "/var/run/sec-auditor/kubernetes/ca.crt",
    "token_file": "/var/run/sec-auditor/kubernetes/token"
  }
}
```

Set this JSON in `SEC_AUDITOR_ALICLOUD_KUBERNETES_CLUSTERS`. Cluster account/region
must be explicitly allowed. This is a trusted operator binding: native Kubernetes
identity is proved by the endpoint CA and Kubernetes token, not by an Alibaba STS
lookup. An agent can select only a registered canonical cluster ID, never a URL,
certificate, file path or arbitrary authentication plugin.

For a remote cluster, provision a network path, its trusted CA and an externally
rotated token for the narrow auditing Kubernetes service account. Do not paste a
cluster-admin kubeconfig into this setting. The service blocks redirects and
metadata/loopback/link-local endpoints and always verifies TLS; endpoints and
credentials are not fetched from untrusted resource documents.

## Registered SLS logstores

Set `SEC_AUDITOR_ALICLOUD_LOGSTORES` to operator-selected destinations, for example:

```json
{
  "production-flows": {
    "account_id": "1234567890123456",
    "region": "cn-hangzhou",
    "project": "security-audit",
    "logstore": "vpc_flows",
    "category": "vpc_flows"
  }
}
```

Allowed categories are `audit`, `vpc_flows`, `firewall` and `kubernetes`. Select the
same category in `query_logs`. The reader uses current `GetLogsV2`, fixed search
`*`, bounded time intervals and at most 100 rows; there is no caller SQL. Configure
separate logstore aliases for audit/flow/firewall formats. Unknown fields are
removed; custom formats require a reviewed projection. Incomplete SLS searches
must be retried at the same offset and are never marked complete.

## Live acceptance

Run representative reads using the actual deployed role: one ECS page, a nested
security-group page, an OSS bucket setting with ownership verification, RAM policy
metadata, one registered Pod page, a short ActionTrail interval, and a registered
SLS interval. Confirm expected denials, pagination and redaction markers. A healthy
HTTP readiness endpoint confirms process readiness, not cloud or Kubernetes
permissions. This repository was tested offline with official SDK signers and
native-shaped fixtures; it has not been deployed into your account.

Primary references:

- [RRSA token projection, trust conditions and manual configuration](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services)
- [Projected service-account tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [SLS GetLogsV2](https://www.alibabacloud.com/help/en/sls/developer-reference/api-sls-2020-12-30-getlogsv2)
- [RDS SSL response, including ServerKey](https://www.alibabacloud.com/help/en/rds/developer-reference/api-rds-2014-08-15-describedbinstancessl)
