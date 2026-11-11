# Kubernetes evidence collection on GKE and ACK

The Kubernetes collector reads selected collections from each target cluster's
Kubernetes API. It discovers the endpoint and CA using the GKE API, then sends a
short-lived Google OAuth access token obtained through Application Default
Credentials (ADC). No `gcloud`, `kubectl`, kubeconfig exec plugin, service-account
key file, or Kubernetes Secret read is involved in runtime collection.

## Workload Identity

Run the service under the dedicated Kubernetes service account in the deployment
manifests. With the linked-Google-service-account deployment, grant the Kubernetes
service account `roles/iam.workloadIdentityUser` **on that Google service account**
and annotate the Kubernetes service account with the Google service account email.
The Google service account holds the chosen organization-level audit role. Both
the IAM binding and annotation are required for the linked identity approach.

The GKE metadata server supplies ADC credentials to the process. The collector uses
that Google identity for both GKE metadata and Kubernetes API requests; it never
silently substitutes the pod's Kubernetes API token. A permission denial is returned
as a coverage error. Broad Kubernetes RBAC bindings are not installed by this
project. Existing IAM and RBAC grants can independently affect effective access.

References:

- [Workload Identity Federation for GKE](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [GKE API server authentication](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication)
- [GKE IAM and RBAC](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control)

## Control-plane endpoint selection

The `endpoint_preference` setting accepts:

| Value | Selection |
| --- | --- |
| `auto` | Use the DNS endpoint when user access is enabled; otherwise use an enabled canonical IP endpoint. |
| `dns` | Require an enabled DNS endpoint. |
| `private` | Require the private IP endpoint (`internal` is an API alias). |
| `public` | Require an enabled public IP endpoint (`external` is an API alias). |

DNS endpoints must be under `gke.goog` and use the platform's trusted public CA
store. IP endpoints require a valid `masterAuth.clusterCaCertificate` obtained
from the GKE API; hostname checking and certificate validation remain enabled.
Modern `controlPlaneEndpointsConfig` and older `privateClusterConfig` response
shapes are supported. Redirects, user-supplied endpoints, metadata addresses,
loopback, link-local, multicast, unspecified and reserved IP addresses are rejected.
Proxy settings from the process environment are not used for Kubernetes requests.

Network routing, authorized networks, VPC Service Controls, and IAM still apply.
An internal endpoint requires a network path from the deployment. An enabled DNS
endpoint can be reached through Google API connectivity subject to its controls;
a separate collector inside every target VPC is not inherently required. The
collector reports a failed connection without changing endpoint policy or falling
back to another identity.

Endpoint discovery is cached for five minutes and HTTP connections are reused in
a bounded pool. Each collection has a total deadline, including queueing, metadata
discovery, token acquisition, retries, and response transfer. HTTP 401 permits one
forced credential refresh within a three-attempt budget; 429 and selected 5xx
responses use bounded backoff. Permission denials are not retried.

References:

- [GKE network isolation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation)
- [GKE Cluster API and endpoint configuration](https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters)

## Supported collections

The `capabilities` tool is the machine-readable source of the supported kinds.
The current collector implements list operations for these stable Kubernetes API
collections:

| API | Kinds |
| --- | --- |
| Core `v1` | Pod, Namespace, Node, Service, ServiceAccount, PersistentVolume, PersistentVolumeClaim, ResourceQuota, LimitRange |
| `apps/v1` | Deployment, DaemonSet, StatefulSet, ReplicaSet |
| `batch/v1` | Job, CronJob |
| `networking.k8s.io/v1` | NetworkPolicy, Ingress, IngressClass |
| `rbac.authorization.k8s.io/v1` | Role, RoleBinding, ClusterRole, ClusterRoleBinding |
| `storage.k8s.io/v1` | StorageClass, CSIDriver, CSINode |
| `policy/v1` | PodDisruptionBudget |
| `node.k8s.io/v1` | RuntimeClass |
| `admissionregistration.k8s.io/v1` | ValidatingWebhookConfiguration, MutatingWebhookConfiguration |

No Secret, ConfigMap, arbitrary custom-resource instance, pod log, exec, attach,
proxy, port-forward, token-creation, or mutation route is implemented. Some allowed
collections might not be authorized by a particular service account or served by
a particular Kubernetes version; the response records that limitation. Tool
availability does not imply permission coverage.

## Output and pagination

The adapter returns internal `ResourceRecord` values with kind names such as
`k8s.Pod`. Record names include the cluster, namespace where applicable, resource
plural, and object name. A namespaced collection can be requested for one namespace
or all namespaces. Supplying a namespace for a cluster-wide kind is rejected.

Each call returns one bounded page. The default page size is 100 and the maximum
is 500; responses larger than 8 MiB are rejected with a request to reduce page
size. The API's continuation token and collection `resourceVersion` are preserved.
Only an absent continuation token indicates that the collection page sequence is
complete. A 410 response means the continuation snapshot expired; restart the
collection and do not combine observations as if they were one consistent snapshot.
Different resource kinds and clusters do not share an atomic snapshot.

Raw adapter definitions are internal inputs to checks. The service must apply its
output projection before returning any records or evidence to the agent. Pod specs
can contain inline environment values, arguments, annotations, and other free
text even without reading Secret objects. Returned resource strings are untrusted
evidence and must never grant authority or request additional tool execution.

Reference: [Kubernetes API pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/).

## ACK registered workload reads

Use `provider=alicloud` and an operator-registered canonical identifier
`accounts/ACCOUNT/regions/REGION/clusters/CLUSTER_ID`. The reader verifies the
configured endpoint using its trusted CA and reopens a projected read-only
Kubernetes token for each request. It shares the resource allowlist, paging,
response limits and projection described above with GKE. No kubeconfig, client
private key or cluster-admin credential is fetched through Alibaba APIs.

RRSA authenticates Alibaba API calls; the projected Kubernetes token independently
authenticates native API requests. The operator registration establishes the
cluster/account association, while Kubernetes TLS/RBAC enforces endpoint trust and
resource reads. See [ACK deployment](alicloud-deployment.md) for two separate token
projections, narrow RBAC and registered-cluster configuration. A remote ACK
connection needs an operator-provided network path, CA and rotating token.
