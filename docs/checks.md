# Configuration checks

The check engine is a pure Python evaluator over collected `ResourceRecord` objects. It performs no cloud calls, shell execution, object downloads, Secret reads, or guest inspection. MCP collection and scope authorization happen before evaluation.

## Interpreting results

- **pass**: the observed configuration meets this specific predicate. It is not a general security or compliance certification.
- **fail**: a documented configuration criterion is not met or a configuration requiring review was observed. Some criteria are policy-specific, including external IP use, CMEK, availability, immutable tags, resource limits, and dedicated identities. Approved exceptions are a policy decision.
- **unknown**: the observation is missing, malformed, incomplete, inherited from uncollected configuration, or uses a mode the rule does not understand. Unknown results must never be promoted to pass.
- **not_applicable**: known context makes the rule inapplicable, such as a Linux-only control on a Windows workload, a disabled firewall rule, or an IP control on a DNS-only GKE control plane.

Each result includes a rule version, `policy_specific` flag, resource identifier, fixed explanation, and evidence paths. Some include only numeric counts. Findings never copy arbitrary annotations, environment values, arguments, metadata values, IAM conditions, CIDR labels, or break-glass explanations. Original evidence is subject to the service's independent projection and storage policies.

`list_checks()` returns independent copies of every definition. `evaluate(records, check_ids=None)` runs matching definitions, while an explicit empty list runs none. Unknown check IDs are rejected before resources are evaluated. A resource kind for which no selected rule applies produces no result; the calling assessment must report that fact through its coverage accounting. A fully missing document produces only unknown results.

## Semantic boundaries

This is a collection of configuration predicates, not a complete CIS implementation. It does not compute effective IAM permissions, network reachability, runtime user IDs, an effective combination of all network policies, or guest/container vulnerabilities. A public-IP configuration or broad firewall allow entry does not prove that a service is reachable. IAM conditions and deny policies can change access; a conditional broad grant is still reported as an observed binding requiring analysis.

Kubernetes workload controllers are assessed from their Pod templates. Admission may alter the Pods created from those templates, so inspect actual Pods when runtime configuration is the question. Init and ephemeral containers are included where the Kubernetes field permits them; resource-limit checks exclude ephemeral containers. Pod security-context inheritance is resolved for runAsNonRoot, runAsUser, seccomp, and Windows HostProcess. Missing image or node defaults remain unknown. Optional flags with documented defaults, such as privileged=false and host namespaces=false, use those defaults after a valid Pod spec has been established. Missing allowPrivilegeEscalation has its documented true default. An omitted token-automount flag remains unknown because the ServiceAccount can supply it.

Bucket public access prevention set to `inherited` remains unknown until effective organization policy is evaluated. OS Login absent at the VM remains unknown because project metadata can apply. GKE Dataplane V2 satisfies the network-policy enforcement-capability check, but does not prove a namespace has suitable policies. Binary Authorization continuous-validation-only mode does not satisfy admission enforcement. Subnet-local Flow Logs checks do not evaluate separate Network Management logging configurations. SQL MySQL recovery checks inspect binary logging, while PostgreSQL and SQL Server use PITR configuration; none proves that restoration succeeds. Missing dataset access details from a list summary stay unknown.

CMEK checks only inspect configured references. Unknown or absent CMEK evidence does not imply absence of Google-managed default encryption. A Secret Manager rotation notification schedule does not prove secret material has been rotated.

## GCP catalogue

| Check ID | Resource kind | Meaning |
| --- | --- | --- |
| `gcp.compute.instance.no_external_ip` | `gcp.compute.instances` | Flags an external IPv4 or IPv6 access configuration. This is an observation, not an internet-reachability assessment. Public workloads can have approved exceptions. |
| `gcp.compute.instance.secure_boot` | `gcp.compute.instances` | Checks the explicitly observed shieldedInstanceConfig.enableSecureBoot setting; missing values remain unknown. |
| `gcp.compute.instance.vtpm` | `gcp.compute.instances` | Checks the explicitly observed shieldedInstanceConfig.enableVtpm setting; missing values remain unknown. |
| `gcp.compute.instance.integrity_monitoring` | `gcp.compute.instances` | Checks the explicitly observed shieldedInstanceConfig.enableIntegrityMonitoring setting; missing values remain unknown. |
| `gcp.compute.instance.no_ip_forwarding` | `gcp.compute.instances` | Checks the explicitly observed canIpForward setting; missing values remain unknown. |
| `gcp.compute.instance.dedicated_service_account` | `gcp.compute.instances` | Flags the default Compute Engine service account; it does not infer the account's privileges. |
| `gcp.compute.instance.os_login` | `gcp.compute.instances` | Checks an explicit instance metadata setting. Absent configuration is unknown because project metadata can apply. |
| `gcp.compute.instance.block_project_ssh_keys` | `gcp.compute.instances` | Checks instance metadata; explicitly enabled OS Login makes this key control inapplicable. |
| `gcp.compute.instance.deletion_protection` | `gcp.compute.instances` | Checks the explicitly observed deletionProtection setting; missing values remain unknown. |
| `gcp.compute.disk.cmek` | `gcp.compute.disks` | Policy-specific check for an observed KMS key reference; absence is unknown and does not mean data is unencrypted. |
| `gcp.compute.firewall.no_public_ssh` | `gcp.compute.firewalls` | Examines the local ingress allow rule, IPv4 and IPv6 CIDRs, and port ranges. Priorities, hierarchical policies, targets, and actual reachability are not evaluated. |
| `gcp.compute.firewall.no_public_rdp` | `gcp.compute.firewalls` | Examines the local ingress allow rule, IPv4 and IPv6 CIDRs, and port ranges. Priorities, hierarchical policies, targets, and actual reachability are not evaluated. |
| `gcp.compute.firewall.no_public_all_ports` | `gcp.compute.firewalls` | Examines the local ingress allow rule, IPv4 and IPv6 CIDRs, and port ranges. Priorities, hierarchical policies, targets, and actual reachability are not evaluated. |
| `gcp.compute.firewall.logging` | `gcp.compute.firewalls` | Requires the observed enabled rule to have logging explicitly enabled; disabled rules are inapplicable. |
| `gcp.compute.network.custom_subnets` | `gcp.compute.networks` | Checks the explicitly observed autoCreateSubnetworks setting; missing values remain unknown. |
| `gcp.compute.subnet.flow_logs` | `gcp.compute.subnetworks` | Evaluates only the subnet's local flow-log setting. Separate centralized Network Management configurations may also collect flows. |
| `gcp.compute.subnet.private_google_access` | `gcp.compute.subnetworks` | Checks the explicitly observed privateIpGoogleAccess setting; missing values remain unknown. |
| `gcp.compute.ssl.minimum_tls` | `gcp.compute.sslPolicies` | Checks the observed TLS policy minimum version. |
| `gcp.compute.ssl.modern_profile` | `gcp.compute.sslPolicies` | MODERN and RESTRICTED pass; COMPATIBLE requires review. CUSTOM remains unknown because its cipher configuration needs separate evaluation. |
| `gcp.gke.legacy_abac_disabled` | `gcp.container.clusters` | Checks the explicitly observed legacyAbac.enabled setting; missing values remain unknown. |
| `gcp.gke.workload_identity` | `gcp.container.clusters` | Checks the configured workload identity pool. It does not prove that each node pool or workload uses the intended identity. |
| `gcp.gke.release_channel` | `gcp.container.clusters` | Checks explicit release-channel enrollment; it is not a patch-age or support-lifecycle assessment. |
| `gcp.gke.network_policy` | `gcp.container.clusters` | Checks NetworkPolicy enablement or Dataplane V2. Individual workload isolation policies are not evaluated by this check. |
| `gcp.gke.shielded_nodes` | `gcp.container.clusters` | Checks the explicitly observed shieldedNodes.enabled setting; missing values remain unknown. |
| `gcp.gke.authorized_networks` | `gcp.container.clusters` | Evaluates IP endpoint authorized networks; DNS-only control planes are inapplicable. VPC Service Controls and effective endpoint reachability are not inferred. |
| `gcp.gke.no_client_certificate` | `gcp.container.clusters` | Checks the explicitly observed masterAuth.clientCertificateConfig.issueClientCertificate setting; missing values remain unknown. |
| `gcp.gke.binary_authorization` | `gcp.container.clusters` | Policy-specific admission enforcement check. Continuous-validation-only mode is not admission enforcement. |
| `gcp.gke.node_auto_upgrade` | `gcp.container.clusters` | Evaluates every node pool embedded in the collected cluster. Autopilot is managed and inapplicable; missing node-pool evidence is unknown. |
| `gcp.gke.node_auto_repair` | `gcp.container.clusters` | Evaluates every node pool embedded in the collected cluster. Autopilot is managed and inapplicable; missing node-pool evidence is unknown. |
| `gcp.storage.uniform_access` | `gcp.storage.buckets` | Checks the explicitly observed iamConfiguration.uniformBucketLevelAccess.enabled setting; missing values remain unknown. |
| `gcp.storage.public_access_prevention` | `gcp.storage.buckets` | An enforced bucket setting passes. Inherited settings remain unknown until effective organization policy is evaluated. |
| `gcp.storage.versioning` | `gcp.storage.buckets` | Policy-specific durability check for versioning; soft delete, backups, and retention requirements are separate controls. |
| `gcp.storage.cmek` | `gcp.storage.buckets` | Policy-specific default KMS reference check. It does not inspect existing objects or imply unencrypted storage when unknown. |
| `gcp.iam.no_public_principal` | `gcp.iam.policy` | Flags bindings to allUsers or allAuthenticatedUsers. Conditional bindings are included as observations; effective access is not evaluated. |
| `gcp.iam.no_basic_roles` | `gcp.iam.policy` | Flags Owner, Editor, or Viewer in the observed policy, including conditional bindings. Approved administrative grants can be excepted. |
| `gcp.sql.no_public_ipv4` | `gcp.sql.instances` | Checks the explicitly observed settings.ipConfiguration.ipv4Enabled setting; missing values remain unknown. |
| `gcp.sql.no_unrestricted_networks` | `gcp.sql.instances` | Flags IPv4 or IPv6 /0 CIDRs in the observed authorized networks; authentication and effective reachability are not inferred. |
| `gcp.sql.require_tls` | `gcp.sql.instances` | Checks sslMode and, when appropriate, the legacy requireSsl flag. Unknown modes remain unknown. |
| `gcp.sql.automated_backups` | `gcp.sql.instances` | Reads the primary-instance backup setting; replicas require assessment of their primary. |
| `gcp.sql.point_in_time_recovery` | `gcp.sql.instances` | For MySQL, checks binary logging; for PostgreSQL and SQL Server, checks PITR enablement. Backup completeness and successful restoration are not proven. |
| `gcp.sql.high_availability` | `gcp.sql.instances` | Policy-specific availability requirement; zonal deployments may have approved exceptions. |
| `gcp.sql.deletion_protection` | `gcp.sql.instances` | Checks the explicitly observed settings.deletionProtectionEnabled setting; missing values remain unknown. |
| `gcp.sql.cmek` | `gcp.sql.instances` | Policy-specific KMS reference check; missing key metadata is unknown and does not imply missing default encryption. |
| `gcp.run.restricted_ingress` | `gcp.run.services` | Policy-specific ingress check. Public web services may legitimately accept all ingress; this does not evaluate authentication or load balancer reachability. |
| `gcp.run.invoker_iam` | `gcp.run.services` | Checks the explicitly observed invokerIamDisabled setting; missing values remain unknown. |
| `gcp.run.dedicated_service_account` | `gcp.run.services` | Flags an explicitly observed default Compute Engine service account; missing account evidence is unknown. |
| `gcp.run.binary_authorization` | `gcp.run.services` | Policy-specific default-policy enforcement check. A break-glass configuration is flagged without returning its justification text. |
| `gcp.artifactregistry.immutable_tags` | `gcp.artifactregistry.repositories` | Policy-specific check for standard Docker repositories; remote, virtual, and non-Docker repositories are inapplicable. |
| `gcp.artifactregistry.cmek` | `gcp.artifactregistry.repositories` | Policy-specific observed KMS reference check; it does not inspect artifact content. |
| `gcp.secretmanager.rotation_schedule` | `gcp.secretmanager.secrets` | Checks rotationPeriod metadata. A notification schedule is not proof that secret material is rotated. Secret versions and values are never read. |
| `gcp.pubsub.topic_cmek` | `gcp.pubsub.topics` | Policy-specific KMS reference check; no messages are read. |
| `gcp.pubsub.authenticated_push` | `gcp.pubsub.subscriptions` | Checks that a push endpoint has an OIDC service-account identity. Pull and export subscriptions are not push endpoints. |
| `gcp.bigquery.no_public_access_entry` | `gcp.bigquery.datasets` | Requires dataset access metadata; list-only summaries without access entries remain unknown. IAM inheritance and authorized-view behavior require separate analysis. |
| `gcp.bigquery.cmek` | `gcp.bigquery.datasets` | Policy-specific default KMS reference check; existing tables and data are not inspected. |

## Kubernetes workload controls

Each control below is registered separately for `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `Job`, and `CronJob`. Replace the `k8s.pod.` prefix with the lowercase kind, for example `k8s.deployment.seccomp` or `k8s.cronjob.seccomp`. Each definition has the exact matching `k8s.Kind` resource kind.

| Pod check ID | Meaning |
| --- | --- |
| `k8s.pod.privileged` | Flags privileged containers; an omitted privileged flag uses the API's false default. |
| `k8s.pod.privilege_escalation` | Requires allowPrivilegeEscalation=false. Privileged execution and SYS_ADMIN also permit escalation. |
| `k8s.pod.non_root` | Checks effective pod/container runAsNonRoot and explicit UID conflicts. Unresolved image defaults remain unknown. |
| `k8s.pod.root_uid` | Flags effective runAsUser=0. A pass only means no explicit root UID; image identity is not established. |
| `k8s.pod.seccomp` | Checks container overrides then pod inheritance. RuntimeDefault and Localhost pass; missing node defaults are unknown. |
| `k8s.pod.drop_capabilities` | Requires an explicit drop list containing ALL, consistent with the Restricted Pod Security capability control. |
| `k8s.pod.added_capabilities` | Only NET_BIND_SERVICE may be explicitly added under this control. |
| `k8s.pod.read_only_root` | Policy-specific check; writable mounted volumes are not covered and some applications need writable root filesystems. |
| `k8s.pod.host_ports` | Flags nonzero hostPort requests; service exposure and network reachability are not inferred. |
| `k8s.pod.resource_limits` | Policy-specific resource-isolation check on ordinary and init containers. Ephemeral containers cannot set these limits. |
| `k8s.pod.image_digest` | Policy-specific reproducibility check; an immutable digest does not prove an image is trusted or vulnerability-free. |
| `k8s.pod.host_process` | Checks effective container/pod Windows HostProcess settings without reading host contents. |
| `k8s.pod.no_hostnetwork` | Evaluates the declared pod-spec flag using its false default; templates may be changed by admission before Pods are created. |
| `k8s.pod.no_hostpid` | Evaluates the declared pod-spec flag using its false default; templates may be changed by admission before Pods are created. |
| `k8s.pod.no_hostipc` | Evaluates the declared pod-spec flag using its false default; templates may be changed by admission before Pods are created. |
| `k8s.pod.no_hostpath` | Flags hostPath declarations; host path strings and mounted content are not returned. |
| `k8s.pod.token_automount` | Checks only the workload flag. An omitted flag is unknown because the Kubernetes service account can supply the setting; explicit projected tokens are separate. |
| `k8s.pod.dedicated_service_account` | Policy-specific separation of workload identity. The default service account is selected when the field is omitted. |

## Kubernetes access and namespace controls

| Check ID | Resource kind | Meaning |
| --- | --- | --- |
| `k8s.role.no_wildcards` | `k8s.Role` | Flags wildcard grants in observed rules. A role without bindings grants no access by itself. |
| `k8s.role.no_secret_reads` | `k8s.Role` | Identifies get/list/watch grants for core Secret resources, including wildcards, without reading Secrets. resourceNames restrictions remain relevant to impact. |
| `k8s.clusterrole.no_wildcards` | `k8s.ClusterRole` | Flags wildcard grants in observed rules. A role without bindings grants no access by itself. |
| `k8s.clusterrole.no_secret_reads` | `k8s.ClusterRole` | Identifies get/list/watch grants for core Secret resources, including wildcards, without reading Secrets. resourceNames restrictions remain relevant to impact. |
| `k8s.rolebinding.no_cluster_admin` | `k8s.RoleBinding` | Flags a nonempty binding to ClusterRole/cluster-admin. RoleBindings remain limited to their namespace; approved administrative bindings can be excepted. |
| `k8s.rolebinding.no_broad_groups` | `k8s.RoleBinding` | Flags bindings for all authenticated/unauthenticated identities or the anonymous user; referenced permissions and scope determine impact. |
| `k8s.clusterrolebinding.no_cluster_admin` | `k8s.ClusterRoleBinding` | Flags a nonempty binding to ClusterRole/cluster-admin. RoleBindings remain limited to their namespace; approved administrative bindings can be excepted. |
| `k8s.clusterrolebinding.no_broad_groups` | `k8s.ClusterRoleBinding` | Flags bindings for all authenticated/unauthenticated identities or the anonymous user; referenced permissions and scope determine impact. |
| `k8s.namespace.pod_security` | `k8s.Namespace` | Checks explicit baseline/restricted namespace enforcement; absence is unknown because cluster defaults can apply. |
| `k8s.serviceaccount.token_automount` | `k8s.ServiceAccount` | Policy-specific check of an explicit service-account default. Workload overrides and projected tokens are separate; omitted evidence remains unknown. |

This version registers **211 resource-kind-specific check definitions**: 54 GCP definitions, 21 Alibaba definitions, 18 workload controls for each of seven workload kinds, and 10 additional Kubernetes definitions. This count does not represent 211 independent compliance requirements.

## Primary references used for semantics

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Pod API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/)
- [Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes application security checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/)
- [Compute firewall resource and source-filter semantics](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls)
- [GKE cluster API, including control-plane endpoints and Binary Authorization modes](https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters)
- [Cloud Storage public access prevention inheritance](https://docs.cloud.google.com/storage/docs/public-access-prevention)
- [Cloud Storage bucket metadata](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets)
- [Cloud SQL instance metadata](https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances)
- [Cloud SQL TLS configuration](https://docs.cloud.google.com/sql/docs/mysql/configure-ssl-instance)
- [Cloud Run service API](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services)
- [Artifact Registry repository API](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories)

The predicates and conservative handling of incomplete evidence are tested with mocked native API-shaped documents. Live organization results depend on API availability, the actual service account's permissions, endpoint reachability, and collected fields.

## Alibaba configuration checks

These predicates use Alibaba native field names and explicit values. Missing list-summary fields remain unknown; use the corresponding exact/nested query for evidence. RDS TLS reads are excluded because the native SSL-description action can return private keys. KMS rotation, password length, backup retention and public IP checks are documented policy observations, not universal compliance requirements.

| Check ID | Resource kind | Meaning |
| --- | --- | --- |
| `alicloud.ecs.instance.metadata_tokens` | `alicloud.ecs.instances` | Checks explicit endpoint/token settings on Linux ECS instances; disabled endpoints pass, Windows is inapplicable, missing OS/settings remain unknown. |
| `alicloud.ecs.instance.no_public_ip` | `alicloud.ecs.instances` | Flags a configured public or elastic IP. It does not establish internet reachability or include every independent ENI/NAT association. |
| `alicloud.ecs.instance.deletion_protection` | `alicloud.ecs.instances` | Requires explicit deletion protection; use approved lifecycle exceptions for ephemeral instances. |
| `alicloud.ecs.instance.secure_boot` | `alicloud.ecs.instances` | Inspects explicit SecurityOptions.EnableSecureBoot. Unsupported or omitted capabilities remain unknown. |
| `alicloud.ecs.disk.encryption` | `alicloud.ecs.disks` | Requires the native Encrypted flag; does not access block data or prove key custody. |
| `alicloud.ecs.rule.no_public_ssh` | `alicloud.ecs.securityGroupRules` | Flags an individual accepting ingress rule exposing the TCP port to all IPv4 or IPv6 addresses. Other rules, priorities, targets and reachability are not evaluated. |
| `alicloud.ecs.rule.no_public_rdp` | `alicloud.ecs.securityGroupRules` | Flags an individual accepting ingress rule exposing the TCP port to all IPv4 or IPv6 addresses. Other rules, priorities, targets and reachability are not evaluated. |
| `alicloud.ram.password.minimum_length` | `alicloud.ram.passwordPolicy` | Policy-specific minimum of 14 characters. This is a local account configuration observation, not a complete authentication policy. |
| `alicloud.ram.login.mfa_binding` | `alicloud.ram.loginProfiles` | Requires explicit MFABindRequired for this login profile. Binding requirement does not prove every session was challenged. |
| `alicloud.oss.bucket.private_acl` | `alicloud.oss.bucketAcl` | Checks this bucket ACL only. A private ACL does not resolve RAM policies, bucket policies, object ACLs or inherited public-access controls. |
| `alicloud.oss.bucket.public_access_block` | `alicloud.oss.bucketPublicAccessBlock` | Inspects explicit local BlockPublicAccess; missing/account-level inherited settings remain unknown. |
| `alicloud.oss.bucket.default_encryption` | `alicloud.oss.bucketEncryption` | Accepts AES256, KMS or SM4 as the configured default algorithm; does not inspect any existing object or prove that it was encrypted by this setting. |
| `alicloud.oss.bucket.versioning` | `alicloud.oss.bucketVersioning` | Policy-specific requirement for Enabled versioning; no object versions are read. |
| `alicloud.oss.bucket.access_logging` | `alicloud.oss.bucketLogging` | Checks an explicitly present log destination, without reading delivered log objects. Missing settings remain unknown. |
| `alicloud.vpc.flow_log.active` | `alicloud.vpc.flowLogs` | Checks the state of this existing flow-log configuration; does not prove every VPC/ENI has a flow log. |
| `alicloud.vpc.flow_log.delivery` | `alicloud.vpc.flowLogs` | Checks an explicitly reported delivery status; absent status or transitional states remain unknown. |
| `alicloud.rds.allowlist.no_public_cidr` | `alicloud.rds.ipAllowlists` | Flags all-address IPv4 or IPv6 CIDRs in one IP array. Network endpoints and additional access controls affect actual reachability. |
| `alicloud.rds.encryption.tde` | `alicloud.rds.encryption` | Checks instance-level TDEStatus; engine/database-specific behavior and other encryption layers need separate evidence. |
| `alicloud.rds.backup.retention` | `alicloud.rds.backupPolicy` | Policy-specific minimum seven-day basic backup retention. Advanced policies remain unknown; this does not perform a restore or prove recovery. |
| `alicloud.kms.key.deletion_protection` | `alicloud.kms.keys` | Inspects explicit key metadata; ListKeys summaries need a subsequent DescribeKey query. |
| `alicloud.kms.key.rotation` | `alicloud.kms.keys` | Checks explicit automatic rotation state for supported keys. Asymmetric or imported material uses separate rotation procedures. |

Alibaba semantics references: [ECS DescribeInstances](https://api.alibabacloud.com/document/Ecs/2014-05-26/DescribeInstances), [RAM GetPasswordPolicy](https://www.alibabacloud.com/help/en/ram/developer-reference/api-ram-2015-05-01-getpasswordpolicy), [OSS public-access block](https://www.alibabacloud.com/help/en/oss/developer-reference/getbucketpublicaccessblock), [RDS backup policy](https://www.alibabacloud.com/help/en/rds/developer-reference/api-rds-2014-08-15-describebackuppolicy), and [KMS DescribeKey](https://www.alibabacloud.com/help/en/kms/key-management-service/developer-reference/api-kms-2016-01-20-describekey).
