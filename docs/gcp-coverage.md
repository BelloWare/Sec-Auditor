# GCP query coverage and API catalog

Sec-Auditor exposes reviewed configuration and existing-security-report queries. The catalog answers more than project inventory lists: callers can inspect a specific resource, follow a confined nested parent, select an authorized folder or organization, and read effective firewall or organization-policy evidence. It does not claim to implement every GCP API or establish complete effective access and runtime security from configuration alone.

The machine-readable `capabilities` response is authoritative. Inspect each kind's `operations` and `queries[operation]`: the latter gives the exact endpoint, permission names, scope types, parent format, selectors, resource-ID validation, and pagination. An API permission is a prerequisite, not a promise that a predefined IAM role, API activation, service tier, or network path makes the query available. A denial remains an explicit collection error.

## Calling the query surface

`collect_resources` accepts query objects like these inside its `queries` array. Supply exactly one of `project` or `scope` for GCP. The server authorizes that root against operator configuration and the caller before the provider executes a query.

```json
[
  {
    "provider": "gcp",
    "project": "audit-project",
    "kind": "gcp.compute.instances",
    "operation": "get",
    "location": "us-central1-a",
    "resource_id": "web-1"
  },
  {
    "provider": "gcp",
    "scope": "organizations/123456789",
    "kind": "gcp.iam.denyPolicies",
    "operation": "list"
  },
  {
    "provider": "gcp",
    "project": "audit-project",
    "kind": "gcp.kms.cryptoKeyVersions",
    "parent": "projects/audit-project/locations/us-central1/keyRings/platform/cryptoKeys/data"
  }
]
```

An exact regional/global Compute query requires `selectors.location_type` when both forms exist. For example, a regional backend service uses `kind=gcp.compute.backendServices`, `operation=get`, `selectors={"location_type":"regions"}`, `location=us-central1`, and the bare `resource_id`. Zonal-only kinds such as instances need a zone but no location-type selector. Caller-provided names never become arbitrary URLs or method names.

A nested parent must match the advertised resource type and the authorized root. Numeric aliases for the same project are resolved through Resource Manager before use. Three globally named resources need additional ownership proof: bucket detail/IAM reads first list that bucket prefix in the authorized project; hierarchical firewall-policy gets first prove ownership under the authorized folder/organization; VPC Service Controls reads first find the access policy in the authorized organization's bounded, paginated policy list. Failure to prove ownership stops the nested/global read.

## Exact operation catalog

The following table is generated from the implemented catalog. `projects`, `folders`, and `organizations` name allowed **root scope types**, not implicit cross-scope expansion. `native` preserves upstream page tokens; `client` uses explicitly marked best-effort local paging; `singleton` returns one configuration object. The legacy key collector paginates service accounts, at most 20 accounts per request. IAM-policy POSTs are allowlisted read RPCs.

This build exposes **91 GCP query kinds**, **160 list/get variants**, and **45 explicitly allowed Cloud Asset Inventory types**. Counts describe interface coverage, not independently verified security controls.

| Kind / operation | Fixed API endpoint | Allowed roots | Additional inputs | Permissions | Paging |
| --- | --- | --- | --- | --- | --- |
| `gcp.accesscontextmanager.accessLevels` / get | `GET https://accesscontextmanager.googleapis.com/v1/{parent}/accessLevels/{resource_id}` | organizations | parent: `accessPolicies/{numeric_policy_id}`; `resource_id` | `accesscontextmanager.accessLevels.get` | singleton |
| `gcp.accesscontextmanager.accessLevels` / list | `GET https://accesscontextmanager.googleapis.com/v1/{parent}/accessLevels` | organizations | parent: `accessPolicies/{numeric_policy_id}` | `accesscontextmanager.accessLevels.list` | native |
| `gcp.accesscontextmanager.accessPolicies` / list | `GET https://accesscontextmanager.googleapis.com/v1/accessPolicies` | organizations | — | `accesscontextmanager.policies.list` | native |
| `gcp.accesscontextmanager.servicePerimeters` / get | `GET https://accesscontextmanager.googleapis.com/v1/{parent}/servicePerimeters/{resource_id}` | organizations | parent: `accessPolicies/{numeric_policy_id}`; `resource_id` | `accesscontextmanager.servicePerimeters.get` | singleton |
| `gcp.accesscontextmanager.servicePerimeters` / list | `GET https://accesscontextmanager.googleapis.com/v1/{parent}/servicePerimeters` | organizations | parent: `accessPolicies/{numeric_policy_id}` | `accesscontextmanager.servicePerimeters.list` | native |
| `gcp.artifactanalysis.vulnerabilities` / list | `GET https://containeranalysis.googleapis.com/v1/{scope}/occurrences` | projects | — | `containeranalysis.occurrences.list` | native |
| `gcp.artifactregistry.repositories` / get | `GET https://artifactregistry.googleapis.com/v1/{scope}/locations/{location}/repositories/{resource_id}` | projects | `resource_id`; location: required | `artifactregistry.repositories.get` | singleton |
| `gcp.artifactregistry.repositories` / list | `GET https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories` | projects | location: required | `artifactregistry.repositories.list` | native |
| `gcp.bigquery.datasets` / get | `GET https://bigquery.googleapis.com/bigquery/v2/{scope}/datasets/{resource_id}` | projects | `resource_id` | `bigquery.datasets.get` | singleton |
| `gcp.bigquery.datasets` / list | `GET https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets` | projects | — | `bigquery.datasets.get` | native |
| `gcp.binaryauthorization.policy` / get | `GET https://binaryauthorization.googleapis.com/v1/{scope}/policy` | projects | — | `binaryauthorization.policy.get` | singleton |
| `gcp.cloudfunctions.functions` / get | `GET https://cloudfunctions.googleapis.com/v2/{scope}/locations/{location}/functions/{resource_id}` | projects | `resource_id`; location: required | `cloudfunctions.functions.get` | singleton |
| `gcp.cloudfunctions.functions` / list | `GET https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/{location}/functions` | projects | location: wildcard | `cloudfunctions.functions.list` | native |
| `gcp.compute.addresses` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/addresses/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.addresses.get`, `compute.globalAddresses.get` | singleton |
| `gcp.compute.addresses` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/addresses` | projects | — | `compute.addresses.list` | native |
| `gcp.compute.backendBuckets` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/backendBuckets/{resource_id}` | projects | `resource_id`; Compute: global | `compute.backendBuckets.get` | singleton |
| `gcp.compute.backendBuckets` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/backendBuckets` | projects | — | `compute.backendBuckets.list` | native |
| `gcp.compute.backendServices` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/backendServices/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.backendServices.get`, `compute.regionBackendServices.get` | singleton |
| `gcp.compute.backendServices` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/backendServices` | projects | — | `compute.backendServices.list` | native |
| `gcp.compute.disks` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/disks/{resource_id}` | projects | `resource_id`; Compute: zones, regions; concrete location; `location_type` required | `compute.disks.get` | singleton |
| `gcp.compute.disks` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/disks` | projects | — | `compute.disks.list` | native |
| `gcp.compute.effectiveFirewalls` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/zones/{location}/instances/{resource_id}/getEffectiveFirewalls` | projects | `resource_id`; location: required; `network_interface` optional | `compute.instances.getEffectiveFirewalls` | singleton |
| `gcp.compute.firewalls` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/firewalls/{resource_id}` | projects | `resource_id`; Compute: global | `compute.firewalls.get` | singleton |
| `gcp.compute.firewalls` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls` | projects | — | `compute.firewalls.list` | native |
| `gcp.compute.forwardingRules` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/forwardingRules/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.forwardingRules.get`, `compute.globalForwardingRules.get` | singleton |
| `gcp.compute.forwardingRules` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/forwardingRules` | projects | — | `compute.forwardingRules.list` | native |
| `gcp.compute.healthChecks` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/healthChecks/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.healthChecks.get`, `compute.regionHealthChecks.get` | singleton |
| `gcp.compute.healthChecks` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/healthChecks` | projects | — | `compute.healthChecks.list` | native |
| `gcp.compute.hierarchicalFirewallPolicies` / get | `GET https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies/{resource_id}` | folders, organizations | `resource_id` | `compute.firewallPolicies.list`, `compute.firewallPolicies.get` | singleton |
| `gcp.compute.hierarchicalFirewallPolicies` / list | `GET https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies` | folders, organizations | — | `compute.firewallPolicies.list` | native |
| `gcp.compute.images` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/images/{resource_id}` | projects | `resource_id`; Compute: global | `compute.images.get` | singleton |
| `gcp.compute.images` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/images` | projects | — | `compute.images.list` | native |
| `gcp.compute.instanceGroupManagers` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/instanceGroupManagers/{resource_id}` | projects | `resource_id`; Compute: zones, regions; concrete location; `location_type` required | `compute.instanceGroupManagers.get` | singleton |
| `gcp.compute.instanceGroupManagers` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instanceGroupManagers` | projects | — | `compute.instanceGroupManagers.list` | native |
| `gcp.compute.instanceGroups` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/instanceGroups/{resource_id}` | projects | `resource_id`; Compute: zones, regions; concrete location; `location_type` required | `compute.instanceGroups.get` | singleton |
| `gcp.compute.instanceGroups` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instanceGroups` | projects | — | `compute.instanceGroups.list` | native |
| `gcp.compute.instanceTemplates` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/instanceTemplates/{resource_id}` | projects | `resource_id`; Compute: global | `compute.instanceTemplates.get` | singleton |
| `gcp.compute.instanceTemplates` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/instanceTemplates` | projects | — | `compute.instanceTemplates.list` | native |
| `gcp.compute.instances` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/instances/{resource_id}` | projects | `resource_id`; Compute: zones; concrete location | `compute.instances.get` | singleton |
| `gcp.compute.instances` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances` | projects | — | `compute.instances.list` | native |
| `gcp.compute.networkEndpointGroups` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/networkEndpointGroups/{resource_id}` | projects | `resource_id`; Compute: zones, regions, global; `location_type` required | `compute.globalNetworkEndpointGroups.get`, `compute.networkEndpointGroups.get`, `compute.regionNetworkEndpointGroups.get` | singleton |
| `gcp.compute.networkEndpointGroups` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/networkEndpointGroups` | projects | — | `compute.networkEndpointGroups.list` | native |
| `gcp.compute.networkFirewallPolicies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/firewallPolicies/{resource_id}` | projects | `resource_id`; Compute: global | `compute.firewallPolicies.get` | singleton |
| `gcp.compute.networkFirewallPolicies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/firewallPolicies` | projects | — | `compute.firewallPolicies.list` | native |
| `gcp.compute.networks` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/networks/{resource_id}` | projects | `resource_id`; Compute: global | `compute.networks.get` | singleton |
| `gcp.compute.networks` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/networks` | projects | — | `compute.networks.list` | native |
| `gcp.compute.project` / get | `GET https://compute.googleapis.com/compute/v1/{scope}` | projects | — | `compute.projects.get` | singleton |
| `gcp.compute.project` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}` | projects | — | `compute.projects.get` | singleton |
| `gcp.compute.regionNetworkFirewallPolicies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/regions/{location}/firewallPolicies/{resource_id}` | projects | `resource_id`; location: required | `compute.regionFirewallPolicies.get` | singleton |
| `gcp.compute.regionNetworkFirewallPolicies` / list | `GET https://compute.googleapis.com/compute/v1/{scope}/regions/{location}/firewallPolicies` | projects | location: required | `compute.regionFirewallPolicies.list` | native |
| `gcp.compute.regionSecurityPolicies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/securityPolicies/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.regionSecurityPolicies.get` | singleton |
| `gcp.compute.regionSecurityPolicies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/regions/{location}/securityPolicies` | projects | location: required | `compute.regionSecurityPolicies.list` | native |
| `gcp.compute.routers` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/routers/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.routers.get` | singleton |
| `gcp.compute.routers` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/routers` | projects | — | `compute.routers.list` | native |
| `gcp.compute.routes` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/routes/{resource_id}` | projects | `resource_id`; Compute: global | `compute.routes.get` | singleton |
| `gcp.compute.routes` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/routes` | projects | — | `compute.routes.list` | native |
| `gcp.compute.securityPolicies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/securityPolicies/{resource_id}` | projects | `resource_id`; Compute: global | `compute.securityPolicies.get` | singleton |
| `gcp.compute.securityPolicies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/securityPolicies` | projects | — | `compute.securityPolicies.list` | native |
| `gcp.compute.serviceAttachments` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/serviceAttachments/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.serviceAttachments.get` | singleton |
| `gcp.compute.serviceAttachments` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/serviceAttachments` | projects | — | `compute.serviceAttachments.list` | native |
| `gcp.compute.snapshots` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/snapshots/{resource_id}` | projects | `resource_id`; Compute: global | `compute.snapshots.get` | singleton |
| `gcp.compute.snapshots` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/snapshots` | projects | — | `compute.snapshots.list` | native |
| `gcp.compute.sslPolicies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/sslPolicies/{resource_id}` | projects | `resource_id`; Compute: global | `compute.sslPolicies.get` | singleton |
| `gcp.compute.sslPolicies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/global/sslPolicies` | projects | — | `compute.sslPolicies.list` | native |
| `gcp.compute.subnetworks` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/subnetworks/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.subnetworks.get` | singleton |
| `gcp.compute.subnetworks` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/subnetworks` | projects | — | `compute.subnetworks.list` | native |
| `gcp.compute.targetHttpProxies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/targetHttpProxies/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.regionTargetHttpProxies.get`, `compute.targetHttpProxies.get` | singleton |
| `gcp.compute.targetHttpProxies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/targetHttpProxies` | projects | — | `compute.targetHttpProxies.list` | native |
| `gcp.compute.targetHttpsProxies` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/targetHttpsProxies/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.regionTargetHttpsProxies.get`, `compute.targetHttpsProxies.get` | singleton |
| `gcp.compute.targetHttpsProxies` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/targetHttpsProxies` | projects | — | `compute.targetHttpsProxies.list` | native |
| `gcp.compute.urlMaps` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/urlMaps/{resource_id}` | projects | `resource_id`; Compute: global, regions; `location_type` required | `compute.regionUrlMaps.get`, `compute.urlMaps.get` | singleton |
| `gcp.compute.urlMaps` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/urlMaps` | projects | — | `compute.urlMaps.list` | native |
| `gcp.compute.vpnGateways` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/vpnGateways/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.vpnGateways.get` | singleton |
| `gcp.compute.vpnGateways` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/vpnGateways` | projects | — | `compute.vpnGateways.list` | native |
| `gcp.compute.vpnTunnels` / get | `GET https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/vpnTunnels/{resource_id}` | projects | `resource_id`; Compute: regions; concrete location | `compute.vpnTunnels.get` | singleton |
| `gcp.compute.vpnTunnels` / list | `GET https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/vpnTunnels` | projects | — | `compute.vpnTunnels.list` | native |
| `gcp.container.clusters` / get | `GET https://container.googleapis.com/v1/{scope}/locations/{location}/clusters/{resource_id}` | projects | `resource_id`; location: required | `container.clusters.get` | singleton |
| `gcp.container.clusters` / list | `GET https://container.googleapis.com/v1/projects/{project}/locations/{location}/clusters` | projects | location: wildcard | `container.clusters.list` | client |
| `gcp.container.nodePools` / get | `GET https://container.googleapis.com/v1/{parent}/nodePools/{resource_id}` | projects | parent: `{scope}/locations/{location}/clusters/{cluster}`; `resource_id` | `container.clusters.get` | singleton |
| `gcp.container.nodePools` / list | `GET https://container.googleapis.com/v1/{parent}/nodePools` | projects | parent: `{scope}/locations/{location}/clusters/{cluster}` | `container.clusters.get` | client |
| `gcp.dns.managedZones` / get | `GET https://dns.googleapis.com/dns/v1/{scope}/managedZones/{resource_id}` | projects | `resource_id` | `dns.managedZones.get` | singleton |
| `gcp.dns.managedZones` / list | `GET https://dns.googleapis.com/dns/v1/projects/{project}/managedZones` | projects | — | `dns.managedZones.list` | native |
| `gcp.iam.denyPolicies` / get | `GET https://iam.googleapis.com/v2/policies/{attachment}/denypolicies/{resource_id}` | projects, folders, organizations | `resource_id` | `iam.denypolicies.get` | singleton |
| `gcp.iam.denyPolicies` / list | `GET https://iam.googleapis.com/v2/policies/{attachment}/denypolicies` | projects, folders, organizations | — | `iam.denypolicies.list` | native |
| `gcp.iam.policy` / get | `POST https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy` | projects, folders, organizations | — | `resourcemanager.projects.getIamPolicy`, `resourcemanager.folders.getIamPolicy`, `resourcemanager.organizations.getIamPolicy` | singleton |
| `gcp.iam.policy` / list | `POST https://cloudresourcemanager.googleapis.com/v3/projects/{project}:getIamPolicy` | projects | — | `resourcemanager.projects.getIamPolicy` | policy |
| `gcp.iam.policyBindings` / get | `GET https://iam.googleapis.com/v3/{scope}/locations/global/policyBindings/{resource_id}` | projects, folders, organizations | `resource_id` | `iam.policybindings.get` | singleton |
| `gcp.iam.policyBindings` / list | `GET https://iam.googleapis.com/v3/{scope}/locations/global/policyBindings` | projects, folders, organizations | — | `iam.policybindings.list` | native |
| `gcp.iam.predefinedRoles` / get | `GET https://iam.googleapis.com/v1/roles/{resource_id}` | projects, folders, organizations | `resource_id` | `iam.roles.get` | singleton |
| `gcp.iam.predefinedRoles` / list | `GET https://iam.googleapis.com/v1/roles` | projects, folders, organizations | — | `iam.roles.list` | native |
| `gcp.iam.principalAccessBoundaryPolicies` / get | `GET https://iam.googleapis.com/v3/{scope}/locations/global/principalAccessBoundaryPolicies/{resource_id}` | organizations | `resource_id` | `iam.principalaccessboundarypolicies.get` | singleton |
| `gcp.iam.principalAccessBoundaryPolicies` / list | `GET https://iam.googleapis.com/v3/{scope}/locations/global/principalAccessBoundaryPolicies` | organizations | — | `iam.principalaccessboundarypolicies.list` | native |
| `gcp.iam.roles` / get | `GET https://iam.googleapis.com/v1/{scope}/roles/{resource_id}` | projects, organizations | `resource_id` | `iam.roles.get` | singleton |
| `gcp.iam.roles` / list | `GET https://iam.googleapis.com/v1/{scope}/roles` | projects, organizations | — | `iam.roles.list` | native |
| `gcp.iam.serviceAccountIamPolicy` / get | `POST https://iam.googleapis.com/v1/{scope}/serviceAccounts/{resource_id}:getIamPolicy` | projects | `resource_id` | `iam.serviceAccounts.getIamPolicy` | singleton |
| `gcp.iam.serviceAccountKeyMetadata` / list | `GET https://iam.googleapis.com/v1/{parent}/keys` | projects | parent: `{scope}/serviceAccounts/{email_or_numeric_id}` | `iam.serviceAccountKeys.list` | client |
| `gcp.iam.serviceAccountKeys` / list | `GET https://iam.googleapis.com/v1/projects/{project}/serviceAccounts` | projects | — | `iam.serviceAccounts.list`, `iam.serviceAccountKeys.list` | keys |
| `gcp.iam.serviceAccounts` / get | `GET https://iam.googleapis.com/v1/{scope}/serviceAccounts/{resource_id}` | projects | `resource_id` | `iam.serviceAccounts.get` | singleton |
| `gcp.iam.serviceAccounts` / list | `GET https://iam.googleapis.com/v1/projects/{project}/serviceAccounts` | projects | — | `iam.serviceAccounts.list` | native |
| `gcp.iam.workloadIdentityPools` / list | `GET https://iam.googleapis.com/v1/projects/{project}/locations/global/workloadIdentityPools` | projects | — | `iam.workloadIdentityPools.list`, `resourcemanager.projects.get` | native |
| `gcp.iam.workloadIdentityProviders` / get | `GET https://iam.googleapis.com/v1/{parent}/providers/{resource_id}` | projects | parent: `projects/{project_number}/locations/global/workloadIdentityPools/{pool}`; `resource_id` | `iam.workloadIdentityPoolProviders.get` | singleton |
| `gcp.iam.workloadIdentityProviders` / list | `GET https://iam.googleapis.com/v1/{parent}/providers` | projects | parent: `projects/{project_number}/locations/global/workloadIdentityPools/{pool}` | `iam.workloadIdentityPoolProviders.list` | native |
| `gcp.kms.cryptoKeyVersions` / get | `GET https://cloudkms.googleapis.com/v1/{parent}/cryptoKeyVersions/{resource_id}` | projects | parent: `{scope}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}`; `resource_id` | `cloudkms.cryptoKeyVersions.get` | singleton |
| `gcp.kms.cryptoKeyVersions` / list | `GET https://cloudkms.googleapis.com/v1/{parent}/cryptoKeyVersions` | projects | parent: `{scope}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}` | `cloudkms.cryptoKeyVersions.list` | native |
| `gcp.kms.cryptoKeys` / get | `GET https://cloudkms.googleapis.com/v1/{parent}/cryptoKeys/{resource_id}` | projects | parent: `{scope}/locations/{location}/keyRings/{key_ring}`; `resource_id` | `cloudkms.cryptoKeys.get` | singleton |
| `gcp.kms.cryptoKeys` / list | `GET https://kmsinventory.googleapis.com/v1/projects/{project}/cryptoKeys` | projects | — | `cloudkms.cryptoKeys.list` | native |
| `gcp.kms.keyRings` / get | `GET https://cloudkms.googleapis.com/v1/{scope}/locations/{location}/keyRings/{resource_id}` | projects | `resource_id`; location: required | `cloudkms.keyRings.get` | singleton |
| `gcp.kms.keyRings` / list | `GET https://cloudkms.googleapis.com/v1/projects/{project}/locations/{location}/keyRings` | projects | location: required | `cloudkms.keyRings.list` | native |
| `gcp.kms.liveCryptoKeys` / get | `GET https://cloudkms.googleapis.com/v1/{parent}/cryptoKeys/{resource_id}` | projects | parent: `{scope}/locations/{location}/keyRings/{key_ring}`; `resource_id` | `cloudkms.cryptoKeys.get` | singleton |
| `gcp.kms.liveCryptoKeys` / list | `GET https://cloudkms.googleapis.com/v1/{parent}/cryptoKeys` | projects | parent: `{scope}/locations/{location}/keyRings/{key_ring}` | `cloudkms.cryptoKeys.list` | native |
| `gcp.logging.buckets` / get | `GET https://logging.googleapis.com/v2/{scope}/locations/{location}/buckets/{resource_id}` | projects, folders, organizations | `resource_id`; location: required | `logging.buckets.get` | singleton |
| `gcp.logging.buckets` / list | `GET https://logging.googleapis.com/v2/{scope}/locations/{location}/buckets` | projects, folders, organizations | location: wildcard | `logging.buckets.list` | native |
| `gcp.logging.cmekSettings` / get | `GET https://logging.googleapis.com/v2/{scope}/cmekSettings` | projects, folders, organizations | — | `logging.cmekSettings.get` | singleton |
| `gcp.logging.exclusions` / get | `GET https://logging.googleapis.com/v2/{scope}/exclusions/{resource_id}` | projects, folders, organizations | `resource_id` | `logging.exclusions.get` | singleton |
| `gcp.logging.exclusions` / list | `GET https://logging.googleapis.com/v2/{scope}/exclusions` | projects, folders, organizations | — | `logging.exclusions.list` | native |
| `gcp.logging.metrics` / get | `GET https://logging.googleapis.com/v2/{scope}/metrics/{resource_id}` | projects | `resource_id` | `logging.logMetrics.get` | singleton |
| `gcp.logging.metrics` / list | `GET https://logging.googleapis.com/v2/{scope}/metrics` | projects | — | `logging.logMetrics.list` | native |
| `gcp.logging.settings` / get | `GET https://logging.googleapis.com/v2/{scope}/settings` | projects, folders, organizations | — | `logging.settings.get` | singleton |
| `gcp.logging.sinks` / get | `GET https://logging.googleapis.com/v2/{scope}/sinks/{resource_id}` | projects, folders, organizations | `resource_id` | `logging.sinks.get` | singleton |
| `gcp.logging.sinks` / list | `GET https://logging.googleapis.com/v2/{scope}/sinks` | projects, folders, organizations | — | `logging.sinks.list` | native |
| `gcp.logging.views` / get | `GET https://logging.googleapis.com/v2/{parent}/views/{resource_id}` | projects, folders, organizations | parent: `{scope}/locations/{location}/buckets/{bucket}`; `resource_id` | `logging.views.get` | singleton |
| `gcp.logging.views` / list | `GET https://logging.googleapis.com/v2/{parent}/views` | projects, folders, organizations | parent: `{scope}/locations/{location}/buckets/{bucket}` | `logging.views.list` | native |
| `gcp.monitoring.alertPolicies` / get | `GET https://monitoring.googleapis.com/v3/{scope}/alertPolicies/{resource_id}` | projects | `resource_id` | `monitoring.alertPolicies.get` | singleton |
| `gcp.monitoring.alertPolicies` / list | `GET https://monitoring.googleapis.com/v3/projects/{project}/alertPolicies` | projects | — | `monitoring.alertPolicies.list` | native |
| `gcp.networkmanagement.orgVpcFlowLogsConfigs` / list | `GET https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs:queryOrgVpcFlowLogsConfigs` | projects | — | `networkmanagement.vpcflowlogsconfigs.list` | native |
| `gcp.networkmanagement.vpcFlowLogsConfigs` / get | `GET https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs/{resource_id}` | projects, organizations | `resource_id` | `networkmanagement.vpcflowlogsconfigs.get` | singleton |
| `gcp.networkmanagement.vpcFlowLogsConfigs` / list | `GET https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs` | projects, organizations | — | `networkmanagement.vpcflowlogsconfigs.list` | native |
| `gcp.orgpolicy.constraints` / list | `GET https://orgpolicy.googleapis.com/v2/{scope}/constraints` | projects, folders, organizations | — | `orgpolicy.constraints.list` | native |
| `gcp.orgpolicy.customConstraints` / get | `GET https://orgpolicy.googleapis.com/v2/{scope}/customConstraints/{resource_id}` | organizations | `resource_id` | `orgpolicy.customConstraints.get` | singleton |
| `gcp.orgpolicy.customConstraints` / list | `GET https://orgpolicy.googleapis.com/v2/{scope}/customConstraints` | organizations | — | `orgpolicy.customConstraints.list` | native |
| `gcp.orgpolicy.effectivePolicies` / get | `GET https://orgpolicy.googleapis.com/v2/{scope}/policies/{resource_id}:getEffectivePolicy` | projects, folders, organizations | `resource_id` | `orgpolicy.policy.get` | singleton |
| `gcp.orgpolicy.policies` / get | `GET https://orgpolicy.googleapis.com/v2/{scope}/policies/{resource_id}` | projects, folders, organizations | `resource_id` | `orgpolicy.policy.get` | singleton |
| `gcp.orgpolicy.policies` / list | `GET https://orgpolicy.googleapis.com/v2/{scope}/policies` | projects, folders, organizations | — | `orgpolicy.policies.list` | native |
| `gcp.osconfig.inventories` / list | `GET https://osconfig.googleapis.com/v1/projects/{project}/locations/{location}/instances/-/inventories` | projects | location: required | `osconfig.inventories.list` | native |
| `gcp.osconfig.vulnerabilityReports` / list | `GET https://osconfig.googleapis.com/v1/projects/{project}/locations/{location}/instances/-/vulnerabilityReports` | projects | location: required | `osconfig.vulnerabilityReports.list` | native |
| `gcp.pubsub.subscriptions` / get | `GET https://pubsub.googleapis.com/v1/{scope}/subscriptions/{resource_id}` | projects | `resource_id` | `pubsub.subscriptions.get` | singleton |
| `gcp.pubsub.subscriptions` / list | `GET https://pubsub.googleapis.com/v1/projects/{project}/subscriptions` | projects | — | `pubsub.subscriptions.list` | native |
| `gcp.pubsub.topics` / get | `GET https://pubsub.googleapis.com/v1/{scope}/topics/{resource_id}` | projects | `resource_id` | `pubsub.topics.get` | singleton |
| `gcp.pubsub.topics` / list | `GET https://pubsub.googleapis.com/v1/projects/{project}/topics` | projects | — | `pubsub.topics.list` | native |
| `gcp.resourcemanager.folder` / get | `GET https://cloudresourcemanager.googleapis.com/v3/{scope}` | folders | — | `resourcemanager.folders.get` | singleton |
| `gcp.resourcemanager.folders` / list | `GET https://cloudresourcemanager.googleapis.com/v3/folders` | folders, organizations | — | `resourcemanager.folders.list` | native |
| `gcp.resourcemanager.organization` / get | `GET https://cloudresourcemanager.googleapis.com/v3/{scope}` | organizations | — | `resourcemanager.organizations.get` | singleton |
| `gcp.resourcemanager.project` / get | `GET https://cloudresourcemanager.googleapis.com/v3/{scope}` | projects | — | `resourcemanager.projects.get` | singleton |
| `gcp.resourcemanager.project` / list | `GET https://cloudresourcemanager.googleapis.com/v3/projects/{project}` | projects | — | `resourcemanager.projects.get` | singleton |
| `gcp.resourcemanager.projects` / list | `GET https://cloudresourcemanager.googleapis.com/v3/projects` | folders, organizations | — | `resourcemanager.projects.list` | native |
| `gcp.run.jobs` / get | `GET https://run.googleapis.com/v2/{scope}/locations/{location}/jobs/{resource_id}` | projects | `resource_id`; location: required | `run.jobs.get` | singleton |
| `gcp.run.jobs` / list | `GET https://run.googleapis.com/v2/projects/{project}/locations/{location}/jobs` | projects | location: required | `run.jobs.list` | native |
| `gcp.run.services` / get | `GET https://run.googleapis.com/v2/{scope}/locations/{location}/services/{resource_id}` | projects | `resource_id`; location: required | `run.services.get` | singleton |
| `gcp.run.services` / list | `GET https://run.googleapis.com/v2/projects/{project}/locations/{location}/services` | projects | location: required | `run.services.list` | native |
| `gcp.secretmanager.secrets` / get | `GET https://secretmanager.googleapis.com/v1/{scope}/secrets/{resource_id}` | projects | `resource_id` | `secretmanager.secrets.get` | singleton |
| `gcp.secretmanager.secrets` / list | `GET https://secretmanager.googleapis.com/v1/projects/{project}/secrets` | projects | — | `secretmanager.secrets.list` | native |
| `gcp.securitycenter.findings` / list | `GET https://securitycenter.googleapis.com/v2/{scope}/sources/{source_id}/locations/{location}/findings` | projects, folders, organizations | location: global; `source_id` optional; `state` optional | `securitycenter.findings.list` | native |
| `gcp.securitycenter.sources` / get | `GET https://securitycenter.googleapis.com/v2/{scope}/sources/{resource_id}` | organizations | `resource_id` | `securitycenter.sources.get` | singleton |
| `gcp.securitycenter.sources` / list | `GET https://securitycenter.googleapis.com/v2/{scope}/sources` | organizations | — | `securitycenter.sources.list` | native |
| `gcp.serviceusage.services` / list | `GET https://serviceusage.googleapis.com/v1/projects/{project}/services` | projects | — | `serviceusage.services.list`, `resourcemanager.projects.get` | native |
| `gcp.sql.instances` / get | `GET https://sqladmin.googleapis.com/sql/v1beta4/{scope}/instances/{resource_id}` | projects | `resource_id` | `cloudsql.instances.get` | singleton |
| `gcp.sql.instances` / list | `GET https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances` | projects | — | `cloudsql.instances.list` | native |
| `gcp.storage.bucketIamPolicy` / get | `GET https://storage.googleapis.com/storage/v1/b/{resource_id}/iam` | projects | `resource_id` | `storage.buckets.list`, `storage.buckets.getIamPolicy` | singleton |
| `gcp.storage.buckets` / get | `GET https://storage.googleapis.com/storage/v1/b/{resource_id}` | projects | `resource_id` | `storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy` | singleton |
| `gcp.storage.buckets` / list | `GET https://storage.googleapis.com/storage/v1/b` | projects | — | `storage.buckets.list` | native |

For Compute gets with several locations, the permissions table lists the possible variants; `permissions_by_location_type` identifies the permission for the selected path. For the direct Resource Manager IAM-policy read, only the permission corresponding to the selected root type applies. Bucket full-metadata reads can also require `storage.buckets.getIpFilter` to expose IP-filter settings; missing optional fields must not be treated as proof that the feature is disabled.

## Inventory and IAM discovery

`search_inventory` provides Cloud Asset resource search, allowed resource snapshots, and IAM-policy search at explicitly authorized organization/folder/project roots. These are indexed observations and carry `freshness=inventory`. Native configuration queries are preferable when present freshness matters. Asset coverage differs across upstream search and list methods; neither a successful page nor an empty page proves all expected resources have been inventoried.

IAM search can return only bindings matching the search query. It must not be used to assert that a resource has no other bindings. Reading the direct Resource Manager, bucket, or service-account policy requests version 3 so conditions are preserved. The service-account policy describes **who can act on the service account**, not every grant that account has elsewhere. Predefined and organization/project custom role definitions are separate query scopes. Deny-policy list returns **metadata without rules**: get each returned policy to inspect its rules, and inspect relevant ancestor attachments. PAB definitions and policy bindings are separate evidence; neither alone establishes effective access.

Hierarchy discovery lists direct child projects and folders; explicitly traverse folder pages when the task needs a complete authorized organization inventory. It does not silently recurse beyond page or assessment budgets.

## Evidence semantics and incomplete coverage

- Preserve every continuation token, including on short or empty pages. Stopping early is partial coverage. A parent membership proof is bounded and fails closed if ownership cannot be established within that bound.
- Aggregated Compute scope warnings and unreachable locations remain errors; `NO_RESULTS_ON_PAGE` alone is an ordinary empty scope. Effective VM firewall rules describe one NIC's applicable rules, not observed traffic reachability across every network hop.
- Effective organization-policy reads use the constraint ID without `constraints/`, for example `compute.requireOsLogin`. The API merges hierarchy and evaluates conditions; it does not expand `under:` subtrees. Direct policy list/get is not a substitute for this effective read.
- GKE clusters, node pools, and per-account key lists lack upstream pagination. Their deterministic `offset:N` pages re-read the collection and can shift as resources change. Responses identify that behavior as best effort.
- KMS `gcp.kms.cryptoKeys` list uses KMS Inventory and is a snapshot. Its exact get and `gcp.kms.liveCryptoKeys` nested list use the live Cloud KMS API. Version queries request metadata only and exclude attestation/key data. Key creation/expiry/disabled metadata is not an authoritative last-used timestamp.
- BigQuery dataset summaries are enriched with `datasets.get`; any enrichment failure is visible. Dataset configuration is covered; table rows, query jobs, extracts, and table-level schema/policy collectors are not implemented.
- SCC findings and Artifact Analysis vulnerability occurrences are already-existing reports. Activation, tier, location, scanner coverage and permissions determine what exists. SCC `global` is a data location, not a wildcard for `eu`, `us`, or `sa`. Artifact Analysis accepts only the fixed vulnerability filter and discards other occurrence kinds, including secret-discovery occurrences.
- VM Manager inventory and vulnerability reports require prior VM Manager reporting configuration. The list collectors request only their documented list permission (inventory uses FULL view); no guest agent is installed and no new scan is started.
- Logging buckets/views/sinks/exclusions/metrics/settings describe retention, routing, filtering, encryption, and alert inputs. Dedicated `query_logs` handles bounded entry queries. Organization/project Network Management configs, applicable organization configs, and subnet-level flow logging are distinct evidence; no API call here enables logging.
- VPC Service Controls `status` is enforced perimeter configuration; `spec` is dry-run configuration. Inspect both when reasoning about rollout. Configuration reads do not simulate enforcement or establish end-to-end exfiltration resistance.
- Query availability and automatic check availability are distinct. A newly collected resource family may be useful to the agent even when no built-in deterministic check is registered for it. Use `list_security_checks` to discover actual checks.

## Intentional exclusions and remaining product gaps

No generic shell, CLI, API URL, request body, or filter execution exists. The MCP does not list/download GCS objects or artifact bytes; retrieve Kubernetes Secrets/ConfigMaps or Secret Manager versions; read IAM private/public key data; fetch VM console, screenshots, serial output, or guest attributes; execute in VMs/pods; pull Pub/Sub messages; connect to SQL or read rows; decrypt/sign; enable APIs; trigger scans; mutate infrastructure; change IAM; or remediate findings.

Runtime OS hardening, processes, running container filesystem state, malware evidence, exploit validation and application vulnerabilities require separately approved sensors/scanners. Group/directory expansion, arbitrary IAM condition evaluation, and a full effective-access simulator are not implemented. The registered catalog is not a complete coverage claim for every GCP product: examples of missing native detail collectors include BigQuery table-level policies, Cloud SQL database/user grants, IAP application policy evaluation, DNS record sets, Cloud Build/Deploy pipelines, and service-specific security posture for products outside the catalog. Inventory or IAM search may expose limited metadata for a resource without providing full native configuration or a built-in check. See [query-coverage.md](query-coverage.md) for the question-level matrix and [alicloud-coverage.md](alicloud-coverage.md) for Alibaba's separate implementation boundary.

Rich configuration can contain inline environment values, annotations, metadata, credentials, source references or other sensitive fields. The central projection/redaction layer is part of the security boundary and runs before MCP responses and evidence storage. Do not expose raw provider adapters as an alternate API. Kubernetes authorization and network reachability remain independent concerns; see [kubernetes.md](kubernetes.md).

## Primary API references

API routing and edge cases were checked against primary documentation; automated tests use mocked upstream responses. Live acceptance with the target organization's credentials is still required to establish real permission, quota, API-activation and data availability.

- [Resource Manager direct-child project list](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/list)
- [Cloud Asset supported types and consistency](https://docs.cloud.google.com/asset-inventory/docs/asset-types)
- [Cloud Asset IAM search and filtered-binding semantics](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies)
- [Compute aggregated instances](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList)
- [Effective VM NIC firewall rules](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getEffectiveFirewalls)
- [Hierarchical firewall policy list and parentId](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewallPolicies/list)
- [Global network firewall policy permissions](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networkFirewallPolicies/list)
- [Regional network firewall policy permissions](https://docs.cloud.google.com/compute/docs/reference/rest/v1/regionNetworkFirewallPolicies/list)
- [Custom/predefined roles and FULL view](https://docs.cloud.google.com/iam/docs/reference/rest/v1/organizations.roles/list)
- [Service-account policy read transcoding](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/getIamPolicy)
- [IAM deny list omits rules](https://docs.cloud.google.com/iam/docs/reference/rest/v2/policies/listPolicies)
- [PAB policy definitions](https://docs.cloud.google.com/iam/docs/reference/rest/v3/organizations.locations.principalAccessBoundaryPolicies/list)
- [PAB policy bindings](https://docs.cloud.google.com/iam/docs/reference/rest/v3/organizations.locations.policyBindings/list)
- [Organization Policy permissions by method (GetPolicy/GetEffectivePolicy use orgpolicy.policy.get)](https://docs.cloud.google.com/organization-policy/audit-logging)
- [Effective organization policy semantics](https://docs.cloud.google.com/organization-policy/reference/rest/v2/projects.policies/getEffectivePolicy)
- [Bucket full metadata and ACLs](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get)
- [Bucket IAM version selection](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/getIamPolicy)
- [Logging view definitions](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets.views/list)
- [KMS version metadata](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list)
- [SCC source/location findings](https://docs.cloud.google.com/security-command-center/docs/reference/rest/v2/projects.sources.locations.findings/list)
- [Artifact Analysis vulnerability filter](https://docs.cloud.google.com/artifact-analysis/docs/investigate-vulnerabilities)
- [Artifact Analysis occurrence kinds, including SECRET](https://docs.cloud.google.com/artifact-analysis/docs/reference/rest/v1/projects.occurrences)
- [Flow log configuration at project and organization scope](https://docs.cloud.google.com/vpc/docs/using-flow-logs)
- [Access Context Manager policy ownership](https://docs.cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies/list)
- [VPC Service Controls perimeter reads](https://docs.cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies.servicePerimeters/list)
- [OS Config inventory list](https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.inventories/list)
- [OS Config vulnerability-report list](https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports/list)
