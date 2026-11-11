"""Explicit GCP read routes. Adding a kind is a reviewed code change.

No caller can supply a URL, method, API version, response field expression, or
request body. The catalog contains configuration and security-report reads only.
"""

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class ResourceSpec:
    kind: str
    url: str
    items_key: str
    permissions: tuple[str, ...]
    location_mode: Literal["none", "required", "wildcard", "global"] = "none"
    pagination: Literal["native", "client", "singleton", "keys", "policy"] = "native"
    page_size_key: str = "pageSize"
    max_page_size: int = 1000
    aggregation_key: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    asset_type: str | None = None
    freshness: Literal["live", "inventory"] = "live"
    project_number: bool = False
    notes: str = ""

    def capability(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.notes or f"Read {self.kind} resource configuration.",
            "operation": "list",
            "endpoint": self.url,
            "permissions": list(self.permissions),
            "requires_location": self.location_mode == "required",
            "location_mode": self.location_mode,
            "pagination": self.pagination,
            "max_page_size": self.max_page_size,
            "freshness": self.freshness,
            "uses_project_number": self.project_number,
            "notes": self.notes,
        }


def _compute(
    collection: str, *, aggregated: bool = False, asset: str | None = None
) -> ResourceSpec:
    scope = "aggregated" if aggregated else "global"
    route = "firewallPolicies" if collection == "networkFirewallPolicies" else collection
    return ResourceSpec(
        kind=f"gcp.compute.{collection}",
        url=f"https://compute.googleapis.com/compute/v1/projects/{{project}}/{scope}/{route}",
        items_key="items",
        permissions=(f"compute.{route}.list",),
        page_size_key="maxResults",
        max_page_size=500,
        aggregation_key=collection if aggregated else None,
        params={"returnPartialSuccess": "true"} if aggregated else {},
        asset_type=f"compute.googleapis.com/{asset}" if asset else None,
        notes="All regions/zones; partial scope failures are returned as errors."
        if aggregated
        else "Global collection only.",
    )


_SPECS = [
    *[
        _compute(collection, aggregated=True, asset=asset)
        for collection, asset in (
            ("instances", "Instance"),
            ("disks", "Disk"),
            ("subnetworks", "Subnetwork"),
            ("routers", "Router"),
            ("addresses", "Address"),
            ("forwardingRules", "ForwardingRule"),
            ("backendServices", "BackendService"),
            ("instanceGroupManagers", "InstanceGroupManager"),
            ("instanceGroups", "InstanceGroup"),
            ("networkEndpointGroups", "NetworkEndpointGroup"),
            ("vpnGateways", "VpnGateway"),
            ("vpnTunnels", "VpnTunnel"),
            ("serviceAttachments", "ServiceAttachment"),
            ("targetHttpProxies", "TargetHttpProxy"),
            ("targetHttpsProxies", "TargetHttpsProxy"),
            ("urlMaps", "UrlMap"),
            ("healthChecks", "HealthCheck"),
        )
    ],
    *[
        _compute(collection, asset=asset)
        for collection, asset in (
            ("firewalls", "Firewall"),
            ("networks", "Network"),
            ("routes", "Route"),
            ("sslPolicies", "SslPolicy"),
            ("securityPolicies", "SecurityPolicy"),
            ("instanceTemplates", "InstanceTemplate"),
            ("images", "Image"),
            ("snapshots", "Snapshot"),
            ("backendBuckets", "BackendBucket"),
            ("networkFirewallPolicies", None),
        )
    ],
    ResourceSpec(
        "gcp.compute.project",
        "https://compute.googleapis.com/compute/v1/projects/{project}",
        "",
        ("compute.projects.get",),
        pagination="singleton",
        notes="Project-level Compute configuration, including metadata; output filtering removes arbitrary metadata values.",
    ),
    ResourceSpec(
        "gcp.resourcemanager.project",
        "https://cloudresourcemanager.googleapis.com/v3/projects/{project}",
        "",
        ("resourcemanager.projects.get",),
        pagination="singleton",
        asset_type="cloudresourcemanager.googleapis.com/Project",
    ),
    ResourceSpec(
        "gcp.compute.regionSecurityPolicies",
        "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{location}/securityPolicies",
        "items",
        ("compute.regionSecurityPolicies.list",),
        location_mode="required",
        page_size_key="maxResults",
        max_page_size=500,
        notes="One region; global securityPolicies are a separate kind.",
    ),
    ResourceSpec(
        "gcp.container.clusters",
        "https://container.googleapis.com/v1/projects/{project}/locations/{location}/clusters",
        "clusters",
        ("container.clusters.list",),
        location_mode="wildcard",
        pagination="client",
        asset_type="container.googleapis.com/Cluster",
        notes="All locations by default. Node-pool configurations are included in cluster objects. The upstream method has no pagination; local pages are best-effort observations of a changing collection.",
    ),
    ResourceSpec(
        "gcp.storage.buckets",
        "https://storage.googleapis.com/storage/v1/b",
        "items",
        ("storage.buckets.list",),
        page_size_key="maxResults",
        params={"project": "{project}", "projection": "noAcl"},
        asset_type="storage.googleapis.com/Bucket",
        notes="Bucket configuration only; no object listing/download. Bucket IAM is available through scoped IAM-policy search.",
    ),
    ResourceSpec(
        "gcp.iam.serviceAccounts",
        "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts",
        "accounts",
        ("iam.serviceAccounts.list",),
        max_page_size=100,
        asset_type="iam.googleapis.com/ServiceAccount",
    ),
    ResourceSpec(
        "gcp.iam.serviceAccountKeys",
        "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts",
        "keys",
        ("iam.serviceAccounts.list", "iam.serviceAccountKeys.list"),
        pagination="keys",
        max_page_size=20,
        notes="USER_MANAGED key metadata. Page size counts service accounts (at most 20); page token continues the account collection. No key bytes are returned. Per-account denials make coverage incomplete.",
    ),
    ResourceSpec(
        "gcp.iam.policy",
        "https://cloudresourcemanager.googleapis.com/v3/projects/{project}:getIamPolicy",
        "",
        ("resourcemanager.projects.getIamPolicy",),
        pagination="policy",
        notes="Direct project allow policy, requested version 3; not an effective-permissions calculation. Ancestor policies can be read through get_iam_policy.",
    ),
    ResourceSpec(
        "gcp.iam.roles",
        "https://iam.googleapis.com/v1/projects/{project}/roles",
        "roles",
        ("iam.roles.list",),
        params={"view": "FULL"},
        notes="Project custom roles, including permissions; predefined and organization custom roles are separate scopes.",
    ),
    ResourceSpec(
        "gcp.iam.workloadIdentityPools",
        "https://iam.googleapis.com/v1/projects/{project}/locations/global/workloadIdentityPools",
        "workloadIdentityPools",
        ("iam.workloadIdentityPools.list", "resourcemanager.projects.get"),
        project_number=True,
    ),
    ResourceSpec(
        "gcp.sql.instances",
        "https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances",
        "items",
        ("cloudsql.instances.list",),
        page_size_key="maxResults",
        max_page_size=1000,
        asset_type="sqladmin.googleapis.com/Instance",
        notes="Instance settings; no SQL connection, users/passwords, or database row access.",
    ),
    ResourceSpec(
        "gcp.run.services",
        "https://run.googleapis.com/v2/projects/{project}/locations/{location}/services",
        "services",
        ("run.services.list",),
        location_mode="required",
        asset_type="run.googleapis.com/Service",
        notes="A concrete region is required by the native v2 API; '-' is not accepted.",
    ),
    ResourceSpec(
        "gcp.run.jobs",
        "https://run.googleapis.com/v2/projects/{project}/locations/{location}/jobs",
        "jobs",
        ("run.jobs.list",),
        location_mode="required",
        asset_type="run.googleapis.com/Job",
        notes="One region; returns job definitions only, never executes jobs.",
    ),
    ResourceSpec(
        "gcp.cloudfunctions.functions",
        "https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/{location}/functions",
        "functions",
        ("cloudfunctions.functions.list",),
        location_mode="wildcard",
        asset_type="cloudfunctions.googleapis.com/Function",
        notes="Definitions returned by the v2 API; no source archive download or invocation.",
    ),
    ResourceSpec(
        "gcp.artifactregistry.repositories",
        "https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories",
        "repositories",
        ("artifactregistry.repositories.list",),
        location_mode="required",
        asset_type="artifactregistry.googleapis.com/Repository",
        notes="Repository settings for an explicit region or multi-region; artifact/package bytes are never downloaded.",
    ),
    ResourceSpec(
        "gcp.bigquery.datasets",
        "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets",
        "datasets",
        ("bigquery.datasets.get",),
        page_size_key="maxResults",
        asset_type="bigquery.googleapis.com/Dataset",
        notes="List summaries are enriched with datasets.get for security configuration. No tabledata, query jobs, exports, or row access.",
    ),
    ResourceSpec(
        "gcp.pubsub.topics",
        "https://pubsub.googleapis.com/v1/projects/{project}/topics",
        "topics",
        ("pubsub.topics.list",),
        asset_type="pubsub.googleapis.com/Topic",
    ),
    ResourceSpec(
        "gcp.pubsub.subscriptions",
        "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions",
        "subscriptions",
        ("pubsub.subscriptions.list",),
        asset_type="pubsub.googleapis.com/Subscription",
        notes="Subscription settings only; no pull, acknowledgment, seek, or message retrieval.",
    ),
    ResourceSpec(
        "gcp.dns.managedZones",
        "https://dns.googleapis.com/dns/v1/projects/{project}/managedZones",
        "managedZones",
        ("dns.managedZones.list",),
        page_size_key="maxResults",
        asset_type="dns.googleapis.com/ManagedZone",
    ),
    ResourceSpec(
        "gcp.logging.sinks",
        "https://logging.googleapis.com/v2/projects/{project}/sinks",
        "sinks",
        ("logging.sinks.list",),
        asset_type="logging.googleapis.com/LogSink",
    ),
    ResourceSpec(
        "gcp.logging.buckets",
        "https://logging.googleapis.com/v2/projects/{project}/locations/{location}/buckets",
        "buckets",
        ("logging.buckets.list",),
        location_mode="wildcard",
        asset_type="logging.googleapis.com/LogBucket",
    ),
    ResourceSpec(
        "gcp.logging.exclusions",
        "https://logging.googleapis.com/v2/projects/{project}/exclusions",
        "exclusions",
        ("logging.exclusions.list",),
    ),
    ResourceSpec(
        "gcp.orgpolicy.policies",
        "https://orgpolicy.googleapis.com/v2/projects/{project}/policies",
        "policies",
        ("orgpolicy.policies.list",),
        asset_type="orgpolicy.googleapis.com/Policy",
        notes="Explicitly attached project policies; absent policy is not evidence that no inherited policy applies.",
    ),
    ResourceSpec(
        "gcp.secretmanager.secrets",
        "https://secretmanager.googleapis.com/v1/projects/{project}/secrets",
        "secrets",
        ("secretmanager.secrets.list",),
        asset_type="secretmanager.googleapis.com/Secret",
        notes="Secret resource metadata (replication, rotation, labels) only; global collection. No versions or payload access.",
    ),
    ResourceSpec(
        "gcp.kms.keyRings",
        "https://cloudkms.googleapis.com/v1/projects/{project}/locations/{location}/keyRings",
        "keyRings",
        ("cloudkms.keyRings.list",),
        location_mode="required",
        asset_type="cloudkms.googleapis.com/KeyRing",
    ),
    ResourceSpec(
        "gcp.kms.cryptoKeys",
        "https://kmsinventory.googleapis.com/v1/projects/{project}/cryptoKeys",
        "cryptoKeys",
        ("cloudkms.cryptoKeys.list",),
        freshness="inventory",
        asset_type="cloudkms.googleapis.com/CryptoKey",
        notes="KMS Inventory snapshot metadata across the project; may lag live state. No encrypt/decrypt, key material, or signatures.",
    ),
    ResourceSpec(
        "gcp.osconfig.inventories",
        "https://osconfig.googleapis.com/v1/projects/{project}/locations/{location}/instances/-/inventories",
        "inventories",
        ("osconfig.inventories.list",),
        location_mode="required",
        params={"view": "FULL"},
        notes="Existing VM Manager inventory for one zone. VM Manager must already collect inventory; this service installs no guest agent.",
    ),
    ResourceSpec(
        "gcp.osconfig.vulnerabilityReports",
        "https://osconfig.googleapis.com/v1/projects/{project}/locations/{location}/instances/-/vulnerabilityReports",
        "vulnerabilityReports",
        ("osconfig.vulnerabilityReports.list",),
        location_mode="required",
        notes="Existing reports for one zone; no guest execution or new vulnerability scan.",
    ),
    ResourceSpec(
        "gcp.networkmanagement.vpcFlowLogsConfigs",
        "https://networkmanagement.googleapis.com/v1/projects/{project}/locations/global/vpcFlowLogsConfigs",
        "vpcFlowLogsConfigs",
        ("networkmanagement.vpcflowlogsconfigs.list",),
        notes="Project-level Network Management flow-log configuration. Subnet flow-log configuration is also present in Compute subnetworks; organization-level configurations require a separate authorized organization read.",
    ),
    ResourceSpec(
        "gcp.serviceusage.services",
        "https://serviceusage.googleapis.com/v1/projects/{project}/services",
        "services",
        ("serviceusage.services.list", "resourcemanager.projects.get"),
        max_page_size=200,
        params={"filter": "state:ENABLED"},
        project_number=True,
        notes="Enabled service names/configuration only; services are never enabled or disabled.",
    ),
    ResourceSpec(
        "gcp.monitoring.alertPolicies",
        "https://monitoring.googleapis.com/v3/projects/{project}/alertPolicies",
        "alertPolicies",
        ("monitoring.alertPolicies.list",),
        notes="Alert policy configuration; notification-channel credentials are not collected.",
    ),
    ResourceSpec(
        "gcp.securitycenter.findings",
        "https://securitycenter.googleapis.com/v2/projects/{project}/sources/-/locations/{location}/findings",
        "listFindingsResults",
        ("securitycenter.findings.list",),
        location_mode="global",
        notes="Existing SCC findings across sources in the selected SCC data location, default global. SCC activation/tier and permissions determine available findings.",
    ),
]

RESOURCE_SPECS: dict[str, ResourceSpec] = {spec.kind: spec for spec in _SPECS}

# RESOURCE asset reads are deliberately allowlisted: no Kubernetes Secrets,
# storage objects, database rows, arbitrary custom resource data, or key bytes.
SAFE_ASSET_TYPES: frozenset[str] = frozenset(spec.asset_type for spec in _SPECS if spec.asset_type)

ASSET_KIND_MAP: dict[str, str] = {spec.asset_type: spec.kind for spec in _SPECS if spec.asset_type}
