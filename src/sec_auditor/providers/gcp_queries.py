"""Reviewed, purpose-specific GCP query routes beyond project inventory lists.

This catalog deliberately does not accept arbitrary API names, URLs, filters,
field masks or request bodies. A security question maps to one fixed operation.
Every nested parent is validated against the already authorized scope.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

from sec_auditor.providers.catalog import RESOURCE_SPECS

HIERARCHY = ("projects", "folders", "organizations")
NAME = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,1023}"
ACCOUNT = r"(?:[0-9]{1,30}|[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[a-z0-9.-]+\.gserviceaccount\.com)"
BUCKET = r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]"
LOCATION = r"[a-z][a-z0-9-]{0,62}"


@dataclass(frozen=True)
class QuerySpec:
    kind: str
    operation: Literal["list", "get"]
    url: str
    permissions: tuple[str, ...]
    items_key: str | None = None
    scopes: tuple[str, ...] = ("projects",)
    location_mode: Literal["none", "required", "global", "wildcard"] = "none"
    parent_suffix: str | None = None
    parent_example: str | None = None
    resource_pattern: str = NAME
    params: dict[str, Any] = field(default_factory=dict)
    selectors: dict[str, str] = field(default_factory=dict)
    defaults: dict[str, str] = field(default_factory=dict)
    selector_params: dict[str, str] = field(default_factory=dict)
    pagination: Literal["native", "client", "singleton"] = "native"
    page_size_key: str = "pageSize"
    max_page_size: int = 1000
    compute_scopes: tuple[str, ...] = ()
    compute_permissions: dict[str, str] = field(default_factory=dict)
    special: str = ""
    notes: str = ""

    @property
    def needs_resource_id(self) -> bool:
        return "{resource_id}" in self.url or self.special in {
            "bucket",
            "bucket_policy",
            "hierarchical_get",
        }

    def capability(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "endpoint": self.url,
            "permissions": list(self.permissions),
            "scope_types": list(self.scopes),
            "required_scopes": list(self.scopes),
            "requires_location": self.location_mode == "required"
            or bool(self.compute_scopes and "global" not in self.compute_scopes),
            "location_mode": self.location_mode,
            "requires_parent": self.parent_suffix is not None,
            "parent_format": self.parent_example,
            "requires_resource_id": self.needs_resource_id,
            "resource_id_pattern": self.resource_pattern if self.needs_resource_id else None,
            "selectors": {
                name: {
                    "required": name not in self.defaults,
                    "pattern": pattern,
                    "default": self.defaults.get(name),
                }
                for name, pattern in self.selectors.items()
            },
            "compute_location_types": list(self.compute_scopes),
            "location_requirements": {
                location_type: "not_required" if location_type == "global" else "required"
                for location_type in self.compute_scopes
            },
            "permissions_by_location_type": dict(self.compute_permissions),
            "method": "POST" if self.special in {"sa_policy", "crm_policy"} else "GET",
            "pagination": self.pagination,
            "max_page_size": self.max_page_size,
            "freshness": "live",
            "notes": self.notes,
        }


_QUERIES: list[QuerySpec] = []


def _collection(
    kind: str,
    url: str,
    items_key: str,
    permission: str,
    *,
    get_permission: str | None = None,
    **options: Any,
) -> None:
    _QUERIES.append(QuerySpec(kind, "list", url, (permission,), items_key=items_key, **options))
    if get_permission:
        get_options = dict(options)
        get_options.pop("params", None)
        get_options.pop("pagination", None)
        _QUERIES.append(
            QuerySpec(
                kind,
                "get",
                url + "/{resource_id}",
                (get_permission,),
                pagination="singleton",
                **get_options,
            )
        )


# Exact Compute reads need their actual regional/zonal/global scope. Aggregated
# list endpoints cannot be changed into a get endpoint simply by appending a name.
_COMPUTE_SCOPES = {
    "instances": ("zones",),
    "disks": ("zones", "regions"),
    "subnetworks": ("regions",),
    "routers": ("regions",),
    "addresses": ("global", "regions"),
    "forwardingRules": ("global", "regions"),
    "backendServices": ("global", "regions"),
    "instanceGroupManagers": ("zones", "regions"),
    "instanceGroups": ("zones", "regions"),
    "networkEndpointGroups": ("zones", "regions", "global"),
    "vpnGateways": ("regions",),
    "vpnTunnels": ("regions",),
    "serviceAttachments": ("regions",),
    "targetHttpProxies": ("global", "regions"),
    "targetHttpsProxies": ("global", "regions"),
    "urlMaps": ("global", "regions"),
    "healthChecks": ("global", "regions"),
}
_COMPUTE_PERMISSION_VARIANTS = {
    ("addresses", "global"): "globalAddresses",
    ("forwardingRules", "global"): "globalForwardingRules",
    ("backendServices", "regions"): "regionBackendServices",
    ("networkEndpointGroups", "regions"): "regionNetworkEndpointGroups",
    ("networkEndpointGroups", "global"): "globalNetworkEndpointGroups",
    ("targetHttpProxies", "regions"): "regionTargetHttpProxies",
    ("targetHttpsProxies", "regions"): "regionTargetHttpsProxies",
    ("urlMaps", "regions"): "regionUrlMaps",
    ("healthChecks", "regions"): "regionHealthChecks",
    ("networkFirewallPolicies", "global"): "firewallPolicies",
}
for _kind, _native in RESOURCE_SPECS.items():
    if not _kind.startswith("gcp.compute.") or _kind == "gcp.compute.project":
        continue
    _collection_name = _kind.rsplit(".", 1)[-1]
    _scopes = _COMPUTE_SCOPES.get(_collection_name, ("global",))
    if _collection_name == "regionSecurityPolicies":
        _scopes = ("regions",)
    _route = {
        "networkFirewallPolicies": "firewallPolicies",
        "regionSecurityPolicies": "securityPolicies",
    }.get(_collection_name, _collection_name)
    _get_permissions = {
        scope: f"compute.{_COMPUTE_PERMISSION_VARIANTS.get((_collection_name, scope), _collection_name)}.get"
        for scope in _scopes
    }
    _QUERIES.append(
        QuerySpec(
            _kind,
            "get",
            "https://compute.googleapis.com/compute/v1/{scope}/{compute_path}/"
            + _route
            + "/{resource_id}",
            tuple(sorted(set(_get_permissions.values()))),
            compute_scopes=_scopes,
            compute_permissions=_get_permissions,
            selectors={"location_type": "(?:" + "|".join(_scopes) + ")"}
            if len(_scopes) > 1
            else {},
            pagination="singleton",
            notes="Exact configuration. For multiple possible scopes, select location_type; a concrete location is required for zones/regions.",
        )
    )

# Straightforward exact configuration reads for existing project collectors.
for _kind, _url, _permission, _location in (
    (
        "gcp.compute.project",
        "https://compute.googleapis.com/compute/v1/{scope}",
        "compute.projects.get",
        "none",
    ),
    (
        "gcp.resourcemanager.project",
        "https://cloudresourcemanager.googleapis.com/v3/{scope}",
        "resourcemanager.projects.get",
        "none",
    ),
    (
        "gcp.container.clusters",
        "https://container.googleapis.com/v1/{scope}/locations/{location}/clusters/{resource_id}",
        "container.clusters.get",
        "required",
    ),
    (
        "gcp.sql.instances",
        "https://sqladmin.googleapis.com/sql/v1beta4/{scope}/instances/{resource_id}",
        "cloudsql.instances.get",
        "none",
    ),
    (
        "gcp.run.services",
        "https://run.googleapis.com/v2/{scope}/locations/{location}/services/{resource_id}",
        "run.services.get",
        "required",
    ),
    (
        "gcp.run.jobs",
        "https://run.googleapis.com/v2/{scope}/locations/{location}/jobs/{resource_id}",
        "run.jobs.get",
        "required",
    ),
    (
        "gcp.cloudfunctions.functions",
        "https://cloudfunctions.googleapis.com/v2/{scope}/locations/{location}/functions/{resource_id}",
        "cloudfunctions.functions.get",
        "required",
    ),
    (
        "gcp.artifactregistry.repositories",
        "https://artifactregistry.googleapis.com/v1/{scope}/locations/{location}/repositories/{resource_id}",
        "artifactregistry.repositories.get",
        "required",
    ),
    (
        "gcp.pubsub.topics",
        "https://pubsub.googleapis.com/v1/{scope}/topics/{resource_id}",
        "pubsub.topics.get",
        "none",
    ),
    (
        "gcp.pubsub.subscriptions",
        "https://pubsub.googleapis.com/v1/{scope}/subscriptions/{resource_id}",
        "pubsub.subscriptions.get",
        "none",
    ),
    (
        "gcp.dns.managedZones",
        "https://dns.googleapis.com/dns/v1/{scope}/managedZones/{resource_id}",
        "dns.managedZones.get",
        "none",
    ),
    (
        "gcp.secretmanager.secrets",
        "https://secretmanager.googleapis.com/v1/{scope}/secrets/{resource_id}",
        "secretmanager.secrets.get",
        "none",
    ),
    (
        "gcp.monitoring.alertPolicies",
        "https://monitoring.googleapis.com/v3/{scope}/alertPolicies/{resource_id}",
        "monitoring.alertPolicies.get",
        "none",
    ),
    (
        "gcp.kms.keyRings",
        "https://cloudkms.googleapis.com/v1/{scope}/locations/{location}/keyRings/{resource_id}",
        "cloudkms.keyRings.get",
        "required",
    ),
    (
        "gcp.binaryauthorization.policy",
        "https://binaryauthorization.googleapis.com/v1/{scope}/policy",
        "binaryauthorization.policy.get",
        "none",
    ),
):
    _QUERIES.append(
        QuerySpec(
            _kind,
            "get",
            _url,
            (_permission,),
            location_mode=_location,
            pagination="singleton",
            notes="Resource configuration only; no invocation, content access, or execution.",
        )
    )

_QUERIES.extend(
    [
        QuerySpec(
            "gcp.bigquery.datasets",
            "get",
            "https://bigquery.googleapis.com/bigquery/v2/{scope}/datasets/{resource_id}",
            ("bigquery.datasets.get",),
            resource_pattern=r"[A-Za-z0-9_]{1,1024}",
            pagination="singleton",
        ),
        QuerySpec(
            "gcp.storage.buckets",
            "get",
            "https://storage.googleapis.com/storage/v1/b/{resource_id}",
            ("storage.buckets.list", "storage.buckets.get", "storage.buckets.getIamPolicy"),
            resource_pattern=BUCKET,
            params={"projection": "full"},
            pagination="singleton",
            special="bucket",
            notes="Proves membership by project-scoped buckets.list first; full bucket metadata includes bucket/default ACLs where applicable, never object ACLs or object data.",
        ),
        QuerySpec(
            "gcp.storage.bucketIamPolicy",
            "get",
            "https://storage.googleapis.com/storage/v1/b/{resource_id}/iam",
            ("storage.buckets.list", "storage.buckets.getIamPolicy"),
            resource_pattern=BUCKET,
            params={"optionsRequestedPolicyVersion": 3},
            pagination="singleton",
            special="bucket_policy",
            notes="Direct bucket allow policy version 3; project membership checked before the global bucket request.",
        ),
        QuerySpec(
            "gcp.compute.effectiveFirewalls",
            "get",
            "https://compute.googleapis.com/compute/v1/{scope}/zones/{location}/instances/{resource_id}/getEffectiveFirewalls",
            ("compute.instances.getEffectiveFirewalls",),
            location_mode="required",
            selectors={"network_interface": r"nic[0-9]{1,3}"},
            defaults={"network_interface": "nic0"},
            selector_params={"network_interface": "networkInterface"},
            pagination="singleton",
            notes="Effective firewall rules for one VM network interface, including applicable firewall policies and VPC rules. Does not prove end-to-end reachability.",
        ),
        QuerySpec(
            "gcp.compute.hierarchicalFirewallPolicies",
            "list",
            "https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies",
            ("compute.firewallPolicies.list",),
            items_key="items",
            scopes=("folders", "organizations"),
            params={"parentId": "{scope}"},
            page_size_key="maxResults",
            max_page_size=500,
            notes="Policies owned by exactly this folder or organization; rules and associations are returned in each policy.",
        ),
        QuerySpec(
            "gcp.compute.hierarchicalFirewallPolicies",
            "get",
            "https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies/{resource_id}",
            ("compute.firewallPolicies.list", "compute.firewallPolicies.get"),
            scopes=("folders", "organizations"),
            resource_pattern=r"[0-9]{1,20}",
            pagination="singleton",
            special="hierarchical_get",
            notes="Proves ownership with parent-scoped list before reading the global numeric policy ID.",
        ),
        QuerySpec(
            "gcp.iam.serviceAccounts",
            "get",
            "https://iam.googleapis.com/v1/{scope}/serviceAccounts/{resource_id}",
            ("iam.serviceAccounts.get",),
            resource_pattern=ACCOUNT,
            pagination="singleton",
        ),
        QuerySpec(
            "gcp.iam.serviceAccountIamPolicy",
            "get",
            "https://iam.googleapis.com/v1/{scope}/serviceAccounts/{resource_id}:getIamPolicy",
            ("iam.serviceAccounts.getIamPolicy",),
            resource_pattern=ACCOUNT,
            pagination="singleton",
            special="sa_policy",
            notes="Version-3 allow policy ON the service account (who can use/manage it), not the roles granted TO that account elsewhere.",
        ),
        QuerySpec(
            "gcp.iam.serviceAccountKeyMetadata",
            "list",
            "https://iam.googleapis.com/v1/{parent}/keys",
            ("iam.serviceAccountKeys.list",),
            items_key="keys",
            parent_suffix=r"serviceAccounts/" + ACCOUNT,
            parent_example="{scope}/serviceAccounts/{email_or_numeric_id}",
            params={"keyTypes": "USER_MANAGED"},
            pagination="client",
            notes="One account's user-managed key metadata. No key bytes; creation/expiry/disabled state do not establish last use.",
        ),
    ]
)

_collection(
    "gcp.compute.regionNetworkFirewallPolicies",
    "https://compute.googleapis.com/compute/v1/{scope}/regions/{location}/firewallPolicies",
    "items",
    "compute.regionFirewallPolicies.list",
    get_permission="compute.regionFirewallPolicies.get",
    location_mode="required",
    page_size_key="maxResults",
    max_page_size=500,
)
_collection(
    "gcp.iam.roles",
    "https://iam.googleapis.com/v1/{scope}/roles",
    "roles",
    "iam.roles.list",
    get_permission="iam.roles.get",
    scopes=("projects", "organizations"),
    params={"view": "FULL"},
    notes="Custom role definitions with includedPermissions. Organization roles use organization scope explicitly.",
)
_QUERIES.append(
    QuerySpec(
        "gcp.iam.policy",
        "get",
        "https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy",
        (
            "resourcemanager.projects.getIamPolicy",
            "resourcemanager.folders.getIamPolicy",
            "resourcemanager.organizations.getIamPolicy",
        ),
        scopes=HIERARCHY,
        pagination="singleton",
        special="crm_policy",
        notes="Direct version-3 allow policy on this exact project/folder/organization; the permission matching the selected scope applies. Not an effective-access verdict.",
    )
)
_collection(
    "gcp.iam.predefinedRoles",
    "https://iam.googleapis.com/v1/roles",
    "roles",
    "iam.roles.list",
    get_permission="iam.roles.get",
    scopes=HIERARCHY,
    params={"view": "FULL"},
    notes="Global predefined role definitions; authorization context remains the supplied allowed scope.",
)
_collection(
    "gcp.iam.denyPolicies",
    "https://iam.googleapis.com/v2/policies/{attachment}/denypolicies",
    "policies",
    "iam.denypolicies.list",
    get_permission="iam.denypolicies.get",
    scopes=HIERARCHY,
    resource_pattern=r"[A-Za-z0-9][A-Za-z0-9-]{0,62}",
    special="deny",
    notes="List returns policy metadata WITHOUT rules; get each policy ID to inspect deny rules. These are policies attached directly to the scope; inspect ancestors separately.",
)
_collection(
    "gcp.iam.principalAccessBoundaryPolicies",
    "https://iam.googleapis.com/v3/{scope}/locations/global/principalAccessBoundaryPolicies",
    "principalAccessBoundaryPolicies",
    "iam.principalaccessboundarypolicies.list",
    get_permission="iam.principalaccessboundarypolicies.get",
    scopes=("organizations",),
    notes="Organization-owned PAB policy definitions. Bindings must also be queried; listing a policy alone does not prove applicability.",
)
_collection(
    "gcp.iam.policyBindings",
    "https://iam.googleapis.com/v3/{scope}/locations/global/policyBindings",
    "policyBindings",
    "iam.policybindings.list",
    get_permission="iam.policybindings.get",
    scopes=HIERARCHY,
    notes="PAB binding resources owned by this scope; inspect relevant ancestor/descendant bindings before evaluating effective access.",
)
_collection(
    "gcp.iam.workloadIdentityProviders",
    "https://iam.googleapis.com/v1/{parent}/providers",
    "workloadIdentityPoolProviders",
    "iam.workloadIdentityPoolProviders.list",
    get_permission="iam.workloadIdentityPoolProviders.get",
    parent_suffix=r"locations/global/workloadIdentityPools/" + NAME,
    parent_example="projects/{project_number}/locations/global/workloadIdentityPools/{pool}",
    notes="Provider trust, issuer, allowed audiences and attribute conditions; parent must use this authorized project's numeric ID.",
)

_collection(
    "gcp.orgpolicy.policies",
    "https://orgpolicy.googleapis.com/v2/{scope}/policies",
    "policies",
    "orgpolicy.policies.list",
    get_permission="orgpolicy.policy.get",
    scopes=HIERARCHY,
    notes="Directly attached policy; not a claim about inherited/effective enforcement.",
)
_collection(
    "gcp.orgpolicy.constraints",
    "https://orgpolicy.googleapis.com/v2/{scope}/constraints",
    "constraints",
    "orgpolicy.constraints.list",
    scopes=HIERARCHY,
    notes="Constraint definitions and default behavior; query each desired effective policy separately.",
)
_collection(
    "gcp.orgpolicy.customConstraints",
    "https://orgpolicy.googleapis.com/v2/{scope}/customConstraints",
    "customConstraints",
    "orgpolicy.customConstraints.list",
    get_permission="orgpolicy.customConstraints.get",
    scopes=("organizations",),
)
_QUERIES.append(
    QuerySpec(
        "gcp.orgpolicy.effectivePolicies",
        "get",
        "https://orgpolicy.googleapis.com/v2/{scope}/policies/{resource_id}:getEffectivePolicy",
        ("orgpolicy.policy.get",),
        scopes=HIERARCHY,
        pagination="singleton",
        notes="resource_id is the constraint name without 'constraints/' (for example compute.requireOsLogin). Server evaluates hierarchy/conditions; under: subtrees are not expanded.",
    )
)

for _collection_name, _permission in (("sinks", "sinks"), ("exclusions", "exclusions")):
    _collection(
        f"gcp.logging.{_collection_name}",
        "https://logging.googleapis.com/v2/{scope}/" + _collection_name,
        _collection_name,
        f"logging.{_permission}.list",
        get_permission=f"logging.{_permission}.get",
        scopes=HIERARCHY,
        notes="Direct configuration at the supplied project/folder/organization; aggregated sinks and exclusions remain visible.",
    )
_collection(
    "gcp.logging.buckets",
    "https://logging.googleapis.com/v2/{scope}/locations/{location}/buckets",
    "buckets",
    "logging.buckets.list",
    scopes=HIERARCHY,
    location_mode="wildcard",
)
_QUERIES.append(
    QuerySpec(
        "gcp.logging.buckets",
        "get",
        "https://logging.googleapis.com/v2/{scope}/locations/{location}/buckets/{resource_id}",
        ("logging.buckets.get",),
        scopes=HIERARCHY,
        location_mode="required",
        pagination="singleton",
    )
)
_collection(
    "gcp.logging.views",
    "https://logging.googleapis.com/v2/{parent}/views",
    "views",
    "logging.views.list",
    get_permission="logging.views.get",
    scopes=HIERARCHY,
    parent_suffix=r"locations/" + LOCATION + r"/buckets/" + NAME,
    parent_example="{scope}/locations/{location}/buckets/{bucket}",
    notes="View filter definitions only, not log entries. Entry reads remain in the dedicated bounded query_logs tool.",
)
_collection(
    "gcp.logging.metrics",
    "https://logging.googleapis.com/v2/{scope}/metrics",
    "metrics",
    "logging.logMetrics.list",
    get_permission="logging.logMetrics.get",
    notes="Log-based metric configuration; no metric time-series or application payloads.",
)
for _name, _permission in (
    ("settings", "logging.settings.get"),
    ("cmekSettings", "logging.cmekSettings.get"),
):
    _QUERIES.append(
        QuerySpec(
            f"gcp.logging.{_name}",
            "get",
            "https://logging.googleapis.com/v2/{scope}/" + _name,
            (_permission,),
            scopes=HIERARCHY,
            pagination="singleton",
        )
    )

_collection(
    "gcp.kms.liveCryptoKeys",
    "https://cloudkms.googleapis.com/v1/{parent}/cryptoKeys",
    "cryptoKeys",
    "cloudkms.cryptoKeys.list",
    get_permission="cloudkms.cryptoKeys.get",
    parent_suffix=r"locations/" + LOCATION + r"/keyRings/" + NAME,
    parent_example="{scope}/locations/{location}/keyRings/{key_ring}",
    notes="Live key configuration; gcp.kms.cryptoKeys is the separate inventory snapshot across the project's locations.",
)
_QUERIES.append(
    QuerySpec(
        "gcp.kms.cryptoKeys",
        "get",
        "https://cloudkms.googleapis.com/v1/{parent}/cryptoKeys/{resource_id}",
        ("cloudkms.cryptoKeys.get",),
        parent_suffix=r"locations/" + LOCATION + r"/keyRings/" + NAME,
        parent_example="{scope}/locations/{location}/keyRings/{key_ring}",
        pagination="singleton",
        notes="Exact live key configuration; list on this kind retains the existing KMS Inventory snapshot behavior.",
    )
)
_collection(
    "gcp.kms.cryptoKeyVersions",
    "https://cloudkms.googleapis.com/v1/{parent}/cryptoKeyVersions",
    "cryptoKeyVersions",
    "cloudkms.cryptoKeyVersions.list",
    get_permission="cloudkms.cryptoKeyVersions.get",
    parent_suffix=r"locations/" + LOCATION + r"/keyRings/" + NAME + r"/cryptoKeys/" + NAME,
    parent_example="{scope}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}",
    params={"view": "BASIC"},
    notes="Version state, algorithm, protection level and timestamps only. No public/private key material, attestation, cryptographic operation, or export.",
)
_collection(
    "gcp.container.nodePools",
    "https://container.googleapis.com/v1/{parent}/nodePools",
    "nodePools",
    "container.clusters.get",
    get_permission="container.clusters.get",
    parent_suffix=r"locations/" + LOCATION + r"/clusters/" + NAME,
    parent_example="{scope}/locations/{location}/clusters/{cluster}",
    pagination="client",
    notes="GKE node pool configuration; not Kubernetes node/pod runtime inspection.",
)

_collection(
    "gcp.securitycenter.sources",
    "https://securitycenter.googleapis.com/v2/{scope}/sources",
    "sources",
    "securitycenter.sources.list",
    get_permission="securitycenter.sources.get",
    scopes=("organizations",),
    notes="SCC source metadata owned by this organization. Findings are queried independently by source and data location.",
)
_QUERIES.append(
    QuerySpec(
        "gcp.securitycenter.findings",
        "list",
        "https://securitycenter.googleapis.com/v2/{scope}/sources/{source_id}/locations/{location}/findings",
        ("securitycenter.findings.list",),
        items_key="listFindingsResults",
        scopes=HIERARCHY,
        location_mode="global",
        selectors={"source_id": r"(?:-|[0-9]{1,30})", "state": r"(?:ACTIVE|INACTIVE|ALL)"},
        defaults={"source_id": "-", "state": "ALL"},
        special="scc",
        notes="Existing SCC findings across selected sources and explicit data location. global is not a wildcard for regionalized SCC data. Optional state filter is fixed syntax.",
    )
)
_QUERIES.append(
    QuerySpec(
        "gcp.artifactanalysis.vulnerabilities",
        "list",
        "https://containeranalysis.googleapis.com/v1/{scope}/occurrences",
        ("containeranalysis.occurrences.list",),
        items_key="occurrences",
        params={"filter": 'kind="VULNERABILITY"', "returnPartialSuccess": "true"},
        special="vulnerabilities",
        notes="Existing vulnerability occurrences only, never image bytes or arbitrary occurrence kinds (which can include discovered secrets). Missing reports are unknown coverage, not a clean scan.",
    )
)

# Organization flow-log configuration is separate from per-subnet Compute config.
_collection(
    "gcp.networkmanagement.vpcFlowLogsConfigs",
    "https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs",
    "vpcFlowLogsConfigs",
    "networkmanagement.vpcflowlogsconfigs.list",
    get_permission="networkmanagement.vpcflowlogsconfigs.get",
    scopes=("projects", "organizations"),
    notes="Network Management flow-log configuration. This does not generate traffic or read log payloads; query_logs handles existing flow entries.",
)
_collection(
    "gcp.networkmanagement.orgVpcFlowLogsConfigs",
    "https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs:queryOrgVpcFlowLogsConfigs",
    "vpcFlowLogsConfigs",
    "networkmanagement.vpcflowlogsconfigs.list",
    notes="Existing organization-level configurations applicable to this project. Project-native configurations and subnet flow logging remain separate evidence.",
)

_collection(
    "gcp.accesscontextmanager.accessPolicies",
    "https://accesscontextmanager.googleapis.com/v1/accessPolicies",
    "accessPolicies",
    "accesscontextmanager.policies.list",
    scopes=("organizations",),
    params={"parent": "{scope}"},
    notes="Access-policy containers owned by this organization, including scoped policies. Nested reads first prove ownership using this list.",
)
for _resource in ("servicePerimeters", "accessLevels"):
    _collection(
        f"gcp.accesscontextmanager.{_resource}",
        "https://accesscontextmanager.googleapis.com/v1/{parent}/" + _resource,
        _resource,
        f"accesscontextmanager.{_resource}.list",
        get_permission=f"accesscontextmanager.{_resource}.get",
        scopes=("organizations",),
        parent_suffix=r"accessPolicies/[0-9]{1,20}",
        parent_example="accessPolicies/{numeric_policy_id}",
        special="access_policy_parent",
        notes="Organization ownership is verified before this global parent is read. Perimeter status is enforced configuration; spec is dry-run configuration. No perimeter simulation or reachability probe is performed.",
    )

for _resource in ("folders", "projects"):
    _collection(
        f"gcp.resourcemanager.{_resource}",
        "https://cloudresourcemanager.googleapis.com/v3/" + _resource,
        _resource,
        f"resourcemanager.{_resource}.list",
        scopes=("folders", "organizations"),
        params={"parent": "{scope}"},
        notes="Direct children of this authorized parent only. Recurse through folder pages explicitly; no claim that one organization list enumerates all descendant projects.",
    )
for _scope_type, _kind in (("folders", "folder"), ("organizations", "organization")):
    _QUERIES.append(
        QuerySpec(
            f"gcp.resourcemanager.{_kind}",
            "get",
            "https://cloudresourcemanager.googleapis.com/v3/{scope}",
            (f"resourcemanager.{_scope_type}.get",),
            scopes=(_scope_type,),
            pagination="singleton",
            notes="Metadata of the explicitly authorized hierarchy node, including its parent when available.",
        )
    )

QUERY_SPECS: dict[tuple[str, str], QuerySpec] = {
    (spec.kind, spec.operation): spec for spec in _QUERIES
}
if len(QUERY_SPECS) != len(_QUERIES):
    raise RuntimeError("Duplicate reviewed GCP query route")


def query_capabilities() -> list[dict[str, Any]]:
    """One discoverable entry per kind, with exact per-operation requirements."""
    capabilities = {kind: spec.capability() for kind, spec in RESOURCE_SPECS.items()}
    for item in capabilities.values():
        item["operations"] = ["list"]
        item["scope_types"] = ["projects"]
        item["required_scopes"] = ["projects"]
        item["queries"] = {"list": dict(item)}
    for (kind, operation), spec in QUERY_SPECS.items():
        if kind not in capabilities:
            capabilities[kind] = {
                "kind": kind,
                "description": spec.notes or f"Read {kind} security configuration.",
                "operations": [],
                "queries": {},
            }
        item = capabilities[kind]
        if operation not in item["operations"]:
            item["operations"].append(operation)
        item["queries"][operation] = spec.capability()
        item["scope_types"] = sorted(
            {scope for query in item["queries"].values() for scope in query["scope_types"]}
        )
        item["required_scopes"] = item["scope_types"]
        if len(item["operations"]) == 1:
            item.update(
                {key: value for key, value in spec.capability().items() if key != "operation"}
            )
            item["operation"] = operation
    return [capabilities[kind] for kind in sorted(capabilities)]
