"""Regression cases exercise policy semantics, incomplete evidence, and data boundaries."""

import json
from copy import deepcopy

import pytest

from sec_auditor.checks import evaluate, list_checks
from sec_auditor.models import ResourceRecord


def result(check_id, data, kind=None):
    if kind is None:
        kind = next(c.resource_kind for c in list_checks() if c.id == check_id)
    return evaluate([ResourceRecord(kind=kind, name="resource-under-test", data=data)], [check_id])[
        0
    ]


def workload(kind="Pod", **changes):
    spec = {
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "serviceAccountName": "application",
        "automountServiceAccountToken": False,
        "containers": [
            {
                "name": "application",
                "image": "example.test/app@sha256:" + "a" * 64,
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
            }
        ],
    }
    spec.update(changes)
    if kind == "Pod":
        return {"metadata": {"name": "app"}, "spec": spec}
    if kind == "CronJob":
        return {"spec": {"jobTemplate": {"spec": {"template": {"spec": spec}}}}}
    return {"spec": {"template": {"spec": spec}}}


def test_registry_is_unique_and_cannot_be_mutated_through_list_checks():
    first = list_checks()
    assert len({c.id for c in first}) == len(first)
    assert len(first) >= 60
    original = first[0].id
    first[0].id = "changed"
    assert list_checks()[0].id == original


def test_unknown_check_ids_rejected_even_without_records():
    with pytest.raises(ValueError, match="Unknown check IDs"):
        evaluate([], ["nonexistent"])


def test_empty_selection_and_unrelated_kinds_do_not_claim_passes():
    assert evaluate([ResourceRecord(kind="gcp.compute.instances", name="vm", data={})], []) == []
    assert evaluate([ResourceRecord(kind="unsupported.kind", name="unknown", data={})]) == []


def test_duplicate_requested_checks_evaluated_once():
    check = "gcp.compute.instance.no_ip_forwarding"
    record = ResourceRecord(kind="gcp.compute.instances", name="vm", data={"canIpForward": False})
    assert len(evaluate([record], [check, check])) == 1


def test_empty_evidence_never_passes_any_check():
    records = [
        ResourceRecord(kind=k, name=k, data={}) for k in {c.resource_kind for c in list_checks()}
    ]
    assert {r.status for r in evaluate(records)} == {"unknown"}


@pytest.mark.parametrize(
    "kind", ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"]
)
def test_hardened_workload_shapes_pass_all_matching_controls(kind):
    outcomes = evaluate([ResourceRecord(kind=f"k8s.{kind}", name="workload", data=workload(kind))])
    assert len(outcomes) == 18
    assert {r.status for r in outcomes} == {"pass"}


@pytest.mark.parametrize("field", ["containers", "initContainers", "ephemeralContainers"])
def test_privileged_init_and_ephemeral_containers_are_not_missed(field):
    data = workload()
    data["spec"][field] = [{"name": "unsafe", "securityContext": {"privileged": True}}]
    found = result("k8s.pod.privileged", data)
    assert found.status == "fail"
    assert any(field + "[0]" in path for path in found.evidence_paths)


def test_container_overrides_pod_nonroot_setting():
    data = workload()
    data["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = False
    assert result("k8s.pod.non_root", data).status == "fail"


def test_missing_nonroot_keeps_image_defaults_unknown():
    data = workload(securityContext={})
    assert result("k8s.pod.non_root", data).status == "unknown"
    assert result("k8s.pod.root_uid", data).status == "pass"  # Only explicit UID 0 is checked.


def test_explicit_root_uid_conflicts_with_nonroot_flag():
    data = workload()
    data["spec"]["securityContext"]["runAsUser"] = 0
    assert result("k8s.pod.non_root", data).status == "fail"
    assert result("k8s.pod.root_uid", data).status == "fail"


def test_sys_admin_and_privileged_mode_override_no_escalation_flag():
    data = workload()
    context = data["spec"]["containers"][0]["securityContext"]
    context["capabilities"]["add"] = ["SYS_ADMIN"]
    assert result("k8s.pod.privilege_escalation", data).status == "fail"
    context["capabilities"]["add"] = []
    context["privileged"] = True
    assert result("k8s.pod.privilege_escalation", data).status == "fail"


def test_default_privilege_escalation_is_not_mistaken_for_disabled():
    data = workload()
    del data["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"]
    assert result("k8s.pod.privilege_escalation", data).status == "fail"


def test_seccomp_container_override_and_unknown_node_default():
    data = workload()
    data["spec"]["containers"][0]["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
    assert result("k8s.pod.seccomp", data).status == "fail"
    del data["spec"]["containers"][0]["securityContext"]["seccompProfile"]
    del data["spec"]["securityContext"]["seccompProfile"]
    assert result("k8s.pod.seccomp", data).status == "unknown"


def test_windows_skips_linux_controls_but_detects_host_process():
    data = workload(os={"name": "windows"})
    data["spec"]["securityContext"]["windowsOptions"] = {"hostProcess": True}
    assert result("k8s.pod.seccomp", data).status == "not_applicable"
    assert result("k8s.pod.privileged", data).status == "not_applicable"
    assert result("k8s.pod.host_process", data).status == "fail"


def test_token_automount_does_not_guess_service_account_inheritance():
    data = workload()
    del data["spec"]["automountServiceAccountToken"]
    assert result("k8s.pod.token_automount", data).status == "unknown"


def test_default_service_account_is_known_api_default():
    data = workload()
    del data["spec"]["serviceAccountName"]
    assert result("k8s.pod.dedicated_service_account", data).status == "fail"


@pytest.mark.parametrize("value", ["0", "0m", "0.0", "0Mi", 0])
def test_zero_resource_limits_are_not_counted_as_positive(value):
    data = workload()
    data["spec"]["containers"][0]["resources"]["limits"]["cpu"] = value
    assert result("k8s.pod.resource_limits", data).status == "fail"


def test_ephemeral_container_limits_are_not_required():
    data = workload(ephemeralContainers=[{"name": "debugger"}])
    assert result("k8s.pod.resource_limits", data).status == "pass"


@pytest.mark.parametrize("value", ["arbitrary text", "NaN", "Infinity", True, "1 KB", [], {}])
def test_invalid_resource_quantities_are_unknown(value):
    data = workload()
    data["spec"]["containers"][0]["resources"]["limits"]["cpu"] = value
    assert result("k8s.pod.resource_limits", data).status == "unknown"


@pytest.mark.parametrize("value", [".5", "1e3", "10E-2", "100m", 1, 0.5])
def test_valid_positive_resource_quantities_are_accepted(value):
    data = workload()
    data["spec"]["containers"][0]["resources"]["limits"]["cpu"] = value
    assert result("k8s.pod.resource_limits", data).status == "pass"


@pytest.mark.parametrize("value", ["-1", "-100m", "-0.5", "+0m"])
def test_nonpositive_resource_quantities_do_not_satisfy_limits(value):
    data = workload()
    data["spec"]["containers"][0]["resources"]["limits"]["cpu"] = value
    assert result("k8s.pod.resource_limits", data).status == "fail"


def test_hostpath_and_image_values_do_not_leak_into_findings():
    secret = "DO_NOT_RETURN_THIS_SENSITIVE_VALUE"
    data = workload(volumes=[{"name": "mount", "hostPath": {"path": "/" + secret}}])
    data["metadata"]["annotations"] = {"prompt": secret}
    container = data["spec"]["containers"][0]
    container["env"] = [{"name": "PASSWORD", "value": secret}]
    container["args"] = [secret]
    container["image"] = secret
    outcomes = evaluate([ResourceRecord(kind="k8s.Pod", name="safe-identifier", data=data)])
    encoded = json.dumps([o.model_dump() for o in outcomes])
    assert secret not in encoded
    assert result("k8s.pod.no_hostpath", data).status == "fail"
    assert result("k8s.pod.image_digest", data).status == "fail"


def test_malformed_fields_return_unknown_without_exception_content():
    data = workload()
    data["spec"]["containers"] = "sensitive malformed data"
    outcomes = evaluate([ResourceRecord(kind="k8s.Pod", name="safe", data=data)])
    assert {r.status for r in outcomes} == {"unknown"}
    assert "sensitive" not in json.dumps([r.model_dump() for r in outcomes])


def test_vm_external_ipv6_is_detected_without_claiming_reachability():
    data = {"networkInterfaces": [{"ipv6AccessConfigs": [{"type": "DIRECT_IPV6"}]}]}
    found = result("gcp.compute.instance.no_external_ip", data)
    assert found.status == "fail"
    assert "reachability is not established" in found.summary
    assert (
        result("gcp.compute.instance.no_external_ip", {"networkInterfaces": [{}]}).status == "pass"
    )


def test_instance_metadata_inheritance_stays_unknown():
    assert result("gcp.compute.instance.os_login", {"metadata": {"items": []}}).status == "unknown"
    data = {"metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}
    assert result("gcp.compute.instance.os_login", data).status == "pass"
    assert result("gcp.compute.instance.block_project_ssh_keys", data).status == "not_applicable"


def test_duplicate_metadata_keys_do_not_create_an_arbitrary_answer():
    data = {
        "metadata": {
            "items": [
                {"key": "enable-oslogin", "value": "true"},
                {"key": "enable-oslogin", "value": "false"},
            ]
        }
    }
    assert result("gcp.compute.instance.os_login", data).status == "unknown"


def test_attached_default_gsa_is_observed_without_inferred_permissions():
    data = {"serviceAccounts": [{"email": "123456-compute@developer.gserviceaccount.com"}]}
    assert result("gcp.compute.instance.dedicated_service_account", data).status == "fail"
    assert (
        result("gcp.compute.instance.dedicated_service_account", {"serviceAccounts": []}).status
        == "pass"
    )


def firewall(**changes):
    data = {
        "name": "rule",
        "direction": "INGRESS",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    }
    data.update(changes)
    return data


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_firewall_public_cidrs_and_port_ranges(cidr):
    data = firewall(sourceRanges=[cidr], allowed=[{"IPProtocol": "6", "ports": ["20-25"]}])
    assert result("gcp.compute.firewall.no_public_ssh", data).status == "fail"
    assert result("gcp.compute.firewall.no_public_rdp", data).status == "pass"


def test_source_selectors_do_not_narrow_an_explicit_public_cidr():
    data = firewall(sourceTags=["some-source"])
    assert result("gcp.compute.firewall.no_public_ssh", data).status == "fail"
    del data["sourceRanges"]
    assert result("gcp.compute.firewall.no_public_ssh", data).status == "pass"


def test_missing_source_filter_uses_compute_unrestricted_default():
    data = firewall()
    del data["sourceRanges"]
    assert result("gcp.compute.firewall.no_public_ssh", data).status == "fail"


def test_firewall_disabled_egress_and_deny_are_not_ingress_findings():
    assert (
        result("gcp.compute.firewall.no_public_ssh", firewall(disabled=True)).status
        == "not_applicable"
    )
    assert (
        result("gcp.compute.firewall.no_public_ssh", firewall(direction="EGRESS")).status
        == "not_applicable"
    )
    assert (
        result(
            "gcp.compute.firewall.no_public_ssh",
            firewall(allowed=[], denied=[{"IPProtocol": "all"}]),
        ).status
        == "not_applicable"
    )


def test_firewall_protocol_all_and_empty_ports_cover_ssh():
    assert (
        result(
            "gcp.compute.firewall.no_public_ssh", firewall(allowed=[{"IPProtocol": "all"}])
        ).status
        == "fail"
    )
    assert (
        result(
            "gcp.compute.firewall.no_public_ssh", firewall(allowed=[{"IPProtocol": "tcp"}])
        ).status
        == "fail"
    )
    assert (
        result(
            "gcp.compute.firewall.no_public_ssh",
            firewall(allowed=[{"IPProtocol": "udp", "ports": ["22"]}]),
        ).status
        == "pass"
    )


def test_firewall_all_port_ranges_are_combined_within_and_across_allow_entries():
    one_entry = firewall(allowed=[{"IPProtocol": "tcp", "ports": ["32768-65535", "1-32767"]}])
    assert result("gcp.compute.firewall.no_public_all_ports", one_entry).status == "fail"
    separate_entries = firewall(
        allowed=[
            {"IPProtocol": "tcp", "ports": ["1-32767"]},
            {"IPProtocol": "6", "ports": ["32768-65535"]},
        ]
    )
    assert result("gcp.compute.firewall.no_public_all_ports", separate_entries).status == "fail"
    separate_entries["allowed"][1]["IPProtocol"] = "udp"
    assert result("gcp.compute.firewall.no_public_all_ports", separate_entries).status == "pass"
    gap = firewall(allowed=[{"IPProtocol": "tcp", "ports": ["1-32767", "32769-65535"]}])
    assert result("gcp.compute.firewall.no_public_all_ports", gap).status == "pass"


@pytest.mark.parametrize("ports", [["23-22"], ["-1"], ["65536"], ["injected-value"]])
def test_malformed_firewall_ports_are_unknown(ports):
    assert (
        result(
            "gcp.compute.firewall.no_public_ssh",
            firewall(allowed=[{"IPProtocol": "tcp", "ports": ports}]),
        ).status
        == "unknown"
    )


def test_firewall_invalid_cidr_is_unknown():
    assert (
        result("gcp.compute.firewall.no_public_ssh", firewall(sourceRanges=["invalid"])).status
        == "unknown"
    )


def test_bucket_public_access_prevention_inheritance_is_not_a_failure_or_pass():
    inherited = {"iamConfiguration": {"publicAccessPrevention": "inherited"}}
    assert result("gcp.storage.public_access_prevention", inherited).status == "unknown"
    inherited["iamConfiguration"]["publicAccessPrevention"] = "enforced"
    assert result("gcp.storage.public_access_prevention", inherited).status == "pass"


def test_cmek_absence_does_not_mean_no_encryption():
    found = result("gcp.storage.cmek", {"name": "bucket"})
    assert found.status == "unknown"
    assert found.details["policy_specific"] is True


def test_conditioned_iam_binding_still_observed_without_leaking_condition():
    data = {
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["allUsers"],
                "condition": {"expression": "DO_NOT_COPY_CONDITION"},
            }
        ]
    }
    for check in ("gcp.iam.no_public_principal", "gcp.iam.no_basic_roles"):
        found = result(check, data)
        assert found.status == "fail"
        assert "effective access require separate analysis" in found.summary
        assert "DO_NOT_COPY_CONDITION" not in found.model_dump_json()


def test_empty_and_missing_iam_bindings_are_different():
    assert result("gcp.iam.no_public_principal", {"bindings": []}).status == "pass"
    assert result("gcp.iam.no_public_principal", {}).status == "unknown"


def test_gke_dataplane_v2_network_policy_and_dns_only_endpoints():
    assert (
        result(
            "gcp.gke.network_policy", {"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}}
        ).status
        == "pass"
    )
    assert (
        result(
            "gcp.gke.authorized_networks",
            {"controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enabled": False}}},
        ).status
        == "not_applicable"
    )


def test_modern_gke_authorized_networks_take_precedence_over_legacy():
    data = {
        "masterAuthorizedNetworksConfig": {"enabled": True},
        "controlPlaneEndpointsConfig": {
            "ipEndpointsConfig": {"enabled": True, "authorizedNetworksConfig": {"enabled": False}}
        },
    }
    assert result("gcp.gke.authorized_networks", data).status == "fail"


def test_gke_continuous_validation_is_not_admission_enforcement():
    assert (
        result(
            "gcp.gke.binary_authorization",
            {"binaryAuthorization": {"evaluationMode": "POLICY_BINDINGS", "enabled": True}},
        ).status
        == "fail"
    )
    assert (
        result(
            "gcp.gke.binary_authorization",
            {"binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}},
        ).status
        == "pass"
    )


def test_gke_node_pools_need_evidence_except_managed_autopilot():
    assert result("gcp.gke.node_auto_upgrade", {"nodePools": []}).status == "unknown"
    assert (
        result("gcp.gke.node_auto_upgrade", {"autopilot": {"enabled": True}}).status
        == "not_applicable"
    )
    data = {
        "nodePools": [{"management": {"autoUpgrade": True}}, {"management": {"autoUpgrade": False}}]
    }
    assert result("gcp.gke.node_auto_upgrade", data).status == "fail"


def test_sql_ssl_mode_overrides_legacy_boolean():
    data = {"settings": {"ipConfiguration": {"sslMode": "ENCRYPTED_ONLY", "requireSsl": False}}}
    assert result("gcp.sql.require_tls", data).status == "pass"
    data["settings"]["ipConfiguration"]["sslMode"] = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    data["settings"]["ipConfiguration"]["requireSsl"] = True
    assert result("gcp.sql.require_tls", data).status == "fail"


@pytest.mark.parametrize(
    "version,field",
    [
        ("MYSQL_8_0", "binaryLogEnabled"),
        ("POSTGRES_16", "pointInTimeRecoveryEnabled"),
        ("SQLSERVER_2022_STANDARD", "pointInTimeRecoveryEnabled"),
    ],
)
def test_sql_recovery_settings_follow_database_family(version, field):
    data = {"databaseVersion": version, "settings": {"backupConfiguration": {field: True}}}
    assert result("gcp.sql.point_in_time_recovery", data).status == "pass"
    data["instanceType"] = "READ_REPLICA_INSTANCE"
    assert result("gcp.sql.point_in_time_recovery", data).status == "not_applicable"


def test_sql_authorized_networks_do_not_return_cidr_values():
    data = {
        "settings": {
            "ipConfiguration": {
                "authorizedNetworks": [{"value": "0.0.0.0/0", "name": "sensitive-label"}]
            }
        }
    }
    found = result("gcp.sql.no_unrestricted_networks", data)
    assert found.status == "fail"
    assert "sensitive-label" not in found.model_dump_json()


def test_cloud_run_breakglass_is_flagged_without_justification():
    data = {
        "binaryAuthorization": {
            "useDefault": True,
            "breakglassJustification": "PRIVATE INCIDENT DETAILS",
        }
    }
    found = result("gcp.run.binary_authorization", data)
    assert found.status == "fail"
    assert "PRIVATE INCIDENT DETAILS" not in found.model_dump_json()


def test_immutable_tags_applies_to_standard_docker_repositories():
    assert (
        result("gcp.artifactregistry.immutable_tags", {"format": "MAVEN"}).status
        == "not_applicable"
    )
    assert (
        result(
            "gcp.artifactregistry.immutable_tags", {"format": "DOCKER", "mode": "REMOTE_REPOSITORY"}
        ).status
        == "not_applicable"
    )
    assert (
        result(
            "gcp.artifactregistry.immutable_tags",
            {"format": "DOCKER", "dockerConfig": {"immutableTags": True}},
        ).status
        == "pass"
    )


def test_pubsub_push_auth_and_pull():
    assert result("gcp.pubsub.authenticated_push", {"pushConfig": {}}).status == "not_applicable"
    data = {"pushConfig": {"pushEndpoint": "https://example.test/hooks"}}
    assert result("gcp.pubsub.authenticated_push", data).status == "fail"
    data["pushConfig"]["oidcToken"] = {
        "serviceAccountEmail": "push@example.iam.gserviceaccount.com"
    }
    assert result("gcp.pubsub.authenticated_push", data).status == "pass"


def test_bigquery_summary_without_access_details_remains_unknown():
    assert (
        result(
            "gcp.bigquery.no_public_access_entry", {"datasetReference": {"datasetId": "test"}}
        ).status
        == "unknown"
    )
    assert (
        result(
            "gcp.bigquery.no_public_access_entry",
            {"access": [{"specialGroup": "allAuthenticatedUsers"}]},
        ).status
        == "fail"
    )


def test_rbac_wildcard_secret_read_and_aggregated_role_incompleteness():
    data = {
        "rules": [
            {
                "verbs": ["list"],
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": ["restricted-name"],
            }
        ]
    }
    assert result("k8s.role.no_secret_reads", data).status == "fail"
    assert result("k8s.role.no_wildcards", data).status == "pass"
    data["rules"][0]["resources"] = ["*"]
    assert result("k8s.role.no_wildcards", data).status == "fail"
    assert (
        result(
            "k8s.clusterrole.no_wildcards",
            {"rules": [], "aggregationRule": {"clusterRoleSelectors": [{}]}},
        ).status
        == "unknown"
    )


def test_rbac_noncore_secret_named_resource_is_not_core_secret_read():
    data = {
        "rules": [{"verbs": ["get"], "apiGroups": ["custom.example"], "resources": ["secrets"]}]
    }
    assert result("k8s.role.no_secret_reads", data).status == "pass"


def test_rolebinding_cluster_admin_does_not_claim_cluster_wide_scope():
    data = {
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "operator", "namespace": "team"}],
    }
    found = result("k8s.rolebinding.no_cluster_admin", data)
    assert found.status == "fail"
    assert "namespace scope" in found.summary
    data["subjects"] = []
    assert result("k8s.rolebinding.no_cluster_admin", data).status == "pass"


def test_namespace_absent_label_may_inherit_cluster_defaults():
    assert result("k8s.namespace.pod_security", {"metadata": {"labels": {}}}).status == "unknown"
    assert (
        result(
            "k8s.namespace.pod_security",
            {"metadata": {"labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
        ).status
        == "pass"
    )


def test_input_documents_are_not_modified():
    data = workload()
    original = deepcopy(data)
    evaluate([ResourceRecord(kind="k8s.Pod", name="app", data=data)])
    assert data == original
