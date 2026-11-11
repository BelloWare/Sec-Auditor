"""Regression cases for credential-bearing fields and truthful omissions."""

import copy
import json

import pytest

from sec_auditor.models import ResourceRecord
from sec_auditor.projection import REDACTED, project_log_entry, project_record, safe_text, sanitize


def project(data, kind="k8s.Pod"):
    return project_record(ResourceRecord(kind=kind, name="example", data=data))


def test_workload_projection_preserves_security_settings_and_secret_references():
    data = {
        "metadata": {
            "name": "web",
            "namespace": "apps",
            "annotations": {"last-applied": "PRIVATE-ANNOTATION"},
        },
        "spec": {
            "serviceAccountName": "workload",
            "hostNetwork": False,
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "web",
                    "image": "example/web:1",
                    "securityContext": {"privileged": False, "allowPrivilegeEscalation": False},
                    "command": ["command-with-sensitive-argument"],
                    "args": ["PRIVATE-ARG"],
                    "env": [
                        {"name": "PLAIN", "value": "PRIVATE-ENV"},
                        {
                            "name": "SECRET",
                            "valueFrom": {"secretKeyRef": {"name": "db-login", "key": "password"}},
                        },
                        {
                            "name": "POD_NAME",
                            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
                        },
                    ],
                    "envFrom": [
                        {"secretRef": {"name": "app-settings"}},
                        {"configMapRef": {"name": "nonsecret-settings"}},
                    ],
                }
            ],
            "volumes": [{"name": "settings", "secret": {"secretName": "app-settings"}}],
        },
    }
    original = copy.deepcopy(data)
    result = project(data)
    output = result["data"]
    container = output["spec"]["containers"][0]
    assert output["spec"]["securityContext"] == {"runAsNonRoot": True}
    assert container["securityContext"]["privileged"] is False
    assert container["env"][0]["value"] == REDACTED
    assert container["env"][1]["valueFrom"]["secretKeyRef"] == {
        "name": "db-login",
        "key": "password",
    }
    assert container["env"][2]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    assert output["spec"]["volumes"][0]["secret"]["secretName"] == "app-settings"
    assert container["envFrom"][0]["secretRef"]["name"] == "app-settings"
    for marker in ["PRIVATE-ENV", "PRIVATE-ARG", "PRIVATE-ANNOTATION"]:
        assert marker not in json.dumps(result)
    assert "data.spec.containers[0].env[0].value" in result["redacted_paths"]
    assert result["content_is_untrusted"] is True
    assert data == original


def test_cloud_run_value_source_and_function_environment_maps():
    result = project(
        {
            "template": {
                "containers": [
                    {
                        "env": [
                            {"name": "PLAIN", "value": "PRIVATE-LITERAL"},
                            {
                                "name": "REF",
                                "valueSource": {
                                    "secretKeyRef": {
                                        "secret": "projects/prod-a/secrets/db",
                                        "version": "latest",
                                    }
                                },
                            },
                        ]
                    }
                ]
            },
            "serviceConfig": {"environmentVariables": {"SETTING": "PRIVATE-MAP"}},
        },
        kind="gcp.run.services",
    )
    env = result["data"]["template"]["containers"][0]["env"]
    assert env[0]["value"] == REDACTED
    assert env[1]["valueSource"]["secretKeyRef"]["secret"] == "projects/prod-a/secrets/db"
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("probe", ["livenessProbe", "readinessProbe", "startupProbe"])
def test_probe_headers_and_relative_queries_are_filtered(probe):
    result = project(
        {
            "spec": {
                "containers": [
                    {
                        probe: {
                            "httpGet": {
                                "path": "/health?opaque=PRIVATE-QUERY#PRIVATE-FRAGMENT",
                                "port": 8080,
                                "httpHeaders": [
                                    {"name": "Authorization", "value": "Basic PRIVATE-HEADER"},
                                    {"name": "X-Custom", "value": "PRIVATE-CUSTOM"},
                                ],
                            }
                        }
                    }
                ]
            }
        }
    )
    probe_output = result["data"]["spec"]["containers"][0][probe]["httpGet"]
    assert probe_output["port"] == 8080
    assert probe_output["httpHeaders"][0]["name"] == "Authorization"
    assert all(header["value"] == REDACTED for header in probe_output["httpHeaders"])
    assert probe_output["path"] == "/health?[REDACTED]#[REDACTED]"
    assert "PRIVATE" not in json.dumps(result)
    assert (
        f"data.spec.containers[0].{probe}.httpGet.httpHeaders[1].value" in result["redacted_paths"]
    )


def test_lifecycle_headers_termination_messages_and_opaque_volume_options():
    result = project(
        {
            "spec": {
                "containers": [
                    {
                        "lifecycle": {
                            "postStart": {
                                "httpGet": {
                                    "path": "/init?opaque=PRIVATE-PATH",
                                    "httpHeaders": [
                                        {"name": "X-API-Key", "value": "PRIVATE-HEADER"}
                                    ],
                                }
                            }
                        }
                    }
                ],
                "volumes": [
                    {
                        "name": "csi",
                        "csi": {
                            "driver": "example.csi",
                            "readOnly": True,
                            "volumeAttributes": {"opaque": "PRIVATE-CSI"},
                            "nodePublishSecretRef": {"name": "driver-login"},
                        },
                    },
                    {
                        "name": "flex",
                        "flexVolume": {
                            "driver": "vendor/driver",
                            "options": {"opaque": "PRIVATE-FLEX"},
                            "secretRef": {"name": "driver-login"},
                        },
                    },
                ],
            },
            "status": {
                "phase": "Failed",
                "message": "PRIVATE-STATUS",
                "containerStatuses": [
                    {
                        "state": {
                            "terminated": {
                                "exitCode": 1,
                                "reason": "Error",
                                "message": "PRIVATE-TERMINATION",
                            }
                        },
                        "lastState": {"terminated": {"message": "PRIVATE-PREVIOUS"}},
                    }
                ],
            },
        }
    )
    assert "PRIVATE" not in json.dumps(result)
    assert result["data"]["status"]["phase"] == "Failed"
    termination = result["data"]["status"]["containerStatuses"][0]["state"]["terminated"]
    assert termination["exitCode"] == 1
    assert termination["reason"] == "Error"
    assert (
        result["data"]["spec"]["volumes"][0]["csi"]["nodePublishSecretRef"]["name"]
        == "driver-login"
    )
    assert (
        "data.status.containerStatuses[0].lastState.terminated.message" in result["redacted_paths"]
    )
    assert "data.spec.volumes[1].flexVolume.options" in result["redacted_paths"]


def test_storage_class_preserves_reviewable_settings_and_secret_references():
    result = project(
        {
            "provisioner": "pd.csi.storage.gke.io",
            "reclaimPolicy": "Retain",
            "parameters": {
                "type": "pd-balanced",
                "replication-type": "regional-pd",
                "disk-encryption-kms-key": "projects/prod-a/locations/us/keyRings/r/cryptoKeys/k",
                "csi.storage.k8s.io/node-stage-secret-name": "driver-login",
                "csi.storage.k8s.io/node-stage-secret-namespace": "storage",
                "arbitrary-driver-setting": "PRIVATE-DRIVER",
                "password": "PRIVATE-PASSWORD",
            },
        },
        kind="k8s.StorageClass",
    )
    parameters = result["data"]["parameters"]
    assert parameters["type"] == "pd-balanced"
    assert parameters["csi.storage.k8s.io/node-stage-secret-name"] == "driver-login"
    assert parameters["arbitrary-driver-setting"] == REDACTED
    assert result["data"]["reclaimPolicy"] == "Retain"
    assert "PRIVATE" not in json.dumps(result)


def test_vm_metadata_allowlist_does_not_expose_custom_values():
    result = project(
        {
            "metadata": {
                "items": [
                    {"key": "enable-oslogin", "value": "TRUE"},
                    {"key": "block-project-ssh-keys", "value": "true"},
                    {"key": "custom-setting", "value": "PRIVATE-CUSTOM"},
                    {"key": "enable-oslogin-2fa", "value": "PRIVATE-MALFORMED"},
                    {"key": "startup-script", "value": "PRIVATE-SCRIPT"},
                ]
            }
        },
        kind="gcp.compute.instances",
    )
    items = result["data"]["metadata"]["items"]
    assert items[0]["value"] == "TRUE"
    assert items[1]["value"] == "true"
    assert all(item["value"] == REDACTED for item in items[2:])
    assert "PRIVATE" not in json.dumps(result)
    assert "data.metadata.items[3].value" in result["redacted_paths"]


def test_sensitive_field_names_and_content_patterns():
    result = sanitize(
        {
            "private_key": "PRIVATE-KEY",
            "apiKey": "PRIVATE-API",
            "access_token": "PRIVATE-TOKEN",
            "headers": {"X-Custom": "PRIVATE-HEADER"},
            "binaryData": {"a": "PRIVATE-BYTES"},
            "description": 'password="PRIVATE-VALUE"',
            "pem": "-----BEGIN PRIVATE KEY-----\nPRIVATE-PEM\n-----END PRIVATE KEY-----",
        }
    )
    assert "PRIVATE" not in json.dumps(result)
    assert result["headers"]["X-Custom"] == REDACTED


def test_basic_auth_pattern_preserves_security_check_descriptions():
    assert safe_text("Disable GKE basic authentication") == "Disable GKE basic authentication"
    assert safe_text("Basic dXNlcjpwYXNzd29yZA==") == REDACTED


@pytest.mark.parametrize(
    "url",
    [
        "https://user:PRIVATE@host.example/health?opaque=PRIVATE#PRIVATE",
        "//user:PRIVATE@host.example/health?opaque=PRIVATE",
        "/health?opaque=PRIVATE",
        "health?opaque=PRIVATE",
        "https://host.example/#PRIVATE",
    ],
)
def test_url_minimization_handles_absolute_and_relative_urls(url):
    output = safe_text(url)
    assert "PRIVATE" not in output
    assert REDACTED in output


def test_all_redacted_paths_are_reported_and_safe_errors_remain_useful():
    result = project(
        {
            "spec": {
                "containers": [
                    {
                        "env": [
                            {"name": f"SETTING_{index}", "value": f"PRIVATE-{index}"}
                            for index in range(300)
                        ]
                    }
                ]
            }
        }
    )
    assert result["redacted_path_count"] == 300
    assert len(result["redacted_paths"]) == 300
    assert "data.spec.containers[0].env[299].value" in result["redacted_paths"]
    assert (
        sanitize({"message": "Google API returned HTTP 403"})["message"]
        == "Google API returned HTTP 403"
    )


def test_list_and_depth_limits_are_explicit():
    paths = []
    output = sanitize([0] * 501, path="items", redactions=paths)
    assert output[-1] == {"omitted_items": 1}
    assert paths == ["items[500:]"]
    nested = current = {}
    for _ in range(35):
        current["nested"] = {}
        current = current["nested"]
    output = sanitize(nested, redactions=paths)
    assert "[DEPTH_LIMIT]" in json.dumps(output)


def test_audit_projection_reports_nested_omissions_and_filters_payloads():
    entry = {
        "logName": "projects/prod-a/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": "2026-11-11T00:00:00Z",
        "severity": "NOTICE",
        "textPayload": "PRIVATE-TEXT",
        "labels": {"opaque": "PRIVATE-LABEL"},
        "protoPayload": {
            "serviceName": "compute.googleapis.com",
            "methodName": "v1.compute.instances.insert",
            "resourceName": "projects/prod-a/zones/us-central1-a/instances/vm",
            "request": {"metadata": "PRIVATE-REQUEST"},
            "response": {"anything": "PRIVATE-RESPONSE"},
            "authenticationInfo": {
                "principalEmail": "auditor@example.com",
                "principalSubject": "serviceAccount:auditor@example.com",
                "thirdPartyPrincipal": {"opaque": "PRIVATE-THIRD-PARTY"},
                "serviceAccountDelegationInfo": [
                    {
                        "principalSubject": "principal://workload",
                        "firstPartyPrincipal": {
                            "principalEmail": "workload@example.com",
                            "serviceMetadata": {"opaque": "PRIVATE-SERVICE"},
                        },
                        "thirdPartyPrincipal": {"thirdPartyClaims": {"opaque": "PRIVATE-CLAIMS"}},
                    }
                ],
            },
            "requestMetadata": {
                "callerIp": "192.0.2.1",
                "callerSuppliedUserAgent": "auditor/1",
                "requestAttributes": {"opaque": "PRIVATE-ATTR"},
            },
            "authorizationInfo": [
                {
                    "permission": "compute.instances.create",
                    "granted": True,
                    "resource": "vm",
                    "resourceAttributes": {
                        "service": "compute.googleapis.com",
                        "name": "vm",
                        "type": "compute.Instance",
                        "labels": {"opaque": "PRIVATE-RESOURCE-LABEL"},
                    },
                    "opaque": "PRIVATE-AUTHZ",
                }
            ],
            "status": {
                "code": 7,
                "message": "PRIVATE-ERROR",
                "details": [{"opaque": "PRIVATE-DETAILS"}],
            },
        },
    }
    before = copy.deepcopy(entry)
    result = project_log_entry(entry, "audit")
    assert "PRIVATE" not in json.dumps(result)
    assert result["protoPayload"]["status"] == {"code": 7}
    assert result["protoPayload"]["authenticationInfo"]["principalEmail"] == "auditor@example.com"
    assert result["protoPayload"]["authorizationInfo"][0]["granted"] is True
    expected = {
        "textPayload",
        "labels",
        "protoPayload.request",
        "protoPayload.response",
        "protoPayload.status.message",
        "protoPayload.status.details",
        "protoPayload.authenticationInfo.thirdPartyPrincipal",
        "protoPayload.authenticationInfo.serviceAccountDelegationInfo[0].thirdPartyPrincipal",
        "protoPayload.authenticationInfo.serviceAccountDelegationInfo[0].firstPartyPrincipal.serviceMetadata",
        "protoPayload.requestMetadata.requestAttributes",
        "protoPayload.authorizationInfo[0].resourceAttributes.labels",
        "protoPayload.authorizationInfo[0].opaque",
    }
    assert expected <= set(result["omitted_payload_fields"])
    assert expected <= set(result["redacted_paths"])
    assert result["redacted_path_count"] == len(result["redacted_paths"])
    assert result["content_is_untrusted"] is True
    assert entry == before


def test_flow_and_firewall_projection_preserves_network_evidence():
    connection = {"src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "dest_port": 443, "protocol": 6}
    flow = project_log_entry(
        {"jsonPayload": {"connection": connection, "bytes_sent": "1234", "opaque": "PRIVATE-FLOW"}},
        "vpc_flows",
    )
    assert flow["jsonPayload"]["connection"] == connection
    assert flow["jsonPayload"]["bytes_sent"] == "1234"
    assert "jsonPayload.opaque" in flow["redacted_paths"]
    firewall = project_log_entry(
        {
            "jsonPayload": {
                "connection": connection,
                "disposition": "DENIED",
                "opaque": "PRIVATE-FIREWALL",
            }
        },
        "firewall",
    )
    assert firewall["jsonPayload"]["disposition"] == "DENIED"
    assert "PRIVATE" not in json.dumps([flow, firewall])


@pytest.mark.parametrize("payload", ["PRIVATE", ["PRIVATE"], 4, None])
def test_malformed_log_payloads_do_not_escape_or_crash(payload):
    result = project_log_entry({"protoPayload": payload, "jsonPayload": payload}, "vpc_flows")
    assert "protoPayload" not in result
    assert "jsonPayload" not in result
    assert "PRIVATE" not in json.dumps(result)
