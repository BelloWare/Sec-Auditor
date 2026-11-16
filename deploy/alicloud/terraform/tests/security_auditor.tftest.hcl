# Provider-mocked plan tests: no credentials, cloud reads or RAM writes.
mock_provider "alicloud" {}

variables {
  auditor_role_name = "sec-auditor-test"
}

run "reviewed_permission_boundary" {
  command = plan

  assert {
    condition = (
      jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Version == "1" &&
      length(jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Statement) == 1 &&
      jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Statement[0].Effect == "Allow" &&
      jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Statement[0].Resource == "*" &&
      toset(jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Statement[0].Action) ==
      toset(jsondecode(file("${path.module}/policy-review.json")).allowed_actions)
    )
    error_message = "The actual Allow document must grant exactly the independently reviewed action set on all resources."
  }

  assert {
    condition = (
      jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Version == "1" &&
      length(jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement) == 1 &&
      jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0].Effect == "Deny" &&
      jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0].Resource == "*" &&
      toset(keys(jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0])) ==
      toset(["Effect", "NotAction", "Resource"]) &&
      toset(jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0].NotAction) ==
      toset(jsondecode(alicloud_ram_policy.security_auditor_allow.policy_document).Statement[0].Action)
    )
    error_message = "One unconditional guard must deny all other actions using the SAME FULL union; split exceptions would deny valid reads."
  }

  assert {
    condition = alltrue([
      for action in jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0].NotAction :
      can(regex("^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]+$", action))
    ])
    error_message = "Wildcard grants, non-ASCII actions and service/action patterns must never become guard exceptions."
  }

  assert {
    condition = alltrue([
      for action in concat(jsondecode(file("${path.module}/policy-review.json")).reviewed_exclusions, [
        "oss:GetObject", "oss:GetObjectVersion", "oss:HeadObject", "oss:ListObjects",
        "oss:ListObjectVersions", "oss:SelectObject", "oss:PutObject", "oss:DeleteObject",
        "kms:GetSecretValue", "kms:Decrypt", "kms:GenerateDataKey", "kms:GetPrivateKey",
        "ecs:RunCommand", "ecs:InvokeCommand", "ecs:DescribeInvocationResults",
        "ecs:DescribeInstanceVncUrl", "ecs:RebootInstance", "ecs:DeleteInstance",
        "ram:CreateAccessKey", "ram:CreateVirtualMFADevice", "ram:AttachPolicyToRole",
        "ram:CreatePolicyVersion", "ram:UpdateRole", "sts:AssumeRole",
        "sts:AssumeRoleWithOIDC", "sts:AssumeRoleWithSAML",
        "cs:DescribeClusterUserKubeconfig", "cr:GetAuthorizationToken",
        "log:GetLogStoreLogs", "log:GetLogStoreHistogram", "log:PullLogs",
        "fc:InvokeFunction", "ots:GetRow", "ots:GetRange", "ots:SQLQuery",
        "mq:QueryMessage", "mq:SendMessage", "rocketmq:GetMessageDetail",
        "some-future-service:ReadNewDataEndpoint"
      ]) : !contains(jsondecode(alicloud_ram_policy.security_auditor_guard.policy_document).Statement[0].NotAction, action)
    ])
    error_message = "Data, credentials, mixed responses, role chaining, execution, mutations and unknown future actions must remain subject to the explicit deny."
  }

  assert {
    condition = (
      length(alicloud_ram_policy.security_auditor_allow.policy_document) <= 6144 &&
      length(alicloud_ram_policy.security_auditor_guard.policy_document) <= 6144 &&
      length(alicloud_ram_policy.security_auditor_allow.policy_document) ==
      jsondecode(file("${path.module}/policy-review.json")).rendered_policy_sizes_bytes.Allow &&
      length(alicloud_ram_policy.security_auditor_guard.policy_document) ==
      jsondecode(file("${path.module}/policy-review.json")).rendered_policy_sizes_bytes.Deny
    )
    error_message = "Both actual compact policies must fit RAM's non-adjustable policy quota and match the documented sizes."
  }

  assert {
    condition = (
      toset([
        for record in jsondecode(file("${path.module}/policy-review.json")).actions :
        record.action if record.decision == "allow"
      ]) == toset(local.security_auditor_actions) &&
      toset([
        for record in jsondecode(file("${path.module}/policy-review.json")).actions :
        record.action if record.decision == "exclude"
      ]) == toset(jsondecode(file("${path.module}/policy-review.json")).reviewed_exclusions) &&
      alltrue([
        for record in jsondecode(file("${path.module}/policy-review.json")).actions :
        length(record.reviews) > 0 && alltrue([
          for review in record.reviews : length(review.reason) > 0 && length(review.sources) > 0
        ])
      ])
    )
    error_message = "Every approved action and reviewed exclusion needs a rationale and primary-source provenance."
  }

  assert {
    condition = (
      alicloud_ram_role_policy_attachment.security_auditor_allow.role_name == var.auditor_role_name &&
      alicloud_ram_role_policy_attachment.security_auditor_guard.role_name == var.auditor_role_name &&
      alicloud_ram_role_policy_attachment.security_auditor_allow.policy_type == "Custom" &&
      alicloud_ram_role_policy_attachment.security_auditor_guard.policy_type == "Custom" &&
      alicloud_ram_policy.security_auditor_allow.force == false &&
      alicloud_ram_policy.security_auditor_guard.force == false &&
      contains(local.security_auditor_actions, "sts:GetCallerIdentity")
    )
    error_message = "Both custom policies must target the dedicated role, preserve identity bootstrap and never force-detach other policy users."
  }
}

run "reject_wildcard_role" {
  command = plan
  variables {
    auditor_role_name = "sec-auditor-*"
  }
  expect_failures = [var.auditor_role_name]
}

run "reject_service_linked_role" {
  command = plan
  variables {
    auditor_role_name = "AliyunServiceRoleForExample"
  }
  expect_failures = [var.auditor_role_name]
}

run "reject_reserved_role" {
  command = plan
  variables {
    auditor_role_name = "AliyunReservedSSOExample"
  }
  expect_failures = [var.auditor_role_name]
}

run "reject_invalid_policy_name" {
  command = plan
  variables {
    auditor_policy_name_prefix = "unsafe/policy-name"
  }
  expect_failures = [var.auditor_policy_name_prefix]
}
