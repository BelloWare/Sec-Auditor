# Alibaba Cloud security-configuration auditor -- reviewed 2026-11-16.
# Standalone Terraform HCL: no external JSON, Python package or MCP is required.
#
# Attach to an EXISTING, DEDICATED, ordinary RAM role in the provider's account.
# Keep that role's narrow RRSA/OIDC trust separate. Run Terraform as your normal
# provisioning identity, not as this restricted auditing role.
#
# Scope: all resources for the EXACT actions below, not every Alibaba API.
# Mixed metadata/content APIs are intentionally absent. Resource Center and
# Cloud Config expose only supported, enabled and independently authorized
# summary inventory. Cross-account access and Kubernetes RBAC are separate.
#
# No permission grants for objects, secret values, log/event bodies, database
# rows, messages, image/code downloads, credential issuance, VM/pod execution
# or mutations. Metadata strings can still contain user-embedded secrets.
# An existing allowed API can change its response; review schema changes.
#
# Two documents are necessary to stay below RAM's 6144-character policy limit.
# The guard DENIES every RAM-authorized action outside the full reviewed union.
# NEVER split that NotAction union into separate disjoint deny statements.
# Removing this guard can reactivate other grants attached to the role.
#
# Usage (configure the provider's normal credentials outside this file):
#   terraform init
#   terraform plan -var='auditor_role_name=sec-auditor' -out=auditor.tfplan
#   terraform apply auditor.tfplan
# Sources, exclusions and deployment notes are in README.md/policy-review.json
# beside this file, but neither is required to evaluate this configuration.

terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 2.2.0"
    }
  }
}

# Uses the operator's standard provider configuration/credential environment.
# If incorporating this file in an existing root module, reuse its provider.
provider "alicloud" {}

variable "auditor_role_name" {
  description = "Existing dedicated ordinary RAM role in this provider account. Its trust policy is managed separately."
  type        = string
  nullable    = false

  validation {
    condition = (
      can(regex("^[A-Za-z0-9.-]{1,64}$", var.auditor_role_name)) &&
      !startswith(lower(var.auditor_role_name), "aliyunservicerole") &&
      !startswith(lower(var.auditor_role_name), "aliyunreserved")
    )
    error_message = "Use a dedicated ordinary role name (1-64 letters, digits, dots or dashes), not a service-linked or reserved managed role."
  }
}

variable "auditor_policy_name_prefix" {
  description = "Unique custom-policy prefix for this deployment; changing it replaces both policies and attachments."
  type        = string
  default     = "SecAuditorMetadata"
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,99}$", var.auditor_policy_name_prefix))
    error_message = "The prefix must be 1-100 letters, digits or dashes and start with a letter or digit."
  }
}

locals {
  # Exact action names only. No Get*, Describe*, List*, service:* or * grants.
  # Adding an action requires reviewing every API/response authorized by it.
  security_auditor_action_groups = {
    # Trail configuration and delivery status; no event bodies.
    "actiontrail" = [
      "actiontrail:DescribeTrails",
      "actiontrail:GetTrailStatus",
    ]

    # AnalyticDB inventory, network allowlists and TLS configuration.
    "adb" = [
      "adb:DescribeDBClusterAccessWhiteList",
      "adb:DescribeDBClusterAttribute",
      "adb:DescribeDBClusterSSL",
      "adb:DescribeDBClusters",
    ]

    # ALB inventory, listeners, ACLs, TLS and server groups; no rules or fixed response bodies.
    "alb" = [
      "alb:GetListenerAttribute",
      "alb:GetLoadBalancerAttribute",
      "alb:ListAclEntries",
      "alb:ListAcls",
      "alb:ListListeners",
      "alb:ListLoadBalancers",
      "alb:ListSecurityPolicies",
      "alb:ListServerGroups",
    ]

    # DNS zones, groups and configured records; TXT records are configuration strings.
    "alidns" = [
      "alidns:DescribeDomainGroups",
      "alidns:DescribeDomainInfo",
      "alidns:DescribeDomainRecords",
      "alidns:DescribeDomains",
    ]

    # Kafka ACL and consumer-group metadata; no messages, credentials or opaque instance configuration.
    "alikafka" = [
      "alikafka:ListAcl",
      "alikafka:ListGroup",
    ]

    # API and group summaries; no detailed mock bodies or constant parameters.
    "apigateway" = [
      "apigateway:DescribeApiGroups",
      "apigateway:DescribeApis",
    ]

    # CDN domain summaries; no feature arguments or signing keys.
    "cdn" = [
      "cdn:DescribeCdnDomainDetail",
      "cdn:DescribeUserDomains",
    ]

    # CEN topology, transit routers and routing policies.
    "cen" = [
      "cen:DescribeCenAttachedChildInstances",
      "cen:DescribeCenRouteMaps",
      "cen:DescribeCens",
      "cen:ListTransitRouterRouteEntries",
      "cen:ListTransitRouterRouteTables",
      "cen:ListTransitRouters",
    ]

    # Cloud Config summary inventory and rule listings; no resource configuration bodies or evaluations.
    "config" = [
      "config:ListConfigRules",
      "config:ListDiscoveredResources",
    ]

    # Registry, endpoint, repository and tag metadata; no image layers, pull tokens or scan evidence.
    "cr" = [
      "cr:GetInstance",
      "cr:GetInstanceEndpoint",
      "cr:ListInstance",
      "cr:ListInstanceEndpoint",
      "cr:ListRepository",
      "cr:ListRepositoryTag",
    ]

    # MongoDB inventory, allowlists, security groups, backup-policy configuration, TLS and TDE identifiers.
    "dds" = [
      "dds:DescribeBackupPolicy",
      "dds:DescribeDBInstanceSSL",
      "dds:DescribeDBInstanceTDEInfo",
      "dds:DescribeDBInstances",
      "dds:DescribeSecurityGroupConfiguration",
      "dds:DescribeSecurityIps",
    ]

    # VM, disk, image, snapshot, network and role configuration; no user data, console or execution.
    "ecs" = [
      "ecs:DescribeAutoSnapshotPolicyEx",
      "ecs:DescribeDisks",
      "ecs:DescribeImageSharePermission",
      "ecs:DescribeImages",
      "ecs:DescribeInstanceRamRole",
      "ecs:DescribeInstances",
      "ecs:DescribeLaunchTemplates",
      "ecs:DescribeNetworkInterfaces",
      "ecs:DescribeSecurityGroupAttribute",
      "ecs:DescribeSecurityGroups",
      "ecs:DescribeSnapshots",
    ]

    # Scaling groups, membership and scaling rules; no launch configurations or user data.
    "ess" = [
      "ess:DescribeScalingGroups",
      "ess:DescribeScalingInstances",
      "ess:DescribeScalingRules",
    ]

    # Cloud Backup vault/protection configuration; no backed-up files, restore or download.
    "hbr" = [
      "hbr:DescribePoliciesV2",
      "hbr:DescribeVaults",
    ]

    # Key and secret identifiers, states, versions and policies; no secret values or cryptography.
    "kms" = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetSecretPolicy",
      "kms:ListAliases",
      "kms:ListKeyVersions",
      "kms:ListKeys",
      "kms:ListSecretVersionIds",
      "kms:ListSecrets",
    ]

    # Redis audit/backup/TLS/TDE and network controls; no opaque instance Config.
    "kvstore" = [
      "kvstore:DescribeAuditLogConfig",
      "kvstore:DescribeBackupPolicy",
      "kvstore:DescribeInstanceSSL",
      "kvstore:DescribeInstanceTDEStatus",
      "kvstore:DescribeSecurityGroupConfiguration",
      "kvstore:DescribeSecurityIps",
    ]

    # SLS project, logstore, index and shard configuration; no log events or data queries.
    "log" = [
      "log:GetIndex",
      "log:GetLogStore",
      "log:GetLogging",
      "log:GetProject",
      "log:ListLogStores",
      "log:ListProject",
      "log:ListShards",
    ]

    # Legacy RocketMQ/ONS instance, topic and group metadata; no messages.
    "mq" = [
      "mq:ListGroup",
      "mq:ListTopic",
      "mq:QueryInstanceBaseInfo",
    ]

    # NAS access configuration; no file listing or credential-bearing mount details.
    "nas" = [
      "nas:DescribeAccessGroups",
      "nas:DescribeAccessRules",
      "nas:GetRecycleBinAttribute",
      "nas:ListAccessPoints",
    ]

    # NLB inventory, listeners and TLS policies; no UDP health-check payloads.
    "nlb" = [
      "nlb:GetListenerAttribute",
      "nlb:GetLoadBalancerAttribute",
      "nlb:ListListeners",
      "nlb:ListLoadBalancers",
      "nlb:ListSecurityPolicy",
    ]

    # Bucket/access-point protection settings; no object listing, metadata, bodies or versions.
    "oss" = [
      "oss:GetAccessPoint",
      "oss:GetAccessPointPolicy",
      "oss:GetAccessPointPublicAccessBlock",
      "oss:GetBucketAcl",
      "oss:GetBucketCors",
      "oss:GetBucketEncryption",
      "oss:GetBucketHttpsConfig",
      "oss:GetBucketInfo",
      "oss:GetBucketLifecycle",
      "oss:GetBucketLogging",
      "oss:GetBucketPolicy",
      "oss:GetBucketPublicAccessBlock",
      "oss:GetBucketReferer",
      "oss:GetBucketReplication",
      "oss:GetBucketVersioning",
      "oss:GetBucketWorm",
      "oss:GetPublicAccessBlock",
      "oss:ListAccessPoints",
      "oss:ListBuckets",
    ]

    # TableStore instance metadata; no table contents, row access or SQL.
    "ots" = [
      "ots:GetInstance",
      "ots:ListInstance",
      "ots:ListVpcInfoByInstance",
    ]

    # PolarDB inventory, endpoints, allowlists, backup, TLS and TDE configuration.
    "polardb" = [
      "polardb:DescribeBackupPolicy",
      "polardb:DescribeDBClusterAccessWhitelist",
      "polardb:DescribeDBClusterAttribute",
      "polardb:DescribeDBClusterEndpoints",
      "polardb:DescribeDBClusterSSL",
      "polardb:DescribeDBClusterTDE",
      "polardb:DescribeDBClusters",
    ]

    # Identity, trust, policy, MFA and key-use metadata; no passwords, secret keys or MFA seeds.
    "ram" = [
      "ram:GetAccessKeyLastUsed",
      "ram:GetAccountAlias",
      "ram:GetAccountSummary",
      "ram:GetLoginProfile",
      "ram:GetOIDCProvider",
      "ram:GetPasswordPolicy",
      "ram:GetPolicy",
      "ram:GetPolicyVersion",
      "ram:GetRole",
      "ram:GetSAMLProvider",
      "ram:GetSecurityPreference",
      "ram:GetUser",
      "ram:GetUserMFAInfo",
      "ram:ListAccessKeys",
      "ram:ListGroups",
      "ram:ListGroupsForUser",
      "ram:ListOIDCProviders",
      "ram:ListPolicies",
      "ram:ListPoliciesForGroup",
      "ram:ListPoliciesForRole",
      "ram:ListPoliciesForUser",
      "ram:ListPolicyVersions",
      "ram:ListRoles",
      "ram:ListSAMLProviders",
      "ram:ListUsers",
      "ram:ListUsersForGroup",
      "ram:ListVirtualMFADevices",
    ]

    # RDS summaries and dedicated controls; no opaque recovery info, TLS private keys, SQL or backup files.
    "rds" = [
      "rds:DescribeAccounts",
      "rds:DescribeBackupPolicy",
      "rds:DescribeDBInstanceIPArrayList",
      "rds:DescribeDBInstanceNetInfo",
      "rds:DescribeDBInstanceTDE",
      "rds:DescribeDBInstances",
      "rds:DescribeResourceUsage",
      "rds:DescribeSQLCollectorPolicy",
    ]

    # Supported summary inventory only; discovery still performs underlying service authorization.
    "resourcecenter" = [
      "resourcecenter:SearchMultiAccountResources",
      "resourcecenter:SearchResources",
    ]

    # Account/directory/group inventory and control policies; no automatic member-account access.
    "resourcemanager" = [
      "resourcemanager:GetControlPolicy",
      "resourcemanager:GetFolder",
      "resourcemanager:GetResourceDirectory",
      "resourcemanager:ListAccounts",
      "resourcemanager:ListAncestors",
      "resourcemanager:ListControlPolicies",
      "resourcemanager:ListControlPolicyAttachmentsForTarget",
      "resourcemanager:ListDelegatedAdministrators",
      "resourcemanager:ListDelegatedServicesForAccount",
      "resourcemanager:ListFoldersForParent",
      "resourcemanager:ListResourceGroups",
      "resourcemanager:ListResources",
    ]

    # RocketMQ instance, topic and group summaries; no message retrieval.
    "rocketmq" = [
      "rocketmq:ListConsumerGroups",
      "rocketmq:ListInstances",
      "rocketmq:ListTopics",
    ]

    # CLB topology, ACLs, HTTP/HTTPS/TCP controls and certificate metadata; no UDP bodies or private keys.
    "slb" = [
      "slb:DescribeAccessControlListAttribute",
      "slb:DescribeAccessControlLists",
      "slb:DescribeLoadBalancerAttribute",
      "slb:DescribeLoadBalancerHTTPListenerAttribute",
      "slb:DescribeLoadBalancerHTTPSListenerAttribute",
      "slb:DescribeLoadBalancerTCPListenerAttribute",
      "slb:DescribeLoadBalancers",
      "slb:DescribeServerCertificates",
    ]

    # Caller identity only. Outgoing role assumption is deliberately denied.
    "sts" = [
      "sts:GetCallerIdentity",
    ]

    # VPC, subnet, route, ACL, EIP, NAT, gateway and flow-log configuration; no tunnel PSKs or flow records.
    "vpc" = [
      "vpc:DescribeEipAddresses",
      "vpc:DescribeFlowLogs",
      "vpc:DescribeForwardTableEntries",
      "vpc:DescribeNatGateways",
      "vpc:DescribeNetworkAclAttributes",
      "vpc:DescribeNetworkAcls",
      "vpc:DescribeRouteEntryList",
      "vpc:DescribeRouteTableList",
      "vpc:DescribeSnatTableEntries",
      "vpc:DescribeSslVpnServers",
      "vpc:DescribeVSwitches",
      "vpc:DescribeVpcs",
      "vpc:DescribeVpnGateways",
    ]

    # DDoS protection instance summaries.
    "yundun-ddoscoo" = [
      "yundun-ddoscoo:DescribeInstanceDetails",
      "yundun-ddoscoo:DescribeInstanceIds",
      "yundun-ddoscoo:DescribeInstances",
    ]

    # Security Center asset inventory and aggregate statistics; no captured finding evidence.
    "yundun-sas" = [
      "yundun-sas:DescribeCloudCenterInstances",
      "yundun-sas:DescribeSecurityStatInfo",
    ]

    # WAF domain summaries; no origin header values, arbitrary rules or sampled requests.
    "yundun-waf" = [
      "yundun-waf:DescribeDomains",
    ]

  }

  security_auditor_actions = sort(distinct(flatten(values(local.security_auditor_action_groups))))

  security_auditor_allow_json = jsonencode({
    Version = "1"
    Statement = [{
      Effect   = "Allow"
      Action   = local.security_auditor_actions
      Resource = "*"
    }]
  })

  security_auditor_guard_json = jsonencode({
    Version = "1"
    Statement = [{
      Effect    = "Deny"
      NotAction = local.security_auditor_actions
      Resource  = "*"
    }]
  })
}

resource "alicloud_ram_policy" "security_auditor_guard" {
  policy_name     = "${var.auditor_policy_name_prefix}-Guardrail"
  description     = "Deny every RAM-authorized action outside the reviewed security-metadata allowlist. Keep attached to the dedicated role."
  policy_document = local.security_auditor_guard_json
  rotate_strategy = "DeleteOldestNonDefaultVersionWhenLimitExceeded"
  force           = false

  lifecycle {
    create_before_destroy = true

    precondition {
      # All policy strings are ASCII, so character and byte lengths agree.
      condition     = length(local.security_auditor_guard_json) <= 6144
      error_message = "The complete deny exception list exceeds RAM's 6144-character limit. Do not split NotAction across disjoint policies or replace actions with wildcards."
    }

    precondition {
      condition = alltrue([
        for action in local.security_auditor_actions :
        can(regex("^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]+$", action))
      ])
      error_message = "Every allowed action must be one exact ASCII RAM action. Wildcards and patterns are forbidden."
    }
  }
}

resource "alicloud_ram_role_policy_attachment" "security_auditor_guard" {
  policy_name = alicloud_ram_policy.security_auditor_guard.policy_name
  policy_type = "Custom"
  role_name   = var.auditor_role_name

  lifecycle {
    create_before_destroy = true
  }
}

resource "alicloud_ram_policy" "security_auditor_allow" {
  policy_name     = "${var.auditor_policy_name_prefix}-Allow"
  description     = "Reviewed security configuration and identity metadata. No content, credentials, raw logs, execution or mutations."
  policy_document = local.security_auditor_allow_json
  rotate_strategy = "DeleteOldestNonDefaultVersionWhenLimitExceeded"
  force           = false

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(local.security_auditor_allow_json) <= 6144
      error_message = "The allow policy exceeds RAM's 6144-character limit. Review/reduce the exact action set instead of adding broad read wildcards."
    }
  }
}

resource "alicloud_ram_role_policy_attachment" "security_auditor_allow" {
  policy_name = alicloud_ram_policy.security_auditor_allow.policy_name
  policy_type = "Custom"
  role_name   = var.auditor_role_name

  # Guard first on creation; allow detached first on destruction. RAM policy
  # propagation is eventually consistent, not an atomic global transaction.
  depends_on = [alicloud_ram_role_policy_attachment.security_auditor_guard]

  lifecycle {
    create_before_destroy = true
  }
}

output "security_auditor_policy_names" {
  description = "Both policies must remain attached to the same dedicated role."
  value = {
    role      = var.auditor_role_name
    allow     = alicloud_ram_policy.security_auditor_allow.policy_name
    guardrail = alicloud_ram_policy.security_auditor_guard.policy_name
  }
}

output "security_auditor_action_count" {
  description = "Number of exact reviewed RAM actions; not a claim of complete Alibaba API coverage."
  value       = length(local.security_auditor_actions)
}

output "security_auditor_policy_sizes" {
  description = "Compact ASCII policy sizes, each independently limited to 6144 bytes/characters."
  value = {
    allow_bytes     = length(local.security_auditor_allow_json)
    guardrail_bytes = length(local.security_auditor_guard_json)
  }
}
