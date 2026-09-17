mock_provider "aws" {
  alias           = "primary"
  override_during = plan
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/test:1" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:test.fifo" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:test" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-abcdef" }
  }
}

mock_provider "aws" {
  alias           = "secondary"
  override_during = plan
}

mock_provider "random" {
  override_during = plan
}

# Distinct IDs make set cardinality and network-boundary comparisons known
# during plan without replacing the security-group rules under test.
override_resource {
  target          = module.primary.aws_security_group.app
  override_during = plan
  values          = { id = "sg-app" }
}

override_resource {
  target          = module.primary.aws_security_group.alb
  override_during = plan
  values          = { id = "sg-alb" }
}

override_resource {
  target          = module.primary.aws_security_group.console_ingress
  override_during = plan
  values          = { id = "sg-console" }
}

override_resource {
  target          = module.primary.aws_iam_role.runtime["backend"]
  override_during = plan
  values          = { arn = "arn:aws:iam::123456789012:role/authclaw-test-backend" }
}

variables {
  authclaw_env               = "ci"
  project                    = "authclaw-test"
  aws_account_id             = "123456789012"
  environment                = "test"
  primary_region             = "us-east-1"
  secondary_region           = "us-west-2"
  primary_availability_zones = ["us-east-1a", "us-east-1b"]
  secondary_availability_zones = [
    "us-west-2a",
    "us-west-2b",
  ]
  ci_skip_aws_validation         = true
  enable_secondary               = false
  enable_cross_region_db_replica = false
  primary_certificate_arn        = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000000"
  secondary_certificate_arn      = "arn:aws:acm:us-west-2:123456789012:certificate/00000000-0000-4000-8000-000000000001"
  quota_alert_sns_topic_arns     = { primary = ["arn:aws:sns:us-east-1:123456789012:authclaw-quota-alerts"] }
  container_images = {
    agent          = "example.invalid/authclaw/agent:test"
    backend        = "example.invalid/authclaw/backend:test"
    gateway        = "example.invalid/authclaw/gateway:test"
    console        = "123456789012.dkr.ecr.us-east-1.amazonaws.com/authclaw/console:test"
    audit_consumer = "example.invalid/authclaw/audit-consumer:test"
    opa            = "example.invalid/authclaw/opa:test"
    presidio       = "example.invalid/authclaw/presidio:test"
  }
}


run "execution_roles_only_receive_their_task_secrets" {
  command = plan

  assert {
    condition = alltrue([for name, review in output.execution_iam_review :
      contains(review.secret_names, "WORKER_TOKEN_HMAC_KEY_V1") == contains(["backend", "database_worker_preflight"], name)
    ])
    error_message = "Worker HMAC must be injected only into backend and worker preflight."
  }
  assert {
    condition = alltrue([for name, review in output.execution_iam_review :
      contains(review.secret_names, "AUTHCLAW_INTERNAL_SERVICE_SECRET") == contains(["console", "agent"], name)
    ])
    error_message = "Service signing keys must only reach the console sender and agent verifier."
  }

  assert {
    condition     = output.runtime_iam_review.sidecars_isolated
    error_message = "OPA/Presidio must run in independent tasks."
  }
  assert {
    condition     = toset(output.runtime_iam_review.roles) == toset(["backend", "agent", "gateway", "console", "opa", "presidio", "audit_consumer"])
    error_message = "Every application service must have an independent runtime role."
  }
  assert {
    condition     = alltrue([for name in ["opa", "presidio"] : length(output.execution_iam_review[name].secret_names) == 0])
    error_message = "OPA and Presidio must receive no application secrets."
  }
  assert {
    condition     = contains(output.execution_iam_review.backend.secret_names, "PLATFORM_AUTH_DATABASE_URL")
    error_message = "Backend platform authentication must use its dedicated credential."
  }
  assert {
    condition = alltrue([for name, review in output.execution_iam_review :
      contains(review.secret_names, "AUTHCLAW_QUOTA_METRICS_SECRET") == contains(["gateway", "agent"], name)
    ])
    error_message = "Only gateway and agent may receive the dedicated quota metrics credential."
  }

  assert {
    condition = toset(flatten([for statement in jsondecode(output.execution_iam_review.console.policy).Statement :
      statement.Resource if contains(statement.Action, "ecr:BatchGetImage")
    ])) == toset(["arn:aws:ecr:us-east-1:123456789012:repository/authclaw/console"])
    error_message = "Console image pulls must be restricted to its configured ECR repository."
  }

  assert {
    condition = alltrue([for name, review in output.execution_iam_review :
      toset(flatten([for statement in jsondecode(review.policy).Statement :
        statement.Resource if contains(statement.Action, "secretsmanager:GetSecretValue")
      ])) == toset(review.secret_arns)
    ])
    error_message = "Secret-read grants must exactly match the secrets injected for that task."
  }
  assert {
    condition = alltrue([for name in ["console", "opa", "presidio"] :
      !contains(output.execution_iam_review[name].secret_names, "DATABASE_URL") &&
      !contains(output.execution_iam_review[name].secret_names, "ENVELOPE_KEY") &&
      !contains(output.execution_iam_review[name].secret_names, "JWT_SECRET")
    ])
    error_message = "Console and standalone sidecars must not receive database or unused cryptographic secrets."
  }
  assert {
    condition = alltrue(flatten([for name, review in output.execution_iam_review :
      [for statement in jsondecode(review.policy).Statement :
        try(statement.Condition.StringEquals["kms:ViaService"], "") == "secretsmanager.us-east-1.amazonaws.com" &&
        toset(try(statement.Condition.StringEquals["kms:EncryptionContext:SecretARN"], [])) == toset(review.secret_arns)
        if contains(statement.Action, "kms:Decrypt")
      ]
    ]))
    error_message = "KMS decrypt must be limited to Secrets Manager and the exact task secret encryption contexts."
  }
}

run "evidence_object_access_is_backend_only_and_exportable" {
  command = plan

  variables {
    runtime_s3_bucket_arns = {
      backend = ["arn:aws:s3:::authclaw-evidence-test"]
      agent   = ["arn:aws:s3:::agent-private-test"]
    }
  }

  assert {
    condition = (
      jsondecode(output.primary.evidence_object_access_policy).Principal.AWS == output.runtime_iam_review.task_role_arns.backend &&
      jsondecode(output.primary.evidence_object_access_policy).Action == "s3:DeleteObject" &&
      toset(jsondecode(output.primary.evidence_object_access_policy).Resource) == toset(["arn:aws:s3:::authclaw-evidence-test/tenant-*/*"])
    )
    error_message = "Evidence deletion must be backend-only, object-only, and included in the policy export."
  }
}

run "fargate_service_alarms_cover_memory_and_task_health" {
  command = plan

  assert {
    condition = alltrue([
      contains(output.primary.alarm_names, "authclaw-test-test-primary-backend-high-memory"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-backend-running-tasks-low"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-backend-pending-tasks"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-ecs-deployment-failure"),
    ])
    error_message = "Fargate services must alarm on memory pressure and running/pending task health."
  }
}

run "sqs_runtime_roles_remain_separate" {
  command = plan
  variables {
    audit_stream_transport           = "sqs_fifo"
    enable_policy_sidecar_colocation = true
    internal_tls                     = { enabled = true, namespace = "internal.example.com" }
    enable_audit_consumer            = true
    clickhouse_host                  = "clickhouse.test.invalid"
    audit_consumer_environment       = { CLICKHOUSE_SECURE = "true" }
    audit_consumer_secret_arns = {
      AUDIT_POSTGRES_URL = "arn:aws:secretsmanager:us-east-1:123456789012:secret:audit-postgres-abcdef"
    }
    agent_customer_role_arns = ["arn:aws:iam::210987654321:role/authclaw-customer"]
  }
  assert {
    condition     = toset(output.runtime_iam_review.roles) == toset(["backend", "agent", "gateway", "console", "opa", "presidio", "audit_consumer", "audit_producer"])
    error_message = "SQS transport must use an independent audit producer identity."
  }
  assert {
    condition     = toset(output.execution_iam_review.audit_consumer.secret_names) == toset(["AUDIT_POSTGRES_URL", "CLICKHOUSE_PASSWORD"])
    error_message = "Audit consumer must receive only its verifier and ClickHouse credentials."
  }
  assert {
    condition     = length(output.runtime_iam_review.customer_roles) == 1
    error_message = "Only the configured customer role may be assumed."
  }
  assert {
    condition = (
      output.runtime_iam_review.task_role_arns.gateway == null &&
      contains(output.runtime_iam_review.roles, "audit_producer") &&
      contains(output.execution_iam_review.audit_producer.secret_names, "AUDIT_PRODUCER_SECRET") &&
      !contains(output.execution_iam_review.audit_producer.secret_names, "DATABASE_URL") &&
      !contains(output.execution_iam_review.audit_producer.secret_names, "JWT_SECRET")
    )
    error_message = "The co-located gateway must be credential-free and use a minimally secret-bearing producer task."
  }
}

run "regional_audit_secrets_remain_isolated" {
  command = plan
  variables {
    enable_secondary               = true
    enable_cross_region_db_replica = false
    audit_stream_transport         = "sqs_fifo"
    internal_tls                   = { enabled = true, namespace = "internal.example.com" }
    enable_audit_consumer          = true
    clickhouse_host                = "clickhouse.test.invalid"
    audit_consumer_environment     = { CLICKHOUSE_SECURE = "true" }
    audit_consumer_secret_arns = {
      AUDIT_POSTGRES_URL = "arn:aws:secretsmanager:us-east-1:123456789012:secret:audit-postgres-primary"
    }
    secondary_audit_consumer_secret_arns = {
      AUDIT_POSTGRES_URL = "arn:aws:secretsmanager:us-west-2:123456789012:secret:audit-postgres-secondary"
    }
  }
}

run "policy_sidecars_are_task_local_when_enabled" {
  command = plan
  variables {
    enable_policy_sidecar_colocation = true
  }
  assert {
    condition     = output.runtime_iam_review.policy_sidecars_colocated && output.runtime_iam_review.sidecars_isolated
    error_message = "The step-7 switch must use loopback endpoints while retaining policy services for privileged callers."
  }
  assert {
    condition     = toset(output.runtime_iam_review.roles) == toset(["backend", "agent", "gateway", "console", "opa", "presidio", "audit_consumer"])
    error_message = "Independent policy services must retain their own runtime identities."
  }
  assert {
    condition = (
      toset(output.runtime_iam_review.task_containers.gateway) == toset(["gateway", "opa", "presidio"]) &&
      toset(output.runtime_iam_review.task_containers.backend) == toset(["backend"]) &&
      toset(output.runtime_iam_review.task_containers.agent) == toset(["agent"])
    )
    error_message = "Every OPA/Presidio caller must receive its required local sidecar."
  }
  assert {
    condition = (
      contains(keys(output.execution_iam_review), "opa") &&
      contains(keys(output.execution_iam_review), "presidio") &&
      output.runtime_iam_review.sidecars_have_no_port_mappings &&
      output.runtime_iam_review.colocated_sidecars_have_no_task_role &&
      output.runtime_iam_review.task_role_arns.gateway == null
    )
    error_message = "Co-located policy containers must expose no ENI ports or application task credentials."
  }
  assert {
    condition = (
      { for item in output.runtime_iam_review.task_policy_environment.gateway : item.name => item.value }["OPA_URL"] == "http://127.0.0.1:8181" &&
      { for item in output.runtime_iam_review.task_policy_environment.gateway : item.name => item.value }["PRESIDIO_URL"] == "http://127.0.0.1:3000" &&
      startswith({ for item in output.runtime_iam_review.task_policy_environment.backend : item.name => item.value }["PRESIDIO_URL"], "http") &&
      startswith({ for item in output.runtime_iam_review.task_policy_environment.agent : item.name => item.value }["AUTHCLAW_OPA_POLICY_URL"], "http")
    )
    error_message = "Task-local policy URLs must only be injected into tasks that own the corresponding sidecar."
  }
}

run "tls_and_direct_aws_are_scoped" {
  command = plan
  variables {
    runtime_s3_bucket_arns = { backend = ["arn:aws:s3:::backend-evidence-test"] }
    # New writes use env v2; retained KMS v1 reads must remain independently configurable.
    secret_key_version       = "v2"
    authclaw_env             = "production"
    require_immutable_images = true
    enable_public_edge       = true
    hosted_zone_id           = "Z1234567890"
    edge_certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000010"
    edge_alarm_action_arns   = ["arn:aws:sns:us-east-1:123456789012:authclaw-edge-alerts"]
    container_images = {
      agent          = "example.invalid/authclaw/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      backend        = "example.invalid/authclaw/backend@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      gateway        = "example.invalid/authclaw/gateway@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      console        = "example.invalid/authclaw/console@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      audit_consumer = "example.invalid/authclaw/audit-consumer@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      opa            = "example.invalid/authclaw/opa@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      presidio       = "example.invalid/authclaw/presidio@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
    internal_tls = { enabled = true, namespace = "internal.example.com" }
    direct_aws = {
      backend_kms_versions    = { v1 = "arn:aws:kms:us-east-1:123456789012:key/backend" }
      agent_kms_key           = "arn:aws:kms:us-east-1:123456789012:key/agent"
      agent_previous_kms_keys = ["arn:aws:kms:us-east-1:123456789012:key/agent-old"]
      agent_secrets           = { provider = "arn:aws:secretsmanager:us-east-1:123456789012:secret:provider-abcdef" }
      agent_secret_kms_keys   = ["arn:aws:kms:us-east-1:123456789012:key/provider"]
      agent_s3_buckets        = ["arn:aws:s3:::documents-test"]
      agent_s3_objects        = ["arn:aws:s3:::documents-test/approved.pdf"]
    }
  }
  assert {
    condition = alltrue([for service in ["console", "backend", "agent", "gateway", "opa", "presidio"] :
      startswith(output.runtime_iam_review.internal_urls[service], "https://") &&
      contains(output.execution_iam_review[service].secret_names, "TLS_KEY_PEM")
    ]) && contains(output.runtime_iam_review.roles, "console")
    error_message = "Protected services must use TLS with task-specific certificate injection."
  }
  assert {
    condition = (
      toset(output.runtime_ingress_ports.console_to_app) == toset([8443]) &&
      toset(values(output.runtime_ingress_ports.alb_to_public)) == toset([8443]) &&
      toset(output.runtime_ingress_ports.service_to_service) == toset([8443])
    )
    error_message = "Internal TLS must route console, ALB, and service-to-service traffic only through port 8443."
  }
  assert {
    condition = alltrue(flatten([for statements in output.runtime_iam_review.direct_permissions :
      [for statement in statements : !contains(tolist(statement.Resource), "*")]
    ])) && contains(output.runtime_iam_review.roles, "database_crypto_preflight")
    error_message = "Optional AWS grants must remain exact-resource, including the crypto preflight role."
  }
  assert {
    condition = toset(flatten([
      for statement in jsondecode(output.runtime_iam_review.policies.database_crypto_preflight).Statement :
      statement.Action if statement.Effect == "Allow"
    ])) == toset(["kms:Decrypt"])
    error_message = "Crypto preflight must retain KMS decrypt without inheriting backend S3 access."
  }
  assert {
    condition = alltrue([for role in ["backend", "database_crypto_preflight"] :
      toset(flatten([for statement in jsondecode(output.runtime_iam_review.policies[role]).Statement :
        statement.Resource if statement.Effect == "Allow" && contains(statement.Action, "kms:Decrypt")
      ])) == toset(["arn:aws:kms:us-east-1:123456789012:key/backend"])
      ]) && toset(flatten([
        for statement in jsondecode(output.runtime_iam_review.policies.backend).Statement :
        statement.Action if statement.Effect == "Allow"
    ])) == toset(["kms:Decrypt", "s3:GetObject", "s3:DeleteObject"])
    error_message = "Backend evidence access and both roles' exact KMS decrypt grants must remain intact."
  }
}


override_resource {
  target          = module.primary.aws_secretsmanager_secret.backend_database_url
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:backend_database_url-abcdef" }
}

override_resource {
  target          = module.primary.aws_secretsmanager_secret.agent_database_url
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent_database_url-abcdef" }
}

override_resource {
  target          = module.primary.aws_secretsmanager_secret.app_database_url
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app_database_url-abcdef" }
}

override_resource {
  target          = module.primary.aws_secretsmanager_secret.bootstrap_database_url
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:bootstrap_database_url-abcdef" }
}
override_resource {
  target          = module.primary.aws_ecs_task_definition.service["opa"]
  override_during = plan
  values          = { arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/opa:1" }
}

override_resource {
  target          = module.primary.aws_ecs_task_definition.service["presidio"]
  override_during = plan
  values          = { arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/presidio:1" }
}
