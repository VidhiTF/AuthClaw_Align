mock_provider "aws" {
  alias           = "primary"
  override_during = plan
}

mock_provider "aws" {
  alias           = "secondary"
  override_during = plan
}

mock_provider "random" {
  override_during = plan
}

variables {
  project                    = "authclaw-test"
  environment                = "staging"
  authclaw_env               = "staging"
  primary_region             = "us-east-1"
  secondary_region           = "us-west-2"
  primary_availability_zones = ["us-east-1a", "us-east-1b"]
  ci_skip_aws_validation     = true
  enable_secondary           = false
  primary_certificate_arn    = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000000"
  container_images = {
    agent          = "example.invalid/authclaw/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    backend        = "example.invalid/authclaw/backend@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    gateway        = "example.invalid/authclaw/gateway@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    console        = "example.invalid/authclaw/console@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    audit_consumer = "example.invalid/authclaw/audit@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    opa            = "example.invalid/authclaw/opa@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    presidio       = "example.invalid/authclaw/presidio@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }
}

run "availability_scaling_and_observability_contract" {
  command = plan

  assert {
    condition     = alltrue([for value in values(output.primary.availability_controls.min_capacity) : value >= 2])
    error_message = "Every staging service must have a two-task availability floor."
  }

  assert {
    condition     = output.primary.availability_controls.max_capacity == { for service, value in var.service_max_capacity : service => value if service != "audit_consumer" }
    error_message = "Application Auto Scaling must enforce the configured service ceilings."
  }

  assert {
    condition = (
      output.primary.availability_controls.deployment.minimum_healthy_percent == 100 &&
      output.primary.availability_controls.deployment.maximum_percent == 200 &&
      output.primary.availability_controls.deployment.circuit_breaker &&
      output.primary.availability_controls.deployment.automatic_rollback &&
      output.primary.availability_controls.deployment.drain_seconds == 60 &&
      output.primary.availability_controls.deployment.stop_timeout_seconds == 60
    )
    error_message = "ECS deployment rollback and connection-draining controls must remain enabled."
  }

  assert {
    condition = (
      output.primary.availability_controls.connection_budget.backend == 75 &&
      output.primary.availability_controls.connection_budget.gateway == 60 &&
      output.primary.availability_controls.connection_budget.agent == 40 &&
      output.primary.availability_controls.connection_budget.runtime_total == 175 &&
      output.primary.availability_controls.connection_budget.operational_reserve == 25 &&
      output.primary.availability_controls.connection_budget.rds_max_connections == 200
    )
    error_message = "The default maximum task/pool calculation must consume 175 runtime connections and retain 25 operational connections."
  }

  assert {
    condition     = !output.primary.availability_controls.rds_proxy_used
    error_message = "RDS Proxy must remain absent without measured connection-churn evidence."
  }

  assert {
    condition = toset(values(output.primary.observability.dashboards)) == toset([
      "authclaw-test-staging-primary-services",
      "authclaw-test-staging-primary-data",
      "authclaw-test-staging-primary-network",
      "authclaw-test-staging-primary-nat",
    ])
    error_message = "Service, data, network, and NAT dashboards must be provisioned."
  }

  assert {
    condition = alltrue([
      contains(output.primary.observability.critical_alarm_names, "authclaw-test-staging-primary-backend-running-below-minimum"),
      contains(output.primary.observability.critical_alarm_names, "authclaw-test-staging-primary-ecs-deployment-failed"),
      contains(output.primary.observability.critical_alarm_names, "authclaw-test-staging-primary-rds-failover"),
      contains(output.primary.observability.critical_alarm_names, "authclaw-test-staging-primary-audit-verification-failures"),
    ])
    error_message = "Critical task, deployment, RDS, and audit-integrity alarms must exist."
  }

  assert {
    condition = (
      output.primary.observability.alert_configuration.owner == "platform-operations-unassigned" &&
      output.primary.observability.alert_configuration.acknowledgement_minutes == 15 &&
      output.primary.observability.alert_configuration.action_arns_configured == false &&
      output.primary.observability.alert_configuration.action_destination_variable == "edge_alarm_action_arns"
    )
    error_message = "Alarm ownership and destination metadata must be deployment-ready without inventing a destination."
  }
}
