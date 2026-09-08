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

variables {
  authclaw_env               = "ci"
  project                    = "authclaw-test"
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
  container_images = {
    agent          = "example.invalid/authclaw/agent:test"
    backend        = "example.invalid/authclaw/backend:test"
    gateway        = "example.invalid/authclaw/gateway:test"
    console        = "example.invalid/authclaw/console:test"
    audit_consumer = "example.invalid/authclaw/audit-consumer:test"
    opa            = "example.invalid/authclaw/opa:test"
    presidio       = "example.invalid/authclaw/presidio:test"
  }
}

run "single_nat_for_lower_environments" {
  command = plan

  variables {
    nat_gateway_mode = "single"
  }

  assert {
    condition     = length(output.primary.nat_gateway_ids) == 1
    error_message = "Single mode must create exactly one NAT gateway."
  }

  assert {
    condition     = length(output.primary.private_route_table_ids) == 2
    error_message = "Every private subnet must have its own route table."
  }

  assert {
    condition     = alltrue([for nat_key in values(output.primary.private_route_nat_keys) : nat_key == "0"])
    error_message = "Single mode must route every private subnet through NAT key 0."
  }

  assert {
    condition     = toset(keys(output.primary.gateway_endpoint_route_table_ids)) == toset(["s3"])
    error_message = "Only the confirmed S3 gateway endpoint must exist."
  }

  assert {
    condition     = alltrue([for count in values(output.primary.gateway_endpoint_route_table_count) : count == 2])
    error_message = "Gateway endpoints must attach to every private route table."
  }

  assert {
    condition = toset(keys(output.primary.interface_endpoint_private_dns)) == toset([
      "ecr_api",
      "ecr_dkr",
      "kms",
      "logs",
      "secretsmanager",
      "sts",
    ]) && alltrue(values(output.primary.interface_endpoint_private_dns))
    error_message = "The six required interface endpoints must exist and enable private DNS."
  }

  assert {
    condition     = toset(keys(output.primary.interface_endpoint_policies)) == toset(keys(output.primary.interface_endpoint_private_dns)) && toset(keys(output.primary.gateway_endpoint_policies)) == toset(["s3"])
    error_message = "Every configured gateway and interface endpoint must select an explicit endpoint policy."
  }

  assert {
    condition     = output.primary.endpoint_ingress_source_count == 2 && output.primary.endpoint_ingress_public_cidr_count == 0
    error_message = "Interface endpoint ingress must allow only application task groups, with no public CIDRs."
  }
}

run "sqs_transport_adds_only_sqs_endpoint" {
  command = plan

  variables {
    nat_gateway_mode       = "single"
    audit_stream_transport = "sqs_fifo"
    internal_tls           = { enabled = true, namespace = "internal.example.com" }
  }

  assert {
    condition = toset(keys(output.primary.interface_endpoint_private_dns)) == toset([
      "ecr_api",
      "ecr_dkr",
      "kms",
      "logs",
      "secretsmanager",
      "sqs",
      "sts",
    ])
    error_message = "SQS mode must add only the SQS endpoint to the six always-on interface endpoints."
  }

  assert {
    condition     = !contains(keys(output.primary.vpc_endpoint_ids), "kinesis") && !contains(keys(output.primary.vpc_endpoint_ids), "dynamodb")
    error_message = "Kinesis and DynamoDB endpoints must remain absent without confirmed runtime dependencies."
  }

  assert {
    condition     = toset(keys(output.primary.interface_endpoint_policies)) == toset(keys(output.primary.interface_endpoint_private_dns))
    error_message = "The conditional SQS endpoint must also select an explicit endpoint policy."
  }

  assert {
    condition     = toset(keys(output.primary.application_task_role_arns)) == toset(["agent", "audit_consumer", "audit_producer", "backend", "console", "gateway", "opa", "presidio"])
    error_message = "Every application service must have a separated task role."
  }
}

run "sqs_transport_rejects_plaintext_producer" {
  command = plan

  variables {
    audit_stream_transport = "sqs_fifo"
  }

  expect_failures = [var.audit_stream_transport]
}

run "approved_runtime_arn_allowlists_plan" {
  command = plan

  variables {
    runtime_s3_bucket_arns = {
      backend = ["arn:aws:s3:::authclaw-test-documents"]
      agent   = ["arn:aws:s3:::approved-customer-evidence"]
    }
    runtime_kms_key_arns = {
      backend = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000010"]
      agent   = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000011"]
    }
    runtime_secrets_manager_secret_arns = {
      agent = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:authclaw/customer/test"]
    }
    runtime_sts_assume_role_arns = [
      "arn:aws:iam::210987654321:role/AuthClawReadOnlyConnector",
    ]
    vpc_endpoint_external_principal_arns = [
      "arn:aws:iam::210987654321:role/AuthClawReadOnlyConnector",
    ]
  }

  assert {
    condition     = toset(keys(output.primary.application_task_role_arns)) == toset(["agent", "audit_consumer", "backend", "console", "gateway", "opa", "presidio"])
    error_message = "Approved runtime allowlists must plan with all separated application task roles."
  }
}

run "per_az_nat_for_production" {
  command = plan

  variables {
    nat_gateway_mode = "per_az"
  }

  assert {
    condition     = length(output.primary.nat_gateway_ids) == 2
    error_message = "Per-AZ mode must create one NAT gateway per configured Availability Zone."
  }

  assert {
    condition     = output.primary.private_route_nat_keys == { "0" = "0", "1" = "1" }
    error_message = "Per-AZ routes must use the NAT gateway with the matching subnet key."
  }

  assert {
    condition = output.primary.nat_gateway_azs == {
      "0" = "us-east-1a"
      "1" = "us-east-1b"
    }
    error_message = "NAT gateway keys must preserve the configured Availability Zone mapping."
  }
}
