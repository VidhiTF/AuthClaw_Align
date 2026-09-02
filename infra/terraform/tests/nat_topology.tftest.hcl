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
    condition     = toset(keys(output.primary.gateway_endpoint_route_table_ids)) == toset(["s3", "dynamodb"])
    error_message = "S3 and DynamoDB gateway endpoints must both exist."
  }

  assert {
    condition     = alltrue([for count in values(output.primary.gateway_endpoint_route_table_count) : count == 2])
    error_message = "Gateway endpoints must attach to every private route table."
  }

  assert {
    condition     = length(output.primary.interface_endpoint_private_dns) == 5 && alltrue(values(output.primary.interface_endpoint_private_dns))
    error_message = "All five interface endpoints must enable private DNS."
  }

  assert {
    condition     = output.primary.endpoint_ingress_source_count == 1 && output.primary.endpoint_ingress_public_cidr_count == 0
    error_message = "Interface endpoint ingress must have one security-group source and no public CIDRs."
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
