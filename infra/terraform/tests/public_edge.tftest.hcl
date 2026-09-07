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
  aws_account_id             = "123456789012"
  environment                = "edge-test"
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
  enable_public_edge             = true
  hosted_zone_id                 = "Z1234567890"
  edge_certificate_arn           = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000010"
  primary_certificate_arn        = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000011"
  edge_alarm_action_arns         = ["arn:aws:sns:us-east-1:123456789012:authclaw-edge-alerts"]
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

run "staging_has_one_documented_edge_per_public_hostname" {
  command = plan

  variables {
    authclaw_env = "staging"
  }

  assert {
    condition = output.public_edge.domains == {
      marketing = "dev.authclaw.ai"
      www       = ""
      console   = "dev.authclaw.ai"
      api       = "api.dev.authclaw.ai"
      gateway   = "gateway.dev.authclaw.ai"
    }
    error_message = "Staging must use only the ADR-0002 hostnames."
  }

  assert {
    condition     = toset(keys(output.public_edge.distribution_ids)) == toset(["console", "api", "gateway"])
    error_message = "Staging must use its combined marketing/console edge plus separate API and gateway edges."
  }

  assert {
    condition     = output.public_edge.primary_origin_boundary.public_cidr_rule_count == 0
    error_message = "Private origins must not accept any public CIDR."
  }

  assert {
    condition     = output.public_edge.primary_origin_boundary.prefix_list_rule_count == 1
    error_message = "Private origins must accept only the CloudFront origin-facing prefix list."
  }

  assert {
    condition     = length(output.public_edge.primary_origin_boundary.listener_ports) == 1 && contains(output.public_edge.primary_origin_boundary.listener_ports, 443)
    error_message = "Every private origin must expose only HTTPS port 443."
  }

  assert {
    condition = output.public_edge.runtime_url_boundary == {
      console_url       = "https://dev.authclaw.ai"
      api_url           = "https://api.dev.authclaw.ai/api/v1"
      gateway_url       = "https://gateway.dev.authclaw.ai"
      cors_origins      = ["https://dev.authclaw.ai"]
      oidc_redirect_uri = "https://dev.authclaw.ai/api/auth/oidc/callback"
      cookie_secure     = true
      cookie_domain     = null
    }
    error_message = "Staging runtime URLs, CORS, callback, and cookie boundary must be exact."
  }
}

run "production_domains_and_distributions_are_isolated" {
  command = plan

  variables {
    public_url_environment = "production"
  }

  assert {
    condition = output.public_edge.domains == {
      marketing = "authclaw.ai"
      www       = "www.authclaw.ai"
      console   = "app.authclaw.ai"
      api       = "api.authclaw.ai"
      gateway   = "gateway.authclaw.ai"
    }
    error_message = "Production must use only the ADR-0002 hostnames."
  }

  assert {
    condition     = toset(keys(output.public_edge.distribution_ids)) == toset(["marketing", "console", "api", "gateway"])
    error_message = "Production marketing, console, API, and gateway must have explicit distribution boundaries."
  }


  assert {
    condition = output.public_edge.runtime_url_boundary == {
      console_url       = "https://app.authclaw.ai"
      api_url           = "https://api.authclaw.ai/api/v1"
      gateway_url       = "https://gateway.authclaw.ai"
      cors_origins      = ["https://app.authclaw.ai"]
      oidc_redirect_uri = "https://app.authclaw.ai/api/auth/oidc/callback"
      cookie_secure     = true
      cookie_domain     = null
    }
    error_message = "Production runtime URLs, CORS, callback, and cookie boundary must be exact."
  }
}

run "production_rejects_a_missing_public_edge" {
  command = plan

  variables {
    public_url_environment = "production"
    enable_public_edge     = false
  }

  expect_failures = [terraform_data.production_edge_required]
}

run "prod_environment_rejects_a_missing_public_edge" {
  command = plan

  variables {
    environment        = "prod"
    enable_public_edge = false
  }

  expect_failures = [terraform_data.production_edge_required]
}

run "prod_runtime_rejects_a_missing_public_edge" {
  command = plan

  variables {
    authclaw_env       = "prod"
    enable_public_edge = false
  }

  expect_failures = [terraform_data.production_edge_required]
}
