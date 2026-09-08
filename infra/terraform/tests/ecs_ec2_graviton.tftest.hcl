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
  authclaw_env               = "ci"
  project                    = "authclaw-test"
  environment                = "test"
  primary_region             = "us-east-1"
  secondary_region           = "us-west-2"
  primary_availability_zones = ["us-east-1a", "us-east-1b"]
  ci_skip_aws_validation     = true
  enable_secondary           = false
  primary_certificate_arn    = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000000"
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

run "fargate_remains_default" {
  command = plan

  assert {
    condition     = output.primary.ecs_launch_model.mode == "FARGATE"
    error_message = "P0-05 must be disabled by default."
  }

  assert {
    condition     = output.primary.ecs_launch_model.task_compatibilities == ["FARGATE"]
    error_message = "Default task definitions must remain Fargate compatible."
  }

  assert {
    condition     = output.primary.ecs_launch_model.capacity_provider_name == null
    error_message = "Default plans must not create the EC2 capacity provider."
  }

  assert {
    condition     = output.crypto_preflight.launch_model.mode == "FARGATE"
    error_message = "Database one-off tasks must inherit the default Fargate launch model."
  }
}

run "ec2_graviton_capacity_provider" {
  command = plan

  variables {
    ecs_ec2_graviton = {
      enabled           = true
      instance_type     = "m7g.large"
      min_size          = 2
      desired_size      = 3
      max_size          = 5
      image_id          = "ami-0123456789abcdef0"
      root_volume_size  = 80
      alarm_action_arns = ["arn:aws:sns:us-east-1:123456789012:platform-alerts"]
    }
  }

  assert {
    condition     = output.primary.ecs_launch_model.mode == "EC2_GRAVITON"
    error_message = "Enabling P0-05 must switch the launch model to EC2 Graviton."
  }

  assert {
    condition     = output.primary.ecs_launch_model.task_compatibilities == ["EC2"]
    error_message = "P0-05 task definitions must require EC2 compatibility."
  }

  assert {
    condition     = alltrue([for architecture in values(output.primary.ecs_launch_model.runtime_architectures) : architecture == "ARM64"])
    error_message = "P0-05 must run all ECS services as ARM64."
  }

  assert {
    condition     = output.primary.ecs_launch_model.asg_min_size == 2 && output.primary.ecs_launch_model.asg_desired_size == 3 && output.primary.ecs_launch_model.asg_max_size == 5
    error_message = "P0-05 ASG capacity must use the measured reservation and headroom inputs."
  }

  assert {
    condition     = output.primary.ecs_launch_model.capacity_provider_name == "authclaw-test-test-primary-graviton"
    error_message = "P0-05 must create the expected ECS capacity provider."
  }

  assert {
    condition     = output.crypto_preflight.launch_model.capacity_provider_name == output.primary.ecs_launch_model.capacity_provider_name
    error_message = "Database one-off tasks must use the selected Graviton capacity provider."
  }

  assert {
    condition     = !output.primary.ecs_launch_model.x86_provider_enabled
    error_message = "The P0-05 x86 capacity-provider decision must default to false."
  }

  assert {
    condition     = output.primary.ecs_launch_model.awsvpc_block_imds
    error_message = "EC2-backed awsvpc tasks must be blocked from instance metadata credentials."
  }

  assert {
    condition = alltrue([
      contains(output.primary.alarm_names, "authclaw-test-test-primary-ecs-graviton-capacity-reservation"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-ecs-graviton-instance-health"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-ecs-placement-failure"),
      contains(output.primary.alarm_names, "authclaw-test-test-primary-gateway-pending-tasks"),
    ])
    error_message = "P0-05 must add cluster-capacity, instance-health, placement-failure, and pending-task alarms."
  }
}

run "ec2_graviton_defaults_have_capacity" {
  command = plan

  variables {
    ecs_ec2_graviton = {
      enabled  = true
      image_id = "ami-0123456789abcdef0"
    }
  }

  assert {
    condition     = var.ecs_ec2_graviton.instance_type == "m7g.2xlarge"
    error_message = "The default Graviton instances must fit the default ECS service CPU footprint."
  }
}
