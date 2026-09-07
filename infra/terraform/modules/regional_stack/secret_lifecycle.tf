# Values are provisioned outside Terraform. Never add secret-version data sources.
resource "aws_secretsmanager_secret" "additional" {
  for_each                = toset(concat(["platform_auth_database_url"], var.smtp_host != "" ? ["smtp_username", "smtp_password"] : []))
  name                    = "${var.name}/${replace(each.key, "_", "-")}"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 30
  tags                    = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

output "required_secret_arns" {
  description = "External provisioner must populate AWSCURRENT before starting database jobs or services."
  value       = distinct(flatten(values(local.execution_secret_arns)))
}

# Retain old task definitions for explicitly reviewed rollback, without deploying them.
removed {
  from = aws_ecs_task_definition.gateway_with_sidecars
  lifecycle { destroy = false }
}
removed {
  from = aws_ecs_task_definition.backend_with_presidio
  lifecycle { destroy = false }
}
removed {
  from = aws_ecs_task_definition.agent_with_opa
  lifecycle { destroy = false }
}
