variable "agent_customer_role_arns" {
  description = "Approved customer roles used by agent connectors/remediation. No ambient customer-cloud grants."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([for arn in var.agent_customer_role_arns :
      can(regex("^arn:aws:iam::[0-9]{12}:role/[^*?]+$", arn))
    ])
    error_message = "Customer roles must be exact IAM role ARNs, without wildcards."
  }
}

resource "aws_iam_role" "runtime" {
  for_each             = toset(concat(keys(local.service_configs), ["audit_consumer"], local.backend_kms_enabled ? ["database_crypto_preflight"] : []))
  name                 = "${var.name}-${replace(each.key, "_", "-")}-runtime"
  permissions_boundary = var.iam_permissions_boundary_arn
  assume_role_policy   = try(aws_iam_role.task_execution[each.key].assume_role_policy, aws_iam_role.task_execution["backend"].assume_role_policy)
  tags                 = var.tags
}

# Runtime credentials must never retrieve deployment/database credentials.
# Injected secrets are read by ECS using the independent execution role.
resource "aws_iam_role_policy" "runtime" {
  for_each = aws_iam_role.runtime
  role     = each.value.id
  name     = "runtime-boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Effect   = "Deny"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = distinct(flatten(values(local.execution_secret_arns)))
      }, {
      Effect   = "Deny"
      Action   = ["secretsmanager:BatchGetSecretValue"]
      Resource = "*"
      }], [for statement in [{
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.agent_customer_role_arns
      }] : statement if each.key == "agent" && length(var.agent_customer_role_arns) > 0],
      lookup(local.direct_aws_statements, each.key == "database_crypto_preflight" ? "backend" : each.key, [])
    )
  })
}

output "runtime_iam_review" {
  value = {
    roles              = keys(aws_iam_role.runtime)
    customer_roles     = var.agent_customer_role_arns
    direct_permissions = local.direct_aws_statements
    internal_urls      = local.internal_urls
    tls_services       = local.tls_services
    sidecars_isolated = alltrue([for name in ["opa", "presidio"] :
      aws_ecs_service.private[name].task_definition == aws_ecs_task_definition.service[name].arn
    ])
  }
}
