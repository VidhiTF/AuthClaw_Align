variable "iam_account_id" {
  type    = string
  default = null
}
data "aws_caller_identity" "tasks" {
  count = var.iam_account_id == null ? 1 : 0
}

locals {
  iam_account_id = var.iam_account_id == null ? data.aws_caller_identity.tasks[0].account_id : var.iam_account_id
  execution_tasks = merge(
    { for name, config in local.task_definition_configs : name => {
      secrets = concat(local.service_secrets[name], lookup(local.tls_secrets, name, []))
      images  = concat([config.image], contains(local.tls_services, name) ? [var.internal_tls.proxy_image] : [])
      logs    = [aws_cloudwatch_log_group.service[name].arn]
    } },
    { for name, config in local.database_jobs : "database_${name}" => {
      secrets = config.secrets
      images  = [config.image]
      logs    = [aws_cloudwatch_log_group.database_job[name].arn]
    } },
    var.enable_audit_consumer ? { audit_consumer = {
      secrets = local.audit_consumer_secrets
      images  = [var.container_images.audit_consumer]
      logs    = [aws_cloudwatch_log_group.service["audit_consumer"].arn]
    } } : {}
  )
  execution_secret_arns = { for name, config in local.execution_tasks : name => distinct([for secret in config.secrets : secret.valueFrom]) }
  execution_ecr_arns = { for name, config in local.execution_tasks : name => distinct(flatten([
    for image in config.images : [for parts in regexall("^([0-9]{12})\\.dkr\\.ecr\\.([a-z0-9-]+)\\.amazonaws\\.com/([^:@]+)", image) :
      "arn:aws:ecr:${parts[1]}:${parts[0]}:repository/${parts[2]}"
    ]
  ])) }
}

resource "aws_iam_role" "task_execution" {
  for_each             = local.execution_tasks
  name                 = "${var.name}-${replace(each.key, "_", "-")}-exec"
  permissions_boundary = var.iam_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.iam_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.region}:${local.iam_account_id}:*" }
      }
    }]
  })
  tags = var.tags
}

variable "iam_permissions_boundary_arn" {
  type        = string
  default     = null
  description = "Optional organization-approved permissions boundary; no policy is invented by this module."
}

output "execution_iam_review" {
  description = "Value-free task secret names and rendered policies for offline and Access Analyzer review."
  value = { for name, config in local.execution_tasks : name => {
    secret_names = [for secret in config.secrets : secret.name]
    secret_arns  = local.execution_secret_arns[name]
    policy       = local.execution_policies[name]
  } }
}

resource "aws_iam_role_policy" "task_execution" {
  for_each = local.execution_tasks
  role     = aws_iam_role.task_execution[each.key].id
  name     = "task-startup"
  policy   = local.execution_policies[each.key]
}

locals {
  execution_policies = { for name, config in local.execution_tasks : name => jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [for arn in config.logs : "${arn}:*"]
      }
      ], [for statement in [
        { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
        {
          Effect   = "Allow"
          Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
          Resource = local.execution_ecr_arns[name]
        }
        ] : statement if length(local.execution_ecr_arns[name]) > 0], [for statement in [
        {
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = local.execution_secret_arns[name]
        },
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = aws_kms_key.main.arn
          Condition = {
            StringEquals = {
              "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
              "kms:EncryptionContext:SecretARN" = local.execution_secret_arns[name]
            }
          }
        }
    ] : statement if length(local.execution_secret_arns[name]) > 0])
  }) }
}
