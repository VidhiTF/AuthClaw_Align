locals {
  ecr_services = toset([
    "agent",
    "audit-consumer",
    "backend",
    "console",
    "gateway",
    "opa-bundle",
    "presidio",
  ])
}

resource "aws_kms_key" "registry" {
  provider                = aws.primary
  description             = "AuthClaw ${var.environment} container registry encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "registry" {
  provider      = aws.primary
  name          = "alias/${var.project}-${var.environment}-ecr"
  target_key_id = aws_kms_key.registry.key_id
}

resource "aws_ecr_repository" "service" {
  provider             = aws.primary
  for_each             = local.ecr_services
  name                 = "${var.project}-${var.environment}/${each.key}"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.registry.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "service" {
  provider   = aws.primary
  for_each   = aws_ecr_repository.service
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the latest 30 controlled-beta builds"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 30
      }
      action = { type = "expire" }
    }]
  })
}
