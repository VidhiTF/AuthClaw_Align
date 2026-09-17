variable "direct_aws" {
  description = "Opt-in exact resources only. Agent secret metadata is externally provisioned; customer inventory uses STS."
  type = object({
    backend_kms_versions    = optional(map(string), {})
    agent_kms_key           = optional(string, "")
    agent_previous_kms_keys = optional(set(string), [])
    agent_secrets           = optional(map(string), {})
    agent_secret_kms_keys   = optional(set(string), [])
    agent_s3_buckets        = optional(set(string), [])
    agent_s3_objects        = optional(set(string), [])
    document_role_arn       = optional(string, "")
    document_external_id    = optional(string, "")
  })
  default = {}
  validation {
    condition = alltrue(concat(
      [for arn in concat(values(var.direct_aws.backend_kms_versions), var.direct_aws.agent_kms_key == "" ? [] : [var.direct_aws.agent_kms_key], tolist(var.direct_aws.agent_previous_kms_keys), tolist(var.direct_aws.agent_secret_kms_keys)) : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[^*?]+$", arn))],
      [for arn in values(var.direct_aws.agent_secrets) : can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[^*?]+$", arn))],
      [for arn in var.direct_aws.agent_s3_buckets : can(regex("^arn:aws:s3:::[^/*?]+$", arn))],
      [for arn in var.direct_aws.agent_s3_objects : can(regex("^arn:aws:s3:::[^/*?]+/[^*?]+$", arn))],
      [for version in keys(var.direct_aws.backend_kms_versions) : can(regex("^v[1-9][0-9]*$", version))]
    ))
    error_message = "Direct AWS access requires exact key, secret, bucket and object ARNs and versioned key names."
  }
  validation {
    condition     = alltrue([for arn in concat(values(var.direct_aws.backend_kms_versions), values(var.direct_aws.agent_secrets), var.direct_aws.agent_kms_key == "" ? [] : [var.direct_aws.agent_kms_key], tolist(var.direct_aws.agent_previous_kms_keys), tolist(var.direct_aws.agent_secret_kms_keys)) : try(split(":", arn)[3], "") == var.region])
    error_message = "Direct KMS and Secrets Manager resources must match the task's AWS region."
  }
  validation {
    condition     = var.direct_aws.document_role_arn == "" || contains(var.agent_customer_role_arns, var.direct_aws.document_role_arn)
    error_message = "The document connector role must be in the approved customer role allowlist."
  }
}

resource "aws_secretsmanager_secret" "wrapped_key" {
  for_each   = var.direct_aws.backend_kms_versions
  name       = "${var.name}/kms-wrapped-data-key/${each.key}"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

locals {
  backend_kms_enabled = length(var.direct_aws.backend_kms_versions) > 0
  backend_kms_environment = concat(
    # Shared gateway records must remain env envelopes; KMS enables retained backend-only reads.
    [{ name = "AUTHCLAW_SECRET_PROVIDER", value = "env" }],
    [for version, arn in var.direct_aws.backend_kms_versions : { name = "AUTHCLAW_AWS_KMS_KEY_ID_${upper(version)}", value = arn }]
  )
  backend_kms_secrets = [for version, secret in aws_secretsmanager_secret.wrapped_key : {
    name = "AWS_KMS_ENCRYPTED_DATA_KEY_${upper(version)}", valueFrom = secret.arn
  }]
  agent_aws_environment = [
    { name = "AUTHCLAW_SECRET_BACKEND", value = "ecs_injected" },
    { name = "AUTHCLAW_AWS_SECRET_ARNS", value = jsonencode(var.direct_aws.agent_secrets) },
    { name = "AUTHCLAW_ENVELOPE_PROVIDER", value = var.direct_aws.agent_kms_key == "" ? "" : "aws_kms" },
    { name = "AUTHCLAW_AWS_KMS_KEY_ID", value = var.direct_aws.agent_kms_key },
    { name = "AUTHCLAW_AWS_ROLE_ARN", value = var.direct_aws.document_role_arn },
    { name = "AUTHCLAW_AWS_EXTERNAL_ID", value = var.direct_aws.document_external_id }
  ]
  backend_kms_statements = [for statement in [{
    Effect = "Allow", Action = ["kms:Decrypt"], Resource = values(var.direct_aws.backend_kms_versions)
  }] : statement if local.backend_kms_enabled]
  direct_aws_statements = {
    database_crypto_preflight = local.backend_kms_statements
    backend = concat(local.backend_kms_statements, [for statement in [{
      Effect    = "Allow", Action = ["s3:GetObject", "s3:DeleteObject"],
      Resource  = local.backend_evidence_deletion_statement.Resource
      Condition = { Bool = { "aws:SecureTransport" = "true" } }
    }] : statement if length(local.backend_evidence_deletion_statement.Resource) > 0])
    agent = concat(
      [for statement in [{
        Effect    = "Allow", Action = ["kms:GenerateDataKey"], Resource = [var.direct_aws.agent_kms_key]
        Condition = { StringEquals = { "kms:EncryptionContext:authclaw:purpose" = "database-field" } }
        }, {
        Effect    = "Allow", Action = ["kms:Decrypt"], Resource = concat([var.direct_aws.agent_kms_key], tolist(var.direct_aws.agent_previous_kms_keys))
        Condition = { StringEquals = { "kms:EncryptionContext:authclaw:purpose" = "database-field" } }
      }] : statement if var.direct_aws.agent_kms_key != ""],
      [for statement in [{
        Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:DeleteSecret"], Resource = values(var.direct_aws.agent_secrets)
      }] : statement if length(var.direct_aws.agent_secrets) > 0],
      [for statement in [{
        Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.direct_aws.agent_secret_kms_keys
        Condition = { StringEquals = {
          "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
          "kms:EncryptionContext:SecretARN" = values(var.direct_aws.agent_secrets)
        } }
      }] : statement if length(var.direct_aws.agent_secret_kms_keys) > 0 && length(var.direct_aws.agent_secrets) > 0],
      [for statement in [{
        Effect = "Allow", Action = ["s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration", "s3:GetBucketVersioning", "s3:GetBucketLogging", "s3:GetBucketPolicyStatus"], Resource = var.direct_aws.agent_s3_buckets
      }] : statement if length(var.direct_aws.agent_s3_buckets) > 0],
      [for statement in [{
        Effect = "Allow", Action = ["s3:GetObject"], Resource = var.direct_aws.agent_s3_objects
      }] : statement if length(var.direct_aws.agent_s3_objects) > 0]
    )
  }
}
