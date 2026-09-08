variable "kms_break_glass_role_arns" {
  description = "Organization-approved emergency roles. Empty disables scheduling key deletion through this policy."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([for arn in var.kms_break_glass_role_arns :
      can(regex("^arn:aws:iam::[0-9]{12}:role/[^*?]+$", arn))
    ])
    error_message = "Break-glass identities must be exact role ARNs."
  }
}

resource "aws_kms_key_policy" "main" {
  key_id = aws_kms_key.main.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountIAM"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.iam_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      merge({
        Sid       = "RequireApprovedEmergencyRoleForDisablingOrDeleting"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["kms:DisableKey", "kms:ScheduleKeyDeletion"]
        Resource  = "*"
        }, length(var.kms_break_glass_role_arns) == 0 ? {} : {
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = var.kms_break_glass_role_arns } }
      })
    ]
  })
}
