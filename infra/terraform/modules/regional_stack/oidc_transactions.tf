variable "oidc_bff_exchange_secret" {
  description = "Deprecated: provision the secret externally; values must not enter Terraform."
  type        = string
  default     = null
  sensitive   = true
  validation {
    condition     = var.oidc_bff_exchange_secret == null || var.oidc_bff_exchange_secret == ""
    error_message = "Secret values must be supplied by the external provisioner, not Terraform variables."
  }
}

variable "oidc_login_paused" {
  type        = bool
  default     = true
  description = "Keep new SSO logins paused until the approved drain/cutover is complete."
}

removed {
  from = random_password.oidc_bff_exchange
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "oidc_bff_exchange" {
  name       = "${var.name}/oidc-bff-exchange"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.oidc_bff_exchange
  lifecycle {
    destroy = false
  }
}
