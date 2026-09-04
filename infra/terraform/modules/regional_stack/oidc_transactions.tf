variable "oidc_bff_exchange_secret" {
  type      = string
  sensitive = true
  default   = null
}

variable "oidc_login_paused" {
  type        = bool
  default     = true
  description = "Keep new SSO logins paused until the approved drain/cutover is complete."
}

resource "random_password" "oidc_bff_exchange" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "oidc_bff_exchange" {
  name       = "${var.name}/oidc-bff-exchange"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "oidc_bff_exchange" {
  secret_id     = aws_secretsmanager_secret.oidc_bff_exchange.id
  secret_string = coalesce(var.oidc_bff_exchange_secret, random_password.oidc_bff_exchange.result)
}
