variable "worker_token_hmac_secret" {
  type      = string
  sensitive = true
  default   = null
}

variable "worker_token_issuance_paused" {
  type    = bool
  default = true
}

resource "random_password" "worker_token_hmac" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "worker_token_hmac" {
  name       = "${var.name}/worker-token-hmac-v1"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "worker_token_hmac" {
  secret_id     = aws_secretsmanager_secret.worker_token_hmac.id
  secret_string = coalesce(var.worker_token_hmac_secret, random_password.worker_token_hmac.result)
}
