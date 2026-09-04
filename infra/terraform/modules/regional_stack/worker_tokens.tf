variable "worker_token_hmac_secret" {
  type      = string
  sensitive = true
  default   = null
  validation {
    condition     = var.worker_token_hmac_secret == null || var.worker_token_hmac_secret == ""
    error_message = "Provision worker HMAC values externally, not through Terraform state."
  }
}

variable "worker_token_issuance_paused" {
  type    = bool
  default = true
}

removed {
  from = random_password.worker_token_hmac
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "worker_token_hmac" {
  name       = "${var.name}/worker-token-hmac-v1"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.worker_token_hmac
  lifecycle {
    destroy = false
  }
}
