removed {
  from = random_password.worker_token_hmac
  lifecycle {
    destroy = false
  }
}

variable "worker_token_issuance_paused" {
  type        = bool
  default     = true
  description = "Keep issuance paused until the 32-minute database cutover gate has passed."
}
