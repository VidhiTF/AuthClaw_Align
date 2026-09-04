resource "random_password" "worker_token_hmac" {
  length  = 48
  special = false
}

variable "worker_token_issuance_paused" {
  type        = bool
  default     = true
  description = "Keep issuance paused until the 32-minute database cutover gate has passed."
}
