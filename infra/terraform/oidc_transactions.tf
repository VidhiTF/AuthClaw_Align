removed {
  from = random_password.oidc_bff_exchange
  lifecycle {
    destroy = false
  }
}

variable "oidc_login_paused" {
  type        = bool
  default     = true
  description = "Pause new SSO logins until every console/backend has completed the coordinated cutover."
}
