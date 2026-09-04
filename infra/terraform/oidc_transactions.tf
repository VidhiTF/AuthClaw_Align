resource "random_password" "oidc_bff_exchange" {
  length  = 48
  special = false
}

variable "oidc_login_paused" {
  type        = bool
  default     = true
  description = "Pause new SSO logins until every console/backend has completed the coordinated cutover."
}
