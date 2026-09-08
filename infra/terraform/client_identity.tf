removed {
  from = random_password.bff_client_ip
  lifecycle {
    destroy = false
  }
}

variable "forwarded_header_mode" {
  description = "Trusted proxy rollout mode: off, compare, or enforce."
  type        = string
  default     = "compare"
  validation {
    condition     = contains(["off", "compare", "enforce"], var.forwarded_header_mode)
    error_message = "forwarded_header_mode must be off, compare, or enforce."
  }
}

variable "bff_client_ip_enabled" {
  description = "Enable signed console login identity after the verifier is deployed."
  type        = bool
  default     = false
}

variable "bff_client_ip_signing_enabled" {
  description = "Enable console signing only after all backend tasks accept signed context."
  type        = bool
  default     = false
}
