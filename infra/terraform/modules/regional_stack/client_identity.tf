variable "bff_client_ip_secret" {
  description = "Deprecated: provision the secret externally; values must not enter Terraform."
  type        = string
  default     = null
  sensitive   = true
  validation {
    condition     = var.bff_client_ip_secret == null || var.bff_client_ip_secret == ""
    error_message = "Secret values must be supplied by the external provisioner, not Terraform variables."
  }
}

variable "forwarded_header_mode" {
  description = "Client identity rollout: compare first, enforce after hop validation; off restores socket peers."
  type        = string
  default     = "compare"
  validation {
    condition     = contains(["off", "compare", "enforce"], var.forwarded_header_mode)
    error_message = "forwarded_header_mode must be off, compare, or enforce."
  }
}

variable "bff_client_ip_enabled" {
  description = "Enable signed console login client identity after backend verifier deployment."
  type        = bool
  default     = false
}

variable "bff_client_ip_signing_enabled" {
  description = "Enable console emission after backend verification is rolled out."
  type        = bool
  default     = false
}

removed {
  from = random_password.bff_client_ip
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "bff_client_ip" {
  name       = "${var.name}/bff-client-ip"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.bff_client_ip
  lifecycle {
    destroy = false
  }
}

# Only ALB nodes can reach the console. This is the prerequisite for trusting
# the final address appended by ALB, rather than arbitrary inbound XFF values.
resource "aws_security_group" "console_ingress" {
  name        = "${var.name}-console-ingress"
  description = "Console ingress exclusively from ALB"
  vpc_id      = aws_vpc.main.id
  ingress {
    description     = "ALB console listener"
    from_port       = local.service_ports.console
    to_port         = local.service_ports.console
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description = "Backend via public TLS ALB and identity providers"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    #trivy:ignore:AVD-AWS-0104 Console requires outbound backend and identity-provider access through NAT.
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = var.tags
}

output "client_identity" {
  value = {
    console_alb_only      = one(aws_security_group.console_ingress.ingress).security_groups == toset([aws_security_group.alb.id])
    console_task_isolated = one(aws_ecs_service.public["console"].network_configuration).security_groups == toset([aws_security_group.console_ingress.id])
    proxy_mode            = var.forwarded_header_mode
    verifier_enabled      = var.bff_client_ip_enabled
    signing_enabled       = var.bff_client_ip_signing_enabled
  }
}
