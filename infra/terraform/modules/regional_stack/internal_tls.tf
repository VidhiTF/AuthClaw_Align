variable "internal_tls" {
  description = "Runtime PEM secrets use certificates trusted by application system CAs, with service.namespace SANs."
  type = object({
    enabled     = optional(bool, false)
    namespace   = optional(string, "")
    proxy_image = optional(string, "nginxinc/nginx-unprivileged@sha256:9b87ad3dd9f431c733f19dfb278c7eb3dba9dca381942c79818bb42f1a566a83")
  })
  default = {}
  validation {
    condition = !var.internal_tls.enabled || (
      can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.internal_tls.namespace)) &&
      can(regex("@sha256:[0-9a-f]{64}$", var.internal_tls.proxy_image))
    )
    error_message = "TLS requires a DNS namespace matching issued certificates and an immutable proxy image."
  }
}

locals {
  tls_services  = var.internal_tls.enabled ? toset(keys(local.service_configs)) : toset([])
  service_ports = { for name, config in local.service_configs : name => contains(local.tls_services, name) ? 8443 : config.container_port }
  internal_urls = { for name, port in local.service_ports : name => "${contains(local.tls_services, name) ? "https" : "http"}://${name}.${local.namespace_name}:${port}" }
  tls_secrets = { for name in local.tls_services : name => [
    { name = "TLS_CERT_PEM", valueFrom = aws_secretsmanager_secret.tls["${name}/cert"].arn },
    { name = "TLS_KEY_PEM", valueFrom = aws_secretsmanager_secret.tls["${name}/key"].arn }
  ] }
  tls_containers = { for name in local.tls_services : name => {
    name              = "tls"
    image             = var.internal_tls.proxy_image
    user              = "101"
    essential         = true
    memoryReservation = 32
    memory            = 128
    portMappings      = [{ containerPort = 8443, protocol = "tcp" }]
    entryPoint        = ["/bin/sh", "-ec"]
    command           = [file("${path.module}/tls-entrypoint.sh")]
    secrets           = local.tls_secrets[name]
    environment       = [{ name = "TLS_CONFIG", value = templatefile("${path.module}/tls-nginx.conf.tftpl", { port = local.service_configs[name].container_port }) }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.service[name].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "tls"
      }
    }
  } }
}

resource "aws_secretsmanager_secret" "tls" {
  for_each                = toset(flatten([for name in local.tls_services : ["${name}/cert", "${name}/key"]]))
  name                    = "${var.name}/tls/${each.key}"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 30
  tags                    = var.tags
}
