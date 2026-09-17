data "aws_availability_zones" "available" {
  count = length(var.availability_zones) == 0 ? 1 : 0
  state = "available"
}

data "aws_ssm_parameter" "ecs_arm64_ami" {
  count = var.ecs_ec2_graviton.enabled && var.ecs_ec2_graviton.image_id == "" ? 1 : 0
  name  = "/aws/service/ecs/optimized-ami/amazon-linux-2023/arm64/recommended/image_id"
}

locals {
  discovered_azs = length(var.availability_zones) > 0 ? var.availability_zones : data.aws_availability_zones.available[0].names
  azs            = slice(local.discovered_azs, 0, var.az_count)
  az_map         = { for idx, az in local.azs : tostring(idx) => az }
  runtime_architectures = var.ecs_ec2_graviton.enabled ? {
    agent          = "ARM64"
    backend        = "ARM64"
    gateway        = "ARM64"
    console        = "ARM64"
    audit_consumer = "ARM64"
    audit_producer = "ARM64"
    opa            = "ARM64"
    presidio       = "ARM64"
    } : merge({
      agent          = "X86_64"
      backend        = "X86_64"
      gateway        = "X86_64"
      console        = "X86_64"
      audit_consumer = "X86_64"
      audit_producer = "X86_64"
      opa            = "X86_64"
      presidio       = "X86_64"
      }, var.service_cpu_architectures, {
      # The producer reuses the exact gateway image digest.
      audit_producer = lookup(var.service_cpu_architectures, "gateway", "X86_64")
  })
  ecs_launch_compatibilities = var.ecs_ec2_graviton.enabled ? ["EC2"] : ["FARGATE"]
  ec2_capacity_provider_name = "${var.name}-graviton"
  ec2_ami_id                 = var.ecs_ec2_graviton.enabled ? (var.ecs_ec2_graviton.image_id != "" ? var.ecs_ec2_graviton.image_id : data.aws_ssm_parameter.ecs_arm64_ami[0].value) : ""
  interface_endpoint_services = merge({
    ecr_api        = "ecr.api"
    ecr_dkr        = "ecr.dkr"
    logs           = "logs"
    secretsmanager = "secretsmanager"
    kms            = "kms"
    sts            = "sts"
  }, var.audit_stream_transport == "sqs_fifo" ? { sqs = "sqs" } : {})
  namespace_name        = var.internal_tls.enabled ? var.internal_tls.namespace : "${var.name}.local"
  listener_protocol     = "HTTPS"
  public_scheme         = "https"
  console_host          = var.enable_public_edge ? var.public_domain_names.console : (var.domain_name != "" ? var.domain_name : aws_lb.service["console"].dns_name)
  api_host              = var.enable_public_edge ? var.public_domain_names.api : (var.domain_name != "" ? var.domain_name : aws_lb.service["backend"].dns_name)
  gateway_host          = var.enable_public_edge ? var.public_domain_names.gateway : (var.domain_name != "" ? var.domain_name : aws_lb.service["gateway"].dns_name)
  console_base_url      = "${local.public_scheme}://${local.console_host}"
  api_base_url          = "${local.public_scheme}://${local.api_host}${var.enable_public_edge ? "/api/v1" : ":8000"}"
  gateway_base_url      = "${local.public_scheme}://${local.gateway_host}${var.enable_public_edge ? "" : ":8080"}"
  internal_agent_url    = local.internal_urls.agent
  internal_opa_url      = local.internal_urls.opa
  internal_presidio_url = local.internal_urls.presidio
  db_address            = var.create_db_replica ? aws_db_instance.postgres_replica[0].address : aws_db_instance.postgres_primary[0].address
  db_arn                = var.create_db_replica ? aws_db_instance.postgres_replica[0].arn : aws_db_instance.postgres_primary[0].arn
  nat_subnets           = var.nat_gateway_mode == "per_az" ? aws_subnet.public : { "0" = aws_subnet.public["0"] }

  public_services = {
    console = {
      image          = var.container_images.console
      container_port = 3001
      health_path    = "/"
      command        = null
    }
    backend = {
      image          = var.container_images.backend
      container_port = 8000
      health_path    = "/health"
      command        = null
    }
    gateway = {
      image          = var.container_images.gateway
      container_port = 8080
      health_path    = "/ready"
      command        = null
    }
  }

  private_services = merge({
    agent = {
      image          = var.container_images.agent
      container_port = 8001
      command        = null
    }
    }, var.audit_stream_transport == "sqs_fifo" ? {
    audit_producer = {
      image          = var.container_images.gateway
      container_port = 8090
      command        = ["--audit-producer"]
    }
  } : {})

  legacy_sidecar_services = {
    opa = {
      image          = var.container_images.opa
      container_port = 8181
      command        = ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]
    }
    presidio = {
      image          = var.container_images.presidio
      container_port = 3000
      command        = ["poetry", "run", "gunicorn", "-w", "1", "-b", "0.0.0.0:3000", "app:create_app()"]
    }
  }

  policy_sidecars = var.enable_policy_sidecar_colocation ? {
    agent          = []
    audit_producer = []
    backend        = []
    console        = []
    gateway        = ["opa", "presidio"]
    opa            = []
    presidio       = []
  } : { for name in concat(keys(local.public_services), keys(local.private_services), keys(local.legacy_sidecar_services)) : name => [] }
  policy_sidecar_configs = {
    opa = {
      image         = var.container_images.opa
      cpu           = 256
      memory        = 384
      command       = ["run", "--server", "--addr=127.0.0.1:8181", "/policies"]
      port_mappings = []
    }
    presidio = {
      image         = var.container_images.presidio
      cpu           = 768
      memory        = 2048
      command       = ["poetry", "run", "gunicorn", "-w", "1", "-b", "127.0.0.1:3000", "app:create_app()"]
      port_mappings = []
    }
  }
  policy_environment = [
    { name = "OPA_URL", value = local.internal_opa_url },
    { name = "PRESIDIO_URL", value = local.internal_presidio_url },
    { name = "AUTHCLAW_OPA_POLICY_URL", value = "${local.internal_opa_url}/v1/data/authclaw/policy/decision" },
  ]
  service_policy_environment = var.enable_policy_sidecar_colocation ? {
    agent          = local.policy_environment
    audit_producer = []
    backend        = local.policy_environment
    console        = local.policy_environment
    gateway = [
      { name = "OPA_URL", value = "http://127.0.0.1:8181" },
      { name = "PRESIDIO_URL", value = "http://127.0.0.1:3000" },
      { name = "AUTHCLAW_OPA_POLICY_URL", value = "http://127.0.0.1:8181/v1/data/authclaw/policy/decision" },
    ]
    opa      = local.policy_environment
    presidio = local.policy_environment
  } : { for name in keys(local.service_configs) : name => local.policy_environment }
  colocated_task_cpu = {
    agent = var.agent_sidecar_task_cpu, backend = var.backend_sidecar_task_cpu, gateway = var.gateway_sidecar_task_cpu
  }
  colocated_task_memory = {
    agent = var.agent_sidecar_task_memory, backend = var.backend_sidecar_task_memory, gateway = var.gateway_sidecar_task_memory
  }
  colocated_primary_cpu    = { agent = 768, backend = 768, gateway = 768 }
  colocated_primary_memory = { agent = 1536, backend = 1536, gateway = 1280 }

  service_configs = merge(
    local.public_services,
    local.private_services,
    local.legacy_sidecar_services,
  )
  task_definition_configs = local.service_configs
  ecs_alarm_services      = toset(concat(keys(local.service_configs), var.enable_audit_consumer ? ["audit_consumer"] : []))
  ecs_service_desired_counts = merge(
    { for name in keys(local.service_configs) : name => var.desired_count },
    var.enable_audit_consumer ? { audit_consumer = 1 } : {},
  )

  service_writable_paths = {
    agent          = ["/tmp", "/app/logs", "/app/watched_documents", "/app/scratch"]
    audit_consumer = ["/tmp"]
    audit_producer = ["/tmp"]
    backend        = ["/tmp", "/app/.authclaw"]
    console        = ["/tmp", "/app/.authclaw"]
    gateway        = ["/tmp"]
    opa            = ["/tmp"]
    presidio       = ["/tmp"]
  }
  service_health_checks = {
    agent          = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/v1/agent/health/ready', timeout=3)\""]
    audit_consumer = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:9108/metrics', timeout=3)\""]
    audit_producer = ["CMD", "/healthcheck", "http://127.0.0.1:8090/health"]
    backend        = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)\""]
    console        = ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:3001/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""]
    gateway        = ["CMD", "/healthcheck", "http://127.0.0.1:8080/health"]
    opa            = ["CMD", "/healthcheck"]
    presidio       = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/health', timeout=3)\""]
  }

  common_environment = [
    { name = "AUTHCLAW_ENV", value = var.authclaw_env },
    { name = "AUTHCLAW_EXPECTED_DB_REVISION", value = var.expected_db_revision },
    { name = "AUTHCLAW_FORWARDED_HEADER_MODE", value = var.forwarded_header_mode },
    { name = "AUTHCLAW_FORWARDED_FOR_MAX_HOPS", value = "8" },
    { name = "AUTHCLAW_TRUSTED_PROXY_CIDRS", value = join(",", values(aws_subnet.public)[*].cidr_block) },
    { name = "MFA_FAILURE_THRESHOLD", value = "5" },
    { name = "MFA_ATTEMPT_WINDOW_SECONDS", value = "300" },
    { name = "MFA_BASE_COOLDOWN_SECONDS", value = "30" },
    { name = "MFA_MAX_COOLDOWN_SECONDS", value = "300" },
    { name = "MFA_ESCALATING_COOLDOWN_ENABLED", value = "true" },
    { name = "AUTHCLAW_REQUIRE_SERVICE_TLS", value = tostring(var.authclaw_env == "production") },
    { name = "AUTHCLAW_SECRET_PROVIDER", value = "env" },
    { name = "AUTHCLAW_SECRET_KEY_VERSION", value = var.secret_key_version },
    { name = "AUTHCLAW_JWT_KEY_VERSION", value = var.jwt_key_version },
    { name = "AUTHCLAW_SESSION_KEY_VERSION", value = var.session_key_version },
    { name = "REDIS_URL", value = "rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379" },
    { name = "AUTHCLAW_RATE_LIMIT_ENABLED", value = "true" },
    { name = "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT", value = "false" },
    { name = "AUTHCLAW_RATE_LIMIT_PER_MINUTE", value = "30" },
    { name = "AUTHCLAW_RATE_LIMIT_USER_RPM", value = "20" },
    { name = "AUTHCLAW_RATE_LIMIT_KEY_RPM", value = "10" },
    { name = "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM", value = "20" },
    { name = "AGENT_INTERNAL_URL", value = local.internal_agent_url },
    { name = "AUTHCLAW_GO_GATEWAY_URL", value = local.internal_urls.gateway },
    { name = "AUTHCLAW_DISABLE_BACKGROUND_MONITOR", value = "true" },
    { name = "AWS_STS_REGIONAL_ENDPOINTS", value = "regional" },
    { name = "PUBLIC_GATEWAY_URL", value = local.gateway_base_url },
    { name = "GATEWAY_INTERNAL_URL", value = local.internal_urls.gateway },
    { name = "NEXT_PUBLIC_GATEWAY_URL", value = local.gateway_base_url },
    { name = "NEXT_PUBLIC_API_URL", value = local.api_base_url },
    { name = "PUBLIC_API_URL", value = local.api_base_url },
    { name = "NEXT_PUBLIC_CONSOLE_URL", value = local.console_base_url },
    { name = "PUBLIC_CONSOLE_URL", value = local.console_base_url },
    { name = "API_URL", value = local.internal_urls.backend },
    { name = "GATEWAY_URL", value = local.internal_urls.gateway },
    { name = "ALLOWED_ORIGINS", value = jsonencode([local.console_base_url]) },
    { name = "OIDC_REDIRECT_URI", value = "${local.console_base_url}/api/auth/oidc/callback" },
    { name = "AUTHCLAW_COOKIE_SECURE", value = "true" },
    { name = "AUTHCLAW_SESSION_COOKIE_NAME", value = var.enable_public_edge ? (var.public_url_environment == "production" ? "authclaw_session_prod" : "authclaw_session_stg") : "authclaw_session" },
    { name = "AUTHCLAW_OIDC_STATE_COOKIE_NAME", value = var.enable_public_edge ? (var.public_url_environment == "production" ? "authclaw_oidc_state_prod" : "authclaw_oidc_state_stg") : "authclaw_oidc_state" },
    { name = "DEMO_OTP_VISIBLE", value = "false" },
    { name = "SMTP_HOST", value = var.smtp_host },
    { name = "SMTP_FROM", value = var.smtp_from },
    { name = "KAFKA_BROKERS", value = var.kafka_brokers },
    { name = "CLICKHOUSE_HOST", value = var.clickhouse_host },
    { name = "CLICKHOUSE_PORT", value = tostring(var.clickhouse_port) },
    { name = "CLICKHOUSE_DB", value = var.clickhouse_db },
    { name = "CLICKHOUSE_USER", value = var.clickhouse_user }
  ]
}

resource "aws_kms_key" "main" {
  description             = "AuthClaw ${var.environment} ${var.region} encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(var.tags, { Name = "${var.name}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name}-igw" })
}

resource "aws_subnet" "public" {
  for_each = local.az_map

  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, tonumber(each.key))
  map_public_ip_on_launch = true
  tags                    = merge(var.tags, { Name = "${var.name}-public-${each.value}" })
}

resource "aws_subnet" "private" {
  for_each = local.az_map

  vpc_id            = aws_vpc.main.id
  availability_zone = each.value
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, tonumber(each.key) + 10)
  tags              = merge(var.tags, { Name = "${var.name}-private-${each.value}" })
}

resource "aws_eip" "nat" {
  for_each = local.nat_subnets

  domain = "vpc"
  tags = merge(var.tags, {
    Name             = "${var.name}-nat-eip-${each.value.availability_zone}"
    AvailabilityZone = each.value.availability_zone
    Region           = var.region
  })
}

resource "aws_nat_gateway" "main" {
  for_each = local.nat_subnets

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
  tags = merge(var.tags, {
    Name             = "${var.name}-nat-${each.value.availability_zone}"
    AvailabilityZone = each.value.availability_zone
    Region           = var.region
  })
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  for_each = aws_subnet.public

  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name}-public-rt-${each.value.availability_zone}" })
}

resource "aws_route" "public_internet" {
  for_each = aws_route_table.public

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[each.key].id
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private

  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${var.name}-private-rt-${each.value.availability_zone}" })
}

resource "aws_route" "private_nat" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[var.nat_gateway_mode == "per_az" ? each.key : "0"].id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
  depends_on     = [aws_route.private_nat]
}

moved {
  from = aws_eip.nat
  to   = aws_eip.nat["0"]
}

moved {
  from = aws_nat_gateway.main
  to   = aws_nat_gateway.main["0"]
}

moved {
  from = aws_route_table.public
  to   = aws_route_table.public["0"]
}

moved {
  from = aws_route_table.private
  to   = aws_route_table.private["0"]
}

moved {
  from = aws_route.public_internet
  to   = aws_route.public_internet["0"]
}

moved {
  from = aws_route.private_nat
  to   = aws_route.private_nat["0"]
}

resource "aws_vpc_endpoint" "gateway" {
  for_each = var.enable_private_aws_endpoints ? toset(["s3"]) : toset([])

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = values(aws_route_table.private)[*].id
  policy            = local.gateway_endpoint_policies[each.key]

  tags = merge(var.tags, { Name = "${var.name}-${each.value}-endpoint" })
}

data "aws_ec2_managed_prefix_list" "cloudfront_origin" {
  count = var.enable_public_edge ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

data "aws_partition" "current" {}

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "CloudFront-only private origin ingress"
  vpc_id      = aws_vpc.main.id

  dynamic "ingress" {
    for_each = var.enable_public_edge ? [1] : []
    content {
      description     = "HTTPS from CloudFront origin-facing network only"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront_origin[0].id]
    }
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    #trivy:ignore:AVD-AWS-0104 AuthClaw requires outbound provider/API access through NAT; app/data access is still security-group scoped inbound.
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_security_group" "app" {
  name        = "${var.name}-app"
  description = "ECS service ingress"
  vpc_id      = aws_vpc.main.id

  dynamic "ingress" {
    for_each = var.internal_tls.enabled ? toset([8443]) : toset([8000, 8001, 8080])
    content {
      description     = "Console outbound API and health-check calls"
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [aws_security_group.console_ingress.id]
    }
  }

  dynamic "ingress" {
    for_each = local.public_services
    content {
      from_port       = local.service_ports[ingress.key]
      to_port         = local.service_ports[ingress.key]
      protocol        = "tcp"
      security_groups = [aws_security_group.alb.id]
    }
  }

  dynamic "ingress" {
    for_each = toset(values(local.service_ports))
    content {
      from_port = ingress.value
      to_port   = ingress.value
      protocol  = "tcp"
      self      = true
    }
  }

  dynamic "ingress" {
    for_each = var.enable_audit_consumer ? [1] : []
    content {
      from_port = 9108
      to_port   = 9108
      protocol  = "tcp"
      self      = true
    }
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    #trivy:ignore:AVD-AWS-0104 AuthClaw services call managed providers, KMS, Secrets Manager, and telemetry endpoints through NAT.
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_private_aws_endpoints ? 1 : 0

  name        = "${var.name}-vpc-endpoints"
  description = "HTTPS access to private AWS service endpoints from AuthClaw workloads"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "AWS API HTTPS from ECS workloads"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id, aws_security_group.console_ingress.id]
  }

  tags = merge(var.tags, { Name = "${var.name}-vpc-endpoints" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each = var.enable_private_aws_endpoints ? local.interface_endpoint_services : {}

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = values(aws_subnet.private)[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true
  policy              = local.interface_endpoint_policies[each.key]

  tags = merge(var.tags, { Name = "${var.name}-${replace(each.value, ".", "-")}-endpoint" })
}

resource "aws_security_group" "data" {
  name        = "${var.name}-data"
  description = "Data plane access from ECS services"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    #trivy:ignore:AVD-AWS-0104 Managed data services keep security-group scoped ingress; egress remains available for service control-plane flows.
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

removed {
  from = random_password.db
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.backend_migrator_db
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.backend_app_db
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.agent_migrator_db
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.agent_runtime_db
  lifecycle {
    destroy = false
  }
}
removed {
  from = random_password.jwt
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.jwt_v2
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.session
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.session_v2
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.envelope
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.envelope_v2
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.internal_service
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_id.agent_encryption
  lifecycle {
    destroy = false
  }
}

removed {
  from = random_password.agent_redaction
  lifecycle {
    destroy = false
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.name}-db"
  subnet_ids = values(aws_subnet.private)[*].id
  tags       = var.tags
}

resource "aws_db_instance" "postgres_primary" {
  count = var.create_db_replica ? 0 : 1

  identifier                    = "${var.name}-postgres"
  engine                        = "postgres"
  engine_version                = var.db_engine_version
  instance_class                = var.db_instance_class
  allocated_storage             = var.db_allocated_storage
  db_name                       = "authclaw"
  username                      = "authclaw"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.main.arn
  db_subnet_group_name          = aws_db_subnet_group.main.name
  vpc_security_group_ids        = [aws_security_group.data.id]
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.main.arn
  multi_az                      = var.is_primary
  backup_retention_period       = 14
  deletion_protection           = var.is_primary
  skip_final_snapshot           = !var.is_primary
  tags                          = var.tags
}

resource "aws_db_instance" "postgres_replica" {
  count = var.create_db_replica ? 1 : 0

  identifier             = "${var.name}-postgres"
  replicate_source_db    = var.replica_source_db_arn
  instance_class         = var.db_instance_class
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.data.id]
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.main.arn
  multi_az               = false
  deletion_protection    = false
  skip_final_snapshot    = true
  tags                   = merge(var.tags, { Role = "cross-region-read-replica" })
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.name}-redis"
  subnet_ids = values(aws_subnet.private)[*].id
  tags       = var.tags
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.name}-redis"
  description                = "AuthClaw Redis cache"
  engine                     = "redis"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = var.is_primary ? 2 : 1
  automatic_failover_enabled = var.is_primary
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.data.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  tags                       = var.tags
}

resource "aws_secretsmanager_secret" "jwt" {
  name       = "${var.name}/jwt-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.jwt
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "jwt_v2" {
  name       = "${var.name}/jwt-secret/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.jwt_v2
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "session" {
  name       = "${var.name}/session-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.session
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "session_v2" {
  name       = "${var.name}/session-secret/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.session_v2
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "envelope" {
  name       = "${var.name}/envelope-key/v1"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.envelope
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "envelope_v2" {
  name       = "${var.name}/envelope-key/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.envelope_v2
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "bootstrap_database_url" {
  name       = "${var.name}/bootstrap-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.bootstrap_database_url
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "backend_migration_database_url" {
  name       = "${var.name}/backend-migration-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.backend_migration_database_url
  lifecycle {
    destroy = false
  }
}
resource "aws_secretsmanager_secret" "backend_database_url" {
  name       = "${var.name}/backend-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.backend_database_url
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "app_database_url" {
  name       = "${var.name}/app-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.app_database_url
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "agent_migration_database_url" {
  name       = "${var.name}/agent-migration-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.agent_migration_database_url
  lifecycle {
    destroy = false
  }
}
resource "aws_secretsmanager_secret" "agent_database_url" {
  name       = "${var.name}/agent-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.agent_database_url
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "internal_service" {
  name       = "${var.name}/internal-service-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.internal_service
  lifecycle {
    destroy = false
  }
}

# Shared only by the credential-free gateway container and the isolated SQS
# producer. Other services cannot authenticate arbitrary producer requests.
resource "aws_secretsmanager_secret" "audit_producer" {
  name       = "${var.name}/audit-producer-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret" "agent_encryption" {
  name       = "${var.name}/agent-encryption-key"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.agent_encryption
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "agent_redaction" {
  name       = "${var.name}/agent-redaction-salt"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.agent_redaction
  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "clickhouse_password" {
  count      = var.clickhouse_host != "" ? 1 : 0
  name       = "${var.name}/clickhouse-password"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

removed {
  from = aws_secretsmanager_secret_version.clickhouse_password
  lifecycle {
    destroy = false
  }
}

resource "aws_ecs_cluster" "main" {
  name = "${var.name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = var.tags
}

resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = local.namespace_name
  description = "AuthClaw private service discovery for ${var.name}"
  vpc         = aws_vpc.main.id
  tags        = var.tags
}

resource "aws_service_discovery_service" "service" {
  for_each = local.service_configs

  name = each.key

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "service" {
  for_each          = toset(concat(keys(local.task_definition_configs), ["opa", "presidio"], var.enable_audit_consumer ? ["audit_consumer"] : []))
  name              = "/authclaw/${var.name}/${each.key}"
  retention_in_days = 30
  tags              = var.tags
}

locals {
  application_task_role_arns = { for service, role in aws_iam_role.runtime : service => role.arn if service != "database_crypto_preflight" }
  effective_task_role_arns = {
    for name in keys(local.task_definition_configs) : name => (
      name != "gateway" && length(local.policy_sidecars[name]) == 0 ? lookup(local.application_task_role_arns, name, null) : null
    )
  }
  ecs_secret_arns = concat([
    aws_secretsmanager_secret.jwt.arn,
    aws_secretsmanager_secret.jwt_v2.arn,
    aws_secretsmanager_secret.session.arn,
    aws_secretsmanager_secret.session_v2.arn,
    aws_secretsmanager_secret.envelope.arn,
    aws_secretsmanager_secret.envelope_v2.arn,
    aws_secretsmanager_secret.bootstrap_database_url.arn,
    aws_secretsmanager_secret.backend_migration_database_url.arn,
    aws_secretsmanager_secret.backend_database_url.arn,
    aws_secretsmanager_secret.app_database_url.arn,
    aws_secretsmanager_secret.agent_migration_database_url.arn,
    aws_secretsmanager_secret.agent_database_url.arn,
    aws_secretsmanager_secret.internal_service.arn,
    aws_secretsmanager_secret.audit_producer.arn,
    aws_secretsmanager_secret.bff_client_ip.arn,
    aws_secretsmanager_secret.oidc_bff_exchange.arn,
    aws_secretsmanager_secret.worker_token_hmac.arn,
    aws_secretsmanager_secret.agent_encryption.arn,
    aws_secretsmanager_secret.agent_redaction.arn,
  ], var.clickhouse_host != "" ? [aws_secretsmanager_secret.clickhouse_password[0].arn] : [])

  runtime_s3_bucket_arns   = sort(distinct(flatten([for arns in values(var.runtime_s3_bucket_arns) : tolist(arns)])))
  runtime_kms_key_arns     = sort(distinct(flatten([for arns in values(var.runtime_kms_key_arns) : tolist(arns)])))
  runtime_secret_arns      = sort(distinct(flatten([for arns in values(var.runtime_secrets_manager_secret_arns) : tolist(arns)])))
  runtime_principal_arns   = distinct(concat([aws_iam_role.runtime["backend"].arn, aws_iam_role.runtime["agent"].arn], sort(tolist(var.vpc_endpoint_external_principal_arns))))
  execution_principal_arns = values(aws_iam_role.task_execution)[*].arn

  deny_insecure_transport_statement = {
    Sid       = "DenyInsecureTransport"
    Effect    = "Deny"
    Principal = "*"
    Action    = "*"
    Resource  = "*"
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }

  gateway_endpoint_policies = {
    s3 = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowECRImageLayers"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = "s3:GetObject"
          Resource  = "arn:${data.aws_partition.current.partition}:s3:::prod-${var.region}-starport-layer-bucket/*"
        }
        ], [for statement in [
          {
            Sid       = "AllowApprovedRuntimeBucketActions"
            Effect    = "Allow"
            Principal = { AWS = local.runtime_principal_arns }
            Action = [
              "s3:ListBucket",
              "s3:GetBucketLocation",
              "s3:GetBucketPublicAccessBlock",
              "s3:GetEncryptionConfiguration",
              "s3:GetBucketVersioning",
              "s3:GetBucketLogging",
              "s3:GetBucketPolicyStatus",
              "s3:PutBucketPublicAccessBlock",
              "s3:GetObject",
              "s3:PutObject",
            ]
            Resource = concat(local.runtime_s3_bucket_arns, [for arn in local.runtime_s3_bucket_arns : "${arn}/*"])
          },
          {
            Sid       = "AllowApprovedRuntimeBucketDiscovery"
            Effect    = "Allow"
            Principal = { AWS = local.runtime_principal_arns }
            Action    = "s3:ListAllMyBuckets"
            Resource  = "*"
          }
      ] : statement if length(local.runtime_s3_bucket_arns) > 0])
    })
  }

  interface_endpoint_policies = {
    ecr_api = jsonencode({
      Version = "2012-10-17"
      Statement = [
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowTaskECRToken"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = "ecr:GetAuthorizationToken"
          Resource  = "*"
        },
        {
          Sid       = "AllowTaskImagePull"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
          Resource  = sort(tolist(var.ecr_repository_arns))
        }
      ]
    })
    ecr_dkr = jsonencode({
      Version = "2012-10-17"
      Statement = [
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowTaskRegistryPull"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
          Resource  = sort(tolist(var.ecr_repository_arns))
        }
      ]
    })
    logs = jsonencode({
      Version = "2012-10-17"
      Statement = [
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowTaskLogDelivery"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
          Resource  = concat([for group in values(aws_cloudwatch_log_group.service) : "${group.arn}:*"], [for group in values(aws_cloudwatch_log_group.database_job) : "${group.arn}:*"])
        }
      ]
    })
    secretsmanager = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowTaskSecretInjection"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = "secretsmanager:GetSecretValue"
          Resource  = local.ecs_secret_arns
        }
        ], [for statement in [
          {
            Sid       = "AllowApprovedRuntimeSecrets"
            Effect    = "Allow"
            Principal = { AWS = local.runtime_principal_arns }
            Action    = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret"]
            Resource  = local.runtime_secret_arns
          }
      ] : statement if length(local.runtime_secret_arns) > 0])
    })
    kms = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowTaskSecretDecryption"
          Effect    = "Allow"
          Principal = { AWS = local.execution_principal_arns }
          Action    = "kms:Decrypt"
          Resource  = aws_kms_key.main.arn
        }
        ], [for statement in [
          {
            Sid       = "AllowApprovedRuntimeCryptography"
            Effect    = "Allow"
            Principal = { AWS = local.runtime_principal_arns }
            Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
            Resource  = local.runtime_kms_key_arns
          }
      ] : statement if length(local.runtime_kms_key_arns) > 0])
    })
    sts = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        local.deny_insecure_transport_statement,
        {
          Sid       = "AllowRuntimeIdentityCheck"
          Effect    = "Allow"
          Principal = { AWS = distinct(concat(values(local.application_task_role_arns), sort(tolist(var.vpc_endpoint_external_principal_arns)))) }
          Action    = "sts:GetCallerIdentity"
          Resource  = "*"
        }
        ], [for statement in [
          {
            Sid       = "AllowApprovedRuntimeRoleAssumption"
            Effect    = "Allow"
            Principal = { AWS = aws_iam_role.runtime["agent"].arn }
            Action    = "sts:AssumeRole"
            Resource  = sort(tolist(var.runtime_sts_assume_role_arns))
          }
      ] : statement if length(var.runtime_sts_assume_role_arns) > 0])
    })
    sqs = jsonencode({
      Version = "2012-10-17"
      Statement = [
        local.deny_insecure_transport_statement,
        {
          Sid    = "AllowAuditTransport"
          Effect = "Allow"
          Principal = { AWS = compact([
            aws_iam_role.runtime["backend"].arn,
            try(aws_iam_role.runtime["audit_producer"].arn, ""),
            try(aws_iam_role.runtime["audit_consumer"].arn, "")
          ]) }
          Action   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
          Resource = try(aws_sqs_queue.audit[0].arn, "*")
        }
      ]
    })
  }
}

resource "aws_iam_role" "ecs_instance" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name = "${var.name}-ecs-instance"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_instance" {
  for_each = var.ecs_ec2_graviton.enabled ? toset([
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ]) : toset([])

  role       = aws_iam_role.ecs_instance[0].name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "ecs_instance" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name = "${var.name}-ecs-instance"
  role = aws_iam_role.ecs_instance[0].name
  tags = var.tags
}

resource "aws_launch_template" "ecs_graviton" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name_prefix   = "${var.name}-ecs-graviton-"
  image_id      = local.ec2_ami_id
  instance_type = var.ecs_ec2_graviton.instance_type
  user_data = base64encode(join("\n", [
    "#!/bin/bash",
    "set -euo pipefail",
    "cat >/etc/ecs/ecs.config <<'EOF'",
    "ECS_CLUSTER=${aws_ecs_cluster.main.name}",
    "ECS_ENABLE_SPOT_INSTANCE_DRAINING=true",
    "ECS_CONTAINER_INSTANCE_PROPAGATE_TAGS_FROM=ec2_instance",
    "ECS_AWSVPC_BLOCK_IMDS=true",
    "EOF",
  ]))

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted             = true
      kms_key_id            = aws_kms_key.main.arn
      volume_size           = var.ecs_ec2_graviton.root_volume_size
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_instance[0].name
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  monitoring {
    enabled = true
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = [aws_security_group.app.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name}-ecs-graviton" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(var.tags, { Name = "${var.name}-ecs-graviton-root" })
  }

  update_default_version = true
  tags                   = var.tags
}

resource "aws_autoscaling_group" "ecs_graviton" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name                      = "${var.name}-ecs-graviton"
  min_size                  = var.ecs_ec2_graviton.min_size
  desired_capacity          = var.ecs_ec2_graviton.desired_size
  max_size                  = var.ecs_ec2_graviton.max_size
  vpc_zone_identifier       = values(aws_subnet.private)[*].id
  health_check_type         = "EC2"
  health_check_grace_period = 300
  protect_from_scale_in     = true
  termination_policies      = ["OldestLaunchTemplate", "OldestInstance"]
  enabled_metrics           = ["GroupDesiredCapacity", "GroupInServiceInstances", "GroupPendingInstances", "GroupStandbyInstances", "GroupTerminatingInstances", "GroupTotalInstances"]

  launch_template {
    id      = aws_launch_template.ecs_graviton[0].id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 100
      instance_warmup        = 300
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name}-ecs-graviton"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

resource "aws_ecs_capacity_provider" "graviton" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name = local.ec2_capacity_provider_name

  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.ecs_graviton[0].arn
    managed_draining               = "ENABLED"
    managed_termination_protection = "ENABLED"

    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 80
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = max(1, var.ecs_ec2_graviton.max_size - var.ecs_ec2_graviton.min_size)
      instance_warmup_period    = 300
    }
  }

  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = [aws_ecs_capacity_provider.graviton[0].name]

  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.graviton[0].name
    weight            = 1
    base              = 0
  }
}

resource "random_id" "alb_log_bucket" {
  byte_length = 4
}

resource "aws_s3_bucket" "alb_logs" {
  bucket        = substr(lower("${var.name}-${var.region}-alb-logs-${random_id.alb_log_bucket.hex}"), 0, 63)
  force_destroy = false
  tags          = merge(var.tags, { DataClass = "security-telemetry" })
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#trivy:ignore:AVD-AWS-0132 ALB access-log delivery supports SSE-S3, not customer-managed SSE-KMS keys.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "retention"
    status = "Enabled"
    filter {}
    expiration { days = var.alb_access_log_retention_days }
  }
}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid       = "AllowALBLogDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/AWSLogs/${var.aws_account_id != "" ? var.aws_account_id : "*"}/*"]
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    dynamic "condition" {
      for_each = var.aws_account_id != "" ? [1] : []
      content {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.aws_account_id]
      }
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:elasticloadbalancing:${var.region}:${var.aws_account_id != "" ? var.aws_account_id : "*"}:loadbalancer/*"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs.json
}

moved {
  from = aws_lb.main
  to   = aws_lb.service["console"]
}

resource "aws_lb" "service" {
  for_each = local.public_services

  name                       = trim(substr(replace("${substr(var.name, 0, 20)}-${each.key}-alb", "_", "-"), 0, 32), "-")
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = values(aws_subnet.private)[*].id
  drop_invalid_header_fields = true
  xff_header_processing_mode = "append"
  enable_xff_client_port     = false
  tags                       = var.tags

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = each.key
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_target_group" "service" {
  for_each = local.public_services

  name_prefix = "${substr(each.key, 0, 5)}-"
  port        = local.service_ports[each.key]
  protocol    = contains(local.tls_services, each.key) ? "HTTPS" : "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  lifecycle {
    create_before_destroy = true
  }

  health_check {
    protocol            = contains(local.tls_services, each.key) ? "HTTPS" : "HTTP"
    path                = each.value.health_path
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = var.tags
}

resource "aws_lb_listener" "service" {
  for_each = local.public_services

  load_balancer_arn = aws_lb.service[each.key].arn
  port              = 443
  protocol          = local.listener_protocol
  certificate_arn   = var.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service[each.key].arn
  }
}

locals {
  database_jobs = {
    worker_preflight = {
      image       = var.container_images.backend
      command     = ["python", "scripts/verify_worker_lifecycle.py"]
      environment = [{ name = "WORKER_TOKEN_HMAC_ACTIVE_VERSION", value = "v1" }]
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.bootstrap_database_url.arn },
        { name = "WORKER_TOKEN_HMAC_KEY_V1", valueFrom = aws_secretsmanager_secret.worker_token_hmac.arn }
      ]
    }
    crypto_preflight = {
      image   = var.container_images.backend
      command = ["python", "scripts/verify_secret_retirement.py"]
      environment = [
        { name = "AUTHCLAW_ENV", value = var.authclaw_env },
        { name = "AUTHCLAW_SECRET_PROVIDER", value = "env" },
        { name = "AUTHCLAW_SECRET_KEY_VERSION", value = var.secret_key_version }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.bootstrap_database_url.arn },
        { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V1", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V2", valueFrom = aws_secretsmanager_secret.envelope_v2.arn }
      ]
    }
    bootstrap_prepare = {
      image   = var.container_images.backend
      command = ["python", "scripts/bootstrap_database_security.py", "prepare"]
      environment = [
        { name = "POSTGRES_DB", value = "authclaw" }
      ]
      secrets = [
        { name = "BOOTSTRAP_DATABASE_URL", valueFrom = aws_secretsmanager_secret.bootstrap_database_url.arn },
        { name = "BACKEND_MIGRATION_DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_migration_database_url.arn },
        { name = "BACKEND_DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_database_url.arn },
        { name = "AGENT_MIGRATION_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_migration_database_url.arn },
        { name = "AGENT_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn }
      ]
    }
    backend_migrations = {
      image   = var.container_images.backend
      command = ["alembic", "upgrade", "head"]
      environment = [
        { name = "POSTGRES_APP_USER", value = "authclaw_app" },
        { name = "AUTHCLAW_ENV", value = var.authclaw_env }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_migration_database_url.arn },
        { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "SESSION_SECRET", valueFrom = aws_secretsmanager_secret.session.arn }
      ]
    }
    agent_migrations = {
      image   = var.container_images.agent
      command = ["python", "-m", "database.migrations"]
      environment = [
        { name = "AUTHCLAW_DATABASE_SCHEMA", value = "agent" }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_migration_database_url.arn },
        { name = "MIGRATION_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_migration_database_url.arn }
      ]
    }
    bootstrap_finalize = {
      image   = var.container_images.backend
      command = ["python", "scripts/bootstrap_database_security.py", "finalize"]
      environment = [
        { name = "POSTGRES_DB", value = "authclaw" }
      ]
      secrets = [
        { name = "BOOTSTRAP_DATABASE_URL", valueFrom = aws_secretsmanager_secret.bootstrap_database_url.arn },
        { name = "BACKEND_MIGRATION_DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_migration_database_url.arn },
        { name = "BACKEND_DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_database_url.arn },
        { name = "AGENT_MIGRATION_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_migration_database_url.arn },
        { name = "AGENT_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn }
      ]
    }
    database_security_check = {
      image   = var.container_images.backend
      command = ["python", "scripts/verify_database_security.py"]
      environment = [
        { name = "BACKEND_MIGRATOR_USER", value = "authclaw_migrator" },
        { name = "POSTGRES_APP_USER", value = "authclaw_app" },
        { name = "AGENT_MIGRATOR_USER", value = "authclaw_agent_migrator" },
        { name = "AGENT_RUNTIME_USER", value = "authclaw_agent_runtime" }
      ]
      secrets = [
        { name = "BOOTSTRAP_DATABASE_URL", valueFrom = aws_secretsmanager_secret.bootstrap_database_url.arn },
        { name = "BACKEND_DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_database_url.arn },
        { name = "AGENT_DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn }
      ]
    }
  }
}

resource "aws_cloudwatch_log_group" "database_job" {
  for_each          = local.database_jobs
  name              = "/authclaw/${var.name}/database-${replace(each.key, "_", "-")}"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_ecs_task_definition" "database_job" {
  depends_on               = [aws_iam_role_policy.task_execution, aws_iam_role_policy.runtime]
  for_each                 = local.database_jobs
  family                   = "${var.name}-database-${replace(each.key, "_", "-")}"
  requires_compatibilities = local.ecs_launch_compatibilities
  network_mode             = "awsvpc"
  cpu                      = var.service_cpu
  memory                   = var.service_memory
  execution_role_arn       = aws_iam_role.task_execution["database_${each.key}"].arn
  task_role_arn            = try(aws_iam_role.runtime["database_${each.key}"].arn, null)

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = local.runtime_architectures[each.key == "agent_migrations" ? "agent" : "backend"]
  }

  volume { name = "tmp" }

  container_definitions = jsonencode([{
    name                   = each.key
    image                  = each.value.image
    essential              = true
    cpu                    = var.service_cpu
    memory                 = var.service_memory
    command                = each.value.command
    environment            = each.value.environment
    secrets                = each.value.secrets
    readonlyRootFilesystem = true
    privileged             = false
    stopTimeout            = 30
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.database_job[each.key].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "database"
      }
    }
  }])

  tags = var.tags
}
resource "aws_ecs_task_definition" "service" {
  for_each = local.task_definition_configs

  family                   = "${var.name}-${each.key}"
  requires_compatibilities = local.ecs_launch_compatibilities
  network_mode             = "awsvpc"
  cpu                      = var.enable_policy_sidecar_colocation && contains(keys(local.colocated_task_cpu), each.key) ? local.colocated_task_cpu[each.key] : var.service_cpu
  memory                   = var.enable_policy_sidecar_colocation && contains(keys(local.colocated_task_memory), each.key) ? local.colocated_task_memory[each.key] : var.service_memory
  execution_role_arn       = aws_iam_role.task_execution[each.key].arn
  # ECS task credentials are visible to every container in a task. Colocated
  # OPA/Presidio tasks therefore never receive an application task role.
  task_role_arn = local.effective_task_role_arns[each.key]

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = local.runtime_architectures[each.key]
  }

  dynamic "volume" {
    for_each = local.service_writable_paths[each.key]
    content { name = "writable-${volume.key}" }
  }

  dynamic "volume" {
    for_each = contains(local.tls_services, each.key) ? ["tmp"] : []
    content { name = "tls-${volume.value}" }
  }

  dynamic "volume" {
    for_each = toset(local.policy_sidecars[each.key])
    content { name = "sidecar-${volume.value}-tmp" }
  }

  container_definitions = jsonencode(concat([
    merge({
      name      = each.key
      image     = each.value.image
      essential = true
      cpu       = var.enable_policy_sidecar_colocation && contains(keys(local.colocated_primary_cpu), each.key) ? local.colocated_primary_cpu[each.key] : var.service_cpu
      memory    = var.enable_policy_sidecar_colocation && contains(keys(local.colocated_primary_memory), each.key) ? local.colocated_primary_memory[each.key] : (contains(local.tls_services, each.key) ? var.service_memory - 128 : var.service_memory)
      portMappings = [{
        containerPort = each.value.container_port
        protocol      = "tcp"
      }]
      environment = concat(
        local.common_environment,
        local.service_policy_environment[each.key],
        each.key == "console" ? [
          { name = "AUTHCLAW_BFF_CLIENT_IP_ENABLED", value = tostring(var.bff_client_ip_signing_enabled) },
          { name = "AUTHCLAW_OIDC_LOGIN_PAUSED", value = tostring(var.oidc_login_paused) },
          { name = "AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY", value = "true" }
        ] : [],
        contains(tolist(local.audit_sqs_producer_services), each.key) ? local.audit_sqs_producer_environment : [],
        each.key == "gateway" && local.audit_sqs_enabled ? [
          { name = "AUDIT_PRODUCER_URL", value = "${local.internal_urls.audit_producer}/v1/audit" }
        ] : [],
        each.key == "gateway" ? [
          { name = "REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS", value = "60000" }
        ] : [],
        each.key == "backend" ? [
          { name = "WORKER_TOKEN_HMAC_ACTIVE_VERSION", value = "v1" },
          { name = "WORKER_TOKEN_ISSUANCE_PAUSED", value = tostring(var.worker_token_issuance_paused) },
          { name = "WORKER_CLEANUP_ENABLED", value = "true" },
          { name = "AUTHCLAW_BFF_CLIENT_IP_ENABLED", value = tostring(var.bff_client_ip_enabled) },
          { name = "AUTHCLAW_RUNTIME_DB_ROLE", value = "authclaw_app" }
        ] : [],
        each.key == "agent" ? [
          { name = "AUTHCLAW_DATABASE_SCHEMA", value = "agent" },
          { name = "AUTHCLAW_RUNTIME_DB_ROLE", value = "authclaw_agent_runtime" }
        ] : []
      )
      secrets                = local.service_secrets[each.key]
      readonlyRootFilesystem = true
      privileged             = false
      stopTimeout            = 30
      mountPoints = [for index, path in local.service_writable_paths[each.key] : {
        sourceVolume  = "writable-${index}"
        containerPath = path
        readOnly      = false
      }]
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      healthCheck = {
        command     = local.service_health_checks[each.key]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      dependsOn = [for sidecar in local.policy_sidecars[each.key] : {
        containerName = sidecar
        condition     = "HEALTHY"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service[each.key].name
          awslogs-region        = var.region
          awslogs-stream-prefix = each.key
        }
      }
      },
      each.value.command == null ? {} : { command = each.value.command }
    )],
    [for sidecar in local.policy_sidecars[each.key] : {
      name                   = sidecar
      image                  = local.policy_sidecar_configs[sidecar].image
      essential              = true
      cpu                    = local.policy_sidecar_configs[sidecar].cpu
      memory                 = local.policy_sidecar_configs[sidecar].memory
      command                = local.policy_sidecar_configs[sidecar].command
      portMappings           = local.policy_sidecar_configs[sidecar].port_mappings
      readonlyRootFilesystem = true
      privileged             = false
      stopTimeout            = 30
      mountPoints            = [{ sourceVolume = "sidecar-${sidecar}-tmp", containerPath = "/tmp", readOnly = false }]
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      healthCheck = {
        command     = local.service_health_checks[sidecar]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = sidecar == "presidio" ? 60 : 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service[sidecar].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "${each.key}-${sidecar}"
        }
      }
    }],
    contains(local.tls_services, each.key) ? [local.tls_containers[each.key]] : [],
  ))

  lifecycle {
    precondition {
      condition     = !var.bff_client_ip_signing_enabled || var.bff_client_ip_enabled
      error_message = "Enable backend client-identity verification before console signing."
    }
    precondition {
      condition = !contains(["production", "prod"], var.authclaw_env) || alltrue([
        startswith(local.internal_agent_url, "https://"),
        startswith(local.internal_opa_url, "https://") || local.internal_opa_url == "http://127.0.0.1:8181",
        startswith(local.internal_presidio_url, "https://") || local.internal_presidio_url == "http://127.0.0.1:3000",
        startswith(local.internal_urls.gateway, "https://")
      ])
      error_message = "Production is blocked until agent, gateway, OPA, and Presidio use authenticated TLS or exact task-local loopback policy endpoints."
    }
  }

  tags = var.tags
}

resource "aws_ecs_service" "public" {
  for_each = local.public_services

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  name                   = "${var.name}-${each.key}"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.service[each.key].arn
  desired_count          = var.desired_count
  launch_type            = var.ecs_ec2_graviton.enabled ? null : "FARGATE"
  enable_execute_command = false

  dynamic "capacity_provider_strategy" {
    for_each = var.ecs_ec2_graviton.enabled ? [1] : []
    content {
      capacity_provider = aws_ecs_capacity_provider.graviton[0].name
      weight            = 1
      base              = 0
    }
  }

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = each.key == "console" ? [aws_security_group.console_ingress.id] : [aws_security_group.app.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.service[each.key].arn
    container_name   = contains(local.tls_services, each.key) ? "tls" : each.key
    container_port   = local.service_ports[each.key]
  }

  service_registries {
    registry_arn = aws_service_discovery_service.service[each.key].arn
  }

  depends_on = [aws_lb_listener.service, aws_ecs_cluster_capacity_providers.main]
  tags       = var.tags
}

resource "aws_ecs_service" "private" {
  for_each = merge(local.private_services, local.legacy_sidecar_services)

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  name                   = "${var.name}-${each.key}"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.service[each.key].arn
  desired_count          = var.desired_count
  launch_type            = var.ecs_ec2_graviton.enabled ? null : "FARGATE"
  enable_execute_command = false

  dynamic "capacity_provider_strategy" {
    for_each = var.ecs_ec2_graviton.enabled ? [1] : []
    content {
      capacity_provider = aws_ecs_capacity_provider.graviton[0].name
      weight            = 1
      base              = 0
    }
  }

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.service[each.key].arn
  }

  depends_on = [aws_ecs_cluster_capacity_providers.main]
  tags       = var.tags
}

resource "aws_ecs_task_definition" "audit_consumer" {
  count = var.enable_audit_consumer ? 1 : 0

  family                   = "${var.name}-audit-consumer"
  requires_compatibilities = local.ecs_launch_compatibilities
  network_mode             = "awsvpc"
  cpu                      = var.service_cpu
  memory                   = var.service_memory
  execution_role_arn       = aws_iam_role.task_execution["audit_consumer"].arn
  task_role_arn            = aws_iam_role.runtime["audit_consumer"].arn

  lifecycle {
    precondition {
      condition     = trimspace(var.clickhouse_host) != ""
      error_message = "Audit consumer requires a ClickHouse host and externally provisioned password secret."
    }
    precondition {
      condition     = lookup(var.audit_consumer_environment, "CLICKHOUSE_SECURE", "false") == "true" && contains(keys(var.audit_consumer_secret_arns), "AUDIT_POSTGRES_URL") && (var.audit_stream_transport != "kafka" || (lookup(var.audit_consumer_environment, "KAFKA_SECURITY_PROTOCOL", "") == "SASL_SSL" && contains(keys(var.audit_consumer_secret_arns), "KAFKA_SASL_USERNAME") && contains(keys(var.audit_consumer_secret_arns), "KAFKA_SASL_PASSWORD")))
      error_message = "Shared audit consumers require verified HTTPS, a PostgreSQL verifier secret and authenticated Kafka TLS when Kafka is selected."
    }
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = local.runtime_architectures.audit_consumer
  }

  volume { name = "tmp" }

  container_definitions = jsonencode([
    {
      name      = "audit_consumer"
      image     = var.container_images.audit_consumer
      essential = true
      cpu       = var.service_cpu
      memory    = var.service_memory
      environment = concat(local.common_environment, local.audit_sqs_environment, local.audit_sqs_consumer_environment, [for name, value in var.audit_consumer_environment : { name = name, value = value }], [
        { name = "KAFKA_TOPICS", value = "gateway.traffic,audit.events" },
        { name = "KAFKA_DLQ_TOPIC", value = "audit.deadletter" },
        { name = "AUDIT_CONSUMER_METRICS_PORT", value = "9108" },
        { name = "AUDIT_CONSUMER_METRICS_HOST", value = "0.0.0.0" },
        { name = "CLICKHOUSE_HOST", value = var.clickhouse_host },
        { name = "CLICKHOUSE_PORT", value = tostring(var.clickhouse_port) },
        { name = "CLICKHOUSE_DB", value = var.clickhouse_db },
        { name = "CLICKHOUSE_USER", value = var.clickhouse_user }
      ])
      portMappings = [
        {
          containerPort = 9108
          protocol      = "tcp"
        }
      ]
      secrets                = local.audit_consumer_secrets
      readonlyRootFilesystem = true
      privileged             = false
      stopTimeout            = 30
      mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      healthCheck = {
        command     = local.service_health_checks.audit_consumer
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["audit_consumer"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "audit_consumer"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "audit_consumer" {
  count = var.enable_audit_consumer ? 1 : 0

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  name                   = "${var.name}-audit-consumer"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.audit_consumer[0].arn
  desired_count          = 1
  launch_type            = var.ecs_ec2_graviton.enabled ? null : "FARGATE"
  enable_execute_command = false

  dynamic "capacity_provider_strategy" {
    for_each = var.ecs_ec2_graviton.enabled ? [1] : []
    content {
      capacity_provider = aws_ecs_capacity_provider.graviton[0].name
      weight            = 1
      base              = 0
    }
  }

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  depends_on = [aws_ecs_cluster_capacity_providers.main]
  tags       = var.tags
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  for_each = local.public_services

  alarm_name          = "${var.name}-${each.key}-unhealthy-hosts"
  alarm_description   = "AuthClaw ${each.key} has an unhealthy ALB target"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "breaching"
  alarm_actions       = var.edge_alarm_action_arns

  dimensions = {
    LoadBalancer = aws_lb.service[each.key].arn_suffix
    TargetGroup  = aws_lb_target_group.service[each.key].arn_suffix
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  for_each = local.ecs_alarm_services

  alarm_name          = "${var.name}-${each.key}-high-cpu"
  alarm_description   = "AuthClaw ${each.key} ECS CPU is above 85 percent"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  period              = 60
  statistic           = "Average"
  threshold           = 85
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = "${var.name}-${replace(each.key, "_", "-")}"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory" {
  for_each = local.ecs_alarm_services

  alarm_name          = "${var.name}-${replace(each.key, "_", "-")}-high-memory"
  alarm_description   = "AuthClaw ${each.key} ECS memory is above 85 percent"
  namespace           = "AWS/ECS"
  metric_name         = "MemoryUtilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  period              = 60
  statistic           = "Average"
  threshold           = 85
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = "${var.name}-${replace(each.key, "_", "-")}"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_running_tasks" {
  for_each = local.ecs_service_desired_counts

  alarm_name          = "${var.name}-${replace(each.key, "_", "-")}-running-tasks-low"
  alarm_description   = "AuthClaw ${each.key} has fewer running ECS tasks than its desired count"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  period              = 60
  statistic           = "Minimum"
  threshold           = each.value
  treat_missing_data  = "breaching"
  alarm_actions       = var.edge_alarm_action_arns

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = "${var.name}-${replace(each.key, "_", "-")}"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_capacity_provider_reservation" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  alarm_name          = "${var.name}-ecs-graviton-capacity-reservation"
  alarm_description   = "ECS Graviton capacity provider reservation is above 90 percent"
  namespace           = "AWS/ECS/ManagedScaling"
  metric_name         = "CapacityProviderReservation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  period              = 60
  statistic           = "Average"
  threshold           = 90
  treat_missing_data  = "breaching"
  alarm_actions       = var.ecs_ec2_graviton.alarm_action_arns

  dimensions = {
    CapacityProviderName = aws_ecs_capacity_provider.graviton[0].name
    ClusterName          = aws_ecs_cluster.main.name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_pending_tasks" {
  for_each = local.ecs_alarm_services

  alarm_name          = "${var.name}-${each.key}-pending-tasks"
  alarm_description   = "AuthClaw ${each.key} has pending ECS tasks"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "PendingTaskCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = distinct(concat(var.edge_alarm_action_arns, var.ecs_ec2_graviton.alarm_action_arns))

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = "${var.name}-${replace(each.key, "_", "-")}"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_instance_health" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  alarm_name          = "${var.name}-ecs-graviton-instance-health"
  alarm_description   = "At least one ECS Graviton container instance has failed EC2 status checks"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.ecs_ec2_graviton.alarm_action_arns

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.ecs_graviton[0].name
  }

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name        = "${var.name}-ecs-placement-failure"
  description = "Captures ECS placement failures for AuthClaw services"
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Service Action"]
    detail = {
      clusterArn = [aws_ecs_cluster.main.arn]
      eventName  = ["SERVICE_TASK_PLACEMENT_FAILURE"]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name              = "/authclaw/${var.name}/ecs-placement-failure"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_cloudwatch_log_resource_policy" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  policy_name = "${var.name}-ecs-placement-failure"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.ecs_placement_failure[0].arn}:*"
    }]
  })
}

resource "aws_cloudwatch_event_target" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  rule = aws_cloudwatch_event_rule.ecs_placement_failure[0].name
  arn  = aws_cloudwatch_log_group.ecs_placement_failure[0].arn
}

resource "aws_cloudwatch_log_metric_filter" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  name           = "${var.name}-ecs-placement-failure"
  log_group_name = aws_cloudwatch_log_group.ecs_placement_failure[0].name
  pattern        = "{ $.detail.eventName = \"SERVICE_TASK_PLACEMENT_FAILURE\" }"

  metric_transformation {
    name      = "PlacementFailureCount"
    namespace = "AuthClaw/ECS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_placement_failure" {
  count = var.ecs_ec2_graviton.enabled ? 1 : 0

  alarm_name          = "${var.name}-ecs-placement-failure"
  alarm_description   = "ECS reported at least one AuthClaw task placement failure"
  namespace           = "AuthClaw/ECS"
  metric_name         = "PlacementFailureCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.ecs_ec2_graviton.alarm_action_arns

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "ecs_deployment_failure" {
  name        = "${var.name}-ecs-deployment-failure"
  description = "Captures failed ECS circuit-breaker deployments"
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Deployment State Change"]
    detail = {
      clusterArn = [aws_ecs_cluster.main.arn]
      eventName  = ["SERVICE_DEPLOYMENT_FAILED"]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "ecs_deployment_failure" {
  name              = "/authclaw/${var.name}/ecs-deployment-failure"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_cloudwatch_log_resource_policy" "ecs_deployment_failure" {
  policy_name = "${var.name}-ecs-deployment-failure"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.ecs_deployment_failure.arn}:*"
    }]
  })
}

resource "aws_cloudwatch_event_target" "ecs_deployment_failure" {
  rule = aws_cloudwatch_event_rule.ecs_deployment_failure.name
  arn  = aws_cloudwatch_log_group.ecs_deployment_failure.arn
}

resource "aws_cloudwatch_log_metric_filter" "ecs_deployment_failure" {
  name           = "${var.name}-ecs-deployment-failure"
  log_group_name = aws_cloudwatch_log_group.ecs_deployment_failure.name
  pattern        = "{ $.detail.eventName = \"SERVICE_DEPLOYMENT_FAILED\" }"

  metric_transformation {
    name      = "DeploymentFailureCount"
    namespace = "AuthClaw/ECS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_deployment_failure" {
  alarm_name          = "${var.name}-ecs-deployment-failure"
  alarm_description   = "ECS reported a failed AuthClaw deployment and circuit-breaker rollback"
  namespace           = "AuthClaw/ECS"
  metric_name         = "DeploymentFailureCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.edge_alarm_action_arns

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "nat_port_allocation" {
  for_each = aws_nat_gateway.main

  alarm_name          = "${var.name}-nat-${each.key}-port-allocation"
  alarm_description   = "NAT gateway ${each.key} could not allocate a source port"
  namespace           = "AWS/NATGateway"
  metric_name         = "ErrorPortAllocation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    NatGatewayId = each.value.id
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "nat_packet_drop" {
  for_each = aws_nat_gateway.main

  alarm_name          = "${var.name}-nat-${each.key}-packet-drop"
  alarm_description   = "NAT gateway ${each.key} dropped more than 0.01 percent of packets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0.01
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "drop_rate"
    expression  = "IF((source_packets + destination_packets) > 0, 100 * dropped_packets / (source_packets + destination_packets), 0)"
    label       = "Dropped packets percent"
    return_data = true
  }

  metric_query {
    id          = "dropped_packets"
    return_data = false

    metric {
      namespace   = "AWS/NATGateway"
      metric_name = "PacketsDropCount"
      period      = 300
      stat        = "Sum"
      dimensions = {
        NatGatewayId = each.value.id
      }
    }
  }

  metric_query {
    id          = "source_packets"
    return_data = false

    metric {
      namespace   = "AWS/NATGateway"
      metric_name = "PacketsInFromSource"
      period      = 300
      stat        = "Sum"
      dimensions = {
        NatGatewayId = each.value.id
      }
    }
  }

  metric_query {
    id          = "destination_packets"
    return_data = false

    metric {
      namespace   = "AWS/NATGateway"
      metric_name = "PacketsInFromDestination"
      period      = 300
      stat        = "Sum"
      dimensions = {
        NatGatewayId = each.value.id
      }
    }
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "nat_idle_timeout" {
  for_each = aws_nat_gateway.main

  alarm_name          = "${var.name}-nat-${each.key}-idle-timeout"
  alarm_description   = "NAT gateway ${each.key} idle timeouts exceed the learned baseline"
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold_metric_id = "idle_band"
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "idle"
    return_data = true

    metric {
      namespace   = "AWS/NATGateway"
      metric_name = "IdleTimeoutCount"
      period      = 300
      stat        = "Sum"
      dimensions = {
        NatGatewayId = each.value.id
      }
    }
  }

  metric_query {
    id          = "idle_band"
    expression  = "ANOMALY_DETECTION_BAND(idle, 2)"
    label       = "Expected idle timeouts"
    return_data = true
  }

  tags = var.tags
}

resource "aws_cloudwatch_dashboard" "nat" {
  dashboard_name = "${var.name}-nat"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title   = "NAT connections by Availability Zone"
          region  = var.region
          view    = "timeSeries"
          stacked = false
          metrics = flatten([for key, nat in aws_nat_gateway.main : [
            ["AWS/NATGateway", "ActiveConnectionCount", "NatGatewayId", nat.id, { label = "${key} active", stat = "Maximum" }],
            ["AWS/NATGateway", "ConnectionAttemptCount", "NatGatewayId", nat.id, { label = "${key} attempted", stat = "Sum" }],
            ["AWS/NATGateway", "ConnectionEstablishedCount", "NatGatewayId", nat.id, { label = "${key} established", stat = "Sum" }],
          ]])
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title  = "NAT bytes by Availability Zone"
          region = var.region
          view   = "timeSeries"
          metrics = flatten([for key, nat in aws_nat_gateway.main : [
            ["AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", nat.id, { label = "${key} sent", stat = "Sum" }],
            ["AWS/NATGateway", "BytesInFromDestination", "NatGatewayId", nat.id, { label = "${key} received", stat = "Sum" }],
          ]])
        }
      },
    ]
  })
}
