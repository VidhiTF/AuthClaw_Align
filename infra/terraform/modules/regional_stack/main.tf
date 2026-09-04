data "aws_availability_zones" "available" {
  count = length(var.availability_zones) == 0 ? 1 : 0
  state = "available"
}

locals {
  discovered_azs = length(var.availability_zones) > 0 ? var.availability_zones : data.aws_availability_zones.available[0].names
  azs            = slice(local.discovered_azs, 0, var.az_count)
  az_map         = { for idx, az in local.azs : tostring(idx) => az }
  interface_endpoint_services = merge({
    ecr_api        = "ecr.api"
    ecr_dkr        = "ecr.dkr"
    logs           = "logs"
    secretsmanager = "secretsmanager"
    kms            = "kms"
  }, var.audit_stream_transport == "sqs_fifo" ? { sqs = "sqs" } : {})
  namespace_name        = "${var.name}.local"
  listener_protocol     = "HTTPS"
  public_scheme         = "https"
  public_host           = var.domain_name != "" ? var.domain_name : aws_lb.main.dns_name
  api_base_url          = "${local.public_scheme}://${local.public_host}:8000"
  gateway_base_url      = "${local.public_scheme}://${local.public_host}:8080"
  internal_agent_url    = "http://agent.${local.namespace_name}:8001"
  internal_opa_url      = "http://127.0.0.1:8181"
  internal_presidio_url = "http://127.0.0.1:3000"
  db_password           = var.db_password != "" ? var.db_password : random_password.db.result
  db_address            = var.create_db_replica ? aws_db_instance.postgres_replica[0].address : aws_db_instance.postgres_primary[0].address
  db_arn                = var.create_db_replica ? aws_db_instance.postgres_replica[0].arn : aws_db_instance.postgres_primary[0].arn
  nat_subnets           = var.nat_gateway_mode == "per_az" ? aws_subnet.public : { "0" = aws_subnet.public["0"] }

  public_services = {
    console = {
      image          = var.container_images.console
      container_port = 3001
      listener_port  = 443
      health_path    = "/"
      command        = null
    }
    backend = {
      image          = var.container_images.backend
      container_port = 8000
      listener_port  = 8000
      health_path    = "/health"
      command        = null
    }
    gateway = {
      image          = var.container_images.gateway
      container_port = 8080
      listener_port  = 8080
      health_path    = "/health"
      command        = null
    }
  }

  private_services = {
    agent = {
      image          = var.container_images.agent
      container_port = 8001
      command        = null
    }
  }

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

  service_configs         = merge(local.public_services, local.private_services)
  task_definition_configs = merge(local.service_configs, local.legacy_sidecar_services)

  common_environment = [
    { name = "AUTHCLAW_ENV", value = var.authclaw_env },
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
    { name = "OPA_URL", value = local.internal_opa_url },
    { name = "PRESIDIO_URL", value = local.internal_presidio_url },
    { name = "AGENT_INTERNAL_URL", value = local.internal_agent_url },
    { name = "AUTHCLAW_GO_GATEWAY_URL", value = "http://gateway.${local.namespace_name}:8080" },
    { name = "AUTHCLAW_OPA_POLICY_URL", value = "${local.internal_opa_url}/v1/data/authclaw/policy/decision" },
    { name = "AUTHCLAW_DISABLE_BACKGROUND_MONITOR", value = "true" },
    { name = "PUBLIC_GATEWAY_URL", value = local.gateway_base_url },
    { name = "GATEWAY_INTERNAL_URL", value = "http://gateway.${local.namespace_name}:8080" },
    { name = "NEXT_PUBLIC_GATEWAY_URL", value = local.gateway_base_url },
    { name = "NEXT_PUBLIC_API_URL", value = local.api_base_url },
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

  tags = merge(var.tags, { Name = "${var.name}-${each.value}-endpoint" })
}

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Public ALB ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 8000
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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
    for_each = toset([8000, 8001, 8080])
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
      from_port       = ingress.value.container_port
      to_port         = ingress.value.container_port
      protocol        = "tcp"
      security_groups = [aws_security_group.alb.id]
    }
  }

  dynamic "ingress" {
    for_each = local.service_configs
    content {
      from_port = ingress.value.container_port
      to_port   = ingress.value.container_port
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

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_password" "backend_migrator_db" {
  length  = 32
  special = false
}

resource "random_password" "backend_app_db" {
  length  = 32
  special = false
}

resource "random_password" "agent_migrator_db" {
  length  = 32
  special = false
}

resource "random_password" "agent_runtime_db" {
  length  = 32
  special = false
}
resource "random_password" "jwt" {
  length  = 48
  special = false
}

resource "random_password" "jwt_v2" {
  length  = 48
  special = false
}

resource "random_password" "session" {
  length  = 48
  special = false
}

resource "random_password" "session_v2" {
  length  = 48
  special = false
}

resource "random_password" "envelope" {
  length  = 48
  special = false
}

resource "random_password" "envelope_v2" {
  length  = 48
  special = false
}

resource "random_password" "internal_service" {
  length  = 48
  special = false
}

resource "random_id" "agent_encryption" {
  byte_length = 32
}

resource "random_password" "agent_redaction" {
  length  = 48
  special = false
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.name}-db"
  subnet_ids = values(aws_subnet.private)[*].id
  tags       = var.tags
}

resource "aws_db_instance" "postgres_primary" {
  count = var.create_db_replica ? 0 : 1

  identifier              = "${var.name}-postgres"
  engine                  = "postgres"
  engine_version          = var.db_engine_version
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage
  db_name                 = "authclaw"
  username                = "authclaw"
  password                = local.db_password
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.data.id]
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.main.arn
  multi_az                = var.is_primary
  backup_retention_period = 14
  deletion_protection     = var.is_primary
  skip_final_snapshot     = !var.is_primary
  tags                    = var.tags
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

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = random_password.jwt.result
}

resource "aws_secretsmanager_secret" "jwt_v2" {
  name       = "${var.name}/jwt-secret/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "jwt_v2" {
  secret_id     = aws_secretsmanager_secret.jwt_v2.id
  secret_string = random_password.jwt_v2.result
}

resource "aws_secretsmanager_secret" "session" {
  name       = "${var.name}/session-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "session" {
  secret_id     = aws_secretsmanager_secret.session.id
  secret_string = random_password.session.result
}

resource "aws_secretsmanager_secret" "session_v2" {
  name       = "${var.name}/session-secret/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "session_v2" {
  secret_id     = aws_secretsmanager_secret.session_v2.id
  secret_string = random_password.session_v2.result
}

resource "aws_secretsmanager_secret" "envelope" {
  name       = "${var.name}/envelope-key/v1"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "envelope" {
  secret_id     = aws_secretsmanager_secret.envelope.id
  secret_string = random_password.envelope.result
}

resource "aws_secretsmanager_secret" "envelope_v2" {
  name       = "${var.name}/envelope-key/v2"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "envelope_v2" {
  secret_id     = aws_secretsmanager_secret.envelope_v2.id
  secret_string = random_password.envelope_v2.result
}

resource "aws_secretsmanager_secret" "bootstrap_database_url" {
  name       = "${var.name}/bootstrap-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "bootstrap_database_url" {
  secret_id     = aws_secretsmanager_secret.bootstrap_database_url.id
  secret_string = "postgresql+psycopg://authclaw:${local.db_password}@${local.db_address}:5432/authclaw?sslmode=require"
}

resource "aws_secretsmanager_secret" "backend_migration_database_url" {
  name       = "${var.name}/backend-migration-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "backend_migration_database_url" {
  secret_id     = aws_secretsmanager_secret.backend_migration_database_url.id
  secret_string = "postgresql+psycopg://authclaw_migrator:${random_password.backend_migrator_db.result}@${local.db_address}:5432/authclaw?sslmode=require"
}
resource "aws_secretsmanager_secret" "backend_database_url" {
  name       = "${var.name}/backend-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "backend_database_url" {
  secret_id     = aws_secretsmanager_secret.backend_database_url.id
  secret_string = "postgresql+psycopg://authclaw_app:${random_password.backend_app_db.result}@${local.db_address}:5432/authclaw?sslmode=require"
}

resource "aws_secretsmanager_secret" "app_database_url" {
  name       = "${var.name}/app-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "app_database_url" {
  secret_id     = aws_secretsmanager_secret.app_database_url.id
  secret_string = "postgresql://authclaw_app:${random_password.backend_app_db.result}@${local.db_address}:5432/authclaw?sslmode=require"
}

resource "aws_secretsmanager_secret" "agent_migration_database_url" {
  name       = "${var.name}/agent-migration-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "agent_migration_database_url" {
  secret_id     = aws_secretsmanager_secret.agent_migration_database_url.id
  secret_string = "postgresql://authclaw_agent_migrator:${random_password.agent_migrator_db.result}@${local.db_address}:5432/authclaw?sslmode=require"
}
resource "aws_secretsmanager_secret" "agent_database_url" {
  name       = "${var.name}/agent-database-url"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "agent_database_url" {
  secret_id     = aws_secretsmanager_secret.agent_database_url.id
  secret_string = "postgresql://authclaw_agent_runtime:${random_password.agent_runtime_db.result}@${local.db_address}:5432/authclaw?sslmode=require"
}

resource "aws_secretsmanager_secret" "internal_service" {
  name       = "${var.name}/internal-service-secret"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "internal_service" {
  secret_id     = aws_secretsmanager_secret.internal_service.id
  secret_string = random_password.internal_service.result
}

resource "aws_secretsmanager_secret" "agent_encryption" {
  name       = "${var.name}/agent-encryption-key"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "agent_encryption" {
  secret_id     = aws_secretsmanager_secret.agent_encryption.id
  secret_string = replace(replace(random_id.agent_encryption.b64_std, "+", "-"), "/", "_")
}

resource "aws_secretsmanager_secret" "agent_redaction" {
  name       = "${var.name}/agent-redaction-salt"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "agent_redaction" {
  secret_id     = aws_secretsmanager_secret.agent_redaction.id
  secret_string = random_password.agent_redaction.result
}

resource "aws_secretsmanager_secret" "clickhouse_password" {
  count      = var.clickhouse_password != "" ? 1 : 0
  name       = "${var.name}/clickhouse-password"
  kms_key_id = aws_kms_key.main.arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "clickhouse_password" {
  count         = var.clickhouse_password != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.clickhouse_password[0].id
  secret_string = var.clickhouse_password
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
  for_each          = toset(concat(keys(local.task_definition_configs), var.enable_audit_consumer ? ["audit_consumer"] : []))
  name              = "/authclaw/${var.name}/${each.key}"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_iam_role" "task_execution" {
  name = "${var.name}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_secrets" {
  name = "${var.name}-ecs-secrets"
  role = aws_iam_role.task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = concat([
          aws_secretsmanager_secret.jwt.arn,
          aws_secretsmanager_secret.jwt_v2.arn,
          aws_secretsmanager_secret.session.arn,
          aws_secretsmanager_secret.session_v2.arn,
          aws_secretsmanager_secret.envelope.arn,
          aws_secretsmanager_secret.envelope_v2.arn,
          aws_secretsmanager_secret.bootstrap_database_url.arn,
          aws_secretsmanager_secret.backend_migration_database_url.arn, aws_secretsmanager_secret.backend_database_url.arn,
          aws_secretsmanager_secret.app_database_url.arn,
          aws_secretsmanager_secret.agent_migration_database_url.arn,
          aws_secretsmanager_secret.agent_database_url.arn,
          aws_secretsmanager_secret.internal_service.arn,
          aws_secretsmanager_secret.bff_client_ip.arn,
          aws_secretsmanager_secret.oidc_bff_exchange.arn,
          aws_secretsmanager_secret.agent_encryption.arn,
          aws_secretsmanager_secret.agent_redaction.arn,
          aws_kms_key.main.arn
        ], var.clickhouse_password != "" ? [aws_secretsmanager_secret.clickhouse_password[0].arn] : [])
      }
    ]
  })
}

resource "aws_lb" "main" {
  name = substr(replace("${var.name}-alb", "_", "-"), 0, 32)
  #trivy:ignore:AVD-AWS-0053 This ALB is the intentional public ingress for console/API/gateway traffic; private services are not attached.
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = values(aws_subnet.public)[*].id
  drop_invalid_header_fields = true
  xff_header_processing_mode = "append"
  enable_xff_client_port     = false
  tags                       = var.tags
}

resource "aws_lb_target_group" "service" {
  for_each = local.public_services

  name        = substr(replace("${var.name}-${each.key}", "_", "-"), 0, 32)
  port        = each.value.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
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

  load_balancer_arn = aws_lb.main.arn
  port              = each.value.listener_port
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
  for_each                 = local.database_jobs
  family                   = "${var.name}-database-${replace(each.key, "_", "-")}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.service_cpu
  memory                   = var.service_memory
  execution_role_arn       = aws_iam_role.task_execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, each.key == "agent_migrations" ? "agent" : "backend", "X86_64")
  }

  container_definitions = jsonencode([{
    name        = each.key
    image       = each.value.image
    essential   = true
    command     = each.value.command
    environment = each.value.environment
    secrets     = each.value.secrets
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
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.service_cpu
  memory                   = var.service_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = lookup(local.audit_sqs_task_role_arns, each.key, null)

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, each.key, "X86_64")
  }

  container_definitions = jsonencode([
    merge({
      name      = each.key
      image     = each.value.image
      essential = true
      portMappings = [{
        containerPort = each.value.container_port
        protocol      = "tcp"
      }]
      environment = concat(
        local.common_environment,
        each.key == "console" ? [
          { name = "AUTHCLAW_BFF_CLIENT_IP_ENABLED", value = tostring(var.bff_client_ip_signing_enabled) },
          { name = "AUTHCLAW_OIDC_LOGIN_PAUSED", value = tostring(var.oidc_login_paused) },
          { name = "API_URL", value = local.api_base_url },
          { name = "AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY", value = "true" }
        ] : [],
        contains(tolist(local.audit_sqs_producer_services), each.key) ? local.audit_sqs_producer_environment : [],
        each.key == "gateway" ? [
          { name = "REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS", value = "60000" }
        ] : [],
        each.key == "backend" ? [
          { name = "AUTHCLAW_BFF_CLIENT_IP_ENABLED", value = tostring(var.bff_client_ip_enabled) },
          { name = "AUTHCLAW_RUNTIME_DB_ROLE", value = "authclaw_app" }
        ] : [],
        each.key == "agent" ? [
          { name = "AUTHCLAW_DATABASE_SCHEMA", value = "agent" },
          { name = "AUTHCLAW_RUNTIME_DB_ROLE", value = "authclaw_agent_runtime" }
        ] : []
      )
      secrets = concat(
        contains(["console", "backend"], each.key) ? [
          { name = "BFF_CLIENT_IP_SECRET", valueFrom = aws_secretsmanager_secret.bff_client_ip.arn },
          { name = "OIDC_BFF_EXCHANGE_SECRET", valueFrom = aws_secretsmanager_secret.oidc_bff_exchange.arn }
        ] : [],
        contains(["backend", "gateway", "console"], each.key) ? [
          { name = "DATABASE_URL", valueFrom = each.key == "backend" ? aws_secretsmanager_secret.backend_database_url.arn : aws_secretsmanager_secret.app_database_url.arn },
          { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
          { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
          { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
          { name = "SESSION_SECRET", valueFrom = var.session_key_version == "v2" ? aws_secretsmanager_secret.session_v2.arn : aws_secretsmanager_secret.session.arn },
          { name = "SESSION_SECRET_V1", valueFrom = aws_secretsmanager_secret.session.arn },
          { name = "SESSION_SECRET_V2", valueFrom = aws_secretsmanager_secret.session_v2.arn },
          { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
          { name = "ENVELOPE_KEY_V1", valueFrom = aws_secretsmanager_secret.envelope.arn },
          { name = "ENVELOPE_KEY_V2", valueFrom = aws_secretsmanager_secret.envelope_v2.arn }
        ] : [],
        contains(["console", "agent"], each.key) ? [
          { name = "AUTHCLAW_INTERNAL_SERVICE_SECRET", valueFrom = aws_secretsmanager_secret.internal_service.arn }
        ] : [],
        each.key == "gateway" ? [
          { name = "REDACTION_HASH_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
        ] : [],
        each.key == "agent" ? [
          { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn },
          { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
          { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
          { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
          { name = "AUTHCLAW_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.agent_encryption.arn },
          { name = "AUTHCLAW_REDACTION_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
        ] : []
      )
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service[each.key].name
          awslogs-region        = var.region
          awslogs-stream-prefix = each.key
        }
      }
      },
      each.value.command == null ? {} : { command = each.value.command },
      each.key == "agent" ? {
        healthCheck = {
          command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/v1/agent/health/ready', timeout=3)\""]
          interval    = 30
          timeout     = 5
          retries     = 3
          startPeriod = 30
        }
      } : {}
    )
  ])

  lifecycle {
    precondition {
      condition     = !var.bff_client_ip_signing_enabled || var.bff_client_ip_enabled
      error_message = "Enable backend client-identity verification before console signing."
    }
    precondition {
      condition = var.authclaw_env != "production" || alltrue([
        startswith(local.internal_agent_url, "https://"),
        local.internal_opa_url == "http://127.0.0.1:8181",
        local.internal_presidio_url == "http://127.0.0.1:3000",
        startswith("http://gateway.${local.namespace_name}:8080", "https://")
      ])
      error_message = "Production requires HTTPS for remote agent/gateway calls and exact task-local loopback HTTP endpoints for OPA and Presidio."
    }
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "gateway_with_sidecars" {
  family                   = "${var.name}-gateway-sidecars"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.gateway_sidecar_task_cpu
  memory                   = var.gateway_sidecar_task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, "gateway", "X86_64")
  }

  container_definitions = jsonencode([
    {
      name              = "gateway"
      image             = var.container_images.gateway
      essential         = true
      cpu               = 768
      memory            = 1280
      memoryReservation = 1024
      portMappings = [{
        containerPort = 8080
        protocol      = "tcp"
      }]
      environment = concat(local.common_environment, [
        { name = "REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS", value = "60000" },
        { name = "PRESIDIO_FAIL_CLOSED", value = "true" }
      ])
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.app_database_url.arn },
        { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
        { name = "SESSION_SECRET", valueFrom = var.session_key_version == "v2" ? aws_secretsmanager_secret.session_v2.arn : aws_secretsmanager_secret.session.arn },
        { name = "SESSION_SECRET_V1", valueFrom = aws_secretsmanager_secret.session.arn },
        { name = "SESSION_SECRET_V2", valueFrom = aws_secretsmanager_secret.session_v2.arn },
        { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V1", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V2", valueFrom = aws_secretsmanager_secret.envelope_v2.arn },
        { name = "REDACTION_HASH_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
      ]
      dependsOn = [
        { containerName = "opa", condition = "HEALTHY" },
        { containerName = "presidio", condition = "HEALTHY" }
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "wget -q -O - http://127.0.0.1:8080/health >/dev/null || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["gateway"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "gateway"
        }
      }
    },
    {
      name              = "opa"
      image             = var.container_images.opa
      essential         = true
      cpu               = 256
      memory            = 384
      memoryReservation = 256
      command           = ["run", "--server", "--addr=127.0.0.1:8181", "/policies"]
      healthCheck = {
        command     = ["CMD", "/healthcheck"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["opa"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "gateway-opa"
        }
      }
    },
    {
      name              = "presidio"
      image             = var.container_images.presidio
      essential         = true
      cpu               = 768
      memory            = 2048
      memoryReservation = 1536
      healthCheck = {
        command     = ["CMD-SHELL", "curl -fsS http://127.0.0.1:3000/health >/dev/null || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["presidio"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "gateway-presidio"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.internal_opa_url == "http://127.0.0.1:8181" && local.internal_presidio_url == "http://127.0.0.1:3000"
      error_message = "Gateway sidecars must use the exact task-local OPA and Presidio loopback endpoints."
    }
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "backend_with_presidio" {
  family                   = "${var.name}-backend-presidio"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.backend_sidecar_task_cpu
  memory                   = var.backend_sidecar_task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, "backend", "X86_64")
  }

  container_definitions = jsonencode([
    {
      name              = "backend"
      image             = var.container_images.backend
      essential         = true
      cpu               = 768
      memory            = 1536
      memoryReservation = 1024
      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]
      environment = concat(local.common_environment, [
        { name = "AUTHCLAW_BFF_CLIENT_IP_ENABLED", value = tostring(var.bff_client_ip_enabled) },
        { name = "AGENT_AUDIT_STREAM_TRANSPORT", value = "kafka" }
      ])
      secrets = concat([
        { name = "BFF_CLIENT_IP_SECRET", valueFrom = aws_secretsmanager_secret.bff_client_ip.arn },
        { name = "OIDC_BFF_EXCHANGE_SECRET", valueFrom = aws_secretsmanager_secret.oidc_bff_exchange.arn },
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.backend_database_url.arn },
        { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
        { name = "SESSION_SECRET", valueFrom = var.session_key_version == "v2" ? aws_secretsmanager_secret.session_v2.arn : aws_secretsmanager_secret.session.arn },
        { name = "SESSION_SECRET_V1", valueFrom = aws_secretsmanager_secret.session.arn },
        { name = "SESSION_SECRET_V2", valueFrom = aws_secretsmanager_secret.session_v2.arn },
        { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V1", valueFrom = aws_secretsmanager_secret.envelope.arn },
        { name = "ENVELOPE_KEY_V2", valueFrom = aws_secretsmanager_secret.envelope_v2.arn }
        ], var.clickhouse_password != "" ? [
        { name = "CLICKHOUSE_PASSWORD", valueFrom = aws_secretsmanager_secret.clickhouse_password[0].arn }
      ] : [])
      dependsOn = [{ containerName = "presidio", condition = "HEALTHY" }]
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["backend"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "backend"
        }
      }
    },
    {
      name              = "presidio"
      image             = var.container_images.presidio
      essential         = true
      cpu               = 1024
      memory            = 2048
      memoryReservation = 1536
      healthCheck = {
        command     = ["CMD-SHELL", "curl -fsS http://127.0.0.1:3000/health >/dev/null || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["presidio"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "backend-presidio"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.internal_presidio_url == "http://127.0.0.1:3000"
      error_message = "Backend must use its task-local Presidio loopback endpoint."
    }
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "agent_with_opa" {
  family                   = "${var.name}-agent-opa"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.agent_sidecar_task_cpu
  memory                   = var.agent_sidecar_task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, "agent", "X86_64")
  }

  container_definitions = jsonencode([
    {
      name              = "agent"
      image             = var.container_images.agent
      essential         = true
      cpu               = 768
      memory            = 1536
      memoryReservation = 1024
      portMappings = [{
        containerPort = 8001
        protocol      = "tcp"
      }]
      environment = local.common_environment
      secrets = [
        { name = "AUTHCLAW_INTERNAL_SERVICE_SECRET", valueFrom = aws_secretsmanager_secret.internal_service.arn },
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn },
        { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
        { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
        { name = "AUTHCLAW_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.agent_encryption.arn },
        { name = "AUTHCLAW_REDACTION_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
      ]
      dependsOn = [{ containerName = "opa", condition = "HEALTHY" }]
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/v1/agent/health/ready', timeout=3)\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["agent"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "agent"
        }
      }
    },
    {
      name              = "opa"
      image             = var.container_images.opa
      essential         = true
      cpu               = 256
      memory            = 384
      memoryReservation = 256
      command           = ["run", "--server", "--addr=127.0.0.1:8181", "/policies"]
      healthCheck = {
        command     = ["CMD", "/healthcheck"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["opa"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "agent-opa"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.internal_opa_url == "http://127.0.0.1:8181"
      error_message = "Agent must use its task-local OPA loopback endpoint."
    }
  }

  tags = var.tags
}

resource "aws_ecs_service" "public" {
  for_each = local.public_services

  name            = "${var.name}-${each.key}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = each.key == "gateway" ? aws_ecs_task_definition.gateway_with_sidecars.arn : each.key == "backend" ? aws_ecs_task_definition.backend_with_presidio.arn : aws_ecs_task_definition.service[each.key].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = each.key == "console" ? [aws_security_group.console_ingress.id] : [aws_security_group.app.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.service[each.key].arn
    container_name   = each.key
    container_port   = each.value.container_port
  }

  service_registries {
    registry_arn = aws_service_discovery_service.service[each.key].arn
  }

  depends_on = [aws_lb_listener.service]
  tags       = var.tags
}

resource "aws_ecs_service" "private" {
  for_each = local.private_services

  name            = "${var.name}-${each.key}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = each.key == "agent" ? aws_ecs_task_definition.agent_with_opa.arn : aws_ecs_task_definition.service[each.key].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.service[each.key].arn
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "audit_consumer" {
  count = var.enable_audit_consumer ? 1 : 0

  family                   = "${var.name}-audit-consumer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.service_cpu
  memory                   = var.service_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = lookup(local.audit_sqs_task_role_arns, "audit_consumer", null)

  lifecycle {
    precondition {
      condition = (
        trimspace(var.clickhouse_password) != "" &&
        lower(var.clickhouse_password) != "authclaw" &&
        !strcontains(lower(var.clickhouse_password), "change-me")
      )
      error_message = "clickhouse_password must be a non-default secret when enable_audit_consumer is true."
    }
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = lookup(var.service_cpu_architectures, "audit_consumer", "X86_64")
  }

  container_definitions = jsonencode([
    {
      name      = "audit_consumer"
      image     = var.container_images.audit_consumer
      essential = true
      environment = concat(local.common_environment, local.audit_sqs_environment, local.audit_sqs_consumer_environment, [
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
      secrets = var.clickhouse_password != "" ? [
        { name = "CLICKHOUSE_PASSWORD", valueFrom = aws_secretsmanager_secret.clickhouse_password[0].arn }
      ] : []
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

  name            = "${var.name}-audit-consumer"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.audit_consumer[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  tags = var.tags
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

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.service[each.key].arn_suffix
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  for_each = local.service_configs

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

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = "${var.name}-${each.key}"
  }

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
