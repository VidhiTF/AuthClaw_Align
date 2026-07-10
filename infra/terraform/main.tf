locals {
  name = "${var.project}-${var.environment}"
  tags = merge(var.tags, {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    SRS         = "NFR-3.1"
  })
}

module "primary" {
  source = "./modules/regional_stack"

  providers = {
    aws = aws.primary
  }

  name                  = "${local.name}-primary"
  environment           = var.environment
  region                = var.primary_region
  vpc_cidr              = var.primary_vpc_cidr
  availability_zones    = var.primary_availability_zones
  container_images      = var.container_images
  desired_count         = var.desired_count_primary
  is_primary            = true
  create_db_replica     = false
  authclaw_env          = var.authclaw_env
  certificate_arn       = var.primary_certificate_arn != "" ? var.primary_certificate_arn : var.certificate_arn
  domain_name           = var.domain_name
  smtp_host             = var.smtp_host
  smtp_from             = var.smtp_from
  kafka_brokers         = var.kafka_brokers
  clickhouse_host       = var.clickhouse_host
  clickhouse_port       = var.clickhouse_port
  clickhouse_db         = var.clickhouse_db
  clickhouse_user       = var.clickhouse_user
  clickhouse_password   = var.clickhouse_password
  enable_audit_consumer = var.enable_audit_consumer
  replica_source_db_arn = ""
  tags                  = local.tags
}

module "secondary" {
  count  = var.enable_secondary ? 1 : 0
  source = "./modules/regional_stack"

  providers = {
    aws = aws.secondary
  }

  name                  = "${local.name}-secondary"
  environment           = var.environment
  region                = var.secondary_region
  vpc_cidr              = var.secondary_vpc_cidr
  availability_zones    = var.secondary_availability_zones
  container_images      = var.container_images
  desired_count         = var.desired_count_secondary
  is_primary            = false
  create_db_replica     = var.enable_cross_region_db_replica
  authclaw_env          = var.authclaw_env
  certificate_arn       = var.secondary_certificate_arn != "" ? var.secondary_certificate_arn : var.certificate_arn
  domain_name           = var.domain_name
  smtp_host             = var.smtp_host
  smtp_from             = var.smtp_from
  kafka_brokers         = var.kafka_brokers
  clickhouse_host       = var.clickhouse_host
  clickhouse_port       = var.clickhouse_port
  clickhouse_db         = var.clickhouse_db
  clickhouse_user       = var.clickhouse_user
  clickhouse_password   = var.clickhouse_password
  enable_audit_consumer = var.enable_audit_consumer
  replica_source_db_arn = var.enable_cross_region_db_replica ? module.primary.rds_instance_arn : ""
  db_password           = var.enable_cross_region_db_replica ? module.primary.db_password : ""
  tags                  = local.tags
}

resource "aws_route53_record" "console_primary" {
  provider = aws.primary
  count    = var.hosted_zone_id != "" && var.domain_name != "" ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  set_identifier = "primary"
  failover_routing_policy {
    type = "PRIMARY"
  }

  alias {
    name                   = module.primary.alb_dns_name
    zone_id                = module.primary.alb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "console_secondary" {
  provider = aws.primary
  count    = var.enable_secondary && var.hosted_zone_id != "" && var.domain_name != "" ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  set_identifier = "secondary"
  failover_routing_policy {
    type = "SECONDARY"
  }

  alias {
    name                   = module.secondary[0].alb_dns_name
    zone_id                = module.secondary[0].alb_zone_id
    evaluate_target_health = true
  }
}
