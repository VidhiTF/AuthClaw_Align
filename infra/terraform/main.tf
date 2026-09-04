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

  name                                 = "${local.name}-primary"
  environment                          = var.environment
  region                               = var.primary_region
  vpc_cidr                             = var.primary_vpc_cidr
  availability_zones                   = var.primary_availability_zones
  nat_gateway_mode                     = var.nat_gateway_mode
  enable_private_aws_endpoints         = var.enable_private_aws_endpoints
  container_images                     = var.container_images
  service_cpu_architectures            = var.service_cpu_architectures
  desired_count                        = var.desired_count_primary
  gateway_sidecar_task_cpu             = var.gateway_sidecar_task_cpu
  gateway_sidecar_task_memory          = var.gateway_sidecar_task_memory
  backend_sidecar_task_cpu             = var.backend_sidecar_task_cpu
  backend_sidecar_task_memory          = var.backend_sidecar_task_memory
  agent_sidecar_task_cpu               = var.agent_sidecar_task_cpu
  agent_sidecar_task_memory            = var.agent_sidecar_task_memory
  is_primary                           = true
  create_db_replica                    = false
  authclaw_env                         = var.authclaw_env
  forwarded_header_mode                = var.forwarded_header_mode
  bff_client_ip_enabled                = var.bff_client_ip_enabled
  bff_client_ip_signing_enabled        = var.bff_client_ip_signing_enabled
  bff_client_ip_secret                 = random_password.bff_client_ip.result
  secret_key_version                   = var.secret_key_version
  jwt_key_version                      = var.jwt_key_version
  session_key_version                  = var.session_key_version
  certificate_arn                      = var.primary_certificate_arn != "" ? var.primary_certificate_arn : var.certificate_arn
  domain_name                          = var.domain_name
  smtp_host                            = var.smtp_host
  smtp_from                            = var.smtp_from
  kafka_brokers                        = var.kafka_brokers
  audit_stream_transport               = var.audit_stream_transport
  audit_sqs_max_receive_count          = var.audit_sqs_max_receive_count
  audit_sqs_retention_seconds          = var.audit_sqs_retention_seconds
  audit_sqs_dlq_retention_seconds      = var.audit_sqs_dlq_retention_seconds
  audit_sqs_long_poll_seconds          = var.audit_sqs_long_poll_seconds
  audit_sqs_max_messages               = var.audit_sqs_max_messages
  audit_sqs_visibility_timeout_seconds = var.audit_sqs_visibility_timeout_seconds
  audit_sqs_dlq_depth_alarm_threshold  = var.audit_sqs_dlq_depth_alarm_threshold
  audit_sqs_dlq_age_alarm_seconds      = var.audit_sqs_dlq_age_alarm_seconds
  audit_sqs_main_age_alarm_seconds     = var.audit_sqs_main_age_alarm_seconds
  audit_sqs_backlog_alarm_threshold    = var.audit_sqs_backlog_alarm_threshold
  audit_sqs_alarm_action_arns          = var.audit_sqs_alarm_action_arns
  audit_sqs_require_alarm_actions      = var.audit_sqs_require_alarm_actions
  clickhouse_host                      = var.clickhouse_host
  clickhouse_port                      = var.clickhouse_port
  clickhouse_db                        = var.clickhouse_db
  clickhouse_user                      = var.clickhouse_user
  clickhouse_password                  = var.clickhouse_password
  enable_audit_consumer                = var.enable_audit_consumer
  replica_source_db_arn                = ""
  tags                                 = local.tags
}

module "secondary" {
  count  = var.enable_secondary ? 1 : 0
  source = "./modules/regional_stack"

  providers = {
    aws = aws.secondary
  }

  name                                 = "${local.name}-secondary"
  environment                          = var.environment
  region                               = var.secondary_region
  vpc_cidr                             = var.secondary_vpc_cidr
  availability_zones                   = var.secondary_availability_zones
  nat_gateway_mode                     = var.nat_gateway_mode
  enable_private_aws_endpoints         = var.enable_private_aws_endpoints
  container_images                     = var.container_images
  service_cpu_architectures            = var.service_cpu_architectures
  desired_count                        = var.desired_count_secondary
  gateway_sidecar_task_cpu             = var.gateway_sidecar_task_cpu
  gateway_sidecar_task_memory          = var.gateway_sidecar_task_memory
  backend_sidecar_task_cpu             = var.backend_sidecar_task_cpu
  backend_sidecar_task_memory          = var.backend_sidecar_task_memory
  agent_sidecar_task_cpu               = var.agent_sidecar_task_cpu
  agent_sidecar_task_memory            = var.agent_sidecar_task_memory
  is_primary                           = false
  create_db_replica                    = var.enable_cross_region_db_replica
  authclaw_env                         = var.authclaw_env
  forwarded_header_mode                = var.forwarded_header_mode
  bff_client_ip_enabled                = var.bff_client_ip_enabled
  bff_client_ip_signing_enabled        = var.bff_client_ip_signing_enabled
  bff_client_ip_secret                 = random_password.bff_client_ip.result
  secret_key_version                   = var.secret_key_version
  jwt_key_version                      = var.jwt_key_version
  session_key_version                  = var.session_key_version
  certificate_arn                      = var.secondary_certificate_arn != "" ? var.secondary_certificate_arn : var.certificate_arn
  domain_name                          = var.domain_name
  smtp_host                            = var.smtp_host
  smtp_from                            = var.smtp_from
  kafka_brokers                        = var.kafka_brokers
  audit_stream_transport               = var.audit_stream_transport
  audit_sqs_max_receive_count          = var.audit_sqs_max_receive_count
  audit_sqs_retention_seconds          = var.audit_sqs_retention_seconds
  audit_sqs_dlq_retention_seconds      = var.audit_sqs_dlq_retention_seconds
  audit_sqs_long_poll_seconds          = var.audit_sqs_long_poll_seconds
  audit_sqs_max_messages               = var.audit_sqs_max_messages
  audit_sqs_visibility_timeout_seconds = var.audit_sqs_visibility_timeout_seconds
  audit_sqs_dlq_depth_alarm_threshold  = var.audit_sqs_dlq_depth_alarm_threshold
  audit_sqs_dlq_age_alarm_seconds      = var.audit_sqs_dlq_age_alarm_seconds
  audit_sqs_main_age_alarm_seconds     = var.audit_sqs_main_age_alarm_seconds
  audit_sqs_backlog_alarm_threshold    = var.audit_sqs_backlog_alarm_threshold
  audit_sqs_alarm_action_arns          = var.audit_sqs_alarm_action_arns
  audit_sqs_require_alarm_actions      = var.audit_sqs_require_alarm_actions
  clickhouse_host                      = var.clickhouse_host
  clickhouse_port                      = var.clickhouse_port
  clickhouse_db                        = var.clickhouse_db
  clickhouse_user                      = var.clickhouse_user
  clickhouse_password                  = var.clickhouse_password
  enable_audit_consumer                = var.enable_audit_consumer
  replica_source_db_arn                = var.enable_cross_region_db_replica ? module.primary.rds_instance_arn : ""
  db_password                          = var.enable_cross_region_db_replica ? module.primary.db_password : ""
  tags                                 = local.tags
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
