locals {
  name          = "${var.project}-${var.environment}"
  is_production = contains(["prod", "production"], lower(trimspace(var.environment))) || contains(["prod", "production"], lower(trimspace(var.authclaw_env))) || var.public_url_environment == "production"
  approved_public_domains = var.public_url_environment == "production" ? {
    marketing = "authclaw.ai"
    www       = "www.authclaw.ai"
    console   = "app.authclaw.ai"
    api       = "api.authclaw.ai"
    gateway   = "gateway.authclaw.ai"
    } : {
    marketing = "dev.authclaw.ai"
    www       = ""
    console   = "dev.authclaw.ai"
    api       = "api.dev.authclaw.ai"
    gateway   = "gateway.dev.authclaw.ai"
  }
  tags = merge(var.tags, {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    SRS         = "NFR-3.1"
  })
}

module "primary" {
  source                       = "./modules/regional_stack"
  oidc_bff_exchange_secret     = random_password.oidc_bff_exchange.result
  worker_token_hmac_secret     = random_password.worker_token_hmac.result
  worker_token_issuance_paused = var.worker_token_issuance_paused
  oidc_login_paused            = var.oidc_login_paused

  providers = {
    aws = aws.primary
  }

  name                                 = "${local.name}-primary"
  environment                          = var.environment
  region                               = var.primary_region
  aws_account_id                       = var.aws_account_id
  vpc_cidr                             = var.primary_vpc_cidr
  availability_zones                   = var.primary_availability_zones
  nat_gateway_mode                     = var.nat_gateway_mode
  enable_private_aws_endpoints         = var.enable_private_aws_endpoints
  runtime_s3_bucket_arns               = var.runtime_s3_bucket_arns
  runtime_kms_key_arns                 = var.runtime_kms_key_arns
  runtime_secrets_manager_secret_arns  = var.runtime_secrets_manager_secret_arns
  runtime_sts_assume_role_arns         = var.runtime_sts_assume_role_arns
  vpc_endpoint_external_principal_arns = var.vpc_endpoint_external_principal_arns
  container_images                     = var.container_images
  ecr_repository_arns                  = toset(values(aws_ecr_repository.service)[*].arn)
  service_cpu_architectures            = var.service_cpu_architectures
  ecs_ec2_graviton                     = var.ecs_ec2_graviton
  desired_count                        = var.desired_count_primary
  service_min_capacity                 = var.service_min_capacity
  service_max_capacity                 = var.service_max_capacity
  service_cpu_target                   = var.service_cpu_target
  service_memory_target                = var.service_memory_target
  alb_requests_per_target              = var.alb_requests_per_target
  scale_out_cooldown_seconds           = var.scale_out_cooldown_seconds
  scale_in_cooldown_seconds            = var.scale_in_cooldown_seconds
  deployment_minimum_healthy_percent   = var.deployment_minimum_healthy_percent
  deployment_maximum_percent           = var.deployment_maximum_percent
  health_check_grace_period_seconds    = var.health_check_grace_period_seconds
  alb_deregistration_delay_seconds     = var.alb_deregistration_delay_seconds
  service_log_retention_days           = var.service_log_retention_days
  db_connections_per_task              = var.db_connections_per_task
  rds_max_connections                  = var.rds_max_connections
  rds_connection_reserve               = var.rds_connection_reserve
  rds_slow_query_milliseconds          = var.rds_slow_query_milliseconds
  audit_sqs_scale_out_backlog          = var.audit_sqs_scale_out_backlog
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
  enable_public_edge                   = var.enable_public_edge
  public_domain_names = {
    console = local.approved_public_domains.console
    api     = local.approved_public_domains.api
    gateway = local.approved_public_domains.gateway
  }
  public_url_environment               = var.public_url_environment
  alb_access_log_retention_days        = var.edge_log_retention_days
  edge_alarm_action_arns               = var.edge_alarm_action_arns
  alarm_owner                          = var.alarm_owner
  alarm_acknowledgement_minutes        = var.alarm_acknowledgement_minutes
  alarm_escalation_path                = var.alarm_escalation_path
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
  count                        = var.enable_secondary ? 1 : 0
  source                       = "./modules/regional_stack"
  oidc_bff_exchange_secret     = random_password.oidc_bff_exchange.result
  worker_token_hmac_secret     = random_password.worker_token_hmac.result
  worker_token_issuance_paused = var.worker_token_issuance_paused
  oidc_login_paused            = var.oidc_login_paused

  providers = {
    aws = aws.secondary
  }

  name                                 = "${local.name}-secondary"
  environment                          = var.environment
  region                               = var.secondary_region
  aws_account_id                       = var.aws_account_id
  vpc_cidr                             = var.secondary_vpc_cidr
  availability_zones                   = var.secondary_availability_zones
  nat_gateway_mode                     = var.nat_gateway_mode
  enable_private_aws_endpoints         = var.enable_private_aws_endpoints
  runtime_s3_bucket_arns               = var.runtime_s3_bucket_arns
  runtime_kms_key_arns                 = var.runtime_kms_key_arns
  runtime_secrets_manager_secret_arns  = var.runtime_secrets_manager_secret_arns
  runtime_sts_assume_role_arns         = var.runtime_sts_assume_role_arns
  vpc_endpoint_external_principal_arns = var.vpc_endpoint_external_principal_arns
  container_images                     = var.container_images
  ecr_repository_arns                  = toset(values(aws_ecr_repository.service)[*].arn)
  service_cpu_architectures            = var.service_cpu_architectures
  ecs_ec2_graviton                     = var.ecs_ec2_graviton
  desired_count                        = var.desired_count_secondary
  service_min_capacity                 = var.service_min_capacity
  service_max_capacity                 = var.service_max_capacity
  service_cpu_target                   = var.service_cpu_target
  service_memory_target                = var.service_memory_target
  alb_requests_per_target              = var.alb_requests_per_target
  scale_out_cooldown_seconds           = var.scale_out_cooldown_seconds
  scale_in_cooldown_seconds            = var.scale_in_cooldown_seconds
  deployment_minimum_healthy_percent   = var.deployment_minimum_healthy_percent
  deployment_maximum_percent           = var.deployment_maximum_percent
  health_check_grace_period_seconds    = var.health_check_grace_period_seconds
  alb_deregistration_delay_seconds     = var.alb_deregistration_delay_seconds
  service_log_retention_days           = var.service_log_retention_days
  db_connections_per_task              = var.db_connections_per_task
  rds_max_connections                  = var.rds_max_connections
  rds_connection_reserve               = var.rds_connection_reserve
  rds_slow_query_milliseconds          = var.rds_slow_query_milliseconds
  audit_sqs_scale_out_backlog          = var.audit_sqs_scale_out_backlog
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
  enable_public_edge                   = var.enable_public_edge
  public_domain_names = {
    console = local.approved_public_domains.console
    api     = local.approved_public_domains.api
    gateway = local.approved_public_domains.gateway
  }
  public_url_environment               = var.public_url_environment
  alb_access_log_retention_days        = var.edge_log_retention_days
  edge_alarm_action_arns               = var.edge_alarm_action_arns
  alarm_owner                          = var.alarm_owner
  alarm_acknowledgement_minutes        = var.alarm_acknowledgement_minutes
  alarm_escalation_path                = var.alarm_escalation_path
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
