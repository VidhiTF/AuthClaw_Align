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
  direct_aws                   = var.direct_aws
  internal_tls                 = var.internal_tls
  iam_account_id               = var.ci_skip_aws_validation ? "123456789012" : null
  kms_break_glass_role_arns    = var.kms_break_glass_role_arns
  agent_customer_role_arns     = var.agent_customer_role_arns
  iam_permissions_boundary_arn = var.iam_permissions_boundary_arn
  source                       = "./modules/regional_stack"
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
  gateway_sidecar_task_cpu             = var.gateway_sidecar_task_cpu
  gateway_sidecar_task_memory          = var.gateway_sidecar_task_memory
  enable_policy_sidecar_colocation     = var.enable_policy_sidecar_colocation
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
  enable_audit_consumer                = var.enable_audit_consumer
  replica_source_db_arn                = ""
  tags                                 = local.tags
}

module "secondary" {
  direct_aws                   = var.secondary_direct_aws
  internal_tls                 = var.internal_tls
  iam_account_id               = var.ci_skip_aws_validation ? "123456789012" : null
  kms_break_glass_role_arns    = var.kms_break_glass_role_arns
  agent_customer_role_arns     = var.agent_customer_role_arns
  iam_permissions_boundary_arn = var.iam_permissions_boundary_arn
  count                        = var.enable_secondary ? 1 : 0
  source                       = "./modules/regional_stack"
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
  gateway_sidecar_task_cpu             = var.gateway_sidecar_task_cpu
  gateway_sidecar_task_memory          = var.gateway_sidecar_task_memory
  enable_policy_sidecar_colocation     = var.enable_policy_sidecar_colocation
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
  enable_audit_consumer                = var.enable_audit_consumer
  replica_source_db_arn                = var.enable_cross_region_db_replica ? module.primary.rds_instance_arn : ""
  tags                                 = local.tags
}
