output "alb_dns_name" {
  value = aws_lb.service["console"].dns_name
}

output "alb_zone_id" {
  value = aws_lb.service["console"].zone_id
}

output "origin_load_balancers" {
  value = {
    for service, load_balancer in aws_lb.service : service => {
      arn      = load_balancer.arn
      dns_name = load_balancer.dns_name
      zone_id  = load_balancer.zone_id
      internal = load_balancer.internal
    }
  }
}

output "origin_ingress_boundary" {
  value = {
    public_cidr_rule_count = length(flatten([for rule in aws_security_group.alb.ingress : coalesce(rule.cidr_blocks, [])]))
    prefix_list_rule_count = length(flatten([for rule in aws_security_group.alb.ingress : coalesce(rule.prefix_list_ids, [])]))
    listener_ports         = distinct(values(aws_lb_listener.service)[*].port)
    access_log_bucket      = aws_s3_bucket.alb_logs.id
  }
}

output "runtime_url_boundary" {
  value = {
    console_url       = local.console_base_url
    api_url           = local.api_base_url
    gateway_url       = local.gateway_base_url
    cors_origins      = [local.console_base_url]
    oidc_redirect_uri = "${local.console_base_url}/api/auth/oidc/callback"
    cookie_secure     = true
    cookie_domain     = null
  }
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "ecs_service_names" {
  value = merge(
    { for key, service in aws_ecs_service.public : key => service.name },
    { for key, service in aws_ecs_service.private : key => service.name },
    var.enable_audit_consumer ? { audit_consumer = aws_ecs_service.audit_consumer[0].name } : {},
  )
}

output "public_endpoints" {
  value = {
    console = local.console_base_url
    backend = "${local.public_scheme}://${local.api_host}${var.enable_public_edge ? "" : ":8000"}/health"
    gateway = "${local.gateway_base_url}/health"
  }
}

output "alarm_names" {
  value = concat(
    values(aws_cloudwatch_metric_alarm.unhealthy_hosts)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.ecs_cpu)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.ecs_pending_tasks)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.audit_sqs)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.nat_port_allocation)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.nat_packet_drop)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.nat_idle_timeout)[*].alarm_name,
    aws_cloudwatch_metric_alarm.ecs_capacity_provider_reservation[*].alarm_name,
    aws_cloudwatch_metric_alarm.ecs_instance_health[*].alarm_name,
    aws_cloudwatch_metric_alarm.ecs_placement_failure[*].alarm_name,
  )
}

output "ecs_launch_model" {
  value = {
    mode                   = var.ecs_ec2_graviton.enabled ? "EC2_GRAVITON" : "FARGATE"
    task_compatibilities   = local.ecs_launch_compatibilities
    runtime_architectures  = local.runtime_architectures
    capacity_provider_name = try(aws_ecs_capacity_provider.graviton[0].name, null)
    asg_name               = try(aws_autoscaling_group.ecs_graviton[0].name, null)
    asg_min_size           = var.ecs_ec2_graviton.enabled ? var.ecs_ec2_graviton.min_size : null
    asg_desired_size       = var.ecs_ec2_graviton.enabled ? var.ecs_ec2_graviton.desired_size : null
    asg_max_size           = var.ecs_ec2_graviton.enabled ? var.ecs_ec2_graviton.max_size : null
    x86_provider_enabled   = var.ecs_ec2_graviton.x86_provider_enabled
  }
}

output "nat_gateway_mode" {
  value = var.nat_gateway_mode
}

output "nat_gateway_ids" {
  value = { for key, gateway in aws_nat_gateway.main : key => gateway.id }
}

output "nat_eip_public_ips" {
  value = { for key, address in aws_eip.nat : key => address.public_ip }
}

output "nat_gateway_azs" {
  value = { for key, subnet in local.nat_subnets : key => subnet.availability_zone }
}

output "private_route_table_ids" {
  value = { for key, table in aws_route_table.private : key => table.id }
}

output "private_route_nat_keys" {
  value = { for key, route in aws_route.private_nat : key => var.nat_gateway_mode == "per_az" ? key : "0" }
}

output "gateway_endpoint_route_table_ids" {
  value = { for service, endpoint in aws_vpc_endpoint.gateway : service => endpoint.route_table_ids }
}

output "gateway_endpoint_route_table_count" {
  value = { for service, endpoint in aws_vpc_endpoint.gateway : service => length(aws_route_table.private) }
}

output "interface_endpoint_private_dns_enabled" {
  value = { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.private_dns_enabled }
}

output "gateway_endpoint_policies" {
  value = { for service in keys(aws_vpc_endpoint.gateway) : service => true }
}

output "interface_endpoint_policies" {
  value = { for service in keys(aws_vpc_endpoint.interface) : service => true }
}

output "endpoint_client_security_group_id" {
  value = aws_security_group.app.id
}

output "endpoint_ingress_source_count" {
  value = try(length(one(aws_security_group.vpc_endpoints[0].ingress).security_groups), 0)
}

output "endpoint_ingress_public_cidr_count" {
  value = try(one(aws_security_group.vpc_endpoints[0].ingress).cidr_blocks == null ? 0 : length(one(aws_security_group.vpc_endpoints[0].ingress).cidr_blocks), 0)
}

output "vpc_endpoint_ids" {
  value = merge(
    { for service, endpoint in aws_vpc_endpoint.gateway : service => endpoint.id },
    { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.id },
  )
}

output "application_task_role_arns" {
  value = local.application_task_role_arns
}

output "nat_dashboard_name" {
  value = aws_cloudwatch_dashboard.nat.dashboard_name
}

output "rds_endpoint" {
  value = local.db_address
}

output "rds_instance_arn" {
  value = local.db_arn
}

output "rds_role" {
  value = var.replica_source_db_arn != "" ? "cross-region-read-replica" : "primary"
}

output "replica_source_db_arn" {
  value = var.replica_source_db_arn
}

output "db_password" {
  value     = local.db_password
  sensitive = true
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "secret_arns" {
  value = {
    bootstrap_database_url         = aws_secretsmanager_secret.bootstrap_database_url.arn
    backend_migration_database_url = aws_secretsmanager_secret.backend_migration_database_url.arn
    backend_database_url           = aws_secretsmanager_secret.backend_database_url.arn
    app_database_url               = aws_secretsmanager_secret.app_database_url.arn
    agent_migration_database_url   = aws_secretsmanager_secret.agent_migration_database_url.arn
    agent_database_url             = aws_secretsmanager_secret.agent_database_url.arn
    agent_encryption               = aws_secretsmanager_secret.agent_encryption.arn
    agent_redaction                = aws_secretsmanager_secret.agent_redaction.arn
    internal_service               = aws_secretsmanager_secret.internal_service.arn
    jwt                            = aws_secretsmanager_secret.jwt.arn
    jwt_v2                         = aws_secretsmanager_secret.jwt_v2.arn
    session                        = aws_secretsmanager_secret.session.arn
    session_v2                     = aws_secretsmanager_secret.session_v2.arn
    envelope                       = aws_secretsmanager_secret.envelope.arn
    envelope_v2                    = aws_secretsmanager_secret.envelope_v2.arn
  }
}

output "service_discovery_namespace" {
  value = aws_service_discovery_private_dns_namespace.main.name
}

output "network_path" {
  value = {
    nat_gateway_ids        = values(aws_nat_gateway.main)[*].id
    gateway_endpoint_ids   = { for key, endpoint in aws_vpc_endpoint.gateway : key => endpoint.id }
    interface_endpoint_ids = { for key, endpoint in aws_vpc_endpoint.interface : key => endpoint.id }
  }
}

output "audit_sqs" {
  value = {
    queue_url          = try(aws_sqs_queue.audit[0].url, null)
    queue_arn          = try(aws_sqs_queue.audit[0].arn, null)
    dlq_url            = try(aws_sqs_queue.audit_dlq[0].url, null)
    dlq_arn            = try(aws_sqs_queue.audit_dlq[0].arn, null)
    producer_role_arns = { for service in local.audit_sqs_producer_services : service => aws_iam_role.application_task[service].arn }
    consumer_role_arn  = aws_iam_role.application_task["audit_consumer"].arn
    alarm_names        = values(aws_cloudwatch_metric_alarm.audit_sqs)[*].alarm_name
  }
}

output "database_job_task_definition_arns" {
  value = { for key, task in aws_ecs_task_definition.database_job : key => task.arn }
}

output "database_job_execution_order" {
  value = [
    "bootstrap_prepare",
    "backend_migrations",
    "agent_migrations",
    "bootstrap_finalize",
    "database_security_check",
    "crypto_preflight",
    "worker_preflight",
  ]
}

output "database_job_network_configuration" {
  value = {
    awsvpcConfiguration = {
      subnets        = values(aws_subnet.private)[*].id
      securityGroups = [aws_security_group.app.id]
      assignPublicIp = "DISABLED"
    }
  }
}
