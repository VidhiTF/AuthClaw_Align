output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "alb_zone_id" {
  value = aws_lb.main.zone_id
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
    console = "${local.public_scheme}://${local.public_host}"
    backend = "${local.api_base_url}/health"
    gateway = "${local.gateway_base_url}/health"
  }
}

output "alarm_names" {
  value = concat(
    values(aws_cloudwatch_metric_alarm.unhealthy_hosts)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.ecs_cpu)[*].alarm_name,
    values(aws_cloudwatch_metric_alarm.audit_sqs)[*].alarm_name,
  )
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
    backend_database_url = aws_secretsmanager_secret.backend_database_url.arn
    app_database_url     = aws_secretsmanager_secret.app_database_url.arn
    agent_database_url   = aws_secretsmanager_secret.agent_database_url.arn
    agent_encryption     = aws_secretsmanager_secret.agent_encryption.arn
    agent_redaction      = aws_secretsmanager_secret.agent_redaction.arn
    internal_service     = aws_secretsmanager_secret.internal_service.arn
    jwt                  = aws_secretsmanager_secret.jwt.arn
    jwt_v2               = aws_secretsmanager_secret.jwt_v2.arn
    session              = aws_secretsmanager_secret.session.arn
    session_v2           = aws_secretsmanager_secret.session_v2.arn
    envelope             = aws_secretsmanager_secret.envelope.arn
    envelope_v2          = aws_secretsmanager_secret.envelope_v2.arn
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
    producer_role_arns = { for service, role in aws_iam_role.audit_sqs_producer : service => role.arn }
    consumer_role_arn  = try(aws_iam_role.audit_sqs_consumer[0].arn, null)
    alarm_names        = values(aws_cloudwatch_metric_alarm.audit_sqs)[*].alarm_name
  }
}
