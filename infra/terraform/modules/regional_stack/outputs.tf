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
    jwt                  = aws_secretsmanager_secret.jwt.arn
    session              = aws_secretsmanager_secret.session.arn
    envelope             = aws_secretsmanager_secret.envelope.arn
  }
}

output "service_discovery_namespace" {
  value = aws_service_discovery_private_dns_namespace.main.name
}
