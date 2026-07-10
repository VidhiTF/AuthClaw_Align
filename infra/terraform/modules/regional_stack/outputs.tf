output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "alb_zone_id" {
  value = aws_lb.main.zone_id
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
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
