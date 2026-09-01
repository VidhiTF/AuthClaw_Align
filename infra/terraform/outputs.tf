output "primary" {
  value = {
    region                            = var.primary_region
    alb_dns_name                      = module.primary.alb_dns_name
    ecs_cluster_name                  = module.primary.ecs_cluster_name
    ecs_service_names                 = module.primary.ecs_service_names
    public_endpoints                  = module.primary.public_endpoints
    alarm_names                       = module.primary.alarm_names
    rds_endpoint                      = module.primary.rds_endpoint
    rds_instance_arn                  = module.primary.rds_instance_arn
    rds_role                          = module.primary.rds_role
    redis_endpoint                    = module.primary.redis_endpoint
    kms_key_arn                       = module.primary.kms_key_arn
    secret_arns                       = module.primary.secret_arns
    database_job_task_definition_arns = module.primary.database_job_task_definition_arns
    database_job_execution_order      = module.primary.database_job_execution_order
    service_namespace                 = module.primary.service_discovery_namespace
  }
}

output "secondary" {
  value = var.enable_secondary ? {
    region                            = var.secondary_region
    alb_dns_name                      = module.secondary[0].alb_dns_name
    ecs_cluster_name                  = module.secondary[0].ecs_cluster_name
    ecs_service_names                 = module.secondary[0].ecs_service_names
    public_endpoints                  = module.secondary[0].public_endpoints
    alarm_names                       = module.secondary[0].alarm_names
    rds_endpoint                      = module.secondary[0].rds_endpoint
    rds_instance_arn                  = module.secondary[0].rds_instance_arn
    rds_role                          = module.secondary[0].rds_role
    replica_source_db_arn             = module.secondary[0].replica_source_db_arn
    redis_endpoint                    = module.secondary[0].redis_endpoint
    kms_key_arn                       = module.secondary[0].kms_key_arn
    secret_arns                       = module.secondary[0].secret_arns
    database_job_task_definition_arns = module.secondary[0].database_job_task_definition_arns
    database_job_execution_order      = module.secondary[0].database_job_execution_order
    service_namespace                 = module.secondary[0].service_discovery_namespace
  } : null
}

output "console_failover_domain" {
  value = var.domain_name != "" ? var.domain_name : null
}

output "ecr_repository_urls" {
  value = { for key, repository in aws_ecr_repository.service : key => repository.repository_url }
}

output "ecr_kms_key_arn" {
  value = aws_kms_key.registry.arn
}
