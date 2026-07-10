output "primary" {
  value = {
    region            = var.primary_region
    alb_dns_name      = module.primary.alb_dns_name
    ecs_cluster_name  = module.primary.ecs_cluster_name
    rds_endpoint      = module.primary.rds_endpoint
    rds_instance_arn  = module.primary.rds_instance_arn
    rds_role          = module.primary.rds_role
    redis_endpoint    = module.primary.redis_endpoint
    kms_key_arn       = module.primary.kms_key_arn
    secret_arns       = module.primary.secret_arns
    service_namespace = module.primary.service_discovery_namespace
  }
}

output "secondary" {
  value = var.enable_secondary ? {
    region                = var.secondary_region
    alb_dns_name          = module.secondary[0].alb_dns_name
    ecs_cluster_name      = module.secondary[0].ecs_cluster_name
    rds_endpoint          = module.secondary[0].rds_endpoint
    rds_instance_arn      = module.secondary[0].rds_instance_arn
    rds_role              = module.secondary[0].rds_role
    replica_source_db_arn = module.secondary[0].replica_source_db_arn
    redis_endpoint        = module.secondary[0].redis_endpoint
    kms_key_arn           = module.secondary[0].kms_key_arn
    secret_arns           = module.secondary[0].secret_arns
    service_namespace     = module.secondary[0].service_discovery_namespace
  } : null
}

output "console_failover_domain" {
  value = var.domain_name != "" ? var.domain_name : null
}
