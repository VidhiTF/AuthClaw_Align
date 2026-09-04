output "primary" {
  value = {
    region                             = var.primary_region
    client_identity                    = module.primary.client_identity
    alb_dns_name                       = module.primary.alb_dns_name
    ecs_cluster_name                   = module.primary.ecs_cluster_name
    ecs_service_names                  = module.primary.ecs_service_names
    public_endpoints                   = module.primary.public_endpoints
    alarm_names                        = module.primary.alarm_names
    rds_endpoint                       = module.primary.rds_endpoint
    rds_instance_arn                   = module.primary.rds_instance_arn
    rds_role                           = module.primary.rds_role
    redis_endpoint                     = module.primary.redis_endpoint
    kms_key_arn                        = module.primary.kms_key_arn
    secret_arns                        = module.primary.secret_arns
    database_job_task_definition_arns  = module.primary.database_job_task_definition_arns
    database_job_execution_order       = module.primary.database_job_execution_order
    service_namespace                  = module.primary.service_discovery_namespace
    network_path                       = module.primary.network_path
    audit_sqs                          = module.primary.audit_sqs
    nat_gateway_mode                   = module.primary.nat_gateway_mode
    nat_gateway_ids                    = module.primary.nat_gateway_ids
    nat_eip_public_ips                 = module.primary.nat_eip_public_ips
    nat_gateway_azs                    = module.primary.nat_gateway_azs
    private_route_table_ids            = module.primary.private_route_table_ids
    private_route_nat_keys             = module.primary.private_route_nat_keys
    gateway_endpoint_route_table_ids   = module.primary.gateway_endpoint_route_table_ids
    gateway_endpoint_route_table_count = module.primary.gateway_endpoint_route_table_count
    interface_endpoint_private_dns     = module.primary.interface_endpoint_private_dns_enabled
    endpoint_client_security_group_id  = module.primary.endpoint_client_security_group_id
    endpoint_ingress_source_count      = module.primary.endpoint_ingress_source_count
    endpoint_ingress_public_cidr_count = module.primary.endpoint_ingress_public_cidr_count
    vpc_endpoint_ids                   = module.primary.vpc_endpoint_ids
    nat_dashboard_name                 = module.primary.nat_dashboard_name
  }
}

output "secondary" {
  value = var.enable_secondary ? {
    region                             = var.secondary_region
    client_identity                    = module.secondary[0].client_identity
    alb_dns_name                       = module.secondary[0].alb_dns_name
    ecs_cluster_name                   = module.secondary[0].ecs_cluster_name
    ecs_service_names                  = module.secondary[0].ecs_service_names
    public_endpoints                   = module.secondary[0].public_endpoints
    alarm_names                        = module.secondary[0].alarm_names
    rds_endpoint                       = module.secondary[0].rds_endpoint
    rds_instance_arn                   = module.secondary[0].rds_instance_arn
    rds_role                           = module.secondary[0].rds_role
    replica_source_db_arn              = module.secondary[0].replica_source_db_arn
    redis_endpoint                     = module.secondary[0].redis_endpoint
    kms_key_arn                        = module.secondary[0].kms_key_arn
    secret_arns                        = module.secondary[0].secret_arns
    database_job_task_definition_arns  = module.secondary[0].database_job_task_definition_arns
    database_job_execution_order       = module.secondary[0].database_job_execution_order
    service_namespace                  = module.secondary[0].service_discovery_namespace
    network_path                       = module.secondary[0].network_path
    audit_sqs                          = module.secondary[0].audit_sqs
    nat_gateway_mode                   = module.secondary[0].nat_gateway_mode
    nat_gateway_ids                    = module.secondary[0].nat_gateway_ids
    nat_eip_public_ips                 = module.secondary[0].nat_eip_public_ips
    nat_gateway_azs                    = module.secondary[0].nat_gateway_azs
    private_route_table_ids            = module.secondary[0].private_route_table_ids
    private_route_nat_keys             = module.secondary[0].private_route_nat_keys
    gateway_endpoint_route_table_ids   = module.secondary[0].gateway_endpoint_route_table_ids
    gateway_endpoint_route_table_count = module.secondary[0].gateway_endpoint_route_table_count
    interface_endpoint_private_dns     = module.secondary[0].interface_endpoint_private_dns_enabled
    endpoint_client_security_group_id  = module.secondary[0].endpoint_client_security_group_id
    endpoint_ingress_source_count      = module.secondary[0].endpoint_ingress_source_count
    endpoint_ingress_public_cidr_count = module.secondary[0].endpoint_ingress_public_cidr_count
    vpc_endpoint_ids                   = module.secondary[0].vpc_endpoint_ids
    nat_dashboard_name                 = module.secondary[0].nat_dashboard_name
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
