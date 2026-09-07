variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type = string
}

variable "aws_account_id" {
  type    = string
  default = ""
}

variable "vpc_cidr" {
  type = string
}

variable "az_count" {
  type    = number
  default = 2
}

variable "availability_zones" {
  description = "Optional explicit availability zone names. CI uses this to avoid AWS data-source reads during speculative plans."
  type        = list(string)
  default     = []
}

variable "enable_private_aws_endpoints" {
  description = "Route supported AWS service traffic privately through VPC gateway and interface endpoints."
  type        = bool
  default     = true
}

variable "runtime_s3_bucket_arns" {
  type    = map(set(string))
  default = {}
}

variable "runtime_kms_key_arns" {
  type    = map(set(string))
  default = {}
}

variable "runtime_secrets_manager_secret_arns" {
  type    = map(set(string))
  default = {}
}

variable "runtime_sts_assume_role_arns" {
  type    = set(string)
  default = []
}

variable "vpc_endpoint_external_principal_arns" {
  type    = set(string)
  default = []
}

variable "nat_gateway_mode" {
  type        = string
  description = "NAT topology: single for lower environments, per_az for production."
  default     = "single"

  validation {
    condition     = contains(["single", "per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be single or per_az."
  }
}

variable "container_images" {
  type = object({
    agent          = string
    backend        = string
    gateway        = string
    console        = string
    audit_consumer = string
    opa            = string
    presidio       = string
  })
}

variable "service_cpu_architectures" {
  type    = map(string)
  default = {}

  validation {
    condition     = length(setsubtract(keys(var.service_cpu_architectures), ["agent", "backend", "gateway", "console", "audit_consumer"])) == 0
    error_message = "service_cpu_architectures supports only agent, backend, gateway, console, and audit_consumer."
  }

  validation {
    condition     = alltrue([for architecture in values(var.service_cpu_architectures) : contains(["ARM64", "X86_64"], architecture)])
    error_message = "service_cpu_architectures values must be ARM64 or X86_64."
  }
}

variable "ecs_ec2_graviton" {
  description = "Optional ECS on EC2 Graviton capacity provider for P0-05."
  type = object({
    enabled              = optional(bool, false)
    instance_type        = optional(string, "m7g.2xlarge")
    min_size             = optional(number, 4)
    desired_size         = optional(number, 4)
    max_size             = optional(number, 8)
    usable_cpu_units     = optional(number, 8192)
    usable_memory_mib    = optional(number, 30000)
    image_id             = optional(string, "")
    root_volume_size     = optional(number, 50)
    alarm_action_arns    = optional(list(string), [])
    x86_provider_enabled = optional(bool, false)
  })
  default = {}

  validation {
    condition     = var.ecs_ec2_graviton.min_size >= 0 && var.ecs_ec2_graviton.desired_size >= var.ecs_ec2_graviton.min_size && var.ecs_ec2_graviton.max_size >= var.ecs_ec2_graviton.desired_size
    error_message = "ecs_ec2_graviton capacity must satisfy min_size <= desired_size <= max_size."
  }

  validation {
    condition     = can(regex("^[a-z][0-9]+g\\.", var.ecs_ec2_graviton.instance_type))
    error_message = "ecs_ec2_graviton.instance_type must be an ARM64 Graviton instance family such as m7g.large."
  }
}

variable "ecr_repository_arns" {
  description = "Approved ECR repositories used by ECS task image pulls."
  type        = set(string)
  default     = []
}

variable "authclaw_env" {
  type    = string
  default = "staging"

  validation {
    condition     = contains(["ci", "shared-test", "staging", "stage", "production", "prod"], var.authclaw_env)
    error_message = "authclaw_env must be an explicit shared-test, staging, or production environment."
  }
}

variable "secret_key_version" {
  type    = string
  default = "v1"
}

variable "jwt_key_version" {
  type    = string
  default = "v1"
}

variable "session_key_version" {
  type    = string
  default = "v1"
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "service_min_capacity" {
  description = "Minimum task count per service in staging/production; values must preserve task-failure availability."
  type        = map(number)
  default = {
    console        = 2
    backend        = 2
    gateway        = 2
    agent          = 2
    audit_consumer = 2
  }
  validation {
    condition     = alltrue([for service in ["console", "backend", "gateway", "agent", "audit_consumer"] : contains(keys(var.service_min_capacity), service)])
    error_message = "service_min_capacity must define console, backend, gateway, agent, and audit_consumer."
  }
}

variable "service_max_capacity" {
  description = "Hard task ceilings selected to remain inside the RDS and downstream capacity budget."
  type        = map(number)
  default = {
    console        = 4
    backend        = 5
    gateway        = 6
    agent          = 4
    audit_consumer = 4
  }
}

variable "service_cpu_target" {
  type = map(number)
  default = {
    console = 60, backend = 60, gateway = 55, agent = 60, audit_consumer = 65
  }
}

variable "service_memory_target" {
  type = map(number)
  default = {
    console = 70, backend = 70, gateway = 65, agent = 70, audit_consumer = 70
  }
}

variable "alb_requests_per_target" {
  description = "One-minute ALB request targets. Tune from staging latency and saturation measurements."
  type        = map(number)
  default     = { console = 1200, backend = 600, gateway = 600 }
}

variable "scale_out_cooldown_seconds" {
  type    = number
  default = 60
}

variable "scale_in_cooldown_seconds" {
  type    = number
  default = 300
}

variable "deployment_minimum_healthy_percent" {
  type    = number
  default = 100
}

variable "deployment_maximum_percent" {
  type    = number
  default = 200
}

variable "health_check_grace_period_seconds" {
  type    = number
  default = 60
}

variable "alb_deregistration_delay_seconds" {
  type    = number
  default = 60
}

variable "service_log_retention_days" {
  type    = number
  default = 90
}

variable "db_connections_per_task" {
  description = "Maximum open PostgreSQL connections per runtime task, kept equal to application pool settings."
  type        = map(number)
  default     = { backend = 15, gateway = 10, agent = 10 }
}

variable "rds_max_connections" {
  description = "Measured safe PostgreSQL connection ceiling configured on the RDS parameter group."
  type        = number
  default     = 200
}

variable "rds_connection_reserve" {
  description = "Connections reserved for migrations, monitoring, administration, and failure recovery."
  type        = number
  default     = 25
}

variable "rds_slow_query_milliseconds" {
  type    = number
  default = 1000
}

variable "audit_sqs_scale_out_backlog" {
  description = "SQS visible-message depth that triggers one bounded audit-consumer scale-out step."
  type        = number
  default     = 500
}

variable "is_primary" {
  type    = bool
  default = true
}

variable "create_db_replica" {
  description = "Create this regional database as a replica. Kept explicit so Terraform can plan without depending on unknown ARN values."
  type        = bool
  default     = false
}

variable "service_cpu" {
  type    = number
  default = 512
}

variable "service_memory" {
  type    = number
  default = 1024
}

variable "gateway_sidecar_task_cpu" {
  description = "Fargate CPU units for the combined Gateway, OPA, and Presidio task."
  type        = number
  default     = 2048
}

variable "gateway_sidecar_task_memory" {
  description = "Fargate memory in MiB for the combined Gateway, OPA, and Presidio task."
  type        = number
  default     = 4096
}

variable "backend_sidecar_task_cpu" {
  description = "Fargate CPU units for the Backend and Presidio task."
  type        = number
  default     = 2048
}

variable "backend_sidecar_task_memory" {
  description = "Fargate memory in MiB for the Backend and Presidio task."
  type        = number
  default     = 4096
}

variable "agent_sidecar_task_cpu" {
  description = "Fargate CPU units for the Agent and OPA task."
  type        = number
  default     = 1024
}

variable "agent_sidecar_task_memory" {
  description = "Fargate memory in MiB for the Agent and OPA task."
  type        = number
  default     = 2048
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_engine_version" {
  type    = string
  default = "16"

  validation {
    condition     = startswith(var.db_engine_version, "16")
    error_message = "The managed PostgreSQL parameter group currently supports engine major version 16."
  }
}

variable "db_allocated_storage" {
  type    = number
  default = 100
}

variable "db_password" {
  type      = string
  default   = ""
  sensitive = true
}

variable "replica_source_db_arn" {
  type    = string
  default = ""
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "enable_public_edge" {
  description = "Allow CloudFront ingress to the always-private application ALBs."
  type        = bool
  default     = false
}

variable "public_domain_names" {
  description = "Approved public hostnames used to construct browser-facing runtime URLs."
  type = object({
    console = string
    api     = string
    gateway = string
  })
  default = {
    console = ""
    api     = ""
    gateway = ""
  }
}

variable "public_url_environment" {
  type    = string
  default = "staging"
}

variable "alb_access_log_retention_days" {
  description = "Retention for regional ALB access logs."
  type        = number
  default     = 90

  validation {
    condition     = var.alb_access_log_retention_days >= 30
    error_message = "alb_access_log_retention_days must be at least 30 days."
  }
}

variable "edge_alarm_action_arns" {
  description = "Approved SNS or incident-routing action ARNs. Leave empty until a real destination is approved."
  type        = list(string)
  default     = []
}

variable "alarm_owner" {
  description = "Operations team or rotation responsible for acknowledging critical alarms."
  type        = string
  default     = "platform-operations-unassigned"
}

variable "alarm_acknowledgement_minutes" {
  description = "Expected acknowledgement time for critical alarms."
  type        = number
  default     = 15

  validation {
    condition     = var.alarm_acknowledgement_minutes >= 1 && var.alarm_acknowledgement_minutes <= 120
    error_message = "alarm_acknowledgement_minutes must be between 1 and 120."
  }
}

variable "alarm_escalation_path" {
  description = "Non-secret incident escalation policy label or runbook reference."
  type        = string
  default     = "approved-escalation-policy-required"
}

variable "smtp_host" {
  type    = string
  default = ""
}

variable "smtp_from" {
  type    = string
  default = ""
}

variable "kafka_brokers" {
  type    = string
  default = ""
}

variable "audit_stream_transport" {
  description = "Audit stream transport. Kafka remains the rollback default; sqs_fifo creates SQS FIFO resources."
  type        = string
  default     = "kafka"

  validation {
    condition     = contains(["kafka", "sqs_fifo"], var.audit_stream_transport)
    error_message = "audit_stream_transport must be kafka or sqs_fifo."
  }
}

variable "audit_sqs_max_receive_count" {
  type    = number
  default = 5

  validation {
    condition     = var.audit_sqs_max_receive_count >= 2 && var.audit_sqs_max_receive_count <= 20
    error_message = "audit_sqs_max_receive_count must be between 2 and 20."
  }
}

variable "audit_sqs_retention_seconds" {
  type    = number
  default = 1209600

  validation {
    condition     = var.audit_sqs_retention_seconds >= 60 && var.audit_sqs_retention_seconds <= 1209600
    error_message = "audit_sqs_retention_seconds must be within AWS SQS limits."
  }
}

variable "audit_sqs_dlq_retention_seconds" {
  type    = number
  default = 1209600

  validation {
    condition     = var.audit_sqs_dlq_retention_seconds >= 60 && var.audit_sqs_dlq_retention_seconds <= 1209600
    error_message = "audit_sqs_dlq_retention_seconds must be within AWS SQS limits."
  }
}

variable "audit_sqs_long_poll_seconds" {
  type    = number
  default = 20

  validation {
    condition     = var.audit_sqs_long_poll_seconds >= 1 && var.audit_sqs_long_poll_seconds <= 20
    error_message = "audit_sqs_long_poll_seconds must be between 1 and 20."
  }
}

variable "audit_sqs_max_messages" {
  type    = number
  default = 10

  validation {
    condition     = var.audit_sqs_max_messages >= 1 && var.audit_sqs_max_messages <= 10
    error_message = "audit_sqs_max_messages must be between 1 and 10."
  }
}

variable "audit_sqs_visibility_timeout_seconds" {
  type    = number
  default = 60

  validation {
    condition     = var.audit_sqs_visibility_timeout_seconds >= 10 && var.audit_sqs_visibility_timeout_seconds <= 43200
    error_message = "audit_sqs_visibility_timeout_seconds must be within AWS SQS limits."
  }
}

variable "audit_sqs_dlq_depth_alarm_threshold" {
  type    = number
  default = 0
}

variable "audit_sqs_dlq_age_alarm_seconds" {
  type    = number
  default = 300
}

variable "audit_sqs_main_age_alarm_seconds" {
  type    = number
  default = 300
}

variable "audit_sqs_backlog_alarm_threshold" {
  type    = number
  default = 1000
}

variable "audit_sqs_alarm_action_arns" {
  description = "Approved SNS/action ARNs for SQS audit alarms. Required for production-like SQS deployments."
  type        = list(string)
  default     = []

  validation {
    condition     = var.audit_stream_transport != "sqs_fifo" || (!var.audit_sqs_require_alarm_actions && var.authclaw_env != "production") || length(var.audit_sqs_alarm_action_arns) > 0
    error_message = "production-like sqs_fifo audit transport requires at least one audit_sqs_alarm_action_arns entry."
  }
}

variable "audit_sqs_require_alarm_actions" {
  description = "Require SQS alarm actions for production-like plan validation."
  type        = bool
  default     = false
}

variable "clickhouse_host" {
  type    = string
  default = ""
}

variable "clickhouse_port" {
  type    = number
  default = 8123
}

variable "clickhouse_db" {
  type    = string
  default = "authclaw"
}

variable "clickhouse_user" {
  type    = string
  default = "authclaw"
}

variable "clickhouse_password" {
  type      = string
  default   = ""
  sensitive = true
}

variable "enable_audit_consumer" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
