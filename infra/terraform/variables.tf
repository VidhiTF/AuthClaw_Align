variable "project" {
  description = "Project name used in resource names."
  type        = string
  default     = "authclaw"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "primary_region" {
  description = "Primary AWS region."
  type        = string
  default     = "us-east-1"
}

variable "secondary_region" {
  description = "Secondary AWS region for standby/failover."
  type        = string
  default     = "us-west-2"
}

variable "ci_skip_aws_validation" {
  description = "Skip AWS provider account and credential validation for speculative CI plans that use placeholder credentials."
  type        = bool
  default     = false
}

variable "primary_vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "secondary_vpc_cidr" {
  type    = string
  default = "10.50.0.0/16"
}

variable "primary_availability_zones" {
  description = "Optional explicit primary-region AZ names for speculative CI plans."
  type        = list(string)
  default     = []
}

variable "secondary_availability_zones" {
  description = "Optional explicit secondary-region AZ names for speculative CI plans."
  type        = list(string)
  default     = []
}

variable "enable_private_aws_endpoints" {
  description = "Create private S3, ECR, CloudWatch Logs, Secrets Manager, and KMS VPC endpoints in each regional stack."
  type        = bool
  default     = true
}

variable "nat_gateway_mode" {
  type        = string
  description = "NAT topology for both regional stacks: single or per_az."
  default     = "single"

  validation {
    condition     = contains(["single", "per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be single or per_az."
  }
}

variable "container_images" {
  description = "Container images for AuthClaw runtime services."
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
  description = "Per-service ECS CPU architecture overrides; unspecified services remain X86_64."
  type        = map(string)
  default     = {}

  validation {
    condition     = length(setsubtract(keys(var.service_cpu_architectures), ["agent", "backend", "gateway", "console", "audit_consumer"])) == 0
    error_message = "service_cpu_architectures supports only agent, backend, gateway, console, and audit_consumer."
  }

  validation {
    condition     = alltrue([for architecture in values(var.service_cpu_architectures) : contains(["ARM64", "X86_64"], architecture)])
    error_message = "service_cpu_architectures values must be ARM64 or X86_64."
  }
}

variable "require_immutable_images" {
  description = "Require every runtime image to use an immutable sha256 digest. Enable for controlled-beta deployments."
  type        = bool
  default     = false

  validation {
    condition = !var.require_immutable_images || alltrue([
      for image in values(var.container_images) : can(regex("@sha256:[0-9a-f]{64}$", image))
    ])
    error_message = "Controlled-beta container_images must all end in @sha256:<64 lowercase hex characters>."
  }
}

variable "authclaw_env" {
  description = "Runtime AUTHCLAW_ENV value. Use production only after SMTP and HTTPS inputs are configured."
  type        = string
  default     = "staging"
}

variable "secret_key_version" {
  description = "Active envelope key version. Keep v1 through legacy migration, then set v2."
  type        = string
  default     = "v1"

  validation {
    condition     = contains(["v1", "v2"], var.secret_key_version)
    error_message = "secret_key_version must be v1 or v2."
  }
}

variable "jwt_key_version" {
  description = "Active JWT signing key version; both versions remain available for verification overlap."
  type        = string
  default     = "v1"

  validation {
    condition     = contains(["v1", "v2"], var.jwt_key_version)
    error_message = "jwt_key_version must be v1 or v2."
  }
}

variable "session_key_version" {
  description = "Active console session key version; both versions remain available during rotation."
  type        = string
  default     = "v1"

  validation {
    condition     = contains(["v1", "v2"], var.session_key_version)
    error_message = "session_key_version must be v1 or v2."
  }
}

variable "desired_count_primary" {
  type    = number
  default = 2
}

variable "desired_count_secondary" {
  type    = number
  default = 1
}

variable "gateway_sidecar_task_cpu" {
  type    = number
  default = 2048
}

variable "gateway_sidecar_task_memory" {
  type    = number
  default = 4096
}

variable "backend_sidecar_task_cpu" {
  type    = number
  default = 2048
}

variable "backend_sidecar_task_memory" {
  type    = number
  default = 4096
}

variable "agent_sidecar_task_cpu" {
  type    = number
  default = 1024
}

variable "agent_sidecar_task_memory" {
  type    = number
  default = 2048
}

variable "enable_secondary" {
  description = "Create the secondary regional stack."
  type        = bool
  default     = true
}

variable "enable_cross_region_db_replica" {
  description = "Create the secondary regional PostgreSQL database as a cross-region read replica of the primary database."
  type        = bool
  default     = true
}

variable "hosted_zone_id" {
  description = "Optional Route53 hosted zone for failover records."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Optional public DNS name for console failover, for example authclaw.example.com."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "Optional fallback ACM certificate ARN used by regional ALB listeners."
  type        = string
  default     = ""
}

variable "primary_certificate_arn" {
  description = "Optional ACM certificate ARN in the primary AWS region. Required for primary production HTTPS."
  type        = string
  default     = ""
}

variable "secondary_certificate_arn" {
  description = "Optional ACM certificate ARN in the secondary AWS region. Required for secondary production HTTPS."
  type        = string
  default     = ""
}

variable "smtp_host" {
  description = "SMTP host injected into backend for production email OTP."
  type        = string
  default     = ""
}

variable "smtp_from" {
  description = "SMTP from address injected into backend for production email OTP."
  type        = string
  default     = ""
}

variable "kafka_brokers" {
  description = "Optional managed Kafka/MSK bootstrap brokers for audit streaming."
  type        = string
  default     = ""
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
  description = "Optional managed ClickHouse host for audit query acceleration."
  type        = string
  default     = ""
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
  description = "Optional ClickHouse password. Prefer passing via a secured tfvars source."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_audit_consumer" {
  description = "Run the audit consumer ECS service when Kafka/ClickHouse are configured."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
