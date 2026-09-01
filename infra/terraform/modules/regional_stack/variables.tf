variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type = string
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

variable "authclaw_env" {
  type    = string
  default = "staging"
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

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_engine_version" {
  type    = string
  default = "16"
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
