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
    condition     = length(setsubtract(keys(var.service_cpu_architectures), ["agent", "backend", "gateway", "console", "audit_consumer", "opa", "presidio"])) == 0
    error_message = "service_cpu_architectures contains an unknown runtime service."
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
    min_size             = optional(number, 2)
    desired_size         = optional(number, 2)
    max_size             = optional(number, 4)
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

variable "expected_db_revision" {
  type    = string
  default = "049"

  validation {
    condition     = contains(["048", "049", "048,049"], var.expected_db_revision)
    error_message = "expected_db_revision must be 048, 049, or the temporary 048,049 rollout bridge."
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

variable "enable_policy_sidecar_colocation" {
  description = "Place OPA and Presidio beside the credential-free gateway. Privileged callers retain standalone policy services. Enable only for release-sequence step 7."
  type        = bool
  default     = false
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
}

variable "db_allocated_storage" {
  type    = number
  default = 100
}

variable "db_password" {
  description = "Deprecated: provision the secret externally; values must not enter Terraform."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.db_password == null || var.db_password == ""
    error_message = "Secret values must be supplied by the external provisioner, not Terraform variables."
  }
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
  type    = list(string)
  default = []
}

variable "quota_alert_sns_topic_arns" {
  description = "Approved regional SNS topics for managed quota alerts. Required outside CI."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([for arn in var.quota_alert_sns_topic_arns :
      can(regex("^arn:aws:sns:${var.region}:[0-9]{12}:[A-Za-z0-9_-]+$", arn))
    ])
    error_message = "Quota alert receivers must be exact SNS topic ARNs in this regional stack."
  }

  validation {
    condition     = var.authclaw_env == "ci" || length(var.quota_alert_sns_topic_arns) > 0
    error_message = "Shared-test, staging, and production require an approved quota alert SNS receiver."
  }
}

variable "quota_metrics_collector_image" {
  description = "Immutable multi-architecture AWS OpenTelemetry collector image."
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector@sha256:8aa9ea5f67b8d318f7d6af24677e3c70f7098bc0631147cb5fa91addbe980b06"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.quota_metrics_collector_image))
    error_message = "quota_metrics_collector_image must use an immutable sha256 digest."
  }
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
  validation {
    condition     = var.audit_stream_transport != "sqs_fifo" || var.internal_tls.enabled
    error_message = "SQS audit transport requires internal_tls.enabled=true so gateway-to-producer authentication is encrypted."
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
  description = "Deprecated: provision the secret externally; values must not enter Terraform."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.clickhouse_password == null || var.clickhouse_password == ""
    error_message = "Secret values must be supplied by the external provisioner, not Terraform variables."
  }
}

variable "enable_audit_consumer" {
  type    = bool
  default = false
}

variable "audit_consumer_environment" {
  description = "Non-secret audit TLS settings and certificate paths; shared workers require CLICKHOUSE_SECURE=true and KAFKA_SECURITY_PROTOCOL=SASL_SSL for Kafka."
  type        = map(string)
  default     = {}
  validation {
    condition     = length(setsubtract(toset(keys(var.audit_consumer_environment)), toset(["CLICKHOUSE_SECURE", "CLICKHOUSE_CA_CERT", "KAFKA_SECURITY_PROTOCOL", "KAFKA_SASL_MECHANISM", "KAFKA_SSL_CAFILE"]))) == 0
    error_message = "Only audit TLS options belong here; credentials must use secret ARNs."
  }
}

variable "audit_consumer_secret_arns" {
  description = "Externally provisioned AUDIT_POSTGRES_URL (member of authclaw_audit_verifier, sslmode=verify-full) and Kafka SASL credential secret ARNs."
  type        = map(string)
  default     = {}
  validation {
    condition     = length(setsubtract(toset(keys(var.audit_consumer_secret_arns)), toset(["AUDIT_POSTGRES_URL", "KAFKA_SASL_USERNAME", "KAFKA_SASL_PASSWORD"]))) == 0
    error_message = "Only audit verifier and Kafka SASL credentials belong here."
  }
  validation {
    condition = alltrue([for arn in values(var.audit_consumer_secret_arns) :
      can(regex("^arn:[^:]+:secretsmanager:${var.region}:[0-9]{12}:secret:.+$", arn))
    ])
    error_message = "Audit-consumer secrets must be Secrets Manager ARNs in this stack's region."
  }
}

variable "audit_consumer_secret_kms_key_arns" {
  description = "Customer-managed KMS key ARNs used by external audit-consumer secrets."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([for arn in var.audit_consumer_secret_kms_key_arns :
      can(regex("^arn:[^:]+:kms:${var.region}:[0-9]{12}:key/.+$", arn))
    ])
    error_message = "Audit-consumer KMS keys must be key ARNs in this stack's region."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
