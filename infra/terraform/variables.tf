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

variable "aws_account_id" {
  description = "AWS account ID used to scope service log-delivery policies; required for production."
  type        = string
  default     = ""

  validation {
    condition     = var.aws_account_id == "" || can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be empty or exactly 12 digits."
  }
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
  description = "Create private S3, ECR, CloudWatch Logs, Secrets Manager, KMS, and STS VPC endpoints in each regional stack, plus SQS when selected."
  type        = bool
  default     = true
}

variable "runtime_s3_bucket_arns" {
  description = "Approved S3 bucket ARNs by runtime service (backend or agent). Empty entries fail closed."
  type        = map(set(string))
  default     = {}

  validation {
    condition     = alltrue([for service in keys(var.runtime_s3_bucket_arns) : contains(["backend", "agent"], service)])
    error_message = "runtime_s3_bucket_arns keys must be backend or agent."
  }
}

variable "runtime_kms_key_arns" {
  description = "Approved KMS key ARNs by runtime service (backend or agent). Empty entries fail closed."
  type        = map(set(string))
  default     = {}

  validation {
    condition     = alltrue([for service in keys(var.runtime_kms_key_arns) : contains(["backend", "agent"], service)])
    error_message = "runtime_kms_key_arns keys must be backend or agent."
  }
}

variable "runtime_secrets_manager_secret_arns" {
  description = "Approved Secrets Manager secret ARNs for the agent runtime. Empty entries fail closed."
  type        = map(set(string))
  default     = {}

  validation {
    condition     = alltrue([for service in keys(var.runtime_secrets_manager_secret_arns) : service == "agent"])
    error_message = "runtime_secrets_manager_secret_arns only supports the confirmed agent caller."
  }
}

variable "runtime_sts_assume_role_arns" {
  description = "Exact customer role ARNs the agent runtime may assume. Empty disables runtime role assumption."
  type        = set(string)
  default     = []
}

variable "vpc_endpoint_external_principal_arns" {
  description = "Explicit external IAM principal ARNs allowed to use runtime AWS-service endpoints."
  type        = set(string)
  default     = []
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
    condition     = length(setsubtract(keys(var.service_cpu_architectures), ["agent", "backend", "gateway", "console", "audit_consumer", "opa", "presidio"])) == 0
    error_message = "service_cpu_architectures contains an unknown runtime service."
  }

  validation {
    condition     = alltrue([for architecture in values(var.service_cpu_architectures) : contains(["ARM64", "X86_64"], architecture)])
    error_message = "service_cpu_architectures values must be ARM64 or X86_64."
  }
}

variable "ecs_ec2_graviton" {
  description = "Optional ECS on EC2 Graviton capacity provider for P0-05. Keep disabled until ownership and failure rehearsal gates are approved."
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

check "controlled_environments_require_immutable_images" {
  assert {
    condition     = !contains(["controlled-beta", "staging", "stage", "production", "prod"], var.authclaw_env) || var.require_immutable_images
    error_message = "Staging and production deployments must enable require_immutable_images."
  }
}

variable "authclaw_env" {
  description = "Runtime AUTHCLAW_ENV value. Use production only after SMTP and HTTPS inputs are configured."
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["ci", "shared-test", "staging", "stage", "production", "prod"], var.authclaw_env)
    error_message = "authclaw_env must be an explicit shared-test, staging, or production environment for Terraform deployments."
  }
}

variable "expected_db_revision" {
  description = "Allowed Alembic head: use 046,047 only during the controlled 047 rollout, then tighten to 047."
  type        = string
  default     = "047"

  validation {
    condition     = contains(["046", "047", "046,047"], var.expected_db_revision)
    error_message = "expected_db_revision must be 046, 047, or the temporary 046,047 rollout bridge."
  }
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

variable "enable_policy_sidecar_colocation" {
  description = "Enable the separately reviewed gateway/OPA/Presidio co-location release."
  type        = bool
  default     = false
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

variable "enable_public_edge" {
  description = "Create the approved Route53, CloudFront, WAF, and private-ALB public entry model."
  type        = bool
  default     = false
}

variable "public_url_environment" {
  description = "Approved ADR-0002 public URL boundary to provision independently of runtime hardening gates."
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["staging", "production"], var.public_url_environment)
    error_message = "public_url_environment must be staging or production."
  }
}

variable "edge_certificate_arn" {
  description = "ACM certificate ARN in us-east-1 covering the approved environment domains."
  type        = string
  default     = ""
}

variable "edge_log_retention_days" {
  description = "CloudFront, WAF, and ALB access-log retention."
  type        = number
  default     = 90

  validation {
    condition     = var.edge_log_retention_days >= 30
    error_message = "edge_log_retention_days must be at least 30 days."
  }
}

variable "waf_rate_limit" {
  description = "Maximum requests per five-minute WAF evaluation window for one source IP."
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 100
    error_message = "waf_rate_limit must be at least 100."
  }
}

variable "edge_alarm_action_arns" {
  description = "Approved SNS or incident-action ARNs for edge, origin-health, and ECS service alarms."
  type        = list(string)
  default     = []
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
  description = "Run the audit consumer ECS service when Kafka/ClickHouse are configured."
  type        = bool
  default     = false
}

variable "audit_consumer_environment" {
  description = "Non-secret audit transport TLS settings."
  type        = map(string)
  default     = {}
}

variable "audit_consumer_secret_arns" {
  description = "External PostgreSQL verifier and Kafka SASL secret ARNs."
  type        = map(string)
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
variable "iam_permissions_boundary_arn" {
  type        = string
  default     = null
  description = "Optional organization-approved ECS execution-role boundary ARN."
}
variable "agent_customer_role_arns" {
  type    = set(string)
  default = []
}
variable "kms_break_glass_role_arns" {
  type    = set(string)
  default = []
}
variable "internal_tls" {
  type = object({
    enabled     = optional(bool, false)
    namespace   = optional(string, "")
    proxy_image = optional(string, "nginxinc/nginx-unprivileged@sha256:9b87ad3dd9f431c733f19dfb278c7eb3dba9dca381942c79818bb42f1a566a83")
  })
  default = {}
}
variable "direct_aws" {
  type = object({
    backend_kms_versions    = optional(map(string), {})
    agent_kms_key           = optional(string, "")
    agent_previous_kms_keys = optional(set(string), [])
    agent_secrets           = optional(map(string), {})
    agent_secret_kms_keys   = optional(set(string), [])
    agent_s3_buckets        = optional(set(string), [])
    agent_s3_objects        = optional(set(string), [])
    document_role_arn       = optional(string, "")
    document_external_id    = optional(string, "")
  })
  default = {}
}

variable "secondary_direct_aws" {
  description = "Secondary-region exact resources; never inherit primary-region KMS or secrets."
  type = object({
    backend_kms_versions    = optional(map(string), {})
    agent_kms_key           = optional(string, "")
    agent_previous_kms_keys = optional(set(string), [])
    agent_secrets           = optional(map(string), {})
    agent_secret_kms_keys   = optional(set(string), [])
    agent_s3_buckets        = optional(set(string), [])
    agent_s3_objects        = optional(set(string), [])
    document_role_arn       = optional(string, "")
    document_external_id    = optional(string, "")
  })
  default = {}
}
