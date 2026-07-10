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

variable "container_images" {
  description = "Container images for AuthClaw runtime services."
  type = object({
    backend        = string
    gateway        = string
    console        = string
    audit_consumer = string
    opa            = string
    presidio       = string
  })
}

variable "authclaw_env" {
  description = "Runtime AUTHCLAW_ENV value. Use production only after SMTP and HTTPS inputs are configured."
  type        = string
  default     = "staging"
}

variable "desired_count_primary" {
  type    = number
  default = 2
}

variable "desired_count_secondary" {
  type    = number
  default = 1
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
