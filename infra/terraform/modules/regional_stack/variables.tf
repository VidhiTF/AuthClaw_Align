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

variable "container_images" {
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
  type    = string
  default = "staging"
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
