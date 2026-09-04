locals {
  service_secrets = { for service in keys(local.task_definition_configs) : service => concat(
    service == "console" ? [
      { name = "SESSION_SECRET", valueFrom = var.session_key_version == "v2" ? aws_secretsmanager_secret.session_v2.arn : aws_secretsmanager_secret.session.arn },
      { name = "SESSION_SECRET_V1", valueFrom = aws_secretsmanager_secret.session.arn },
      { name = "SESSION_SECRET_V2", valueFrom = aws_secretsmanager_secret.session_v2.arn }
    ] : [],
    contains(["console", "backend"], service) ? [
      { name = "BFF_CLIENT_IP_SECRET", valueFrom = aws_secretsmanager_secret.bff_client_ip.arn },
      { name = "OIDC_BFF_EXCHANGE_SECRET", valueFrom = aws_secretsmanager_secret.oidc_bff_exchange.arn }
    ] : [],
    contains(["backend", "gateway"], service) ? [
      { name = "DATABASE_URL", valueFrom = service == "backend" ? aws_secretsmanager_secret.backend_database_url.arn : aws_secretsmanager_secret.app_database_url.arn },
      { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
      { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
      { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
      { name = "SESSION_SECRET", valueFrom = var.session_key_version == "v2" ? aws_secretsmanager_secret.session_v2.arn : aws_secretsmanager_secret.session.arn },
      { name = "SESSION_SECRET_V1", valueFrom = aws_secretsmanager_secret.session.arn },
      { name = "SESSION_SECRET_V2", valueFrom = aws_secretsmanager_secret.session_v2.arn },
      { name = "ENVELOPE_KEY", valueFrom = aws_secretsmanager_secret.envelope.arn },
      { name = "ENVELOPE_KEY_V1", valueFrom = aws_secretsmanager_secret.envelope.arn },
      { name = "ENVELOPE_KEY_V2", valueFrom = aws_secretsmanager_secret.envelope_v2.arn }
    ] : [],
    contains(["console", "backend", "agent"], service) ? [
      { name = "AUTHCLAW_INTERNAL_SERVICE_SECRET", valueFrom = aws_secretsmanager_secret.internal_service.arn }
    ] : [],
    service == "backend" ? local.backend_kms_secrets : [],
    service == "backend" ? [
      { name = "WORKER_TOKEN_HMAC_KEY_V1", valueFrom = aws_secretsmanager_secret.worker_token_hmac.arn },
      { name = "PLATFORM_AUTH_DATABASE_URL", valueFrom = aws_secretsmanager_secret.additional["platform_auth_database_url"].arn }
    ] : [],
    service == "backend" && var.smtp_host != "" ? [
      { name = "SMTP_USERNAME", valueFrom = aws_secretsmanager_secret.additional["smtp_username"].arn },
      { name = "SMTP_PASSWORD", valueFrom = aws_secretsmanager_secret.additional["smtp_password"].arn }
    ] : [],
    service == "backend" && var.clickhouse_host != "" ? [
      { name = "CLICKHOUSE_PASSWORD", valueFrom = aws_secretsmanager_secret.clickhouse_password[0].arn }
    ] : [],
    service == "gateway" ? [
      { name = "REDACTION_HASH_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
    ] : [],
    service == "agent" ? [
      { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.agent_database_url.arn },
      { name = "JWT_SECRET", valueFrom = var.jwt_key_version == "v2" ? aws_secretsmanager_secret.jwt_v2.arn : aws_secretsmanager_secret.jwt.arn },
      { name = "JWT_SECRET_V1", valueFrom = aws_secretsmanager_secret.jwt.arn },
      { name = "JWT_SECRET_V2", valueFrom = aws_secretsmanager_secret.jwt_v2.arn },
      { name = "AUTHCLAW_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.agent_encryption.arn },
      { name = "AUTHCLAW_REDACTION_SALT", valueFrom = aws_secretsmanager_secret.agent_redaction.arn }
    ] : []
  ) }
  audit_consumer_secrets = var.clickhouse_host != "" ? [
    { name = "CLICKHOUSE_PASSWORD", valueFrom = aws_secretsmanager_secret.clickhouse_password[0].arn }
  ] : []
}
