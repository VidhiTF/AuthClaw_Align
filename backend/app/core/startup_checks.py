"""Startup validation for production Lite deployments."""
import os
from ipaddress import ip_address
from urllib.parse import urlparse

from sqlalchemy import text


_DEMO_VALUES = {
    "change-this-demo-jwt-secret",
    "change-this-demo-session-secret",
    "change-this-demo-envelope-key",
    "demo-change-me",
    "demo-local-envelope-key-change-me",
    "authclaw-default-32-byte-key-12",
    "your-256-bit-hex-encoded-key-here",
    "dev-secret-change-in-production",
}


def is_production() -> bool:
    return os.getenv("AUTHCLAW_ENV", "").strip().lower() == "production"


def _is_missing_or_demo(value: str | None) -> bool:
    if not value:
        return True
    return value.strip() in _DEMO_VALUES or value.strip().startswith("change-this")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_https_url(value: str | None) -> bool:
    parsed = urlparse((value or "").strip())
    return parsed.scheme == "https" and bool(parsed.hostname)


def _is_secure_sidecar_url(value: str | None) -> bool:
    parsed = urlparse((value or "").strip())
    if parsed.scheme == "https" and parsed.hostname:
        return True
    if parsed.scheme != "http" or not parsed.hostname:
        return False
    try:
        return ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def validate_production_environment() -> None:
    production = is_production()
    require_service_tls = _truthy(
        os.getenv("AUTHCLAW_REQUIRE_SERVICE_TLS", "true" if production else "false")
    )
    if not production and not require_service_tls:
        return

    errors: list[str] = []
    if require_service_tls:
        for name in ("GATEWAY_INTERNAL_URL", "OPA_URL", "PRESIDIO_URL"):
            value = os.getenv(name, "").strip()
            valid = _is_https_url(value) if name == "GATEWAY_INTERNAL_URL" else _is_secure_sidecar_url(value)
            if not valid:
                requirement = "https" if name == "GATEWAY_INTERNAL_URL" else "https or task-local loopback http"
                errors.append(f"{name} must use {requirement} when service TLS is required")

    if not production:
        if errors:
            raise RuntimeError(f"Service TLS validation failed: {'; '.join(errors)}")
        return

    for name in ("JWT_SECRET", "SESSION_SECRET"):
        if _is_missing_or_demo(os.getenv(name)):
            errors.append(f"{name} must be set to a non-demo secret")

    provider = os.getenv("AUTHCLAW_SECRET_PROVIDER", "env").strip().lower()
    key_version = os.getenv("AUTHCLAW_SECRET_KEY_VERSION", "").strip()
    if not key_version:
        errors.append("AUTHCLAW_SECRET_KEY_VERSION must be set in production")

    if provider == "env":
        envelope_key = (
            os.getenv(f"ENVELOPE_KEY_{key_version.upper().replace('-', '_')}")
            or os.getenv("ENVELOPE_KEY")
            or os.getenv("ENCRYPTION_KEY")
        )
        if _is_missing_or_demo(envelope_key):
            errors.append("ENVELOPE_KEY/ENCRYPTION_KEY must be set to a non-demo secret for env secret provider")
        elif len(envelope_key.encode("utf-8")) < 32:
            errors.append("ENVELOPE_KEY/ENCRYPTION_KEY must be at least 32 bytes")
    elif provider == "vault":
        for name in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_SECRET_KEY_PATH"):
            if not os.getenv(name, "").strip():
                errors.append(f"{name} must be configured for vault secret provider")
    elif provider == "aws_kms":
        if not (os.getenv("AWS_KMS_ENCRYPTED_DATA_KEY") or os.getenv("KMS_ENCRYPTED_DATA_KEY")):
            errors.append("AWS_KMS_ENCRYPTED_DATA_KEY must be configured for aws_kms secret provider")
        if not (os.getenv("AUTHCLAW_AWS_KMS_KEY_ID") or os.getenv("AWS_KMS_KEY_ID")):
            errors.append("AUTHCLAW_AWS_KMS_KEY_ID must be configured for aws_kms secret provider")
    else:
        errors.append("AUTHCLAW_SECRET_PROVIDER must be one of: env, vault, aws_kms")

    if os.getenv("DEMO_OTP_VISIBLE", "false").lower() == "true":
        errors.append("DEMO_OTP_VISIBLE must be false in production")

    if not os.getenv("SMTP_HOST", "").strip():
        errors.append("SMTP_HOST must be configured for production email OTP")

    if not (os.getenv("SMTP_FROM") or os.getenv("EMAIL_FROM")):
        errors.append("SMTP_FROM or EMAIL_FROM must be configured")
    if not os.getenv("INTERNAL_LAUNCH_OWNER_EMAIL", "").strip():
        errors.append("INTERNAL_LAUNCH_OWNER_EMAIL must be configured")

    public_gateway = os.getenv("PUBLIC_GATEWAY_URL") or os.getenv("NEXT_PUBLIC_GATEWAY_URL", "")
    if public_gateway and not _is_https_url(public_gateway):
        errors.append("PUBLIC_GATEWAY_URL/NEXT_PUBLIC_GATEWAY_URL must use https:// in production")

    oidc_values = {
        "OIDC_ISSUER_URL": os.getenv("OIDC_ISSUER_URL", "").strip(),
        "OIDC_CLIENT_ID": os.getenv("OIDC_CLIENT_ID", "").strip(),
        "OIDC_REDIRECT_URI": os.getenv("OIDC_REDIRECT_URI", "").strip(),
    }
    if any(oidc_values.values()) and not all(oidc_values.values()):
        missing = ", ".join(name for name, value in oidc_values.items() if not value)
        errors.append(f"OIDC is partially configured; missing {missing}")
    if oidc_values["OIDC_REDIRECT_URI"] and not _is_https_url(oidc_values["OIDC_REDIRECT_URI"]):
        errors.append("OIDC_REDIRECT_URI must use https in production")

    if errors:
        joined = "; ".join(errors)
        raise RuntimeError(f"Production environment validation failed: {joined}")

def validate_database_security(connection) -> None:
    """Refuse startup when the authentication/RLS boundary is incomplete."""
    if connection.dialect.name != "postgresql":
        return

    expected_revision = os.getenv("AUTHCLAW_EXPECTED_DB_REVISION", "041")
    failures: list[str] = []
    if not connection.execute(
        text("SELECT EXISTS (SELECT 1 FROM public.alembic_version WHERE version_num = :revision)"),
        {"revision": expected_revision},
    ).scalar_one():
        failures.append(f"missing Alembic revision {expected_revision}")

    function_security = connection.execute(text("""
        SELECT
            r.rolname = 'authclaw_auth_definer' AS correct_owner,
            p.prosecdef AS security_definer,
            NOT EXISTS (
                SELECT 1
                FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
            ) AS public_execute_revoked
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'authn'
          AND p.proname = 'bind_session_context'
          AND pg_get_function_identity_arguments(p.oid) = 'p_token_hash text'
    """)).mappings().first()
    if not function_security or not all(function_security.values()):
        failures.append("authn.bind_session_context ownership/ACL is insecure")

    if connection.execute(
        text("SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user")
    ).scalar_one():
        failures.append("runtime database role can bypass RLS")

    missing_rls = connection.execute(text("""
        SELECT count(*)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
          )
          AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
    """)).scalar_one()
    if missing_rls:
        failures.append(f"{missing_rls} tenant tables lack forced RLS")

    if failures:
        raise RuntimeError("Database security validation failed: " + "; ".join(failures))
