"""Startup validation for production Lite deployments."""
import os


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


def validate_production_environment() -> None:
    if not is_production():
        return

    errors: list[str] = []
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
    else:
        errors.append("AUTHCLAW_SECRET_PROVIDER must be one of: env, vault, aws_kms")

    if os.getenv("DEMO_OTP_VISIBLE", "false").lower() == "true":
        errors.append("DEMO_OTP_VISIBLE must be false in production")

    if not os.getenv("SMTP_HOST", "").strip():
        errors.append("SMTP_HOST must be configured for production email OTP")

    if not (os.getenv("SMTP_FROM") or os.getenv("EMAIL_FROM")):
        errors.append("SMTP_FROM or EMAIL_FROM must be configured")

    public_gateway = os.getenv("PUBLIC_GATEWAY_URL") or os.getenv("NEXT_PUBLIC_GATEWAY_URL", "")
    if public_gateway and not public_gateway.startswith("https://"):
        errors.append("PUBLIC_GATEWAY_URL/NEXT_PUBLIC_GATEWAY_URL must use https:// in production")

    oidc_values = {
        "OIDC_ISSUER_URL": os.getenv("OIDC_ISSUER_URL", "").strip(),
        "OIDC_CLIENT_ID": os.getenv("OIDC_CLIENT_ID", "").strip(),
        "OIDC_REDIRECT_URI": os.getenv("OIDC_REDIRECT_URI", "").strip(),
    }
    if any(oidc_values.values()) and not all(oidc_values.values()):
        missing = ", ".join(name for name, value in oidc_values.items() if not value)
        errors.append(f"OIDC is partially configured; missing {missing}")
    if oidc_values["OIDC_REDIRECT_URI"] and not oidc_values["OIDC_REDIRECT_URI"].startswith("https://"):
        errors.append("OIDC_REDIRECT_URI must use https in production")

    if errors:
        joined = "; ".join(errors)
        raise RuntimeError(f"Production environment validation failed: {joined}")
