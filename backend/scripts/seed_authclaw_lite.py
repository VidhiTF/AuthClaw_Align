"""Seed AuthClaw Lite demo tenant, admin, key, route, and starter policy."""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.crypto import encrypt_secret
from app.core.auth import hash_key
from app.core.passwords import hash_password


load_dotenv("../.env.local")
load_dotenv(".env.local")

TENANT_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SECONDARY_TENANT_ID = uuid.UUID("11111111-1111-4111-8111-111111111112")
ADMIN_USER_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
ROLE_USERS = (
    (uuid.UUID("22222222-2222-4222-8222-222222222223"), "admin-role@authclaw-lite.demo", "admin"),
    (uuid.UUID("22222222-2222-4222-8222-222222222224"), "operator@authclaw-lite.demo", "operator"),
    (uuid.UUID("22222222-2222-4222-8222-222222222225"), "viewer@authclaw-lite.demo", "viewer"),
)
API_KEY_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
GATEWAY_ID = uuid.UUID("44444444-4444-4444-8444-444444444444")
POLICY_ID = uuid.UUID("55555555-5555-4555-8555-555555555555")
PROVIDER_CREDENTIAL_ID = uuid.UUID("66666666-6666-4666-8666-666666666666")
RAW_API_KEY = os.getenv("AUTHCLAW_LITE_DEMO_KEY", "acl_lite_demo_key")
RAW_ADMIN_PASSWORD = os.getenv("AUTHCLAW_LITE_DEMO_PASSWORD", "AuthClawDemo!234")
RAW_ADMIN_TOTP_SECRET = os.getenv("AUTHCLAW_LITE_DEMO_TOTP_SECRET", "").strip() or None
RAW_PROVIDER_KEY = os.getenv("AUTHCLAW_LITE_PROVIDER_KEY", "ci-mock-provider-key")
PROVIDER_ENDPOINT = os.getenv("AUTHCLAW_LITE_PROVIDER_ENDPOINT", "")
POLICY_REQUESTS_PER_MINUTE = max(0, int(os.getenv("AUTHCLAW_LITE_POLICY_REQUESTS_PER_MINUTE", "60")))

STARTER_POLICY = rf'''regex_rules:
  - name: customer_email
    pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}}\\b"
    reason: "Email addresses are redacted before model egress."
    severity: medium
    action: redact

  - name: patient_health_data
    pattern: "(?i)\\b(patient|diagnosis|prescription|medical record)\\b"
    reason: "Health context requires human approval before model egress."
    severity: high
    action: require_approval
    hitl_timeout_seconds: 1800

  - name: ssn_block
    pattern: "\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b"
    reason: "SSNs are blocked in the Lite demo policy."
    severity: critical
    action: block

model_rules:
  whitelist:
    - gpt-4o-mini
    - gemini-2.5-flash-lite
  blacklist: []

topic_rules: []

rate_limits:
  requests_per_minute: {POLICY_REQUESTS_PER_MINUTE}
'''


def normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def main() -> None:
    database_url = normalize_database_url(
        os.getenv("DATABASE_URL", "postgresql+psycopg://authclaw:authclaw@localhost:5432/authclaw")
    )
    engine = create_engine(database_url, pool_pre_ping=True)
    key_hash = hash_key(RAW_API_KEY)

    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(TENANT_ID)})

        conn.execute(
            text("""
            INSERT INTO tenants (id, name, tier, status)
            VALUES (:id, 'AuthClaw Lite Demo', 'starter', 'active')
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                tier = EXCLUDED.tier,
                status = EXCLUDED.status,
                updated_at = NOW()
            """),
            {"id": TENANT_ID},
        )

        conn.execute(
            text("""
            INSERT INTO tenants (id, name, tier, status)
            VALUES (:id, 'AuthClaw Role Fixture', 'starter', 'active')
            ON CONFLICT (id) DO UPDATE SET status = 'active', updated_at = NOW()
            """),
            {"id": SECONDARY_TENANT_ID},
        )

        conn.execute(
            text("""
            INSERT INTO users (id, tenant_id, email, password_hash, role, platform_role, mfa_enabled, mfa_secret, is_active)
            VALUES (:id, :tenant_id, 'admin@authclaw-lite.demo', :password_hash, 'owner', 'NONE', :mfa_enabled, :mfa_secret, true)
            ON CONFLICT (tenant_id, email) DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                mfa_enabled = EXCLUDED.mfa_enabled,
                mfa_secret = EXCLUDED.mfa_secret,
                is_active = true,
                updated_at = NOW()
            """),
            {
                "id": ADMIN_USER_ID,
                "tenant_id": TENANT_ID,
                "password_hash": hash_password(RAW_ADMIN_PASSWORD),
                "mfa_enabled": RAW_ADMIN_TOTP_SECRET is not None,
                "mfa_secret": (
                    encrypt_secret(RAW_ADMIN_TOTP_SECRET)
                    if RAW_ADMIN_TOTP_SECRET
                    else None
                ),
            },
        )

        for user_id, email, role in ROLE_USERS:
            conn.execute(
                text("""
                INSERT INTO users (id, tenant_id, email, password_hash, role, platform_role, mfa_enabled, is_active)
                VALUES (:id, :tenant_id, :email, :password_hash, :role, 'NONE', false, true)
                ON CONFLICT (tenant_id, email) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    role = EXCLUDED.role,
                    is_active = true,
                    updated_at = NOW()
                """),
                {
                    "id": user_id,
                    "tenant_id": TENANT_ID,
                    "email": email,
                    "password_hash": hash_password(RAW_ADMIN_PASSWORD),
                    "role": role,
                },
            )
            conn.execute(
                text("""
                INSERT INTO users (id, tenant_id, email, password_hash, role, platform_role, mfa_enabled, is_active)
                VALUES (:id, :tenant_id, :email, :password_hash, :role, 'NONE', false, true)
                ON CONFLICT (tenant_id, email) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    role = EXCLUDED.role,
                    is_active = true,
                    updated_at = NOW()
                """),
                {
                    "id": uuid.uuid5(SECONDARY_TENANT_ID, email),
                    "tenant_id": SECONDARY_TENANT_ID,
                    "email": email,
                    "password_hash": hash_password(RAW_ADMIN_PASSWORD),
                    "role": role,
                },
            )

        conn.execute(
            text("""
            INSERT INTO api_keys (id, tenant_id, key_hash, name, description, scopes, is_active, expires_at, created_by)
            VALUES (
                :id, :tenant_id, :key_hash, 'AuthClaw Lite Demo Key',
                'Seeded key for local/AWS Lite demo',
                ARRAY['admin','read','write'], true, NOW() + INTERVAL '90 days', :created_by
            )
            ON CONFLICT (id) DO UPDATE SET
                key_hash = EXCLUDED.key_hash,
                is_active = true,
                expires_at = NOW() + INTERVAL '90 days',
                revoked_at = NULL,
                rotated_at = NULL,
                scopes = ARRAY['admin','read','write'],
                updated_at = NOW()
            """),
            {"id": API_KEY_ID, "tenant_id": TENANT_ID, "key_hash": key_hash, "created_by": ADMIN_USER_ID},
        )

        conn.execute(
            text("""
            INSERT INTO gateway_configs (
                id, tenant_id, name, provider, endpoint, model_whitelist, redaction_strategy, redaction_token_retention_days, is_active
            )
            VALUES (
                :id, :tenant_id, 'Demo Gemini Route', 'gemini',
                'https://generativelanguage.googleapis.com',
                ARRAY['gemini-2.5-flash-lite'], 'mask', 90, true
            )
            ON CONFLICT (id) DO UPDATE SET
                endpoint = EXCLUDED.endpoint,
                model_whitelist = EXCLUDED.model_whitelist,
                redaction_strategy = EXCLUDED.redaction_strategy,
                redaction_token_retention_days = EXCLUDED.redaction_token_retention_days,
                is_active = true,
                updated_at = NOW()
            """),
            {"id": GATEWAY_ID, "tenant_id": TENANT_ID},
        )

        conn.execute(
            text("""
            INSERT INTO provider_credentials (
                id, tenant_id, provider, display_name, endpoint, encrypted_secret,
                auth_scheme, status, created_by, version, revoked_at
            )
            VALUES (
                :id, :tenant_id, 'gemini', 'Demo Gemini Credential', :endpoint, :encrypted_secret,
                'api_key', 'active', :created_by, 1, NULL
            )
            ON CONFLICT (id) DO UPDATE SET
                endpoint = EXCLUDED.endpoint,
                encrypted_secret = EXCLUDED.encrypted_secret,
                status = 'active',
                revoked_at = NULL,
                rotated_at = NOW(),
                version = provider_credentials.version + 1
            """),
            {
                "id": PROVIDER_CREDENTIAL_ID,
                "tenant_id": TENANT_ID,
                "endpoint": PROVIDER_ENDPOINT or None,
                "encrypted_secret": encrypt_secret(RAW_PROVIDER_KEY),
                "created_by": ADMIN_USER_ID,
            },
        )

        conn.execute(text("UPDATE policies SET is_active = false WHERE tenant_id = :tenant_id"), {"tenant_id": TENANT_ID})
        conn.execute(
            text("""
            INSERT INTO policies (
                id, tenant_id, name, description, policy_yaml, version, is_active, created_by
            )
            VALUES (
                :id, :tenant_id, 'AuthClaw Lite Starter Policy',
                'Starter demo policy with redact, HITL, and block actions.',
                :policy_yaml, 1, true, :created_by
            )
            ON CONFLICT (id) DO UPDATE SET
                policy_yaml = EXCLUDED.policy_yaml,
                is_active = true,
                updated_at = NOW()
            """),
            {
                "id": POLICY_ID,
                "tenant_id": TENANT_ID,
                "policy_yaml": STARTER_POLICY,
                "created_by": ADMIN_USER_ID,
            },
        )

    print("AuthClaw Lite demo seed complete.")
    print("Login email: admin@authclaw-lite.demo")
    print("Login password is configured via AUTHCLAW_LITE_DEMO_PASSWORD (not displayed).")
    print(f"Gateway API key fingerprint (hmac-sha3-256): {key_hash[:12]}...")


if __name__ == "__main__":
    main()
