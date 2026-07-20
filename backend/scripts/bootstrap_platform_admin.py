"""Bootstrap, verify, or roll back the first platform administrator."""

from __future__ import annotations

import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.auth import hash_key  # noqa: E402


def _database_url() -> str:
    url = os.environ["OWNER_DATABASE_URL"]
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _identity() -> tuple[str, str]:
    return (
        os.environ["PLATFORM_ADMIN_TENANT"].strip(),
        os.environ["PLATFORM_ADMIN_EMAIL"].strip().lower(),
    )


def main() -> None:
    action = os.getenv("PLATFORM_ADMIN_ACTION", "bootstrap").strip().lower()
    if action not in {"bootstrap", "verify", "rollback"}:
        raise ValueError("PLATFORM_ADMIN_ACTION must be bootstrap, verify, or rollback")

    tenant_name, email = _identity()
    engine = create_engine(_database_url(), pool_pre_ping=True)
    with engine.begin() as connection:
        principal = (
            connection.execute(
                text("""
                SELECT u.id, u.tenant_id, u.is_active, t.status AS tenant_status
                FROM users u
                JOIN tenants t ON t.id = u.tenant_id
                WHERE t.name = :tenant_name AND lower(u.email) = :email
                FOR UPDATE
                """),
                {"tenant_name": tenant_name, "email": email},
            )
            .mappings()
            .one_or_none()
        )
        if not principal:
            raise RuntimeError("Platform administrator identity was not found")
        if action != "rollback" and not principal["is_active"]:
            raise RuntimeError("Platform administrator identity is not active")
        if action != "rollback" and principal["tenant_status"] != "active":
            raise RuntimeError("Platform administrator identity tenant is not active")

        user_id = principal["id"]
        if action == "rollback":
            connection.execute(
                text("""
                    UPDATE api_keys
                    SET is_active = false, revoked_at = NOW(), updated_at = NOW()
                    WHERE created_by = :user_id
                      AND scopes @> ARRAY['platform.admin']::varchar[]
                    """),
                {"user_id": user_id},
            )
            connection.execute(
                text(
                    "UPDATE users SET platform_role = 'NONE', updated_at = NOW() "
                    "WHERE id = :user_id"
                ),
                {"user_id": user_id},
            )
            print(f"Platform administrator rolled back: user_id={user_id}")
            return

        active_keys = connection.execute(
            text("""
                SELECT COUNT(*)
                FROM api_keys
                WHERE created_by = :user_id
                  AND is_active = true
                  AND revoked_at IS NULL
                  AND rotated_at IS NULL
                  AND expires_at > NOW()
                  AND scopes @> ARRAY['platform.admin']::varchar[]
                """),
            {"user_id": user_id},
        ).scalar_one()
        if action == "verify":
            platform_role = connection.execute(
                text("SELECT platform_role FROM users WHERE id = :user_id"),
                {"user_id": user_id},
            ).scalar_one()
            if platform_role != "ADMIN" or active_keys < 1:
                raise RuntimeError("Platform administrator verification failed")
            print(f"Platform administrator verified: user_id={user_id}")
            return
        if active_keys:
            raise RuntimeError("An active platform administrator key already exists")

        raw_key = "ak_" + secrets.token_urlsafe(32)
        connection.execute(
            text(
                "UPDATE users SET platform_role = 'ADMIN', updated_at = NOW() "
                "WHERE id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text("""
                INSERT INTO api_keys (
                    id, tenant_id, key_hash, name, description, scopes,
                    is_active, expires_at, created_by
                )
                VALUES (
                    :id, :tenant_id, :key_hash, 'Platform Administration',
                    'Controlled operational platform key',
                    ARRAY['platform.admin'], true, :expires_at, :user_id
                )
                """),
            {
                "id": uuid.uuid4(),
                "tenant_id": principal["tenant_id"],
                "key_hash": hash_key(raw_key),
                "expires_at": datetime.now(timezone.utc) + timedelta(days=90),
                "user_id": user_id,
            },
        )
        print(f"Platform administrator created: user_id={user_id}")
        print(f"Platform API key (shown once): {raw_key}")


if __name__ == "__main__":
    main()
