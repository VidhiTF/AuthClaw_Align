"""Create and grant the restricted runtime database role for AuthClaw Lite."""
from __future__ import annotations

import os
import re

from sqlalchemy import create_engine, text


ROLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def main() -> None:
    database_url = normalize_database_url(
        os.getenv("OWNER_DATABASE_URL")
        or os.getenv("DATABASE_URL", "postgresql+psycopg://authclaw:authclaw@localhost:5432/authclaw")
    )
    app_user = os.getenv("POSTGRES_APP_USER", "authclaw_app")
    app_password = os.getenv("POSTGRES_APP_PASSWORD", "authclaw_app")
    database_name = os.getenv("POSTGRES_DB", "authclaw")

    if not ROLE_NAME_RE.match(app_user):
        raise ValueError("POSTGRES_APP_USER must be a valid PostgreSQL identifier")
    if not ROLE_NAME_RE.match(database_name):
        raise ValueError("POSTGRES_DB must be a valid PostgreSQL identifier")

    engine = create_engine(database_url, pool_pre_ping=True)
    password_literal = quote_literal(app_password)

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes VARCHAR[];"))
        conn.execute(
            text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{app_user}') THEN
                        CREATE ROLE {app_user} LOGIN PASSWORD {password_literal};
                    ELSE
                        ALTER ROLE {app_user} LOGIN PASSWORD {password_literal};
                    END IF;
                END
                $$;
                """
            )
        )
        conn.execute(text(f"ALTER ROLE {app_user} NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;"))
        conn.execute(text(f"GRANT CONNECT ON DATABASE {database_name} TO {app_user};"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {app_user};"))
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {app_user};"))
        conn.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {app_user};"))
        conn.execute(text(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {app_user};"))
        conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_user};"))
        conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {app_user};"))
        conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {app_user};"))

    print(f"Restricted runtime database role ready: {app_user}")


if __name__ == "__main__":
    main()
