"""Read-only EC2 deployment check using the application's actual RDS URL.

Security-group/private-subnet inspection remains a separate AWS deployment gate.
"""

import json
import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def validate_url(raw):
    url = make_url(raw)
    if url.get_backend_name() != "postgresql" or not url.host:
        raise ValueError("A PostgreSQL RDS endpoint is required")
    if url.query.get("sslmode") != "verify-full":
        raise ValueError("RDS connections must verify the server identity")
    ca = url.query.get("sslrootcert", "")
    if not isinstance(ca, str) or not ca or not Path(ca).is_file():
        raise ValueError("A mounted trusted RDS CA bundle is required")
    return url


def main():
    engine = None
    try:
        engine = create_engine(
            validate_url(os.environ["DATABASE_URL"]),
            connect_args={"connect_timeout": 5},
        )
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL statement_timeout = '5s'"))
            tls = connection.execute(
                text("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            ).scalar_one()
            privileged = connection.execute(text("""
                SELECT rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                    OR coalesce(pg_has_role(current_user, to_regrole('rds_superuser'), 'MEMBER'), false)
                FROM pg_roles WHERE rolname=current_user
            """)).scalar_one()
            if not tls or privileged:
                raise RuntimeError("RDS transport or application role is unsafe")
        result = {
            "transport_and_role_passed": True,
            "private_network_review_required": True,
        }
    except Exception as exc:
        result = {"transport_and_role_passed": False, "error_type": type(exc).__name__}
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(result))
    return 0 if result["transport_and_role_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
