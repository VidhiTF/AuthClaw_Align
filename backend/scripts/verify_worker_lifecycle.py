"""Read-only candidate deployment gate, after operator migration and drain."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine, text
from app.core.worker_tokens import active_version, key_for


def verify(connection):
    connection.execute(text("SET LOCAL statement_timeout = '10s'"))
    connection.execute(text("SET LOCAL row_security = off"))
    ready = connection.execute(
        text(
            "SELECT mode='hmac' AND activated_at IS NOT NULL AND paused_at <= activated_at - interval '32 minutes' FROM worker_maintenance.control WHERE singleton"
        )
    ).scalar_one()
    legacy = connection.execute(
        text(
            "SELECT count(*) FROM public.ephemeral_worker_tokens WHERE hash_algorithm='sha256' AND status='active' AND expires_at>clock_timestamp()"
        )
    ).scalar_one()
    versions = (
        connection.execute(
            text(
                "SELECT DISTINCT hash_key_version FROM public.ephemeral_worker_tokens WHERE hash_algorithm='hmac-sha256-v1' AND status='active' AND expires_at>clock_timestamp()"
            )
        )
        .scalars()
        .all()
    )
    key_for(active_version())
    for version in versions:
        key_for(version)
    return {
        "passed": bool(ready and legacy == 0),
        "unexpired_legacy": legacy,
        "referenced_key_versions": versions,
    }


def main():
    engine = None
    try:
        engine = create_engine(
            os.environ["DATABASE_URL"], connect_args={"connect_timeout": 5}
        )
        with engine.begin() as connection:
            result = verify(connection)
    except Exception as exc:
        result = {"passed": False, "error_type": type(exc).__name__}
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
