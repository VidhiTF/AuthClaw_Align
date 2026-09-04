"""Run from an independent monitor; exit nonzero on stale/missing/unreachable heartbeat.

This script never runs cleanup. Monitoring must wire its exit status to an alert.
"""

import json
import os
import argparse
import time

from sqlalchemy import create_engine, text


def check(connection):
    connection.execute(text("SET LOCAL statement_timeout = '5s'"))
    row = (
        connection.execute(text("SELECT * FROM worker_maintenance.cleanup_health()"))
        .mappings()
        .one()
    )
    return {
        "healthy": not row["overdue"],
        "last_success": str(row["last_success"]) if row["last_success"] else None,
        "last_success_unix": (
            row["last_success"].timestamp() if row["last_success"] else 0
        ),
        "expired_count": row["expired_count"],
        "duration_ms": row["duration_ms"],
    }


def prometheus(result):
    return "\n".join(
        (
            f"authclaw_worker_cleanup_healthy {int(result['healthy'])}",
            f"authclaw_worker_cleanup_last_success_seconds {result.get('last_success_unix', 0)}",
            f"authclaw_worker_cleanup_monitor_timestamp_seconds {time.time()}",
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prometheus", action="store_true")
    args = parser.parse_args()
    engine = None
    try:
        engine = create_engine(
            os.environ["DATABASE_URL"], connect_args={"connect_timeout": 5}
        )
        with engine.begin() as connection:
            result = check(connection)
    except Exception as exc:
        result = {"healthy": False, "error_type": type(exc).__name__}
    finally:
        if engine is not None:
            engine.dispose()
    print(prometheus(result) if args.prometheus else json.dumps(result))
    return 0 if result["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
