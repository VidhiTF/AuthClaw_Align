"""Operator-only drain control; no application credential may change this state."""

import argparse
import json
import os

from sqlalchemy import create_engine, text


def control(connection, action):
    connection.execute(text("SET LOCAL statement_timeout = '15s'"))
    connection.execute(text("SET LOCAL lock_timeout = '10s'"))
    connection.execute(text("SET LOCAL row_security = off"))
    state = (
        connection.execute(
            text("SELECT * FROM worker_maintenance.control WHERE singleton FOR UPDATE")
        )
        .mappings()
        .one()
    )
    if action == "pause":
        # SELECT FOR UPDATE has waited for in-flight issuers holding FOR SHARE.
        connection.execute(
            text(
                "UPDATE worker_maintenance.control SET mode='paused', paused_at=clock_timestamp(), activated_at=NULL WHERE singleton"
            )
        )
        return {"paused": True, "required_drain_seconds": 1920}
    eligible = connection.execute(
        text(
            "SELECT paused_at IS NOT NULL AND paused_at <= clock_timestamp() - interval '32 minutes' FROM worker_maintenance.control WHERE singleton"
        )
    ).scalar_one()
    legacy = connection.execute(
        text(
            "SELECT count(*) FROM public.ephemeral_worker_tokens WHERE hash_algorithm='sha256' AND status='active' AND expires_at > clock_timestamp()"
        )
    ).scalar_one()
    if action == "activate":
        if state["mode"] != "paused" or not eligible or legacy:
            raise RuntimeError("Worker-token drain gate has not passed")
        connection.execute(
            text(
                "UPDATE worker_maintenance.control SET mode='hmac', activated_at=clock_timestamp() WHERE singleton"
            )
        )
    return {
        "drain_elapsed": bool(eligible),
        "unexpired_legacy": legacy,
        "activated": action == "activate",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("pause", "status", "activate"))
    args = parser.parse_args()
    engine = create_engine(
        os.environ["BOOTSTRAP_DATABASE_URL"], connect_args={"connect_timeout": 5}
    )
    try:
        with engine.begin() as connection:
            result = control(connection, args.action)
        print(json.dumps(result))
    except Exception as exc:
        print(json.dumps({"passed": False, "error_type": type(exc).__name__}))
        raise SystemExit(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
