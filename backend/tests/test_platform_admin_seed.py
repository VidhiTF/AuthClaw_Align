import ast
from pathlib import Path
import sqlite3


def _seed_statement():
    source = Path(__file__).parents[1] / "scripts" / "seed_authclaw_lite.py"
    return next(
        node.value
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "INSERT INTO authn.platform_admins" in node.value
    )


def test_platform_seed_preserves_existing_password_and_disabled_state():
    with sqlite3.connect(":memory:") as db:
        db.execute("ATTACH DATABASE ':memory:' AS authn")
        db.execute(
            "CREATE TABLE authn.platform_admins ("
            "id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, "
            "display_name TEXT, role TEXT, is_active BOOLEAN, updated_at TEXT)"
        )
        db.create_function("NOW", 0, lambda: "now")
        params = {"id": "seed-id", "email": "seed@example.invalid", "password_hash": "original-hash"}
        db.execute(_seed_statement(), params)
        assert db.execute("SELECT password_hash, is_active FROM authn.platform_admins").fetchone() == ("original-hash", 1)
        db.execute("UPDATE authn.platform_admins SET is_active = 0")
        db.execute(_seed_statement(), {**params, "password_hash": "replacement-hash"})
        assert db.execute("SELECT password_hash, is_active FROM authn.platform_admins").fetchone() == ("original-hash", 0)
