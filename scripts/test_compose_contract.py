"""Validate security-sensitive Docker Compose wiring from rendered configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DUMMY_GEMINI_KEY = "compose-contract-dummy-gemini-key"


def rendered_compose_config(
    env_file: str = ".env.full.example", **overrides: str
) -> dict:
    environment = os.environ.copy()
    for name in ("DEBUG", "API_DEBUG", "AUTHCLAW_ENV", "SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD"):
        environment.pop(name, None)
    environment["GEMINI_API_KEY"] = DUMMY_GEMINI_KEY
    environment.update(overrides)
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            env_file,
            "-f",
            "docker-compose.full.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker compose config failed:\n{result.stderr}")
    return json.loads(result.stdout)


def main() -> None:
    config = rendered_compose_config()
    backend_environment = config["services"]["backend"]["environment"]
    assert backend_environment["DEBUG"] == "true"
    assert "API_DEBUG" not in backend_environment
    assert backend_environment["AUTHCLAW_ENV"] == "local"
    for name in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD"):
        assert backend_environment[name] == "", f"Local template must not enable incomplete SMTP: {name}"
    audit_environment = config["services"]["audit_consumer"]["environment"]
    assert audit_environment["AUTHCLAW_ENV"] == backend_environment["AUTHCLAW_ENV"]
    assert "KAFKA_SECURITY_PROTOCOL" in audit_environment
    assert "CLICKHOUSE_SECURE" in audit_environment
    assert "AUDIT_POSTGRES_URL" in audit_environment
    agent_environment = config["services"]["agent"]["environment"]
    assert agent_environment["GOOGLE_API_KEY"] == DUMMY_GEMINI_KEY
    assert agent_environment["AUTHCLAW_PROVIDER_GEMINI_API_KEY"] == DUMMY_GEMINI_KEY
    assert agent_environment["MODEL_PROVIDER"] == "gemini"
    assert agent_environment["AUTHCLAW_CLICKHOUSE_ENABLED"] == os.getenv(
        "AUTHCLAW_CLICKHOUSE_ENABLED", "false"
    )

    production_config = rendered_compose_config(".env.production.example")
    production_backend = production_config["services"]["backend"]["environment"]
    assert production_backend["DEBUG"] == "false"
    assert "API_DEBUG" not in production_backend

    legacy_config = rendered_compose_config(DEBUG="", API_DEBUG="true")
    legacy_backend = legacy_config["services"]["backend"]["environment"]
    assert legacy_backend["DEBUG"] == "false"
    assert "API_DEBUG" not in legacy_backend


if __name__ == "__main__":
    main()
