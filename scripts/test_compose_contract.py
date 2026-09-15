"""Validate security-sensitive Docker Compose wiring from rendered configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DUMMY_GEMINI_KEY = "compose-contract-dummy-gemini-key"


def rendered_compose_config() -> dict:
    environment = os.environ.copy()
    environment["GEMINI_API_KEY"] = DUMMY_GEMINI_KEY
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env.full.example",
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
    audit_environment = config["services"]["audit_consumer"]["environment"]
    assert audit_environment["AUTHCLAW_ENV"] == config["services"]["backend"]["environment"]["AUTHCLAW_ENV"]
    assert "KAFKA_SECURITY_PROTOCOL" in audit_environment
    assert "CLICKHOUSE_SECURE" in audit_environment
    assert "AUDIT_POSTGRES_URL" in audit_environment
    agent_environment = config["services"]["agent"]["environment"]
    assert agent_environment["GOOGLE_API_KEY"] == DUMMY_GEMINI_KEY
    assert (
        agent_environment["AUTHCLAW_PROVIDER_GEMINI_API_KEY"] == DUMMY_GEMINI_KEY
    )
    assert agent_environment["MODEL_PROVIDER"] == "gemini"


if __name__ == "__main__":
    main()
