"""Exercise debug environment parsing without database or service dependencies."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.core.config import Settings

BACKEND_ROOT = Path(__file__).resolve().parents[1]


class DebugSettingsTests(unittest.TestCase):
    def settings(self, **environment: str) -> Settings:
        with patch.dict(os.environ, environment, clear=True):
            return Settings(_env_file=None)

    def test_default_and_legacy_name_do_not_enable_debug(self) -> None:
        self.assertFalse(self.settings().DEBUG)
        self.assertFalse(self.settings(API_DEBUG="true").DEBUG)
        self.assertFalse(self.settings(API_DEBUG="false").DEBUG)

    def test_explicit_local_opt_in(self) -> None:
        for runtime in ("local", "development", "dev", "test", " LOCAL "):
            with self.subTest(runtime=runtime):
                self.assertTrue(self.settings(DEBUG="true", AUTHCLAW_ENV=runtime).DEBUG)

    def test_shared_unknown_and_unspecified_modes_fail_closed(self) -> None:
        for runtime in (
            "",
            "production",
            "prod",
            "staging",
            "stage",
            "shared-test",
            "ci",
            "typo",
            " PRODUCTION ",
        ):
            with self.subTest(runtime=runtime):
                self.assertFalse(
                    self.settings(DEBUG="false", AUTHCLAW_ENV=runtime).DEBUG
                )
                with self.assertRaisesRegex(ValidationError, "DEBUG requires"):
                    self.settings(
                        DEBUG="true",
                        API_DEBUG="false",
                        AUTHCLAW_ENV=runtime,
                    )

    def test_invalid_boolean_fails_closed(self) -> None:
        with self.assertRaises(ValidationError):
            self.settings(DEBUG="not-a-boolean", AUTHCLAW_ENV="local")

    def test_dotenv_debug_cannot_bypass_production_guard(self) -> None:
        with TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("DEBUG=true\nAUTHCLAW_ENV=local\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"AUTHCLAW_ENV": "production", "API_DEBUG": "false"},
                clear=True,
            ):
                with self.assertRaisesRegex(ValidationError, "DEBUG requires"):
                    Settings(_env_file=env_file)

    def test_startup_rejection_does_not_log_settings_inputs(self) -> None:
        secret = "t11-secret-input-must-not-appear"
        for debug_value in ("true", "invalid-debug-sentinel"):
            with self.subTest(debug_value=debug_value):
                environment = os.environ.copy()
                environment.update(
                    {
                        "AUTHCLAW_ENV": "production",
                        "DEBUG": debug_value,
                        "ENVELOPE_KEY": secret,
                        "PYTHONPATH": str(BACKEND_ROOT),
                    }
                )
                result = subprocess.run(
                    [sys.executable, "-c", "from app.core.config import settings"],
                    cwd=BACKEND_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ValidationError", output)
                self.assertNotIn("input_value", output)
                self.assertNotIn(secret, output)
                self.assertNotIn("invalid-debug-sentinel", output)

    def test_settings_drive_engine_echo_and_hide_parameters(self) -> None:
        probe = (
            "import json; "
            "from app.db.session import engine; "
            "print(json.dumps([engine.echo, engine.hide_parameters]))"
        )
        for environment, expected_echo in (
            ({"AUTHCLAW_ENV": "production", "DEBUG": "false"}, False),
            ({"AUTHCLAW_ENV": "local", "DEBUG": "true"}, True),
        ):
            with self.subTest(environment=environment):
                process_environment = os.environ.copy()
                process_environment.update(environment)
                process_environment["PYTHONPATH"] = str(BACKEND_ROOT)
                result = subprocess.run(
                    [sys.executable, "-c", probe],
                    cwd=BACKEND_ROOT,
                    env=process_environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                self.assertEqual(
                    json.loads(result.stdout.strip()), [expected_echo, True]
                )


if __name__ == "__main__":
    unittest.main()
