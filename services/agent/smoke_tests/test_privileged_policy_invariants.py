import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from startup.validation import load_and_validate_policy


class PrivilegedPolicyInvariantTests(unittest.TestCase):
    def _policy_with(self, field: str, value: bool) -> str:
        source = Path(__file__).resolve().parents[1] / "policies.yaml"
        policy = source.read_text(encoding="utf-8")
        policy = policy.replace(f"{field}: true", f"{field}: {str(value).lower()}")
        handle, path = tempfile.mkstemp(suffix=".yaml")
        os.close(handle)
        Path(path).write_text(policy, encoding="utf-8")
        self.addCleanup(Path(path).unlink, missing_ok=True)
        return path

    def test_shared_environments_reject_disabled_privileged_controls(self):
        for environment in ("ci", "shared-test", "staging", "production"):
            for field in ("require_mfa", "require_separate_approver"):
                with self.subTest(environment=environment, field=field):
                    with patch.dict(os.environ, {"AUTHCLAW_ENV": environment}):
                        with self.assertRaisesRegex(ValueError, field):
                            load_and_validate_policy(self._policy_with(field, False))

    def test_explicit_local_environment_can_exercise_disabled_controls(self):
        with patch.dict(os.environ, {"AUTHCLAW_ENV": "isolated-test"}):
            policy = load_and_validate_policy(
                self._policy_with("require_mfa", False)
            )
        self.assertFalse(policy["approval"]["require_mfa"])

    def test_unset_environment_rejects_disabled_privileged_controls(self):
        with patch.dict(os.environ, {}, clear=True):
            for field in ("require_mfa", "require_separate_approver"):
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, field):
                        load_and_validate_policy(self._policy_with(field, False))


if __name__ == "__main__":
    unittest.main()
