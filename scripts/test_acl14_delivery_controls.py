import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
DEPLOY = (ROOT / ".github/workflows/deploy-controlled-beta.yml").read_text(encoding="utf-8")
REGISTRY = (ROOT / "infra/terraform/registry.tf").read_text(encoding="utf-8")
VARIABLES = (ROOT / "infra/terraform/variables.tf").read_text(encoding="utf-8")
REGIONAL_STACK = (ROOT / "infra/terraform/modules/regional_stack/main.tf").read_text(encoding="utf-8")


class ACL14DeliveryControlTests(unittest.TestCase):
    def test_ci_executes_for_master_and_master_pull_requests(self):
        self.assertNotIn("  create:\n", CI)
        self.assertIn("  push:\n    branches: [master]", CI)
        self.assertIn("  pull_request:\n    branches: [master]", CI)
        self.assertIn('if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]', CI)
        self.assertIn("before='${{ github.event.pull_request.base.sha }}'", CI)
        self.assertIn("    branches: [master]", DEPLOY)
        self.assertNotIn("pull_request:", DEPLOY)
        for workflow in (CI, DEPLOY):
            self.assertNotIn("schedule:", workflow)
            self.assertNotIn("workflow_dispatch:", workflow)

    def test_default_master_ci_is_minimal_and_path_aware(self):
        self.assertIn("name: ACL-14 Required Checks", CI)
        self.assertIn("name: Detect changed components", CI)
        self.assertIn("if: needs.changes.outputs.backend == 'true'", CI)
        self.assertIn("if: needs.changes.outputs.console == 'true'", CI)
        for job in ("Backend Tests", "Gateway Tests", "Agent Tests", "Console Tests and Build", "Security Scans"):
            self.assertIn(f"name: {job}", CI)
        self.assertIn("github.ref == 'refs/heads/master'", CI)
        self.assertIn("github/codeql-action/analyze@v4", CI)
        self.assertIn("security-events: write", CI)
        self.assertIn("vars.CODEQL_NATIVE_UPLOAD == 'true'", CI)
        self.assertIn("upload-database: false", CI)
        self.assertIn("name: Enforce CodeQL findings", CI)
        self.assertIn("actions/upload-artifact@v6", CI)
        self.assertIn("ghcr.io/gitleaks/gitleaks", CI)
        self.assertIn("aquasecurity/trivy-action", CI)
        self.assertNotIn("Full Stack Integration", CI)

    def test_canonical_local_command_is_documented_and_exercised(self):
        command = "docker compose --env-file .env.full -f docker-compose.full.yml up -d --build --wait"
        self.assertIn(command, (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn(command, (ROOT / "startup_guide.md").read_text(encoding="utf-8"))

    def test_beta_release_is_gated_immutable_encrypted_and_reversible(self):
        self.assertIn("github.event.workflow_run.conclusion == 'success'", DEPLOY)
        self.assertIn("id-token: write", DEPLOY)
        self.assertIn("require_immutable_images: true", DEPLOY)
        self.assertIn("@sha256:[0-9a-f]{64}", VARIABLES)
        self.assertIn('image_tag_mutability = "IMMUTABLE"', REGISTRY)
        self.assertIn('encryption_type = "KMS"', REGISTRY)
        self.assertIn('agent="$(promote agent ', DEPLOY)
        self.assertIn('agent = {', REGIONAL_STACK)
        self.assertIn('/api/v1/agent/health/ready', REGIONAL_STACK)
        self.assertIn('AUTHCLAW_INTERNAL_SERVICE_SECRET', REGIONAL_STACK)
        self.assertIn("Roll back to previous task definitions", DEPLOY)
        self.assertIn("Reject active deployment alarms", DEPLOY)

    def test_master_protection_requires_review_and_pre_merge_ci(self):
        protection = json.loads((ROOT / ".github/branch-protection-master.json").read_text(encoding="utf-8"))
        self.assertTrue(protection["required_status_checks"]["strict"])
        self.assertIn("ACL-14 Required Checks", protection["required_status_checks"]["contexts"])
        self.assertTrue(protection["enforce_admins"])
        self.assertTrue(protection["required_pull_request_reviews"]["require_code_owner_reviews"])
        self.assertFalse(protection["allow_force_pushes"])
        self.assertFalse(protection["allow_deletions"])

    def test_adr_numbers_are_unique(self):
        numbers = [path.name.split("-", 1)[0] for path in (ROOT / "docs/adr").glob("*.md")]
        self.assertEqual(len(numbers), len(set(numbers)))


if __name__ == "__main__":
    unittest.main()
