import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
DEPLOY = (ROOT / ".github/workflows/deploy-controlled-beta.yml").read_text(encoding="utf-8")
WORKFLOWS = tuple((ROOT / ".github/workflows").glob("*.yml")) + tuple(
    (ROOT / ".github/workflows").glob("*.yaml")
)
REGISTRY = (ROOT / "infra/terraform/registry.tf").read_text(encoding="utf-8")
VARIABLES = (ROOT / "infra/terraform/variables.tf").read_text(encoding="utf-8")
REGIONAL_STACK = (ROOT / "infra/terraform/modules/regional_stack/main.tf").read_text(encoding="utf-8")


class ACL14DeliveryControlTests(unittest.TestCase):
    def test_crypto_gate_precedes_runtime_and_bootstraps_only_empty_installation(self):
        gate = DEPLOY.split("- name: Gate runtime rollout", 1)[1].split(
            "- name: Apply controlled-beta", 1
        )[0]
        self.assertIn("fresh=false", gate)
        self.assertIn("[[ ! -s previous-task-definitions.tsv ]]", gate)
        self.assertIn('if [[ "$fresh" == true ]]', gate)
        self.assertIn("bootstrap_prepare backend_migrations agent_migrations bootstrap_finalize database_security_check", gate)
        self.assertIn("run_job crypto_preflight", gate)
        self.assertNotIn("-target=module.primary.aws_ecs_service", gate)
        self.assertIn("-target=module.primary.aws_secretsmanager_secret_version.envelope_v2", gate)
        self.assertIn("all(.tasks[0].containers[]; .exitCode == 0)", gate)
        self.assertIn("vars.CRYPTO_STRICT_ROLLBACK_APPROVED == 'true'", DEPLOY)
        self.assertIn("steps.runtime_release.outcome", DEPLOY)

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
        for job in ("Backend Unit Tests", "Backend PostgreSQL Integration", "Gateway Tests", "Agent Tests", "Console Tests and Build", "Security Scans"):
            self.assertIn(f"name: {job}", CI)
        self.assertIn("github.ref == 'refs/heads/master'", CI)
        self.assertIn("github/codeql-action/analyze@", CI)
        self.assertIn("security-events: write", CI)
        self.assertIn("vars.CODEQL_NATIVE_UPLOAD == 'true'", CI)
        self.assertIn("upload-database: false", CI)
        self.assertIn("name: Enforce CodeQL findings", CI)
        self.assertIn("actions/upload-artifact@", CI)
        self.assertIn("ghcr.io/gitleaks/gitleaks", CI)
        self.assertIn("aquasecurity/trivy-action", CI)
        self.assertNotIn("Full Stack Integration", CI)

    def test_backend_integration_uses_real_postgres_and_current_migration_head(self):
        self.assertIn(
            "image: postgres:16.10-alpine@sha256:"
            "029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297",
            CI,
        )
        self.assertIn("authclaw_ci_test", CI)
        self.assertIn("bootstrap_database_security.py prepare", CI)
        self.assertIn("-m alembic upgrade head", CI)
        self.assertIn("bootstrap_database_security.py finalize-backend", CI)
        self.assertIn("tests/test_tenant_isolation.py", CI)
        self.assertIn("tests/test_endpoints.py", CI)
        self.assertIn("backend-integration", CI)

    def test_arm64_images_do_not_run_for_pull_requests(self):
        self.assertIn(
            "github.event_name == 'push' &&\n"
            "      github.ref == 'refs/heads/master' &&\n"
            "      needs.changes.outputs.runtime_images == 'true'",
            CI,
        )

    def test_external_actions_are_pinned_to_full_commit_shas(self):
        use_pattern = re.compile(r"\buses:\s*([^@\s]+)@([^#\s]+)")
        for workflow_path in WORKFLOWS:
            workflow = workflow_path.read_text(encoding="utf-8")
            for line_number, line in enumerate(workflow.splitlines(), start=1):
                match = use_pattern.search(line)
                if not match or match.group(1).startswith("./"):
                    continue
                reference = match.group(2)
                self.assertRegex(
                    reference,
                    r"^[0-9a-f]{40}$",
                    f"{workflow_path.name}:{line_number} must pin a full commit SHA",
                )
                self.assertRegex(
                    line,
                    r"#\s*v?\d",
                    f"{workflow_path.name}:{line_number} must retain a release comment",
                )

    def test_canonical_local_command_is_documented_and_exercised(self):
        command = "docker compose --env-file .env.full -f docker-compose.full.yml up -d --build --wait"
        self.assertIn(command, (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn(command, (ROOT / "startup_guide.md").read_text(encoding="utf-8"))

    def test_beta_release_is_gated_immutable_encrypted_and_reversible(self):
        self.assertIn('workflows: ["AuthClaw Required CI"]', DEPLOY)
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
