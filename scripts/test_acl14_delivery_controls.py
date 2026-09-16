import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
DEPLOY = (ROOT / ".github/workflows/deploy-controlled-beta.yml").read_text(encoding="utf-8")
RUNBOOK = (ROOT / "docs/runbooks/PRODUCTION_RELEASE.md").read_text(encoding="utf-8")
WORKFLOWS = tuple((ROOT / ".github/workflows").glob("*.yml")) + tuple(
    (ROOT / ".github/workflows").glob("*.yaml")
)
REGISTRY = (ROOT / "infra/terraform/registry.tf").read_text(encoding="utf-8")
VARIABLES = (ROOT / "infra/terraform/variables.tf").read_text(encoding="utf-8")
TERRAFORM_MAIN = (ROOT / "infra/terraform/main.tf").read_text(encoding="utf-8")
REGIONAL_STACK = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "infra/terraform/modules/regional_stack").glob("*.tf"))
RUNTIME_IAM = (ROOT / "infra/terraform/modules/regional_stack/runtime_iam.tf").read_text(encoding="utf-8")
IAM_INVENTORY = (ROOT / "docs/security/P0_10_11_LOCAL_INVENTORY.md").read_text(encoding="utf-8")
AWS_SERVICE_INVENTORY = (ROOT / "docs/compliance/P0_08_RUNTIME_AWS_SERVICE_INVENTORY.md").read_text(encoding="utf-8")
AWS_READINESS_TASKS = (ROOT / "docs/AWS_DEPLOYMENT_READINESS_TASK_LIST.md").read_text(encoding="utf-8")
AUDIT_READINESS_MATRIX = (ROOT / "infra/security/audit-transport-readiness-matrix.md").read_text(encoding="utf-8")
SQS_READINESS = (ROOT / "scripts/sqs_audit_deployment_readiness.py").read_text(encoding="utf-8")
SQS_PENDING_EVIDENCE = tuple(
    (ROOT / path).read_text(encoding="utf-8")
    for path in (
        "infra/security/sqs-audit-deployment-readiness.pending.json",
        "infra/security/sqs-audit-deployment-readiness.pending.md",
    )
)


class ACL14DeliveryControlTests(unittest.TestCase):
    def test_sqs_inventories_match_isolated_producer_boundary(self):
        for inventory in (IAM_INVENTORY, AWS_SERVICE_INVENTORY):
            self.assertIn("isolated", inventory)
            self.assertIn("audit_producer", inventory)
            self.assertIn("no task role", inventory)
            self.assertIn("no task role or direct SQS permission", inventory)
        self.assertNotIn("SQS producer policies attach only to backend/gateway", IAM_INVENTORY)
        self.assertNotIn("SQS — backend and gateway publishers", AWS_SERVICE_INVENTORY)
        self.assertNotIn("backend, gateway, agent, and audit-consumer", AWS_SERVICE_INVENTORY)
        self.assertNotIn("backend/gateway producer-only", AUDIT_READINESS_MATRIX)
        self.assertNotIn("task roles for backend, agent, gateway", AWS_READINESS_TASKS)
        self.assertIn("backend and the isolated `audit_producer`", AUDIT_READINESS_MATRIX)
        self.assertIn("gateway/agent/audit_producer/audit_consumer", SQS_READINESS)
        for pending_evidence in SQS_PENDING_EVIDENCE:
            self.assertIn("gateway/agent/audit_producer/audit_consumer", pending_evidence)

    def test_internal_tls_security_group_routes_only_to_tls_ports(self):
        self.assertIn(
            "for_each = var.internal_tls.enabled ? toset([8443]) : toset([8000, 8001, 8080])",
            REGIONAL_STACK,
        )
        self.assertIn("from_port       = local.service_ports[ingress.key]", REGIONAL_STACK)
        self.assertIn("to_port         = local.service_ports[ingress.key]", REGIONAL_STACK)
        self.assertIn("for_each = toset(values(local.service_ports))", REGIONAL_STACK)

    def test_all_ecs_services_enable_health_based_circuit_breaker_rollback(self):
        services = re.findall(r'resource "aws_ecs_service" "[^"]+" \{(.*?)(?=\nresource |\Z)', REGIONAL_STACK, re.S)
        self.assertEqual(len(services), 3)
        for service in services:
            self.assertRegex(service, r'deployment_circuit_breaker\s*\{\s*enable\s*=\s*true\s*rollback\s*=\s*true')
        self.assertIn('.services[0].taskDefinition == $definition', DEPLOY)
        self.assertIn('.rolloutState == "COMPLETED"', DEPLOY)

    def test_deployment_requires_push_and_complete_release_jobs(self):
        self.assertIn("github.event.workflow_run.event == 'push'", DEPLOY)
        self.assertIn("if: needs.eligibility.outputs.ready == 'true'", DEPLOY)
        self.assertIn('if [[ "$count" == 0 ]]', DEPLOY)
        self.assertIn('length) == 7', DEPLOY)
        self.assertIn('.name == "Release Completion Gate" and .conclusion == "success"', DEPLOY)
        release = CI.split("  release-images:", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("needs.changes.outputs.release == 'true'", release)
        self.assertIn("needs: [changes, checks]", release)

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
        self.assertIn("-target=module.primary.aws_ecs_cluster_capacity_providers.main", gate)
        self.assertIn("aws secretsmanager describe-secret", gate)
        self.assertIn("AWSCURRENT", gate)
        self.assertNotIn("aws_secretsmanager_secret_version", gate)
        self.assertIn('scripts/ecs_database_job.py database-gate.json "$1"', gate)
        self.assertIn('for job in backend_migrations agent_migrations database_security_check', gate)
        self.assertIn('DATABASE_EXPAND_COMPATIBILITY_APPROVED', gate)
        self.assertIn("launch_model", (ROOT / "infra/terraform/outputs.tf").read_text(encoding="utf-8"))
        self.assertIn("vars.CRYPTO_STRICT_ROLLBACK_APPROVED == 'true'", DEPLOY)
        self.assertIn("steps.runtime_release.outcome", DEPLOY)

    def test_ci_executes_for_master_and_master_pull_requests(self):
        self.assertNotIn("  create:\n", CI)
        self.assertIn("  push:\n    branches: [master]", CI)
        self.assertIn("  pull_request:\n    branches: [master]", CI)
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}", CI)
        self.assertIn("    branches: [master]", DEPLOY)
        self.assertNotIn("pull_request:", DEPLOY)
        self.assertIn("  schedule:", CI)
        self.assertIn("  workflow_dispatch:", CI)
        self.assertNotIn("schedule:", DEPLOY)
        self.assertNotIn("workflow_dispatch:", DEPLOY)

    def test_default_master_ci_is_minimal_and_path_aware(self):
        self.assertIn("name: ACL-14 Required Checks", CI)
        self.assertIn("name: Detect changed components", CI)
        self.assertIn("if: needs.changes.outputs.backend == 'true'", CI)
        self.assertIn("if: needs.changes.outputs.console == 'true'", CI)
        for job in ("Backend Unit Tests", "Backend PostgreSQL Integration", "Gateway Tests", "Agent Tests", "Console Tests and Build", "Security Scans"):
            self.assertIn(f"name: {job}", CI)
        self.assertIn("github.ref == 'refs/heads/master'", CI)
        self.assertNotIn("codeql", CI.lower())
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
        self.assertIn("if: needs.changes.outputs.arm64 == 'true'", CI)
        self.assertIn("vars.CI_ARM64_ENABLED == 'true'", CI)
        self.assertIn("description: Also build and smoke-test ARM64 runtime images", CI)

    def test_required_gate_rejects_unexpected_skips_and_release_gate_is_always_run(self):
        self.assertIn("EXPECTED_JOBS: ${{ needs.changes.outputs.expected_jobs }}", CI)
        self.assertIn("NEEDS_JSON: ${{ toJSON(needs) }}", CI)
        self.assertIn("run: python3 scripts/ci_plan.py verify", CI)
        self.assertIn("    name: Release Completion Gate\n    if: always()", CI)
        self.assertIn('test "$RELEASE_RESULT" = success', CI)
        self.assertIn("needs: [changes, checks, release-images]", CI)

    def test_light_master_and_full_regression_execute_real_suites(self):
        self.assertIn("name: Master Smoke and Contract Integration", CI)
        self.assertIn("tests/test_secret_crypto.py tests/test_audit_transport_contract.py", CI)
        self.assertIn("description: Run all established CI component regression suites", CI)
        self.assertIn("name: Run destructive PostgreSQL suites serially", CI)
        self.assertIn("name: Run gateway tests", CI)

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
        self.assertIn("Restore previous topology and runtime configuration", DEPLOY)
        self.assertIn("Reject active deployment alarms", DEPLOY)

    def test_alarm_gate_requires_the_exact_inventory_to_be_ok(self):
        gate = DEPLOY.split("- name: Reject active deployment alarms", 1)[1].split(
            "- name: Capture and verify deployed policy topology", 1
        )[0]
        self.assertIn("deployment-alarms.json", gate)
        self.assertIn("expected-alarm-names.json", gate)
        self.assertIn(".StateValue == \"OK\"", gate)
        self.assertIn("map(.AlarmName) | sort", gate)
        self.assertNotIn("MetricAlarms[?StateValue=='ALARM']", gate)

    def test_automatic_rollback_restores_reviewed_topology(self):
        rollback = DEPLOY.split("- name: Restore previous topology and runtime configuration", 1)[1].split(
            "- name: Upload deployment and rollback evidence", 1
        )[0]
        self.assertIn("ROLLBACK_TFVARS_JSON", DEPLOY)
        self.assertIn(". as $config", DEPLOY)
        self.assertIn("$config", DEPLOY)
        self.assertIn('rollback.tfvars.json', rollback)
        self.assertIn('-var-file="$GITHUB_WORKSPACE/rollback.tfvars.json"', rollback)
        self.assertIn("rollback.tfplan", rollback)
        self.assertIn("rollback-target-task-definitions.tsv", rollback)
        self.assertIn("rollback-image-inventory.json", rollback)
        self.assertNotIn("aws ecs update-service", rollback)

    def test_manual_rollback_restores_topology_before_verification(self):
        rollback = RUNBOOK.split("## Stop conditions and rollback execution", 1)[1].split(
            "| Surface | Recovery procedure |", 1
        )[0]
        self.assertIn("rollback.tfplan", rollback)
        self.assertIn('-var-file="$ROLLBACK_TFVARS"', rollback)
        self.assertIn("terraform -chdir=infra/terraform apply", rollback)
        self.assertIn('select(.address == "module.primary")', rollback)
        self.assertNotIn("aws ecs update-service", rollback)

    def test_rollback_drill_has_executable_functional_checks(self):
        for value in (
            "/health", "/auth/me", "/v1/chat/completions", "X-Request-ID",
            "/audit-logs?", "/audit-logs/store/consistency", ".consistent == true",
        ):
            self.assertIn(value, RUNBOOK)

    def test_colocation_is_an_explicit_reversible_release_switch(self):
        self.assertIn('variable "enable_policy_sidecar_colocation"', VARIABLES)
        self.assertIn("default     = false", VARIABLES)
        self.assertIn("TF_VAR_enable_policy_sidecar_colocation", DEPLOY)
        self.assertIn("ENABLE_POLICY_SIDECAR_COLOCATION must be true or false", DEPLOY)
        self.assertIn('port_mappings = []', REGIONAL_STACK)
        self.assertIn('http://127.0.0.1:8181', REGIONAL_STACK)
        self.assertIn('http://127.0.0.1:3000', REGIONAL_STACK)
        self.assertIn("colocated_sidecars_have_no_task_role", RUNTIME_IAM)
        self.assertIn("AUDIT_PRODUCER_URL", REGIONAL_STACK)

    def test_alarm_gate_polls_initializing_alarms_and_fails_closed(self):
        alarm_gate = DEPLOY.split("- name: Reject active deployment alarms", 1)[1].split("- name:", 1)[0]
        self.assertIn("deadline=$((SECONDS + 600))", alarm_gate)
        self.assertIn('.StateValue != "ALARM"', alarm_gate)
        self.assertIn("sleep 15", alarm_gate)
        self.assertIn("did not all reach OK within 600 seconds", alarm_gate)

    def test_deployment_captures_and_verifies_policy_topology(self):
        self.assertIn("Capture and verify deployed policy topology", DEPLOY)
        self.assertIn("scripts/verify_ecs_colocation.py", DEPLOY)
        self.assertIn('--architecture-map "$TF_VAR_service_cpu_architectures"', DEPLOY)
        self.assertIn("ecs-services.json", DEPLOY)
        self.assertIn("*-task-definition.json", DEPLOY)
        self.assertIn("colocation-verification.json", DEPLOY)

    def test_live_architecture_changes_are_protected_configuration(self):
        self.assertIn("TF_VAR_service_cpu_architectures", DEPLOY)
        self.assertIn("SERVICE_CPU_ARCHITECTURES_JSON must map services", DEPLOY)
        self.assertIn("TF_VAR_audit_stream_transport", DEPLOY)
        self.assertIn("AUDIT_STREAM_TRANSPORT must be kafka or sqs_fifo", DEPLOY)
        self.assertIn("AUDIT_SQS_ALARM_ACTION_ARNS_JSON must be a JSON string array", DEPLOY)
        self.assertIn("EDGE_ALARM_ACTION_ARNS_JSON must contain at least one alarm destination ARN", DEPLOY)
        self.assertIn("CLICKHOUSE_HOST is required when the audit consumer is enabled", DEPLOY)
        self.assertIn("KAFKA_BROKERS is required when Kafka audit transport is enabled", DEPLOY)
        self.assertIn('(.audit_stream_transport != "kafka" or (.kafka_brokers | test("\\\\S")))', DEPLOY)
        self.assertIn("TF_VAR_clickhouse_port", DEPLOY)
        self.assertIn("TF_VAR_audit_consumer_environment", DEPLOY)
        self.assertIn("TF_VAR_audit_consumer_secret_arns", DEPLOY)
        self.assertIn("TF_VAR_audit_consumer_secret_kms_key_arns", DEPLOY)
        self.assertIn("secondary_audit_consumer_secret_arns", VARIABLES)
        self.assertIn("secondary_audit_consumer_secret_kms_key_arns", VARIABLES)
        secondary = TERRAFORM_MAIN.split('module "secondary"', 1)[1]
        self.assertIn("var.secondary_audit_consumer_secret_arns", secondary)
        self.assertIn("var.secondary_audit_consumer_secret_kms_key_arns", secondary)
        self.assertIn("SQS audit transport requires enabled internal TLS", DEPLOY)
        self.assertIn("ECS_AWSVPC_BLOCK_IMDS=true", REGIONAL_STACK)

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
