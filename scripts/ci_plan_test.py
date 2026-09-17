import json
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.ci_plan import HEAVY_JOBS, changed_paths, plan, verify


class CIPlanTests(unittest.TestCase):
    def test_console_signing_changes_run_agent_interoperability(self):
        for path in ("console/src/lib/control-plane-auth.ts", "console/src/lib/api-client.ts"):
            self.assertIn("agent", self.expected("pull_request", [path]))

    def test_review_events_recheck_the_same_pr_plan_without_release(self):
        for paths in (["README.md"], ["gateway/main.go"], ["scripts/repository_policy.py"]):
            self.assertEqual(plan("pull_request_review", paths, release_enabled=True),
                             plan("pull_request", paths, release_enabled=True))

    def expected(self, event, paths, **kwargs):
        return set(json.loads(plan(event, paths, **kwargs)["expected_jobs"]))

    def test_docs_only_is_lightweight_on_pr_and_master(self):
        for event in ("pull_request", "push"):
            self.assertEqual(
                self.expected(event, ["README.md", "docs/security.md"]),
                {"changes", "policy"},
            )

    def test_missing_or_initial_base_falls_back_to_all_tracked_files(self):
        for before in ("", "000000", "missing-sha"):
            with patch.dict(
                os.environ, {"BASE_SHA": before, "GITHUB_SHA": "head-sha"}
            ), patch(
                "scripts.ci_plan.subprocess.run",
                return_value=SimpleNamespace(returncode=1),
            ), patch(
                "scripts.ci_plan.subprocess.check_output",
                return_value=b"gateway/main.go\0README.md\0",
            ) as output:
                self.assertEqual(
                    changed_paths("push"), ["gateway/main.go", "README.md"]
                )
                output.assert_called_once_with(["git", "ls-files", "-z"])

    def test_diff_includes_deleted_rename_source_and_handles_spaces(self):
        with patch.dict(
            os.environ, {"BASE_SHA": "base-sha", "GITHUB_SHA": "head-sha"}
        ), patch(
            "scripts.ci_plan.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ), patch(
            "scripts.ci_plan.subprocess.check_output",
            return_value=b"gateway/main.go\0docs/old source.md\0",
        ) as output:
            paths = changed_paths("pull_request")
            output.assert_called_once_with(
                [
                    "git",
                    "diff",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    "base-sha",
                    "head-sha",
                ]
            )
            self.assertIn("gateway", self.expected("pull_request", paths))

    def test_console_pr_selects_console_and_security_not_unrelated_suites(self):
        self.assertEqual(
            self.expected("pull_request", ["console/src/app/page.tsx"]),
            {"changes", "policy", "console", "security"},
        )

    def test_backend_local_test_change_does_not_fan_out(self):
        self.assertEqual(
            self.expected("pull_request", ["backend/tests/test_endpoints.py"]),
            {
                "changes",
                "policy",
                "backend",
                "backend-integration",
                "security",
            },
        )

    def test_gateway_database_regression_selects_postgres_job(self):
        expected = self.expected("pull_request", ["gateway/audit_context_test.go"])
        self.assertIn("backend-integration", expected)
        self.assertIn("gateway", expected)
        self.assertNotIn("console", expected)

    def test_codeql_is_not_selected_for_any_trigger(self):
        for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
            selected = plan(event, ["gateway/main.go"], full_regression=True)
            self.assertNotIn("codeql", json.loads(selected["expected_jobs"]))
            self.assertNotIn("codeql_languages", selected)

    def test_cross_service_contracts_select_consumers_conservatively(self):
        for path in (
            "backend/app/api/v1/users.py",
            "gateway/provider_contracts.json",
            "services/agent/services/audit_transport.py",
            "audit_consumer/consumer.py",
            "sdk/python/authclaw.py",
            "backend/alembic/versions/new.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    {
                        "backend",
                        "backend-integration",
                        "audit",
                        "agent",
                        "sdk",
                        "gateway",
                        "console",
                    }.issubset(self.expected("pull_request", [path]))
                )

    def test_shared_or_unknown_executable_configuration_selects_all(self):
        for path in (
            "scripts/ci_plan.py",
            ".github/workflows/ci.yml",
            "docker-compose.full.yml",
            "contracts/api.json",
            "docs/generate.py",
            ".gitleaks.toml",
        ):
            self.assertTrue(
                set(HEAVY_JOBS).issubset(self.expected("pull_request", [path]))
            )

    def test_master_code_changes_run_smoke_not_full_suites(self):
        self.assertEqual(
            self.expected("push", ["backend/app/main.py"]),
            {"changes", "policy", "smoke"},
        )

    def test_scheduled_and_manual_full_regression_ignore_changed_paths(self):
        for event, options in (
            ("schedule", {}),
            ("workflow_dispatch", {"full_regression": True}),
        ):
            selected = plan(event, ["README.md"], **options)
            self.assertTrue(
                set(HEAVY_JOBS).issubset(json.loads(selected["expected_jobs"]))
            )
            self.assertEqual(selected["full_regression"], "true")
            self.assertEqual(selected["smoke"], "false")
            self.assertEqual(selected["arm64"], "false")
            self.assertEqual(selected["release"], "false")

    def test_dispatch_smoke_mode(self):
        self.assertEqual(
            self.expected("workflow_dispatch", ["gateway/main.go"]),
            {"changes", "policy", "smoke"},
        )

    def test_arm64_requires_explicit_opt_in_and_never_pr_or_schedule(self):
        for event in ("pull_request", "push", "workflow_dispatch", "schedule"):
            self.assertEqual(plan(event, ["gateway/main.go"])["arm64"], "false")
            self.assertEqual(
                plan(event, ["gateway/main.go"], arm64=True)["arm64"],
                "true" if event in {"push", "workflow_dispatch"} else "false",
            )
        self.assertEqual(
            plan(
                "workflow_dispatch",
                ["gateway/main.go"],
                arm64=True,
                ref="refs/heads/feature",
            )["arm64"],
            "false",
        )

    def test_release_only_on_enabled_master_code_push(self):
        for event in ("pull_request", "push", "workflow_dispatch", "schedule"):
            self.assertEqual(
                plan(event, ["README.md"], release_enabled=True)["release"], "false"
            )
            self.assertEqual(
                plan(event, ["gateway/main.go"], release_enabled=True)["release"],
                "true" if event == "push" else "false",
            )
        self.assertEqual(plan("push", ["gateway/main.go"])["release"], "false")
        self.assertEqual(
            plan("push", [], release_enabled=True, ref="refs/heads/feature")["release"],
            "false",
        )

    def test_expected_skipped_missing_failed_cancelled_jobs_fail_closed(self):
        expected = ["changes", "policy", "backend"]
        for result in ("skipped", "failure", "cancelled", None):
            needs = {job: {"result": "success"} for job in expected}
            if result is None:
                del needs["backend"]
            else:
                needs["backend"]["result"] = result
            with self.assertRaises(ValueError):
                verify(expected, needs)

    def test_unselected_skips_allowed_but_failures_are_not(self):
        needs = {
            "changes": {"result": "success"},
            "policy": {"result": "success"},
            "backend": {"result": "skipped"},
        }
        verify(["changes", "policy"], needs)
        needs["backend"]["result"] = "failure"
        with self.assertRaises(ValueError):
            verify(["changes", "policy"], needs)
        with self.assertRaises(ValueError):
            verify([], needs)

    def test_every_selected_job_has_a_matching_workflow_condition_and_gate_dependency(
        self,
    ):
        workflow = (
            Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
        ).read_text()
        jobs = dict(
            re.findall(
                r"^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)",
                workflow.split("jobs:\n", 1)[1],
                re.M | re.S,
            )
        )
        for event, kwargs in (
            ("pull_request", {}),
            ("push", {}),
            ("schedule", {}),
            ("workflow_dispatch", {"arm64": True, "full_regression": True}),
        ):
            selected = plan(event, ["scripts/ci_plan.py"], **kwargs)
            expected = set(json.loads(selected["expected_jobs"]))
            for job in (*HEAVY_JOBS, "smoke", "arm64-images"):
                key = re.search(
                    r"if: needs.changes.outputs.(\w+) == 'true'", jobs[job]
                ).group(1)
                self.assertEqual(selected[key] == "true", job in expected, job)
                self.assertIn(
                    job, jobs["checks"].split("needs: ", 1)[1].split("\n", 1)[0]
                )


if __name__ == "__main__":
    unittest.main()
