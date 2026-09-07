import copy
import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.release_evidence import record, template, validate


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "raw.txt").write_text("test fixture, not live evidence", encoding="utf-8")
        ref = {"path": "raw.txt", "sha256": hashlib.sha256((self.root / "raw.txt").read_bytes()).hexdigest()}
        self.payload = template()
        release = self.payload["release"]
        release.update(dict.fromkeys(("change_window", "communication_channel", "release_approver", "database_approver", "rollback_owner"), "operator"))
        release.update(commit="a" * 40, images={"backend": "registry/backend@sha256:" + "b" * 64},
                       previous_images={"backend": "registry/backend@sha256:" + "c" * 64}, configuration=ref,
                       current_task_definitions={"backend": "arn:aws:ecs:us-east-1:123456789012:task-definition/authclaw-backend:41"},
                       target_task_definitions={"backend": "arn:aws:ecs:us-east-1:123456789012:task-definition/authclaw-backend:42"},
                       previous_digest_compatible=True, rollback_until="2099-01-01", database_compatible_until="2099-01-01")
        for step in self.payload["steps"]:
            step.update(release_id=f"release-{step['step']}", approver="reviewer", rollback_point=ref)
            for name, check in step["checks"].items():
                check.update(status="PASS", commit=release["commit"], images=release["images"], configuration=ref,
                             time=(dt.datetime(2026, 1, step["step"], tzinfo=dt.timezone.utc)).isoformat(), approver="reviewer", raw=ref)
                if name == "rollback_drill":
                    check.update(duration_seconds=300, retained_artifacts=True, redeployed_images=release["previous_images"],
                                 verified=dict.fromkeys(("health", "authentication", "gateway", "audit_publication", "clickhouse_consistency"), True))

    def test_complete_ledger_and_exact_production_promotion(self):
        validate(self.payload, self.root, 12)

    def test_production_requires_current_and_target_task_revisions(self):
        self.payload["release"]["target_task_definitions"] = {}
        with self.assertRaisesRegex(ValueError, "task-definition revisions"):
            validate(self.payload, self.root, 12)
        validate(self.payload, self.root, 11)

    def test_pending_template_is_blocked(self):
        with self.assertRaises((ValueError, KeyError)):
            validate(template(), self.root)

    def test_cli_initialization_refuses_overwrite_and_checks_package(self):
        ledger = self.root / "release.json"
        command = [sys.executable, "-m", "scripts.release_evidence"]
        def run(action, *extra):
            return subprocess.run([*command, action, str(ledger), *extra], capture_output=True, text=True).returncode
        self.assertEqual(run("init"), 0)
        self.assertEqual(run("check"), 1)
        original = ledger.read_bytes()
        self.assertNotEqual(run("init"), 0)
        self.assertEqual(ledger.read_bytes(), original)
        pending = json.loads(original)
        pending["release"].update(commit=self.payload["release"]["commit"],
                                  images=self.payload["release"]["images"], configuration=self.payload["release"]["configuration"])
        ledger.write_text(json.dumps(pending), encoding="utf-8")
        self.assertEqual(run("record", "--step", "1", "--name", "decisions", "--raw", "raw.txt",
                             "--rollback-point", "raw.txt", "--release-id", "change-1", "--approver", "reviewer"), 0)
        self.assertEqual(json.loads(ledger.read_text(encoding="utf-8"))["steps"][0]["checks"]["decisions"]["status"], "PASS")
        ledger.write_text(json.dumps(self.payload), encoding="utf-8")
        self.assertEqual(run("check"), 0)

    def test_record_hashes_raw_evidence_and_inherits_frozen_identity(self):
        pending = template()
        pending["release"].update(commit=self.payload["release"]["commit"],
                                  images=self.payload["release"]["images"],
                                  configuration=self.payload["release"]["configuration"])
        record(pending, self.root, step_number=1, check_name="decisions",
               raw=Path("raw.txt"), rollback_point=Path("raw.txt"),
               release_id="change-1", approver="named-reviewer", environment=None,
               recorded_at="2026-01-01T00:00:00+00:00", status="PASS", reason="",
               replace=False, duration_seconds=None, retained_artifacts=False,
               verified_all=False)
        check = pending["steps"][0]["checks"]["decisions"]
        self.assertEqual(check["images"], pending["release"]["images"])
        self.assertEqual(check["raw"]["sha256"], hashlib.sha256((self.root / "raw.txt").read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, "already recorded"):
            record(pending, self.root, step_number=1, check_name="decisions",
                   raw=Path("raw.txt"), rollback_point=None, release_id="change-1",
                   approver="named-reviewer", environment=None,
                   recorded_at="2026-01-01T00:00:00+00:00", status="PASS", reason="",
                   replace=False, duration_seconds=None, retained_artifacts=False,
                   verified_all=False)

    def test_record_enforces_waiver_and_rollback_drill_fields(self):
        pending = template()
        pending["release"].update(commit=self.payload["release"]["commit"],
                                  images=self.payload["release"]["images"],
                                  previous_images=self.payload["release"]["previous_images"],
                                  configuration=self.payload["release"]["configuration"])
        common = dict(raw=Path("raw.txt"), rollback_point=Path("raw.txt"),
                      release_id="change-11", approver="reviewer", environment=None,
                      recorded_at="2026-01-11T00:00:00+00:00", replace=False)
        with self.assertRaisesRegex(ValueError, "NOT_APPLICABLE"):
            record(pending, self.root, step_number=11, check_name="authentication",
                   status="NOT_APPLICABLE", reason="not used", duration_seconds=None,
                   retained_artifacts=False, verified_all=False, **common)
        with self.assertRaisesRegex(ValueError, "rollback drill requires"):
            record(pending, self.root, step_number=11, check_name="rollback_drill",
                   status="PASS", reason="", duration_seconds=299,
                   retained_artifacts=False, verified_all=True, **common)
        record(pending, self.root, step_number=11, check_name="rollback_drill",
               status="PASS", reason="", duration_seconds=299,
               retained_artifacts=True, verified_all=True, **common)
        drill = pending["steps"][10]["checks"]["rollback_drill"]
        self.assertEqual(drill["redeployed_images"], pending["release"]["previous_images"])
        self.assertTrue(all(drill["verified"].values()))

    def test_failures_block_promotion(self):
        changes = [
            lambda p: p["steps"].reverse(),
            lambda p: p["steps"][6].update(release_id="release-6"),
            lambda p: p["release"].update(migration_mode="contract"),
            lambda p: p["release"].update(previous_digest_compatible=False),
            lambda p: p["release"].update(database_compatible_until="2020-01-01"),
            lambda p: p["release"].update(images={"backend": "registry/backend:latest"}),
            lambda p: p["steps"][10]["checks"].pop("full_ci"),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(status="PENDING"),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(commit="d" * 40),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(environment="local"),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(time="2026-01-01T00:00:00"),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(time="2025-01-01T00:00:00Z"),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(raw={"path": "raw.txt", "sha256": "0" * 64}),
            lambda p: p["steps"][10]["checks"]["full_ci"].update(raw={"path": "../raw.txt", "sha256": "0" * 64}),
            lambda p: p["steps"][10]["checks"]["rollback_drill"].update(duration_seconds=301),
            lambda p: p["steps"][10]["checks"]["rollback_drill"].update(redeployed_images=p["release"]["images"]),
            lambda p: p["steps"][10]["checks"]["rollback_drill"].update(retained_artifacts=False),
            lambda p: p["steps"][10]["checks"]["rollback_drill"]["verified"].update(clickhouse_consistency=False),
            lambda p: p["steps"][11]["checks"]["production_promotion"].update(images=p["release"]["previous_images"]),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                payload = copy.deepcopy(self.payload)
                change(payload)
                with self.assertRaises((ValueError, KeyError)):
                    validate(payload, self.root, 12)

    def test_only_applicable_drills_can_be_waived_with_evidence(self):
        check = self.payload["steps"][10]["checks"]["regional_failover"]
        check.update(status="NOT_APPLICABLE", reason="Approved single-region staging foundation")
        validate(self.payload, self.root)
        check["reason"] = ""
        with self.assertRaises(ValueError):
            validate(self.payload, self.root)


if __name__ == "__main__":
    unittest.main()
