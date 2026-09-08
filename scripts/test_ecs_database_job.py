import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.ecs_database_job import run_job


class DatabaseJobTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "task.json"
        self.gate = {"cluster": "staging", "task_definitions": {"backend_migrations": "migration:7"},
                     "network_configuration": {}, "launch_model": {"mode": "FARGATE"}}
        self.task = {"taskDefinitionArn": "migration:7", "requiresCompatibilities": ["FARGATE"],
                     "containerDefinitions": [{"name": "backend_migrations", "image": "registry/backend@sha256:" + "a" * 64}]}
        self.started = {"tasks": [{"taskArn": "task/1"}], "failures": []}
        self.finished = {"tasks": [{"taskDefinitionArn": "migration:7", "lastStatus": "STOPPED", "containers": [{"name": "backend_migrations", "exitCode": 0}]}]}

    def execute(self, result):
        with patch("scripts.ecs_database_job.aws", side_effect=[{"taskDefinition": self.task}, self.started, result]), patch("subprocess.run") as wait:
            run_job(self.gate, "backend_migrations", self.output)
            self.assertTrue(wait.call_args.kwargs["check"])

    def test_success_retains_raw_result(self):
        self.execute(self.finished)
        self.assertIn('"exitCode": 0', self.output.read_text())

    def test_graviton_uses_the_recorded_capacity_provider(self):
        self.gate["launch_model"] = {"mode": "EC2_GRAVITON", "capacity_provider_name": "staging-graviton"}
        self.task["requiresCompatibilities"] = ["EC2"]
        with patch("scripts.ecs_database_job.aws", side_effect=[{"taskDefinition": self.task}, self.started, self.finished]) as aws, patch("subprocess.run"):
            run_job(self.gate, "backend_migrations", self.output)
        run_call = aws.call_args_list[1].args
        self.assertIn("--capacity-provider-strategy", run_call)
        self.assertNotIn("--launch-type", run_call)
        strategy = json.loads(run_call[run_call.index("--capacity-provider-strategy") + 1])
        self.assertEqual(strategy, [{"capacityProvider": "staging-graviton", "weight": 1, "base": 0}])

    def test_incomplete_launch_model_never_starts(self):
        for model in ({"mode": "EC2_GRAVITON"}, {"mode": "unknown"}):
            self.gate["launch_model"] = model
            with self.subTest(model=model), patch("scripts.ecs_database_job.aws", return_value={"taskDefinition": self.task}) as aws:
                with self.assertRaises(ValueError):
                    run_job(self.gate, "backend_migrations", self.output)
                self.assertEqual(aws.call_count, 1)

    def test_launch_model_mismatch_never_starts(self):
        cases = (({"mode": "FARGATE"}, "EC2"),
                 ({"mode": "EC2_GRAVITON", "capacity_provider_name": "graviton"}, "FARGATE"))
        for model, compatibility in cases:
            self.gate["launch_model"] = model
            self.task["requiresCompatibilities"] = [compatibility]
            with self.subTest(model=model), patch("scripts.ecs_database_job.aws", return_value={"taskDefinition": self.task}) as aws:
                with self.assertRaises(ValueError):
                    run_job(self.gate, "backend_migrations", self.output)
                self.assertEqual(aws.call_count, 1)

    def test_failed_missing_and_wrong_tasks_block(self):
        results = [{"failures": [{"reason": "missing"}], "tasks": []}]
        for replacement in ({"exitCode": 1}, {"exitCode": None}, {"exitCode": False}, {"name": "wrong"}):
            result = copy.deepcopy(self.finished)
            result["tasks"][0]["containers"][0].update(replacement)
            results.append(result)
        result = copy.deepcopy(self.finished)
        result["tasks"][0]["taskDefinitionArn"] = "migration:6"
        results.append(result)
        for result in results:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                self.execute(result)
            self.assertTrue(self.output.exists())

    def test_mutable_image_never_starts(self):
        self.task["containerDefinitions"][0]["image"] = "registry/backend:latest"
        with patch("scripts.ecs_database_job.aws", return_value={"taskDefinition": self.task}) as aws:
            with self.assertRaises(ValueError):
                run_job(self.gate, "backend_migrations", self.output)
            self.assertEqual(aws.call_count, 1)

    def test_launch_failure_never_waits(self):
        self.started = {"tasks": [], "failures": [{"reason": "capacity"}]}
        with self.assertRaises(RuntimeError):
            self.execute(self.finished)


if __name__ == "__main__":
    unittest.main()
