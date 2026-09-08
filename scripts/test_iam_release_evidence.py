import unittest
from pathlib import Path
from scripts.iam_release_evidence import review


class IAMReviewTests(unittest.TestCase):
    def test_targeted_bootstrap_and_tls_replacement_dependencies(self):
        source = (Path(__file__).resolve().parents[1] / "infra/terraform/modules/regional_stack/main.tf").read_text()
        jobs = source.split('resource "aws_ecs_task_definition" "database_job" {', 1)[1].split('\nresource ', 1)[0]
        self.assertRegex(jobs, r"depends_on\s*=\s*\[aws_iam_role_policy.task_execution, aws_iam_role_policy.runtime\]")
        targets = source.split('resource "aws_lb_target_group" "service" {', 1)[1].split('\nresource ', 1)[0]
        self.assertIn("name_prefix", targets)
        self.assertIn("create_before_destroy = true", targets)

    def plan(self, action="sqs:SendMessage", resource="arn:aws:sqs:us-east-1:123456789012:audit.fifo"):
        import json
        return {"planned_values": {"root_module": {"resources": [{
            "type": "aws_iam_role_policy", "address": "test",
            "values": {"policy": json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": [action], "Resource": resource
            }]})}
        }]}}}

    def test_exact_grant_and_analyzer_evidence(self):
        calls = []
        result = review(self.plan(), lambda *args: calls.append(args) or [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(result, [{"address": "test", "findings": []}])

    def test_wildcards_fail_closed(self):
        for action, resource in [("sqs:*", "queue"), ("sqs:SendMessage", "*")]:
            with self.assertRaises(ValueError):
                review(self.plan(action, resource))

    def test_ecr_token_exception(self):
        self.assertEqual(len(review(self.plan("ecr:GetAuthorizationToken", "*"))), 1)

    def test_empty_and_unresolved_fail_closed(self):
        with self.assertRaises(ValueError):
            review({"planned_values": {"root_module": {}}})
        plan = self.plan()
        plan["planned_values"]["root_module"]["resources"][0]["values"] = {}
        with self.assertRaises(ValueError):
            review(plan)
