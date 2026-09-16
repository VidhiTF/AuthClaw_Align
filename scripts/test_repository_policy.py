"""Regression tests for contribution contracts and fail-closed T01 activation."""

from copy import deepcopy
import base64
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from scripts.repository_policy import approval_users, validate_manifest, verify_github, verify_owner_reviews, verify_t01

ROOT = Path(__file__).resolve().parents[1]


class RepositoryGuidanceTests(unittest.TestCase):
    def test_ten_rules_and_required_evidence_sections(self):
        guide = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^(\d+)\. \*\*", guide, re.M), [str(n) for n in range(1, 11)])
        template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
        for heading in ("Existing-code reuse", "New-line justification", "Test evidence",
                        "Risk", "Rollback", "Reviewer sign-off", "Customer impact",
                        "Release notes", "Schema and rolling-deployment compatibility",
                        "Tenant isolation evidence"):
            self.assertRegex(template, rf"(?m)^## {re.escape(heading)}\s*$")
        tenant = template.split("## Tenant isolation evidence", 1)[1].split("##", 1)[0].lower()
        for concept in ("tenant key", "application", "database", "reads", "inserts",
                        "updates", "exports", "similarity", "observed results", "reason"):
            self.assertIn(concept, tenant)

    def test_local_links_and_policy_entry_points(self):
        paths = ["CONTRIBUTING.md", "AGENTS.md", "README.md", "docs/BRANCH_GOVERNANCE.md",
                 ".github/pull_request_template.md", "infra/terraform/BETA_DEPLOYMENT.md"]
        for name in paths:
            source = ROOT / name
            text = source.read_text(encoding="utf-8")
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if "://" in target:
                    continue
                path, _, fragment = target.partition("#")
                destination = source.parent / path if path else source
                self.assertTrue(destination.is_file(), (name, target))
                if fragment:
                    headings = re.findall(r"^#+ (.+)$", destination.read_text(encoding="utf-8"), re.M)
                    anchors = [re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings]
                    self.assertIn(fragment, anchors, (name, target))
        for name in ("AGENTS.md", "README.md", ".github/pull_request_template.md"):
            self.assertIn("CONTRIBUTING.md", (ROOT / name).read_text(encoding="utf-8"))

    def test_ci_executes_policy_and_protection_requires_two_reviews(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts.test_repository_policy", workflow)
        self.assertIn("python3 scripts/repository_policy.py --verify-github", workflow)
        protection = json.loads((ROOT / ".github/branch-protection-master.json").read_text())
        reviews = protection["required_pull_request_reviews"]
        self.assertGreaterEqual(reviews["required_approving_review_count"], 2)
        for setting in ("require_code_owner_reviews", "dismiss_stale_reviews", "require_last_push_approval"):
            self.assertTrue(reviews[setting])
        self.assertTrue(protection["enforce_admins"])
        self.assertIn("ACL-14 Required Checks", protection["required_status_checks"]["contexts"])

    def test_codeowners_route_distinct_boundaries_and_protect_policy(self):
        entries = {}
        for line in (ROOT / ".github/CODEOWNERS").read_text().splitlines():
            if line and not line.startswith("#"):
                path, *owners = line.split()
                entries[path] = set(owners)
                self.assertGreaterEqual(len(owners), 2)
        self.assertNotEqual(entries["/gateway/"], entries["/console/"])
        for path in ("/.github/", "/AGENTS.md", "/CONTRIBUTING.md",
                     "/scripts/repository_policy.py", "/scripts/test_repository_policy.py"):
            self.assertEqual(entries[path], entries["/.github/"])


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / ".github/t01-activation.json").read_text())
        self.sha = "a" * 40
        self.pr = {
            "number": self.record["pull_request"], "state": "closed", "merged": True,
            "base": {"ref": "master", "repo": {"full_name": self.record["repository"]}},
            "head": {"sha": self.sha}, "user": {"login": self.record["record_owner"]},
            "merge_commit_sha": "b" * 40, "merged_at": "2026-09-16T12:00:00Z",
            "html_url": "https://github.com/example/repo/pull/52",
        }
        self.reviews = [{"id": n, "user": {"login": user}, "state": "APPROVED",
                         "commit_id": self.sha}
                        for n, user in enumerate(self.record["required_approvers"], 1)]

    def test_checked_in_manifest_and_github_merge_evidence(self):
        validate_manifest(self.record)
        evidence = verify_t01(self.record, self.pr, self.reviews)
        self.assertEqual(evidence["status"], "active")
        self.assertEqual(evidence["merged_commit"], "b" * 40)
        self.assertEqual(evidence["effective_at"], self.pr["merged_at"])

    def test_schema_rejects_missing_extra_duplicate_and_mutable_sources(self):
        bad = deepcopy(self.record)
        bad.pop("record_owner")
        cases = [bad, dict(self.record, approved=True), dict(self.record, pull_request=0),
                 dict(self.record, effective_date_source="pr.body"),
                 dict(self.record, required_approvers=["same", "same"])]
        for record in cases:
            with self.subTest(record=record), self.assertRaises(ValueError):
                validate_manifest(record)

    def test_one_or_stale_approval_cannot_activate(self):
        with self.assertRaisesRegex(ValueError, "approvals"):
            verify_t01(self.record, self.pr, self.reviews[:1])
        self.reviews[0]["commit_id"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "approvals"):
            verify_t01(self.record, self.pr, self.reviews)

    def test_dismissal_and_change_request_cancel_approval_but_comment_does_not(self):
        for state in ("DISMISSED", "CHANGES_REQUESTED", "COMMENTED"):
            later = dict(self.reviews[0], id=3, state=state)
            users = approval_users(self.reviews + [later], self.sha, self.pr["user"]["login"])
            self.assertEqual(self.record["required_approvers"][0] in users, state == "COMMENTED")

    def test_self_approval_wrong_identity_and_unmerged_pr_rejected(self):
        for mutation in ({"user": {"login": self.record["required_approvers"][0]}},
                         {"number": 999}, {"merged": False}, {"merge_commit_sha": "invalid"},
                         {"merged_at": "2026-09-16T12:00:00"}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_t01(self.record, dict(self.pr, **mutation), self.reviews)

    def test_bootstrap_still_needs_both_current_approvals(self):
        self.pr.update(merged=False, merged_at=None, state="open")
        evidence = verify_t01(self.record, self.pr, self.reviews, require_merged=False)
        self.assertEqual(evidence["status"], "approved-awaiting-merge")
        self.assertIsNone(evidence["merged_commit"])
        with self.assertRaises(ValueError):
            verify_t01(self.record, self.pr, self.reviews[:1], require_merged=False)

    @patch("scripts.repository_policy.api")
    def test_api_error_or_missing_merge_ancestry_cannot_activate(self, api):
        api.side_effect = [self.pr, self.reviews, {"status": "diverged"}]
        with self.assertRaisesRegex(ValueError, "history"):
            verify_github(self.record, {})
        api.side_effect = RuntimeError("GitHub unavailable")
        with self.assertRaises(RuntimeError):
            verify_github(self.record, {})

    @patch("scripts.repository_policy.api")
    def test_stale_bootstrap_run_cannot_pass(self, api):
        api.side_effect = [self.pr, self.reviews]
        event = {"pull_request": deepcopy(self.pr)}
        event["pull_request"]["head"]["sha"] = "d" * 40
        with self.assertRaisesRegex(ValueError, "Stale"):
            verify_github(self.record, event)

    @patch("scripts.repository_policy.api")
    def test_other_pr_cannot_use_bootstrap_exception(self, api):
        self.pr.update(merged=False, merged_at=None, state="open")
        api.side_effect = [self.pr, self.reviews]
        event = {"pull_request": dict(self.pr, number=53)}
        with self.assertRaisesRegex(ValueError, "not merged"):
            verify_github(self.record, event)


    @patch("scripts.repository_policy.api")
    def test_ownership_uses_base_and_checks_rename_source(self, api):
        current = dict(deepcopy(self.pr), number=53, changed_files=1)
        current["base"]["sha"] = "e" * 40
        primary, deputy = self.record["required_approvers"]
        rules = f"* @{primary} @{deputy}\n/private/ @missing @{deputy}\n"
        content = {"content": base64.b64encode(rules.encode()).decode()}
        api.side_effect = [self.pr, self.reviews, current, self.reviews,
                           [{"filename": "public/file.py", "previous_filename": "private/file.py"}], content]
        with self.assertRaisesRegex(ValueError, "private/file.py"):
            verify_github(self.record, {"pull_request": current})
        self.assertIn("ref=" + "e" * 40, api.call_args.args[0])

    @patch("scripts.repository_policy.api")
    def test_truncated_changed_file_response_fails_closed(self, api):
        current = dict(deepcopy(self.pr), number=53, changed_files=2)
        api.side_effect = [self.pr, self.reviews, current, self.reviews, [{"filename": "README.md"}]]
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            verify_github(self.record, {"pull_request": current})


class OwnerReviewTests(unittest.TestCase):
    RULES = "* @governor @deputy\n/backend/ @platform @agent\n/console/ @console @agent\n"

    def test_each_changed_component_requires_its_independent_primary(self):
        with self.assertRaisesRegex(ValueError, "console"):
            verify_owner_reviews(self.RULES, ["backend/app.py", "console/page.ts"], {"platform", "governor"}, "author")
        verify_owner_reviews(self.RULES, ["backend/app.py", "console/page.ts"], {"platform", "console"}, "author")

    def test_author_requires_deputy_and_two_approvals(self):
        verify_owner_reviews(self.RULES, ["backend/app.py"], {"agent", "governor"}, "platform")
        with self.assertRaisesRegex(ValueError, "Two independent"):
            verify_owner_reviews(self.RULES, ["backend/app.py"], {"platform", "agent"}, "platform")

    def test_last_match_wins_and_unknown_syntax_fails_closed(self):
        rules = self.RULES + "/backend/policy.py @governor @deputy\n"
        with self.assertRaisesRegex(ValueError, "component owner"):
            verify_owner_reviews(rules, ["backend/policy.py"], {"platform", "agent"}, "author")
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            verify_owner_reviews("*.py @owner", ["code.py"], {"owner", "other"}, "author")


if __name__ == "__main__":
    unittest.main()
