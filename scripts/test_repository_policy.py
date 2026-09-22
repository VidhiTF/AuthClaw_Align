"""Regression tests for contribution contracts and fail-closed T01 activation."""

from copy import deepcopy
import base64
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from scripts.repository_policy import (REQUIRED_SECTIONS, api, approval_users, growth_evidence,
    validate_live_rules, validate_manifest, verify_github, verify_live_protection,
    verify_owner_reviews, verify_pr_evidence, verify_t01)
from scripts import check_line_budget
from io import StringIO

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
        for organization_only in ("dismissal_restrictions", "bypass_pull_request_allowances"):
            self.assertNotIn(organization_only, reviews)
        self.assertIsNone(protection["restrictions"])
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
        self.pr["body"] = "\n".join(f"## {heading}\nEvidence documents scripts/repository_policy.py behavior with unit test results."
                                    for heading in REQUIRED_SECTIONS)

    def test_checked_in_manifest_and_github_merge_evidence(self):
        validate_manifest(self.record)
        evidence = verify_t01(self.record, self.pr, self.reviews)
        self.assertEqual(evidence["status"], "active")
        self.assertEqual(evidence["merged_commit"], "b" * 40)
        self.assertEqual(evidence["effective_at"], self.pr["merged_at"])

    @patch("scripts.repository_policy.subprocess.check_output", return_value="{}")
    def test_gh_api_output_is_decoded_as_utf8(self, output):
        self.assertEqual(api("repos/example/repo"), {})
        output.assert_called_once_with(["gh", "api", "repos/example/repo"], text=True, encoding="utf-8")

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
                           [{"filename": "public/file.py", "previous_filename": "private/file.py", "additions": 1, "deletions": 0}], content,
                           {"content": base64.b64encode(b"template").decode()}]
        with self.assertRaisesRegex(ValueError, "private/file.py"):
            verify_github(self.record, {"pull_request": current})
        self.assertIn("ref=" + "e" * 40, api.call_args.args[0])

    @patch("scripts.repository_policy.api")
    def test_truncated_changed_file_response_fails_closed(self, api):
        current = dict(deepcopy(self.pr), number=53, changed_files=2)
        api.side_effect = [self.pr, self.reviews, current, self.reviews, [{"filename": "README.md"}]]
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            verify_github(self.record, {"pull_request": current})

    @patch("scripts.repository_policy.api")
    def test_material_growth_requires_explicit_owner_exception(self, api):
        self.pr.update(state="open", merged=False, merged_at=None, changed_files=1)
        files = [{"filename": "scripts/repository_policy.py", "additions": 100, "deletions": 0}]
        api.side_effect = [self.pr, self.reviews, files]
        with self.assertRaisesRegex(ValueError, "line-growth approval"):
            verify_github(self.record, {"pull_request": self.pr})
        evidence = verify_pr_evidence(self.pr["body"], (ROOT / ".github/pull_request_template.md").read_text())
        _, digest = growth_evidence(files, evidence)
        self.reviews[0]["body"] = f"Line-growth-approved: {self.sha} {digest}"
        api.side_effect = [self.pr, self.reviews, files]
        self.assertEqual(verify_github(self.record, {"pull_request": self.pr})["status"], "approved-awaiting-merge")


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


class LiveProtectionTests(unittest.TestCase):
    def setUp(self):
        self.rules = json.loads((ROOT / ".github/master-review-ruleset.json").read_text())["rules"]

    def test_desired_rules_require_live_review_and_ci_controls(self):
        validate_live_rules(self.rules)
        for kind in ("pull_request", "required_status_checks", "deletion"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                validate_live_rules([rule for rule in self.rules if rule["type"] != kind])
        self.rules[3]["parameters"]["required_approving_review_count"] = 1
        with self.assertRaises(ValueError):
            validate_live_rules(self.rules)

    def test_each_required_control_fails_closed(self):
        for section, key in ((3, "dismiss_stale_reviews_on_push"), (3, "require_code_owner_review"),
                             (3, "require_last_push_approval"), (3, "required_review_thread_resolution"),
                             (4, "strict_required_status_checks_policy")):
            rules = deepcopy(self.rules)
            rules[section]["parameters"][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_live_rules(rules)

    @patch("scripts.repository_policy.api")
    def test_live_missing_or_bypass_rules_cannot_pass(self, api):
        api.return_value = [{"type": "deletion", "ruleset_id": 1}]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verify_live_protection("example/repo")
        rules = [dict(rule, ruleset_id=1) for rule in self.rules]
        for bypass, enforcement in ((1, "ACTIVE"), (0, "EVALUATE")):
            api.side_effect = [rules, {"enforcement": "active", "node_id": "RRS_1"},
                               {"data": {"node": {"enforcement": enforcement, "bypassActors": {"totalCount": bypass}}}}]
            with self.assertRaisesRegex(ValueError, "no administrator"):
                verify_live_protection("example/repo")

    @patch("scripts.repository_policy.api")
    def test_valid_live_rules_pass_and_api_failure_is_not_a_bypass(self, api):
        api.side_effect = [[dict(rule, ruleset_id=1) for rule in self.rules],
                           {"enforcement": "active", "node_id": "RRS_1"},
                           {"data": {"node": {"enforcement": "ACTIVE", "bypassActors": {"totalCount": 0}}}}]
        self.assertEqual(verify_live_protection("example/repo")["ruleset_id"], 1)
        api.side_effect = RuntimeError("API unavailable")
        with self.assertRaises(RuntimeError):
            verify_live_protection("example/repo")


class EvidenceAndBudgetTests(unittest.TestCase):
    def setUp(self):
        self.template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
        self.body = "\n".join(f"## {heading}\nReviewed backend/app paths; tests provide the operation-specific evidence."
                              for heading in REQUIRED_SECTIONS)

    def test_missing_empty_template_placeholder_and_duplicate_sections_fail(self):
        for body in ("", self.template, self.body.replace("## Risk", "## Other"),
                     self.body + "\n## Risk\nDuplicated risk section cannot shadow evidence."):
            with self.subTest(body=body[:30]), self.assertRaises(ValueError):
                verify_pr_evidence(body, self.template)
        for value in ("", "N/A", "TBD", "done", "TBD TODO pending done not applicable"):
            bad = self.body.replace("## Existing-code reuse\nReviewed backend/app paths; tests provide the operation-specific evidence.",
                                    "## Existing-code reuse\n" + value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                verify_pr_evidence(bad, self.template)
        self.assertEqual(set(verify_pr_evidence(self.body, self.template)), set(REQUIRED_SECTIONS))

    def test_growth_cannot_be_offset_by_deletion_or_rename_and_digest_binds_evidence(self):
        evidence = verify_pr_evidence(self.body, self.template)
        files = [{"filename": "scripts/tool.py", "additions": 110, "deletions": 10},
                 {"filename": "backend/old.py", "additions": 0, "deletions": 300},
                 {"filename": "docs/guide.md", "additions": 500, "deletions": 0}]
        growth, digest = growth_evidence(files, evidence)
        self.assertEqual(growth, {"scripts/tool.py": 100})
        self.assertNotEqual(digest, growth_evidence(files, dict(evidence, Risk="Changed risk evidence"))[1])
        files[0]["additions"] += 1
        self.assertNotEqual(digest, growth_evidence(files, evidence)[1])
        growth, _ = growth_evidence([{"filename": "requirements.txt", "additions": 100, "deletions": 0}], evidence)
        self.assertEqual(growth, {"requirements.txt": 100})

    def test_growth_exception_requires_current_explicit_approval_not_old_marker(self):
        marker = "Line-growth-approved: " + "a" * 40 + " " + "b" * 64
        review = {"id": 1, "user": {"login": "owner"}, "state": "APPROVED", "commit_id": "a" * 40, "body": marker}
        self.assertEqual(approval_users([review], "a" * 40, "author", marker), {"owner"})
        for replacement in ({"body": "Approved without growth exception"}, {"state": "DISMISSED"},
                            {"commit_id": "c" * 40}, {"body": "Rejected " + marker}):
            self.assertFalse(approval_users([review, dict(review, id=2, **replacement)], "a" * 40, "author", marker))

    def test_budget_checker_rejects_empty_missing_and_over_budget_reports(self):
        def run(payload):
            with patch("sys.stdin", StringIO(json.dumps(payload))), patch("sys.stdout", StringIO()), \
                 patch.object(check_line_budget, "load_budgets", return_value=[("backend/app/*", 10)]):
                return check_line_budget.main()
        with self.assertRaises(SystemExit):
            run({})
        report = lambda path, code: {"Python": {"reports": [{"name": path, "stats": {"code": code}}]}}
        with self.assertRaises(SystemExit):
            run(report("other/file.py", 1))
        self.assertEqual(run(report("./backend/app/file.py", 10)), 0)
        self.assertEqual(run(report("backend/app/file.py", 11)), 1)


if __name__ == "__main__":
    unittest.main()
