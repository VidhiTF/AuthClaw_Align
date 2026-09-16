"""Verify T01 activation from GitHub evidence, never from a PR description.

Uses the existing Repository Policy job and gh CLI; no new service or dependency.
Run with --verify-github after reviews, rerunning PR CI if approvals were pending.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".github/t01-activation.json"
REQUIRED_SECTIONS = (
    "Existing-code reuse", "New-line justification", "Test evidence", "Risk",
    "Rollback", "Reviewer sign-off", "Customer impact", "Release notes",
    "Schema and rolling-deployment compatibility", "Security and compliance",
    "Tenant isolation evidence", "Material line-growth exception",
)
MATERIAL_GROWTH = 100


def sections(body):
    body = re.sub(r"<!--.*?-->", "", body or "", flags=re.S)
    parts = re.split(r"(?m)^## ([^\n]+)\s*$", body)
    result = {}
    for heading, content in zip(parts[1::2], parts[2::2]):
        if heading.strip() in result:
            raise ValueError("Duplicate PR evidence section: " + heading.strip())
        result[heading.strip()] = content.strip()
    return result


def verify_pr_evidence(body, template):
    supplied, prompts = sections(body), sections(template)
    for heading in REQUIRED_SECTIONS:
        content = supplied.get(heading, "")
        # Remove untouched template prompts; they are instructions, not evidence.
        for line in prompts.get(heading, "").splitlines():
            if line.strip():
                content = content.replace(line.strip(), "")
        content = re.sub(r"(?m)^\s*[-*]?\s*\[[ xX]\]\s*", "", content).strip()
        words = re.findall(r"\w+", content)
        if len(words) < 5 or not (set(word.lower() for word in words) - {"n", "a", "na", "none", "tbd", "todo", "pending", "done", "not", "applicable"}):
            raise ValueError("Missing, blank or placeholder PR evidence: " + heading)
    return {heading: supplied[heading] for heading in REQUIRED_SECTIONS}


def growth_evidence(changed, evidence):
    # Tests/config/tooling count too. Deleting another file cannot offset growth.
    growing = {item["filename"]: max(0, item["additions"] - item["deletions"])
               for item in changed if not (item["filename"].lower().endswith((".md", ".rst"))
                    or (item["filename"].startswith("docs/") and item["filename"].lower().endswith(".txt")))}
    growing = {path: count for path, count in growing.items() if count}
    digest = hashlib.sha256(json.dumps({"evidence": evidence, "growth": growing},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return growing, digest


def validate_live_rules(rules):
    by_type = {rule["type"]: rule.get("parameters", {}) for rule in rules}
    reviews = by_type.get("pull_request", {})
    checks = by_type.get("required_status_checks", {})
    if not {"deletion", "non_fast_forward", "required_linear_history"} <= by_type.keys():
        raise ValueError("Live master rules lack deletion, force-push or linear-history protection")
    if reviews.get("required_approving_review_count", 0) < 2 or not all(
        reviews.get(key) is True for key in ("dismiss_stale_reviews_on_push", "require_code_owner_review",
                                            "require_last_push_approval", "required_review_thread_resolution")
    ):
        raise ValueError("Live master rules must require two approvals, owners, fresh reviews and resolved threads")
    if checks.get("strict_required_status_checks_policy") is not True or "ACL-14 Required Checks" not in {
        check.get("context") for check in checks.get("required_status_checks", [])
    }:
        raise ValueError("Live master rules must strictly require ACL-14 Required Checks")


def verify_live_protection(repo):
    effective = api(f"repos/{repo}/rules/branches/master?per_page=100", paginate=True)
    # Require one complete enforcing ruleset so bypasses cannot hide in a partial union.
    for ruleset_id in {rule.get("ruleset_id") for rule in effective}:
        rules = [rule for rule in effective if rule.get("ruleset_id") == ruleset_id]
        try:
            validate_live_rules(rules)
        except ValueError:
            continue
        detail = api(f"repos/{repo}/rulesets/{ruleset_id}")
        query = "query($id:ID!){node(id:$id){... on RepositoryRuleset {enforcement bypassActors(first:1){totalCount}}}}"
        metadata = api("graphql", query=query, id=detail["node_id"])["data"]["node"]
        if detail["enforcement"] != "active" or metadata["enforcement"] != "ACTIVE" or metadata["bypassActors"]["totalCount"] != 0:
            raise ValueError("Live master rules must be active with no administrator or actor bypass")
        return {"ruleset_id": ruleset_id, "enforcement": "active", "bypass_actors": 0}
    raise ValueError("Live master protection is incomplete: administrator must apply master-review-ruleset.json")


def validate_manifest(record):
    expected = {
        "schema_version", "task", "repository", "pull_request", "base_branch",
        "required_approvers", "record_owner", "effective_date_source",
        "merged_commit_source",
    }
    if set(record) != expected or record["schema_version"] != 1 or record["task"] != "T01":
        raise ValueError("Invalid T01 activation schema")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", record["repository"]):
        raise ValueError("Invalid repository")
    if type(record["pull_request"]) is not int or record["pull_request"] <= 0:
        raise ValueError("Invalid T01 PR number")
    users = record["required_approvers"]
    if not isinstance(users, list) or len(users) != 2 or len(set(users)) != 2:
        raise ValueError("T01 requires two distinct stakeholders")
    if any(not isinstance(user, str) or not re.fullmatch(r"[\w-]+", user) for user in users):
        raise ValueError("Invalid stakeholder login")
    if record["record_owner"] in users or not record["record_owner"]:
        raise ValueError("Recorder cannot replace a stakeholder approval")
    if record["base_branch"] != "master" or record["effective_date_source"] != "github.merged_at" or record["merged_commit_source"] != "github.merge_commit_sha":
        raise ValueError("Activation must use GitHub merge evidence on master")


def approval_users(reviews, head_sha, author, marker=None):
    latest = {}
    for review in sorted(reviews, key=lambda item: item["id"]):
        # A comment does not cancel an approval. A dismissal or change request does.
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user"]["login"]] = review
    return {
        user for user, review in latest.items()
        if user != author and review["state"] == "APPROVED"
        and review["commit_id"] == head_sha
        and (marker is None or re.search(r"(?m)^" + re.escape(marker) + r"\s*$", review.get("body") or ""))
    }


def verify_t01(record, pr, reviews, require_merged=True):
    validate_manifest(record)
    if pr["number"] != record["pull_request"] or pr["base"]["repo"]["full_name"] != record["repository"] or pr["base"]["ref"] != record["base_branch"]:
        raise ValueError("T01 PR identity mismatch")
    missing = set(record["required_approvers"]) - approval_users(reviews, pr["head"]["sha"], pr["user"]["login"])
    if missing:
        raise ValueError("T01 missing current-head approvals: " + ", ".join(sorted(missing)))
    if require_merged:
        if not pr["merged"] or not re.fullmatch(r"[0-9a-f]{40}", pr.get("merge_commit_sha") or ""):
            raise ValueError("T01 is not merged")
        merged_at = dt.datetime.fromisoformat(pr["merged_at"].replace("Z", "+00:00"))
        if merged_at.tzinfo is None:
            raise ValueError("T01 effective date must include timezone")
    elif pr["state"] != "open":
        raise ValueError("T01 bootstrap PR must be open")
    return {"task": "T01", "pull_request": pr["html_url"], "reviewed_commit": pr["head"]["sha"],
            "merged_commit": pr.get("merge_commit_sha") if pr["merged"] else None,
            "effective_at": pr.get("merged_at"), "record_owner": record["record_owner"],
            "status": "active" if pr["merged"] else "approved-awaiting-merge"}


def api(path, paginate=False, **fields):
    args = ["gh", "api", path]
    for name, value in fields.items():
        args += ["-f", f"{name}={value}"]
    if paginate:
        args += ["--paginate", "--slurp"]
    result = json.loads(subprocess.check_output(args, text=True))
    return [item for page in result for item in page] if paginate else result


def verify_owner_reviews(codeowners, paths, approvals, author, minimum_approvals=2):
    """Resolve rooted CODEOWNERS rules, last match wins; reject unknown syntax.

    The first owner is primary; subsequent owners are deputies for author-owned paths.
    """
    rules = []
    for line in codeowners.splitlines():
        parts = line.split("#", 1)[0].split()
        if not parts:
            continue
        pattern, *owners = parts
        if (pattern != "*" and (not pattern.startswith("/") or re.search(r"[*?\[\]!]", pattern))) or not owners or any(not re.fullmatch(r"@[\w-]+", user) for user in owners):
            raise ValueError("Unsupported CODEOWNERS rule; update verifier before changing syntax")
        rules.append((pattern, [user[1:] for user in owners]))
    if len(approvals - {author}) < minimum_approvals:
        raise ValueError("Two independent current-head approvals are required" if minimum_approvals == 2
                         else "Explicit current-head component-owner line-growth approval is required")
    for path in paths:
        selected = []
        for pattern, owners in rules:
            if pattern == "*" or path == pattern[1:] or (pattern.endswith("/") and path.startswith(pattern[1:])):
                selected = owners
        required = set(selected[1:]) if selected and selected[0] == author else set(selected[:1])
        if not (required - {author}) & approvals:
            raise ValueError(f"Missing independent component owner review for {path}")


def verify_github(record, event):
    repo = record["repository"]
    pr_path = f"repos/{repo}/pulls/{record['pull_request']}"
    pr = api(pr_path)
    reviews = api(pr_path + "/reviews?per_page=100", paginate=True)
    current = event.get("pull_request", {})
    bootstrap = current.get("number") == record["pull_request"] and current.get("base", {}).get("repo", {}).get("full_name") == repo
    if bootstrap and current["head"]["sha"] != pr["head"]["sha"]:
        raise ValueError("Stale T01 CI run; verify the latest head")
    evidence = verify_t01(record, pr, reviews, require_merged=not bootstrap)
    if current:
        live = pr if bootstrap else api(f"repos/{repo}/pulls/{current['number']}")
        if live["head"]["sha"] != current["head"]["sha"]:
            raise ValueError("Stale PR CI run; verify the latest head")
        live_reviews = reviews if bootstrap else api(f"repos/{repo}/pulls/{live['number']}/reviews?per_page=100", paginate=True)
        changed = api(f"repos/{repo}/pulls/{live['number']}/files?per_page=100", paginate=True)
        # GitHub caps PR file responses; never accept partial ownership evidence.
        if len(changed) != live["changed_files"]:
            raise ValueError("Incomplete changed-path evidence")
        paths = {item[key] for item in changed for key in ("filename", "previous_filename") if key in item}
        if bootstrap:
            owners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
            template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
        else:
            content = api(f"repos/{repo}/contents/.github/CODEOWNERS?ref={current['base']['sha']}")
            owners = base64.b64decode(content["content"]).decode("utf-8")
            content = api(f"repos/{repo}/contents/.github/pull_request_template.md?ref={current['base']['sha']}")
            template = base64.b64decode(content["content"]).decode("utf-8")
        supplied = verify_pr_evidence(live.get("body"), template)
        growing, digest = growth_evidence(changed, supplied)
        if sum(growing.values()) >= MATERIAL_GROWTH:
            marker = f"Line-growth-approved: {live['head']['sha']} {digest}"
            print(f"Material growth: {sum(growing.values())} lines; component owners must include in an approving review: {marker}")
            exceptions = approval_users(live_reviews, live["head"]["sha"], live["user"]["login"], marker=marker)
            verify_owner_reviews(owners, growing, exceptions, live["user"]["login"], minimum_approvals=1)
        verify_owner_reviews(owners, paths, approval_users(live_reviews, live["head"]["sha"], live["user"]["login"]), live["user"]["login"])
    if pr["merged"]:
        comparison = api(f"repos/{repo}/compare/{pr['merge_commit_sha']}...{record['base_branch']}")
        if comparison["status"] not in {"ahead", "identical"}:
            raise ValueError("T01 merge is not in the master history")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-github", action="store_true")
    parser.add_argument("--pr-evidence", type=int, help="Validate PR fields and print the growth review marker without approving")
    args = parser.parse_args()
    record = json.loads(MANIFEST.read_text(encoding="utf-8"))
    validate_manifest(record)
    if args.pr_evidence:
        path = f"repos/{record['repository']}/pulls/{args.pr_evidence}"
        pr = api(path)
        changed = api(path + "/files?per_page=100", paginate=True)
        if len(changed) != pr["changed_files"]:
            raise ValueError("Incomplete changed-path evidence")
        evidence = verify_pr_evidence(pr.get("body"), (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8"))
        growing, digest = growth_evidence(changed, evidence)
        print(json.dumps({"positive_growth": sum(growing.values()), "files": growing,
                          "review_marker": f"Line-growth-approved: {pr['head']['sha']} {digest}"}, indent=2))
    if args.verify_github:
        protection = verify_live_protection(record["repository"])
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text(encoding="utf-8")) if event_path else {}
        print(json.dumps({**verify_github(record, event), "live_protection": protection}, indent=2))


if __name__ == "__main__":
    main()
