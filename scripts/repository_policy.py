"""Verify T01 activation from GitHub evidence, never from a PR description.

Uses the existing Repository Policy job and gh CLI; no new service or dependency.
Run with --verify-github after reviews, rerunning PR CI if approvals were pending.
"""

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".github/t01-activation.json"


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


def approval_users(reviews, head_sha, author):
    latest = {}
    for review in sorted(reviews, key=lambda item: item["id"]):
        # A comment does not cancel an approval. A dismissal or change request does.
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user"]["login"]] = review
    return {
        user for user, review in latest.items()
        if user != author and review["state"] == "APPROVED"
        and review["commit_id"] == head_sha
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


def api(path, paginate=False):
    args = ["gh", "api", path]
    if paginate:
        args += ["--paginate", "--slurp"]
    result = json.loads(subprocess.check_output(args, text=True))
    return [item for page in result for item in page] if paginate else result


def verify_owner_reviews(codeowners, paths, approvals, author):
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
    if len(approvals - {author}) < 2:
        raise ValueError("Two independent current-head approvals are required")
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
        else:
            content = api(f"repos/{repo}/contents/.github/CODEOWNERS?ref={current['base']['sha']}")
            owners = base64.b64decode(content["content"]).decode("utf-8")
        verify_owner_reviews(owners, paths, approval_users(live_reviews, live["head"]["sha"], live["user"]["login"]), live["user"]["login"])
    if pr["merged"]:
        comparison = api(f"repos/{repo}/compare/{pr['merge_commit_sha']}...{record['base_branch']}")
        if comparison["status"] not in {"ahead", "identical"}:
            raise ValueError("T01 merge is not in the master history")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-github", action="store_true")
    args = parser.parse_args()
    record = json.loads(MANIFEST.read_text(encoding="utf-8"))
    validate_manifest(record)
    if args.verify_github:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text(encoding="utf-8")) if event_path else {}
        print(json.dumps(verify_github(record, event), indent=2))


if __name__ == "__main__":
    main()
