"""Deterministic CI dispatch and fail-closed required-job validation (stdlib only)."""

import json
import os
import subprocess
import sys

COMPONENTS = {
    "backend": "backend/",
    "audit": "audit_consumer/",
    "agent": "services/agent/",
    "sdk": "sdk/python/",
    "gateway": "gateway/",
    "console": "console/",
    "terraform": "infra/terraform/",
}
HEAVY_JOBS = (
    "security",
    "backend",
    "backend-integration",
    "audit",
    "agent",
    "sdk",
    "gateway",
    "console",
    "compose",
    "terraform",
)


def plan(
    event,
    paths,
    *,
    ref="refs/heads/master",
    full_regression=False,
    arm64=False,
    release_enabled=False,
):
    """Unknown executable/config paths fan out, while prose stays lightweight."""
    if event not in {"pull_request", "push", "schedule", "workflow_dispatch"}:
        raise ValueError(f"Unsupported CI event: {event}")
    full = event == "schedule" or (event == "workflow_dispatch" and full_regression)
    affected = {name: full for name in COMPONENTS}
    shared = full
    for path in paths:
        # Only known documentation surfaces are cheap; e.g. docs/*.py is not prose.
        if path.endswith(".md") or (
            path.startswith("docs/") and path.endswith((".png", ".jpg", ".svg", ".txt"))
        ):
            continue
        matched = False
        # This gateway regression runs inside the restricted-role PostgreSQL job.
        if path == "gateway/audit_context_test.go":
            affected["backend"] = True
        for name, prefix in COMPONENTS.items():
            if path.startswith(prefix):
                affected[name] = True
                matched = True
        # Backend public API/schema/crypto and all agent/gateway/audit changes
        # can affect consumers in other languages: prefer conservative fan-out.
        if path.startswith(
            (
                "backend/app/",
                "backend/alembic/",
                "backend/migrations/",
                "audit_consumer/",
                "services/agent/",
                "gateway/",
                "sdk/python/",
            )
        ) and not (
            "/tests/" in path
            or path.endswith("_test.go")
            or path.rsplit("/", 1)[-1].startswith("test_")
        ):
            for name in ("backend", "audit", "agent", "sdk", "gateway", "console"):
                affected[name] = True
        if not matched:
            shared = True
    if shared:
        affected = dict.fromkeys(COMPONENTS, True)
    expensive = event == "pull_request" or full
    selected = {name: value and expensive for name, value in affected.items()}
    selected["audit_transport"] = selected["audit"] or selected["terraform"]
    selected["shared"] = shared and expensive
    selected["security"] = any(
        selected[name]
        for name in ("backend", "audit", "agent", "sdk", "console", "gateway", "terraform")
    )
    selected["full_regression"] = full
    selected["runtime_images"] = any(affected.values())
    selected["smoke"] = (
        event in {"push", "workflow_dispatch"} and not full and any(affected.values())
    )
    selected["arm64"] = (
        arm64
        and event in {"push", "workflow_dispatch"}
        and ref == "refs/heads/master"
        and any(affected.values())
    )
    selected["release"] = (
        release_enabled
        and event == "push"
        and ref == "refs/heads/master"
        and any(affected.values())
    )
    expected = ["changes", "policy"]
    for job in HEAVY_JOBS:
        key = {
            "backend-integration": "backend",
            "audit": "audit_transport",
            "compose": "shared",
        }.get(job, job)
        if selected[key]:
            expected.append(job)
    if selected["smoke"]:
        expected.append("smoke")
    if selected["arm64"]:
        expected.append("arm64-images")
    result = {key: str(value).lower() for key, value in selected.items()}
    result["expected_jobs"] = json.dumps(expected)
    return result


def verify(expected, needs):
    """Expected jobs must succeed; only unselected jobs may be skipped."""
    if not isinstance(expected, list) or not {"changes", "policy"}.issubset(expected):
        raise ValueError("Missing required dispatch plan")
    errors = []
    for job in expected:
        if needs.get(job, {}).get("result") != "success":
            errors.append(
                f"Expected {job}: {needs.get(job, {}).get('result', 'missing')}"
            )
    for job, data in needs.items():
        if data.get("result") not in {"success", "skipped"}:
            errors.append(f"Unsuccessful {job}: {data.get('result')}")
    if errors:
        raise ValueError("; ".join(errors))


def changed_paths(event):
    before = os.environ.get("BASE_SHA", "")
    head = os.environ["GITHUB_SHA"]
    if event in {"schedule", "workflow_dispatch"} or not before or set(before) == {"0"}:
        command = ["git", "ls-files", "-z"]
    else:
        # A shallow/missing base must conservatively select all, never none.
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{before}^{{commit}}"], capture_output=True
        )
        command = (
            ["git", "diff", "--no-renames", "--name-only", "-z", before, head]
            if exists.returncode == 0
            else ["git", "ls-files", "-z"]
        )
    return [
        path for path in subprocess.check_output(command).decode().split("\0") if path
    ]


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        verify(
            json.loads(os.environ["EXPECTED_JOBS"]),
            json.loads(os.environ["NEEDS_JSON"]),
        )
        return
    event = os.environ["GITHUB_EVENT_NAME"]
    outputs = plan(
        event,
        changed_paths(event),
        ref=os.environ["GITHUB_REF"],
        full_regression=os.environ.get("FULL_REGRESSION") == "true",
        arm64=os.environ.get("ARM64_ENABLED") == "true",
        release_enabled=os.environ.get("RELEASE_ENABLED") == "true",
    )
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for key, value in outputs.items():
            print(f"{key}={value}", file=stream)
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
