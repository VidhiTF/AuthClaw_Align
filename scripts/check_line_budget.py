#!/usr/bin/env python3
"""Fail when Tokei reports files over the AGENTS.md line budget."""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path


BUDGET_ROW = re.compile(r"^\|\s*`?([^`|]+?)`?\s*\|\s*(\d+)\s*\|")


def load_budgets(path: Path = Path("AGENTS.md")) -> list[tuple[str, int]]:
    budgets: list[tuple[str, int]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = BUDGET_ROW.match(line.strip())
        if match:
            budgets.append((match.group(1).replace("\\", "/"), int(match.group(2))))
    if not budgets:
        raise SystemExit("No line budgets found in AGENTS.md")
    return budgets


def iter_tokei_reports(payload: dict) -> list[tuple[str, int]]:
    reports: list[tuple[str, int]] = []
    for language, summary in payload.items():
        if language == "Total" or not isinstance(summary, dict):
            continue
        for report in summary.get("reports", []):
            name = str(report.get("name", "")).replace("\\", "/")
            code = report.get("stats", {}).get("code")
            if name and isinstance(code, int):
                reports.append((name, code))
    return reports


def budget_for(path: str, budgets: list[tuple[str, int]]) -> tuple[str, int] | None:
    matches = [
        (pattern, ceiling)
        for pattern, ceiling in budgets
        if fnmatch.fnmatch(path, pattern)
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item[0]))


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        raise SystemExit("Usage: tokei <paths> -o json | python scripts/check_line_budget.py")

    budgets = load_budgets()
    overages: list[tuple[str, int, int, str]] = []
    for path, code_lines in iter_tokei_reports(json.loads(raw)):
        match = budget_for(path, budgets)
        if match and code_lines > match[1]:
            overages.append((path, code_lines, match[1], match[0]))

    if not overages:
        print("Line budget OK")
        return 0

    print("Line budget exceeded:")
    for path, code_lines, ceiling, pattern in sorted(overages):
        print(f"  {path}: {code_lines} > {ceiling} ({pattern})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
