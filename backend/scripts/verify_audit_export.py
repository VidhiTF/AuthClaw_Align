"""Verify an AuthClaw signed audit export JSON file.

Usage:
    python backend/scripts/verify_audit_export.py path/to/export.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.audit_export import verify_signed_audit_export


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python backend/scripts/verify_audit_export.py path/to/export.json", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read export: {exc}", file=sys.stderr)
        return 2

    result = verify_signed_audit_export(artifact)
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0 if result.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
