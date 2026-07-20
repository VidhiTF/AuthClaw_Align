"""Verify an AuthClaw signed audit export JSON file.

Usage:
    python backend/scripts/verify_audit_export.py \
        --trusted-keys path/to/trusted-keys.json path/to/export.json
"""

from __future__ import annotations

import json
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.audit_export import verify_signed_audit_export


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-keys", required=True, type=Path)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
        trusted_keys = json.loads(args.trusted_keys.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read verifier input: {exc}", file=sys.stderr)
        return 2

    result = verify_signed_audit_export(artifact, trusted_keys=trusted_keys)
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0 if result.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
