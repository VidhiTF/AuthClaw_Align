"""Tenant-record authorization for the agent's local evidence files."""

import hashlib
import json
from pathlib import Path
from tempfile import SpooledTemporaryFile
from urllib.parse import quote

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import text


def audit_access(tenant_id, actor, purpose, target):
    from verify_audit import create_audit_block

    if tenant_id is None or not actor:
        raise HTTPException(401, "Authenticated evidence actor required")
    try:
        create_audit_block(
            query=f"evidence:{purpose} {target}",
            response="Access requested",
            allowed=True,
            risk_level="MEDIUM",
            approval_status="N/A",
            username=str(actor),
            tenant_id=tenant_id,
        )
    except Exception as exc:
        raise HTTPException(503, "Evidence audit unavailable") from exc


def download_file(conn, tenant_id, evidence_id):
    # The URL value is a database ID, never a filesystem name or object key.
    if (
        not str(evidence_id).isascii()
        or not str(evidence_id).isdigit()
        or len(str(evidence_id)) > 10
        or int(evidence_id) > 2147483647
    ):
        raise HTTPException(404, "Evidence not found")
    row = (
        conn.execute(
            text(
                "SELECT file_path, hash, metadata FROM compliance_evidence "
                "WHERE id = :id AND tenant_id = :tenant_id"
            ),
            {"id": int(evidence_id), "tenant_id": tenant_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Evidence not found")
    try:
        policy = json.loads(row["metadata"] or "{}")
        root = Path("evidence").resolve() / f"tenant-{tenant_id}"
        key = row["file_path"]
        if not key.startswith(f"/evidence/tenant-{tenant_id}/"):
            raise ValueError("tenant binding missing")
        path = Path(key.removeprefix("/")).resolve()
        if not path.is_relative_to(root) or path == root:
            raise ValueError("invalid object key")
        if (
            not policy.get("retention_class")
            or policy.get("allow_download") is not True
        ):
            raise ValueError("access policy missing")
    except (ValueError, TypeError, AttributeError, OSError, RuntimeError) as exc:
        raise HTTPException(404, "Evidence not found") from exc

    # Verify a private snapshot before any response bytes are released. This
    # also avoids reopening a filename that could change after authorization.
    snapshot = SpooledTemporaryFile(max_size=1024 * 1024)
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(65536):
                if snapshot.tell() + len(chunk) > 64 * 1024 * 1024:
                    raise HTTPException(413, "Evidence file exceeds download limit")
                digest.update(chunk)
                snapshot.write(chunk)
        if row["hash"] != "sha256-" + digest.hexdigest():
            raise HTTPException(409, "Evidence integrity check failed")
        snapshot.seek(0)
    except Exception as exc:
        snapshot.close()
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(503, "Evidence storage unavailable") from exc

    def chunks():
        try:
            while chunk := snapshot.read(65536):
                yield chunk
        finally:
            snapshot.close()

    return StreamingResponse(
        chunks(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename*=UTF-8''"
            + quote(path.name, safe=""),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
