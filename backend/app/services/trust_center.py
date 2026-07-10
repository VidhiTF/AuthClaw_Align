"""Auditor Trust Center share service."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import Tenant, TrustCenterAccessLog, TrustCenterShare
from app.services import compliance_scoring
from app.services.audit_export import (
    build_signed_audit_export,
    signing_key_metadata,
    verify_signed_audit_export,
)

SHARE_TOKEN_PREFIX = "tc"
DEFAULT_PERMISSIONS = ["view_scores", "download_signed_audit_export", "verify_exports"]
DEFAULT_FRAMEWORKS = ["SOC2", "GDPR", "HIPAA"]
MAX_SHARE_TTL_DAYS = 90


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def normalize_frameworks(frameworks: list[str] | None) -> list[str]:
    normalized = sorted({str(item).upper().strip() for item in frameworks or DEFAULT_FRAMEWORKS if str(item).strip()})
    unknown = sorted(set(normalized) - set(DEFAULT_FRAMEWORKS))
    if unknown:
        raise ValueError(f"Unsupported Trust Center frameworks: {', '.join(unknown)}")
    return normalized or DEFAULT_FRAMEWORKS


def hash_share_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_share_token() -> tuple[str, str]:
    prefix = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8]
    return prefix, f"{SHARE_TOKEN_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}"


def public_share_url(base_url: str, raw_token: str) -> str:
    return f"{base_url.rstrip('/')}/trust-center/{raw_token}"


def create_share(
    db: Session,
    *,
    tenant_id: Any,
    label: str,
    auditor_email: str | None = None,
    frameworks: list[str] | None = None,
    expires_in_days: int = 30,
    created_by: Any | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[TrustCenterShare, str]:
    ttl_days = max(1, min(int(expires_in_days), MAX_SHARE_TTL_DAYS))
    prefix, raw_token = generate_share_token()
    share = TrustCenterShare(
        tenant_id=tenant_id,
        label=label.strip() or "Auditor Trust Center",
        auditor_email=auditor_email,
        token_hash=hash_share_token(raw_token),
        token_prefix=prefix,
        frameworks=normalize_frameworks(frameworks),
        permissions=list(DEFAULT_PERMISSIONS),
        status="active",
        expires_at=now_utc() + timedelta(days=ttl_days),
        created_by=created_by,
        metadata_json=metadata or {},
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    return share, raw_token


def list_shares(db: Session, tenant_id: Any) -> list[TrustCenterShare]:
    return (
        db.query(TrustCenterShare)
        .filter(TrustCenterShare.tenant_id == tenant_id)
        .order_by(TrustCenterShare.created_at.desc())
        .limit(100)
        .all()
    )


def revoke_share(db: Session, *, tenant_id: Any, share_id: Any) -> TrustCenterShare | None:
    share = (
        db.query(TrustCenterShare)
        .filter(TrustCenterShare.tenant_id == tenant_id, TrustCenterShare.id == share_id)
        .first()
    )
    if not share:
        return None
    if share.status == "active":
        share.status = "revoked"
        share.revoked_at = now_utc()
        db.commit()
        db.refresh(share)
    return share


def resolve_share_token(db: Session, raw_token: str) -> tuple[TrustCenterShare | None, str]:
    token_hash = hash_share_token(raw_token)
    result = db.execute(
        text("SELECT id, tenant_id, status, expires_at FROM resolve_trust_center_share(:token_hash)"),
        {"token_hash": token_hash},
    ).first()
    if not result:
        return None, "not_found"
    tenant_id = result.tenant_id
    db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {"tenant_id": str(tenant_id)})
    share = (
        db.query(TrustCenterShare)
        .filter(TrustCenterShare.id == result.id, TrustCenterShare.tenant_id == tenant_id)
        .first()
    )
    if not share:
        return None, "not_found"
    expires_at = share.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if share.status != "active":
        return share, share.status
    if expires_at <= now_utc():
        share.status = "expired"
        db.commit()
        return share, "expired"
    return share, "active"


def record_access(
    db: Session,
    share: TrustCenterShare,
    *,
    action: str,
    ip_address: str = "",
    user_agent: str = "",
) -> None:
    share.last_accessed_at = now_utc()
    share.access_count = (share.access_count or 0) + 1
    db.add(
        TrustCenterAccessLog(
            tenant_id=share.tenant_id,
            share_id=share.id,
            action=action,
            ip_address=ip_address[:64],
            user_agent=user_agent[:512],
        )
    )
    db.commit()


def verification_guide(public_key: str, key_id: str) -> list[dict[str, str]]:
    return [
        {
            "title": "Download signed evidence",
            "body": "Use the Signed Audit Export button to download the JSON artifact for the selected framework or full tenant scope.",
        },
        {
            "title": "Verify in AuthClaw",
            "body": "Upload the JSON artifact in the Trust Center verifier or Audit Explorer verifier. The verifier checks Ed25519 signature, SHA-256 digest, and every hash-chain link.",
        },
        {
            "title": "Verify offline",
            "body": "Run python backend/scripts/verify_audit_export.py <export.json>. A zero exit code means the signature, digest, counts, and chain anchors are valid.",
        },
        {
            "title": "Public key pin",
            "body": f"Key {key_id}; Ed25519 public key {public_key}",
        },
    ]


def build_public_package(
    db: Session,
    share: TrustCenterShare,
    *,
    include_export: bool = False,
) -> dict[str, Any]:
    tenant = db.query(Tenant).filter(Tenant.id == share.tenant_id).first()
    scores = compliance_scoring.score_all_frameworks(db, str(share.tenant_id), persist=False)
    allowed = set(share.frameworks or DEFAULT_FRAMEWORKS)
    scores["frameworks"] = [item for item in scores["frameworks"] if item["framework"] in allowed]
    if scores["frameworks"]:
        scores["overall_score"] = round(sum(item["score"] for item in scores["frameworks"]) / len(scores["frameworks"]), 1)
        scores["readiness_level"] = compliance_scoring.readiness_level(scores["overall_score"])
    signing = signing_key_metadata()
    package: dict[str, Any] = {
        "tenant": {
            "id": str(tenant.id) if tenant else str(share.tenant_id),
            "name": tenant.name if tenant else "AuthClaw Tenant",
            "tier": tenant.tier if tenant else "",
        },
        "share": {
            "id": str(share.id),
            "label": share.label,
            "auditor_email": share.auditor_email or "",
            "frameworks": share.frameworks or DEFAULT_FRAMEWORKS,
            "permissions": share.permissions or DEFAULT_PERMISSIONS,
            "status": share.status,
            "expires_at": share.expires_at.isoformat() if share.expires_at else "",
            "created_at": share.created_at.isoformat() if share.created_at else "",
            "last_accessed_at": share.last_accessed_at.isoformat() if share.last_accessed_at else "",
            "access_count": share.access_count or 0,
        },
        "scores": scores,
        "signing_key": signing,
        "verification_guide": verification_guide(signing["public_key"], signing["key_id"]),
        "generated_at": now_utc().isoformat(),
    }
    if include_export:
        package["signed_export"] = build_signed_audit_export(db, tenant_id=str(share.tenant_id))
    return package


def build_share_export(db: Session, share: TrustCenterShare, framework: str | None = None) -> dict[str, Any]:
    selected = framework.upper() if framework else None
    if selected and selected not in set(share.frameworks or DEFAULT_FRAMEWORKS):
        raise ValueError(f"Framework {selected} is not allowed by this Trust Center share")
    return build_signed_audit_export(db, tenant_id=str(share.tenant_id), framework=selected)


def verify_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    return verify_signed_audit_export(artifact).as_dict()
