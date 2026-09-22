"""Auditor Trust Center share service."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.crypto import get_session_key_ring
from app.db.models import Tenant, TrustCenterAccessLog, TrustCenterShare
from app.services.email_service import demo_otp_visible, send_otp_email
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
AUDITOR_OTP_TTL_MINUTES = 15
AUDITOR_OTP_MAX_ATTEMPTS = 5
AUDITOR_OTP_COOLDOWN_SECONDS = 60
AUDITOR_ACCESS_TTL_MINUTES = 60


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _session_secret() -> str:
    active, keys = get_session_key_ring()
    return keys[active]


def _metadata_time(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _auditor_otp_hash(share: TrustCenterShare, otp: str, secret: str | None = None) -> str:
    material = f"{share.id}:{(share.auditor_email or '').strip().lower()}:{otp}".encode()
    return hmac.digest((secret or _session_secret()).encode(), material, "sha256").hex()


def mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    if not separator:
        return "***"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(1, len(local) - len(visible))}@{domain}"


def issue_auditor_otp(db: Session, share: TrustCenterShare, tenant_name: str) -> dict[str, Any]:
    _lock_active_share(db, share)
    email = (share.auditor_email or "").strip().lower()
    if not email:
        raise ValueError("This Trust Center share has no verified auditor email")
    metadata = dict(share.metadata_json or {})
    sent_at = _metadata_time(metadata.get("auditor_otp_sent_at"))
    now = now_utc()
    if sent_at and (now - sent_at).total_seconds() < AUDITOR_OTP_COOLDOWN_SECONDS:
        raise ValueError("Please wait before requesting another verification code")

    otp = f"{secrets.randbelow(1_000_000):06d}"
    delivery = send_otp_email(email, otp, tenant_name, purpose="auditor Trust Center access")
    expires_at = now + timedelta(minutes=AUDITOR_OTP_TTL_MINUTES)
    metadata.update({
        "auditor_otp_hash": _auditor_otp_hash(share, otp),
        "auditor_otp_expires_at": expires_at.isoformat(),
        "auditor_otp_sent_at": now.isoformat(),
        "auditor_otp_attempts": 0,
    })
    share.metadata_json = metadata
    db.commit()
    return {
        "email": mask_email(email),
        "delivery": delivery.method,
        "expires_at": expires_at.isoformat(),
        "dev_otp": otp if delivery.method == "local_outbox" and demo_otp_visible() else None,
    }


def _lock_active_share(db: Session, share: TrustCenterShare) -> None:
    db.refresh(share, with_for_update=True)
    if share.status != "active" or share.revoked_at or _metadata_time(share.expires_at.isoformat()) <= now_utc():
        raise ValueError("Trust Center share is inactive or expired")


def verify_auditor_otp(db: Session, share: TrustCenterShare, raw_share_token: str, otp: str) -> dict[str, Any]:
    _lock_active_share(db, share)
    metadata = dict(share.metadata_json or {})
    expires_at = _metadata_time(metadata.get("auditor_otp_expires_at"))
    attempts = int(metadata.get("auditor_otp_attempts") or 0)
    expected = str(metadata.get("auditor_otp_hash") or "")
    if not expected or not expires_at or expires_at <= now_utc():
        raise ValueError("Verification code is missing or expired")
    if attempts >= AUDITOR_OTP_MAX_ATTEMPTS:
        raise ValueError("Too many invalid verification attempts")
    if not any(
        hmac.compare_digest(expected, _auditor_otp_hash(share, otp.strip(), secret))
        for secret in get_session_key_ring()[1].values()
    ):
        metadata["auditor_otp_attempts"] = attempts + 1
        share.metadata_json = metadata
        db.commit()
        raise ValueError("Invalid verification code")

    for key in ("auditor_otp_hash", "auditor_otp_expires_at", "auditor_otp_attempts"):
        metadata.pop(key, None)
    share.metadata_json = metadata
    expires = now_utc() + timedelta(minutes=AUDITOR_ACCESS_TTL_MINUTES)
    active, keys = get_session_key_ring()
    access_token = jwt.encode(
        {
            "sub": str(share.id),
            "tenant_id": str(share.tenant_id),
            "email": (share.auditor_email or "").strip().lower(),
            "share_token_hash": hash_share_token(raw_share_token),
            "aud": "authclaw-trust-center",
            "exp": expires,
        },
        keys[active],
        algorithm="HS256",
        headers={"kid": active},
    )
    db.commit()
    return {"access_token": access_token, "expires_at": expires.isoformat()}


def verify_auditor_access(share: TrustCenterShare, raw_share_token: str, access_token: str) -> None:
    if not access_token:
        raise ValueError("Auditor email verification is required")
    try:
        _, keys = get_session_key_ring()
        kid = str(jwt.get_unverified_header(access_token).get("kid") or "").lower()
        candidates = [keys[kid]] if kid in keys else ([] if kid else list(dict.fromkeys(keys.values())))
        claims = None
        for secret in candidates:
            try:
                claims = jwt.decode(access_token, secret, algorithms=["HS256"], audience="authclaw-trust-center")
                break
            except jwt.PyJWTError:
                continue
        if claims is None:
            raise ValueError("invalid token")
    except (jwt.PyJWTError, ValueError) as exc:
        raise ValueError("Auditor verification has expired or is invalid") from exc
    expected = {
        "sub": str(share.id),
        "tenant_id": str(share.tenant_id),
        "email": (share.auditor_email or "").strip().lower(),
        "share_token_hash": hash_share_token(raw_share_token),
    }
    if any(not hmac.compare_digest(str(claims.get(key, "")), value) for key, value in expected.items()):
        raise ValueError("Auditor verification does not match this share")


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
    db.query(TrustCenterShare).filter(TrustCenterShare.id == share.id,
        TrustCenterShare.tenant_id == share.tenant_id).update({
            TrustCenterShare.last_accessed_at: now_utc(),
            TrustCenterShare.access_count: TrustCenterShare.access_count + 1,
        }, synchronize_session=False)
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
            "body": "Pin the published key in trusted-keys.json, then run python backend/scripts/verify_audit_export.py --trusted-keys trusted-keys.json <export.json>. A zero exit code means the trusted signature, digest, counts, sequences, and chain anchors are valid.",
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
    scores = compliance_scoring.score_all_frameworks(db, str(share.tenant_id), persist=False, include_traceability=False)
    allowed = set(share.frameworks or DEFAULT_FRAMEWORKS)
    scores["frameworks"] = [item for item in scores["frameworks"] if item["framework"] in allowed]
    trust_summary = scores.get("trust_summary")
    if trust_summary:
        for bucket in ("verified", "in_progress", "planned"):
            trust_summary[bucket] = [item for item in trust_summary[bucket] if item["framework"] in allowed]
        trust_summary["counts"] = {
            bucket: len(trust_summary[bucket]) for bucket in ("verified", "in_progress", "planned")
        }
    scores["overall_score"], scores["readiness_level"] = compliance_scoring.aggregate_readiness(scores["frameworks"])
    timestamps = [item.get("evidence_timestamp") for item in scores["frameworks"]]
    scores["evidence_timestamp"] = min(timestamps) if timestamps and all(timestamps) else None
    for framework in scores["frameworks"]:
        catalog = {item["id"]: item for item in compliance_scoring.CONTROL_CATALOG[framework["framework"]]}
        for control in framework.get("controls", []):
            roles = catalog.get(control["id"], {})
            control["product_owners"] = compliance_scoring.control_assessments.resolve_owners(roles.get("product_roles", ["platform_security"]), public=True)
            control["operational_owners"] = compliance_scoring.control_assessments.resolve_owners(roles.get("operational_roles", ["governance"]), public=True)
            # Public qualification detail is an allowlist, never internal review/source IDs.
            assessment = control.get("evidence_assessment", {})
            control["evidence_assessment"] = {key: assessment[key] for key in (
                "state", "reason_codes", "required_count", "qualified_count", "as_of", "valid_until",
            ) if key in assessment}
            control.pop("traceability", None)
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
            "auditor_email": mask_email(share.auditor_email) if share.auditor_email else "",
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
    allowed = set(share.frameworks or DEFAULT_FRAMEWORKS)
    if selected and selected not in allowed:
        raise ValueError(f"Framework {selected} is not allowed by this Trust Center share")
    if not selected and allowed != set(DEFAULT_FRAMEWORKS):
        raise ValueError("Full export is not allowed by this framework-scoped Trust Center share")
    return build_signed_audit_export(db, tenant_id=str(share.tenant_id), framework=selected)


def verify_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    return verify_signed_audit_export(artifact).as_dict()
