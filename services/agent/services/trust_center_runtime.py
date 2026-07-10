from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional

from fastapi import HTTPException
from sqlalchemy import text

from database import engine


_CACHE: Dict[str, Any] = {"expires_at": 0.0, "payload": None}
_CACHE_LOCK = Lock()


def _certificate_status() -> Dict[str, Any]:
    certificate_arn = os.getenv("AUTHCLAW_CERTIFICATE_ARN") or os.getenv("AWS_ACM_CERTIFICATE_ARN")
    public_url = os.getenv("AUTHCLAW_PUBLIC_URL", "")
    return {
        "status": "configured" if certificate_arn or public_url.startswith("https://") else "not_configured",
        "certificate_arn_configured": bool(certificate_arn),
        "https_public_url": public_url if public_url.startswith("https://") else "",
    }


def _provider_status(tenant_id: int) -> Dict[str, Any]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT provider, health_status, health_checked_at, health_message
                FROM tenant_credentials
                WHERE tenant_id = :tenant_id AND revoked_at IS NULL
                ORDER BY provider
                """
            ),
            {"tenant_id": tenant_id},
        ).fetchall()
    providers = [
        {
            "provider": row.provider,
            "status": row.health_status or "unknown",
            "checked_at": row.health_checked_at.isoformat() if hasattr(row.health_checked_at, "isoformat") else row.health_checked_at,
            "message": row.health_message,
        }
        for row in rows
    ]
    return {
        "status": "configured" if providers else "not_configured",
        "providers": providers,
    }


def _metrics_summary(tenant_id: int) -> Dict[str, Any]:
    tenant_text = str(tenant_id)
    with engine.connect() as conn:
        total_requests = conn.execute(
            text("SELECT COUNT(*) FROM gateway_requests WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_text},
        ).scalar() or 0
        blocked_requests = conn.execute(
            text("SELECT COUNT(*) FROM gateway_requests WHERE tenant_id = :tenant_id AND allowed = FALSE"),
            {"tenant_id": tenant_text},
        ).scalar() or 0
        provider_errors = conn.execute(
            text(
                """
                SELECT COUNT(*)
                FROM gateway_requests
                WHERE tenant_id = :tenant_id
                  AND lower(COALESCE(status, decision, '')) LIKE ANY (ARRAY['%error%', '%fail%', '%unavailable%', '%timeout%'])
                """
            ),
            {"tenant_id": tenant_text},
        ).scalar() or 0
        pending_approvals = conn.execute(
            text("SELECT COUNT(*) FROM gateway_approvals WHERE tenant_id = :tenant_id AND status = 'pending'"),
            {"tenant_id": tenant_id},
        ).scalar() or 0
    return {
        "total_requests": int(total_requests),
        "blocked_requests": int(blocked_requests),
        "provider_errors": int(provider_errors),
        "pending_approvals": int(pending_approvals),
    }


def _active_tenant_row():
    with engine.connect() as conn:
        return conn.execute(
            text(
                """
                SELECT id, name, domain
                FROM tenants
                WHERE COALESCE(status, 'active') = 'active'
                ORDER BY id ASC
                LIMIT 1
                """
            )
        ).fetchone()


def build_public_trust_state(*, force_refresh: bool = False) -> Dict[str, Any]:
    ttl_seconds = max(5, int(os.getenv("AUTHCLAW_TRUST_CENTER_CACHE_SECONDS", "60")))
    now = time.time()
    with _CACHE_LOCK:
        if not force_refresh and _CACHE["payload"] and now < float(_CACHE["expires_at"]):
            cached = dict(_CACHE["payload"])
            cached["cache"] = {"hit": True, "ttl_seconds": ttl_seconds}
            return cached

    from services.compliance_evidence_engine import ComplianceEvidenceEngine
    from services.event_pipeline import EventPipeline
    from services.secret_manager import SecretManager
    from verify_audit import create_signed_export_package, verify_audit_chain, verify_signed_export_package

    row = _active_tenant_row()
    if not row:
        raise HTTPException(status_code=404, detail="No active tenant trust state is available")

    tenant_id = int(row.id)
    evidence_engine = ComplianceEvidenceEngine()
    audit_chain = verify_audit_chain(tenant_id=tenant_id)
    payload = {
        "package_type": "trust_center_state",
        "tenant_id": tenant_id,
        "tenant_name": row.name,
        "tenant_domain": row.domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_scores": evidence_engine.calculate_scores(tenant_id),
        "audit_chain": audit_chain,
        "corpus": evidence_engine.corpus_status(),
        "runtime": {
            "backend": {"status": "operational"},
            "gateway": {"status": "operational"},
            "metrics": _metrics_summary(tenant_id),
            "audit_status": audit_chain,
            "provider_status": _provider_status(tenant_id),
            "certificate_status": _certificate_status(),
            "secrets": SecretManager().selection_policy(),
            "event_pipeline": EventPipeline().delivery_metrics(),
        },
        "verification_endpoint": "/audit/export/verify",
    }
    package = create_signed_export_package(
        payload,
        tenant_id=tenant_id,
        export_type="trust-center-state",
        framework_scope="SOC2,GDPR,HIPAA",
    )
    verification = verify_signed_export_package(payload_b64=package["payload_b64"], manifest=package["manifest"])
    response = {
        "status": "published",
        "payload": package["payload"],
        "manifest": package["manifest"],
        "payload_b64": package["payload_b64"],
        "verification": verification,
        "cache": {"hit": False, "ttl_seconds": ttl_seconds},
    }
    with _CACHE_LOCK:
        _CACHE["payload"] = response
        _CACHE["expires_at"] = now + ttl_seconds
    return response


def trust_runtime_health() -> Dict[str, Any]:
    try:
        state = build_public_trust_state()
        runtime = state.get("payload", {}).get("runtime", {})
        return {
            "status": "healthy" if state.get("verification", {}).get("valid") else "degraded",
            "trust_center": {
                "published": state.get("status") == "published",
                "signature_valid": state.get("verification", {}).get("valid") is True,
                "cache": state.get("cache", {}),
            },
            "runtime": runtime,
        }
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}
