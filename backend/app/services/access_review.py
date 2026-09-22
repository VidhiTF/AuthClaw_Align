"""Tenant access-review export for the ENT-026 authorization contract."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.authorization import normalize_role
from app.db.models import APIKey, User


def build_access_review_export(db: Session, tenant_id: str) -> dict[str, Any]:
    """Build a deterministic, secret-free snapshot of tenant access."""
    users = (
        db.query(User)
        .filter(User.tenant_id == tenant_id)
        .order_by(User.email.asc(), User.id.asc())
        .all()
    )
    keys = (
        db.query(APIKey.created_by, APIKey.scopes, APIKey.is_active, APIKey.expires_at)
        .filter(APIKey.tenant_id == tenant_id)
        .all()
    )
    key_rows: dict[str, list[dict[str, Any]]] = {}
    for key in keys:
        key_rows.setdefault(str(key.created_by), []).append({
            "active": bool(key.is_active),
            "expires_at": key.expires_at.astimezone(timezone.utc).isoformat() if key.expires_at else None,
            "scopes": sorted(str(scope) for scope in (key.scopes or [])),
        })

    records = [
        {
            "user_id": str(user.id),
            "email": user.email,
            "active": bool(user.is_active),
            "role": normalize_role(user.role) or "unknown",
            "legacy_role": str(user.role),
            "platform_role": str(user.platform_role),
            "mfa_enabled": bool(user.mfa_enabled),
            "last_login": user.last_login.astimezone(timezone.utc).isoformat() if user.last_login else None,
            "api_keys": key_rows.get(str(user.id), []),
        }
        for user in users
    ]
    payload = {
        "format": "authclaw.access-review.v1",
        "tenant_id": str(tenant_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records": records,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["integrity_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload
