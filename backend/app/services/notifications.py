"""Small helpers for in-app notifications."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Notification

VALID_SEVERITIES = {"info", "warning", "critical"}
logger = logging.getLogger("services.notifications")


def add_notification(
    db: Session,
    *,
    tenant_id: Any,
    type: str,
    severity: str,
    title: str,
    body: str = "",
    link: str | None = None,
    user_id: Any | None = None,
) -> Notification:
    notification = Notification(
        tenant_id=tenant_id,
        user_id=user_id,
        type=type.strip()[:100],
        severity=severity if severity in VALID_SEVERITIES else "info",
        title=title.strip()[:255],
        body=body.strip(),
        link=link.strip()[:512] if link else None,
    )
    db.add(notification)
    return notification


def create_notification(db: Session, **kwargs: Any) -> Notification | None:
    try:
        notification = add_notification(db, **kwargs)
        db.commit()
        db.refresh(notification)
        return notification
    except Exception as exc:
        db.rollback()
        logger.warning("Failed to create notification: %s", exc)
        return None
