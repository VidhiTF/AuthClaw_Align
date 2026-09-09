"""In-app notification endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_scopes
from app.db.models import Notification

router = APIRouter()


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: str
    severity: str
    title: str
    body: str
    link: str | None
    read_at: Any | None
    created_at: Any


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]
    unread_count: int


def _visible_notifications(db: Session, request: Request):
    tenant_id = request.state.tenant_id
    user_id = getattr(request.state, "user_id", None)
    query = db.query(Notification).filter(Notification.tenant_id == tenant_id)
    if user_id:
        query = query.filter(or_(Notification.user_id.is_(None), Notification.user_id == user_id))
    else:
        query = query.filter(Notification.user_id.is_(None))
    return query


@router.get("", response_model=NotificationListResponse, dependencies=[require_scopes(["read"])])
def list_notifications(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    unread_only: bool = False,
    db: Session = Depends(get_tenant_db),
) -> NotificationListResponse:
    return _notification_list_response(db, request, limit=limit, unread_only=unread_only)


def _notification_list_response(
    db: Session,
    request: Request,
    *,
    limit: int,
    unread_only: bool,
) -> NotificationListResponse:
    """Build the notification list from plain values.

    Endpoints must pass native ``int``/``bool`` values here. FastAPI's
    ``Query`` default objects are not valid SQLAlchemy ``limit`` arguments,
    so endpoint functions must never be called directly as helpers.
    """
    query = _visible_notifications(db, request)
    unread_count = query.filter(Notification.read_at.is_(None)).count()
    if unread_only:
        query = query.filter(Notification.read_at.is_(None))
    items = query.order_by(Notification.created_at.desc()).limit(limit).all()
    return NotificationListResponse(items=items, unread_count=unread_count)


@router.post("/{notification_id}/read", response_model=NotificationResponse, dependencies=[require_scopes(["read"])])
def mark_notification_read(
    notification_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> NotificationResponse:
    notification = _visible_notifications(db, request).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notification.read_at is None:
        notification.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(notification)
    return notification


@router.post("/read-all", response_model=NotificationListResponse, dependencies=[require_scopes(["read"])])
def mark_all_notifications_read(
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> NotificationListResponse:
    now = datetime.now(timezone.utc)
    unread = _visible_notifications(db, request).filter(Notification.read_at.is_(None)).all()
    for notification in unread:
        notification.read_at = now
    if unread:
        db.commit()
    return _notification_list_response(db, request, limit=50, unread_only=False)
