"""Tenant-scoped GDPR data-subject request lifecycle operations."""

import base64
import uuid
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import (
    APIKey,
    AuditLogMetadata,
    DataSubjectRequest,
    Notification,
    OnboardingEmailOTP,
    OnboardingStatus,
    User,
)
from app.services.audit_export import (
    SIGNATURE_ALGORITHM,
    _canonical_bytes,
    _private_key_from_env,
    _sha256_hex,
    signing_key_metadata,
)
from app.services.audit_store import append_audit_event, standardize_timestamp
from app.services.event_backbone import increment_metric

EXPORT_FORMAT = "authclaw.data-subject.export.v1"


def _timestamp(value):
    return standardize_timestamp(value) if value else None


class DataSubjectRequestService:
    @staticmethod
    def _audit(
        db: Session,
        record: DataSubjectRequest,
        actor_id,
        action: str,
        *,
        include_subject: bool = False,
        trace_items: list[str] | None = None,
    ) -> None:
        trace = [f"request_id={record.id}", f"status={record.status}"]
        if include_subject:
            trace.append(f"subject_id={record.subject_id}")
        trace.extend(trace_items or [])
        append_audit_event(
            db,
            {
                "id": str(uuid.uuid4()),
                "idempotency_key": f"data-subject-request:{record.id}:{action}",
                "tenant_id": str(record.tenant_id),
                "timestamp": datetime.now(timezone.utc),
                "actor_id": str(actor_id),
                "actor_type": "operator",
                "action": action,
                "request_id": str(record.id),
                "provider": "privacy",
                "reason": action,
                "response_status": 200,
                "frameworks_affected": ["GDPR"],
                "execution_trace": trace,
            },
        )

    @staticmethod
    def _locked(db: Session, tenant_id, request_id) -> DataSubjectRequest:
        record = (
            db.query(DataSubjectRequest)
            .filter(
                DataSubjectRequest.id == request_id,
                DataSubjectRequest.tenant_id == tenant_id,
            )
            .with_for_update()
            .first()
        )
        if not record:
            raise LookupError("Data-subject request not found")
        return record

    @classmethod
    def create(cls, db: Session, *, tenant_id, actor_id, payload) -> DataSubjectRequest:
        record = DataSubjectRequest(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subject_id=payload.subject_id,
            request_type=payload.request_type,
            scope=payload.scope,
            status="PENDING",
        )
        try:
            db.add(record)
            cls._audit(db, record, actor_id, "request_created")
            db.commit()
            db.refresh(record)
            increment_metric("gdpr_requests_created_total")
            return record
        except Exception:
            db.rollback()
            increment_metric("gdpr_request_failures_total")
            raise

    @classmethod
    def verify(
        cls, db: Session, *, tenant_id, request_id, actor_id
    ) -> DataSubjectRequest:
        try:
            record = cls._locked(db, tenant_id, request_id)
            if record.status != "PENDING":
                raise ValueError("Request is not pending")
            now = datetime.now(timezone.utc)
            record.identity_verified = True
            record.identity_verified_by = actor_id
            record.identity_verified_at = now
            record.status = "VERIFIED"
            record.updated_at = now
            cls._audit(db, record, actor_id, "identity_verified")
            db.commit()
            db.refresh(record)
            increment_metric("gdpr_requests_verified_total")
            return record
        except Exception:
            db.rollback()
            increment_metric("gdpr_request_failures_total")
            raise

    @classmethod
    def _decide(
        cls, db: Session, *, tenant_id, request_id, actor_id, decision, reason
    ) -> DataSubjectRequest:
        try:
            record = cls._locked(db, tenant_id, request_id)
            if record.status != "VERIFIED":
                raise ValueError("Request identity is not verified")
            now = datetime.now(timezone.utc)
            record.decision = decision
            record.decision_reason = reason
            record.decision_by = actor_id
            record.decision_at = now
            record.status = decision
            record.updated_at = now
            cls._audit(
                db,
                record,
                actor_id,
                "request_approved" if decision == "APPROVED" else "request_rejected",
            )
            db.commit()
            db.refresh(record)
            if decision == "APPROVED":
                increment_metric("gdpr_requests_approved_total")
            return record
        except Exception:
            db.rollback()
            increment_metric("gdpr_request_failures_total")
            raise

    @classmethod
    def approve(cls, db: Session, *, tenant_id, request_id, actor_id, reason):
        return cls._decide(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            decision="APPROVED",
            reason=reason,
        )

    @classmethod
    def reject(cls, db: Session, *, tenant_id, request_id, actor_id, reason):
        return cls._decide(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            decision="REJECTED",
            reason=reason,
        )

    @staticmethod
    def get(db: Session, *, tenant_id, request_id) -> DataSubjectRequest:
        record = (
            db.query(DataSubjectRequest)
            .filter(
                DataSubjectRequest.id == request_id,
                DataSubjectRequest.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise LookupError("Data-subject request not found")
        return record

    @staticmethod
    def list(db: Session, *, tenant_id, offset=0, limit=100):
        return (
            db.query(DataSubjectRequest)
            .filter(DataSubjectRequest.tenant_id == tenant_id)
            .order_by(DataSubjectRequest.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def _collect_subject_data(db: Session, record: DataSubjectRequest) -> dict:
        user = DataSubjectRequestService._subject_user(db, record)
        if not user:
            return {"user": None, "api_keys": [], "audit_metadata": []}

        api_keys = (
            db.query(APIKey)
            .filter(
                APIKey.tenant_id == record.tenant_id,
                APIKey.created_by == user.id,
                ~APIKey.scopes.any("platform.admin"),
            )
            .order_by(APIKey.created_at)
            .all()
        )
        audit_records = (
            db.query(AuditLogMetadata)
            .filter(
                AuditLogMetadata.tenant_id == record.tenant_id,
                AuditLogMetadata.actor_id == user.id,
            )
            .order_by(AuditLogMetadata.created_at)
            .all()
        )
        return {
            "user": {
                "id": str(user.id),
                "email": user.email,
                "role": str(user.role),
                "platform_role": str(user.platform_role),
                "mfa_enabled": bool(user.mfa_enabled),
                "is_active": bool(user.is_active),
                "last_login": _timestamp(user.last_login),
                "created_at": _timestamp(user.created_at),
                "updated_at": _timestamp(user.updated_at),
            },
            "api_keys": [
                {
                    "id": str(key.id),
                    "name": key.name,
                    "description": key.description,
                    "scopes": list(key.scopes or []),
                    "is_active": bool(key.is_active),
                    "last_used": _timestamp(key.last_used),
                    "last_used_ip": key.last_used_ip,
                    "last_used_user_agent": key.last_used_user_agent,
                    "expires_at": _timestamp(key.expires_at),
                    "revoked_at": _timestamp(key.revoked_at),
                    "created_at": _timestamp(key.created_at),
                    "updated_at": _timestamp(key.updated_at),
                }
                for key in api_keys
            ],
            "audit_metadata": [
                {
                    "record_id": str(item.record_id),
                    "actor_type": item.actor_type,
                    "action": item.action,
                    "request_id": item.request_id,
                    "provider": item.provider,
                    "model": item.model,
                    "response_status": item.response_status,
                    "duration_ms": item.duration_ms,
                    "frameworks_affected": list(item.frameworks_affected or []),
                    "created_at": _timestamp(item.created_at),
                }
                for item in audit_records
            ],
        }

    @staticmethod
    def _subject_user(db: Session, record: DataSubjectRequest) -> User | None:
        try:
            subject_uuid = uuid.UUID(record.subject_id)
        except ValueError:
            return None
        return (
            db.query(User)
            .filter(User.id == subject_uuid, User.tenant_id == record.tenant_id)
            .first()
        )

    @staticmethod
    def _build_export(
        record: DataSubjectRequest, data: dict, exported_at: datetime
    ) -> dict:
        key = signing_key_metadata()
        body = {
            "manifest": {
                "format_version": EXPORT_FORMAT,
                "generated_at": standardize_timestamp(exported_at),
                "record_counts": {
                    "users": 1 if data["user"] else 0,
                    "api_keys": len(data["api_keys"]),
                    "audit_metadata": len(data["audit_metadata"]),
                },
                "signing": {
                    "trusted_key_id": key["key_id"],
                    "algorithm": SIGNATURE_ALGORITHM,
                },
            },
            "subject": {"id": record.subject_id},
            "exported_at": standardize_timestamp(exported_at),
            "request_id": str(record.id),
            "tenant_id": str(record.tenant_id),
            "data": data,
        }
        body_bytes = _canonical_bytes(body)
        signature = _private_key_from_env().sign(body_bytes)
        return {
            **body,
            "digest": {"algorithm": "SHA-256", "value": _sha256_hex(body_bytes)},
            "signature": {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id": key["key_id"],
                "value": base64.b64encode(signature).decode("ascii"),
            },
        }

    @classmethod
    def export(cls, db: Session, *, tenant_id, request_id, actor_id) -> dict:
        try:
            record = cls._locked(db, tenant_id, request_id)
            if (
                record.request_type != "EXPORT"
                or record.status != "APPROVED"
                or not record.identity_verified
                or record.decision != "APPROVED"
            ):
                raise ValueError("Request is not approved for export")
            cls._audit(db, record, actor_id, "export_started", include_subject=True)
            data = cls._collect_subject_data(db, record)
            completed_at = datetime.now(timezone.utc)
            artifact = cls._build_export(record, data, completed_at)
            record.status = "COMPLETED"
            record.completed_at = completed_at
            record.updated_at = completed_at
            cls._audit(db, record, actor_id, "export_completed", include_subject=True)
            db.commit()
            increment_metric("gdpr_exports_completed_total")
            return artifact
        except Exception:
            db.rollback()
            increment_metric("gdpr_request_failures_total")
            raise

    @staticmethod
    def _delete_subject_data(
        db: Session, record: DataSubjectRequest
    ) -> tuple[dict, dict, list]:
        user = DataSubjectRequestService._subject_user(db, record)
        if not user:
            return {}, {}, []

        tenant_keys = (
            db.query(APIKey)
            .filter(
                APIKey.tenant_id == record.tenant_id,
                APIKey.created_by == user.id,
                ~APIKey.scopes.any("platform.admin"),
            )
            .all()
        )
        key_ids = [key.id for key in tenant_keys]
        platform_key_count = (
            db.query(APIKey)
            .filter(
                APIKey.tenant_id == record.tenant_id,
                APIKey.created_by == user.id,
                APIKey.scopes.any("platform.admin"),
            )
            .count()
        )
        if key_ids:
            db.query(OnboardingEmailOTP).filter(
                OnboardingEmailOTP.tenant_id == record.tenant_id,
                OnboardingEmailOTP.api_key_id.in_(key_ids),
            ).update({OnboardingEmailOTP.api_key_id: None}, synchronize_session=False)
            db.query(APIKey).filter(
                APIKey.tenant_id == record.tenant_id,
                APIKey.rotated_from_id.in_(key_ids),
            ).update({APIKey.rotated_from_id: None}, synchronize_session=False)
            db.query(APIKey).filter(
                APIKey.tenant_id == record.tenant_id,
                APIKey.id.in_(key_ids),
            ).delete(synchronize_session=False)

        deleted = {
            "api_keys": len(key_ids),
            "notifications": db.query(Notification)
            .filter(
                Notification.tenant_id == record.tenant_id,
                Notification.user_id == user.id,
            )
            .delete(synchronize_session=False),
            "onboarding_status": db.query(OnboardingStatus)
            .filter(
                OnboardingStatus.tenant_id == record.tenant_id,
                OnboardingStatus.user_id == user.id,
            )
            .delete(synchronize_session=False),
        }
        audit_count = (
            db.query(AuditLogMetadata)
            .filter(
                AuditLogMetadata.tenant_id == record.tenant_id,
                AuditLogMetadata.actor_id == user.id,
            )
            .count()
        )
        legal_count = (
            db.query(OnboardingEmailOTP)
            .filter(
                OnboardingEmailOTP.tenant_id == record.tenant_id,
                func.lower(OnboardingEmailOTP.email) == user.email.lower(),
            )
            .count()
        )
        retained = {"user_identity": 1}
        reasons = ["user_identity:account_and_tenant_lifecycle"]
        if audit_count:
            retained["immutable_audit_metadata"] = audit_count
            reasons.append("immutable_audit_metadata:security_and_compliance_evidence")
        if legal_count:
            retained["legal_acceptance_records"] = legal_count
            reasons.append("legal_acceptance_records:legal_retention_evidence")
        if platform_key_count:
            retained["platform_api_keys"] = platform_key_count
            reasons.append("platform_api_keys:controlled_operational_management")
        return deleted, retained, reasons

    @staticmethod
    def _deletion_result(record, deleted, retained, reasons) -> dict:
        return {
            "request_id": str(record.id),
            "subject_id": record.subject_id,
            "tenant_id": str(record.tenant_id),
            "deleted_items": deleted,
            "retained_items": retained,
            "exception_reasons": reasons,
            "completed_at": _timestamp(record.completed_at),
        }

    @classmethod
    def delete(cls, db: Session, *, tenant_id, request_id, actor_id) -> dict:
        try:
            record = cls._locked(db, tenant_id, request_id)
            if record.request_type != "DELETION":
                raise ValueError("Request is not approved for deletion")
            if record.status == "COMPLETED":
                result = cls._deletion_result(record, {}, {}, [])
                db.rollback()
                return result
            if (
                record.status != "APPROVED"
                or not record.identity_verified
                or record.decision != "APPROVED"
            ):
                raise ValueError("Request is not approved for deletion")
            cls._audit(db, record, actor_id, "deletion_started", include_subject=True)
            deleted, retained, reasons = cls._delete_subject_data(db, record)
            if retained:
                cls._audit(
                    db,
                    record,
                    actor_id,
                    "deletion_exception_applied",
                    include_subject=True,
                    trace_items=[f"retained_category={item}" for item in retained],
                )
            completed_at = datetime.now(timezone.utc)
            record.status = "COMPLETED"
            record.completed_at = completed_at
            record.updated_at = completed_at
            cls._audit(
                db,
                record,
                actor_id,
                "deletion_completed",
                include_subject=True,
                trace_items=[
                    f"deleted_{name}={count}" for name, count in deleted.items()
                ],
            )
            db.commit()
            increment_metric("gdpr_deletions_completed_total")
            return cls._deletion_result(record, deleted, retained, reasons)
        except Exception:
            db.rollback()
            increment_metric("gdpr_request_failures_total")
            raise
