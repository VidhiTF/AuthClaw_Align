from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime, timedelta, timezone
import os
import pyotp
import qrcode
import io
import base64
from pydantic import BaseModel

from app.db.models import OnboardingEmailOTP, Tenant, User
from app.schemas.models import UserCreate, UserInviteRequest, UserInviteResponse, UserResponse
from app.core.auth import get_tenant_db, require_roles, require_scopes
from app.core.passwords import hash_password
from app.api.v1.endpoints.onboarding import (
    OTP_TTL_MINUTES,
    _deliver_otp,
    _generate_otp,
    _next_resend_at,
    _otp_hash,
)
from app.services.email_service import EmailDeliveryError

router = APIRouter()


class PendingInviteResponse(BaseModel):
    signup_id: UUID
    email: str
    tenant_name: str
    invited_role: str | None = None
    expires_at: datetime
    sent_at: datetime | None = None
    resend_count: int
    delivery: str | None = None
    delivery_error: str | None = None


class MFASecurityResponse(BaseModel):
    user_id: UUID
    email: str
    role: str
    mfa_enabled: bool


class MFASetupResponse(MFASecurityResponse):
    mfa_secret: str
    provisioning_uri: str
    backup_codes: list[str]
    qr_code_base64: str


@router.get("", response_model=list[UserResponse], dependencies=[require_roles(["owner", "admin"])])
def list_users(request: Request, db: Session = Depends(get_tenant_db)):
    """List all users for the tenant (isolated by tenant RLS)"""
    tenant_id = request.state.tenant_id
    return db.query(User).filter(User.tenant_id == tenant_id).all()


@router.get("/me/security", response_model=MFASecurityResponse)
def get_my_security(request: Request, db: Session = Depends(get_tenant_db)):
    """Return security posture for the current console principal."""
    user = db.query(User).filter(
        User.id == request.state.user_id,
        User.tenant_id == request.state.tenant_id,
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return MFASecurityResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        mfa_enabled=bool(user.mfa_enabled),
    )


@router.post("/me/mfa/setup", response_model=MFASetupResponse)
def setup_my_mfa(request: Request, db: Session = Depends(get_tenant_db)):
    """Enable TOTP MFA for approval-sensitive console actions."""
    user = db.query(User).filter(
        User.id == request.state.user_id,
        User.tenant_id == request.state.tenant_id,
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    secret = pyotp.random_base32()
    backup_codes = [pyotp.random_base32()[:8].lower() for _ in range(5)]
    user.mfa_secret = secret
    user.mfa_backup_codes = backup_codes
    user.mfa_enabled = True
    db.commit()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="AuthClaw Lite")

    # Generate QR code as base64 PNG for display in the UI
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return MFASetupResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        mfa_enabled=True,
        mfa_secret=secret,
        provisioning_uri=uri,
        backup_codes=backup_codes,
        qr_code_base64=qr_b64,
    )


@router.post("/me/mfa/disable", response_model=MFASecurityResponse)
def disable_my_mfa(request: Request, db: Session = Depends(get_tenant_db)):
    """Disable TOTP MFA for the current console principal."""
    user = db.query(User).filter(
        User.id == request.state.user_id,
        User.tenant_id == request.state.tenant_id,
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    db.commit()
    return MFASecurityResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        mfa_enabled=False,
    )


@router.get("/invites", response_model=list[PendingInviteResponse], dependencies=[require_roles(["owner"])])
def list_pending_invites(request: Request, db: Session = Depends(get_tenant_db)):
    """List pending tenant member invites."""
    tenant_id = request.state.tenant_id
    rows = db.query(OnboardingEmailOTP).filter(
        OnboardingEmailOTP.tenant_id == tenant_id,
        OnboardingEmailOTP.status == "pending",
        OnboardingEmailOTP.purpose == "invite",
    ).order_by(OnboardingEmailOTP.created_at.desc()).all()
    return [
        PendingInviteResponse(
            signup_id=row.id,
            email=row.email,
            tenant_name=row.tenant_name,
            invited_role=row.invited_role,
            expires_at=row.expires_at,
            sent_at=row.sent_at,
            resend_count=row.resend_count or 0,
            delivery=row.last_delivery,
            delivery_error=row.delivery_error,
        )
        for row in rows
    ]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def create_user(
    request: Request,
    user_in: UserCreate,
    db: Session = Depends(get_tenant_db)
):
    """Create a new user under the active tenant"""
    tenant_id = request.state.tenant_id
    
    # Check if user with same email exists in this tenant
    existing = db.query(User).filter(
        User.tenant_id == tenant_id,
        User.email == user_in.email
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists in this tenant"
        )
        
    try:
        user = User(
            tenant_id=tenant_id,
            email=user_in.email,
            password_hash=hash_password(user_in.password),
            role=user_in.role,
            mfa_enabled=False,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )


@router.post("/invite", response_model=UserInviteResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def invite_user(
    request: Request,
    invite_in: UserInviteRequest,
    db: Session = Depends(get_tenant_db),
):
    """Send an email OTP invite for adding a user to the active tenant."""
    tenant_id = request.state.tenant_id
    inviter_id = request.state.user_id
    email = invite_in.email.strip().lower()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_TTL_MINUTES)

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    existing = db.query(User).filter(
        User.tenant_id == tenant_id,
        User.email == email,
        User.is_active == True,
    ).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An active user already exists for this tenant")

    pending = db.query(OnboardingEmailOTP).filter(
        OnboardingEmailOTP.tenant_id == tenant_id,
        OnboardingEmailOTP.email == email,
        OnboardingEmailOTP.status == "pending",
        OnboardingEmailOTP.purpose == "invite",
    ).first()

    otp = _generate_otp()
    if pending:
        invite_row = pending
        invite_row.otp_hash = _otp_hash(email, otp)
        invite_row.attempts = 0
        invite_row.expires_at = expires_at
        invite_row.sent_at = now
        invite_row.resend_count = (invite_row.resend_count or 0) + 1
        invite_row.invited_role = invite_in.role
        invite_row.invited_by = inviter_id
        invite_row.delivery_error = None
    else:
        invite_row = OnboardingEmailOTP(
            email=email,
            tenant_name=tenant.name,
            otp_hash=_otp_hash(email, otp),
            status="pending",
            expires_at=expires_at,
            sent_at=now,
            purpose="invite",
            invited_role=invite_in.role,
            invited_by=inviter_id,
            tenant_id=tenant_id,
        )
        db.add(invite_row)
    db.flush()

    console_url = (
        os.getenv("PUBLIC_CONSOLE_URL")
        or os.getenv("NEXT_PUBLIC_CONSOLE_URL")
        or os.getenv("NEXT_PUBLIC_APP_URL")
    )
    action_url = f"{console_url.rstrip('/')}/signup?invite={invite_row.id}" if console_url else None

    try:
        delivery, dev_otp = _deliver_otp(
            email,
            otp,
            tenant.name,
            purpose="tenant invite",
            action_url=action_url,
        )
        invite_row.last_delivery = delivery
        invite_row.delivery_error = None
        db.commit()
        db.refresh(invite_row)
        return UserInviteResponse(
            signup_id=invite_row.id,
            email=email,
            tenant_name=tenant.name,
            invited_role=invite_in.role,
            expires_at=invite_row.expires_at,
            delivery=delivery,
            next_resend_at=_next_resend_at(invite_row.sent_at),
            dev_otp=dev_otp,
        )
    except EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.delete("/invites/{id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def cancel_invite(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
):
    """Cancel a pending tenant member invite."""
    tenant_id = request.state.tenant_id
    invite = db.query(OnboardingEmailOTP).filter(
        OnboardingEmailOTP.id == id,
        OnboardingEmailOTP.tenant_id == tenant_id,
        OnboardingEmailOTP.status == "pending",
        OnboardingEmailOTP.purpose == "invite",
    ).first()
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending invite not found")

    invite.status = "cancelled"
    db.commit()


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[require_roles(["owner"]), require_scopes(["admin"])])
def delete_user(
    id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db)
):
    """Delete a user for the tenant"""
    tenant_id = request.state.tenant_id
    user = db.query(User).filter(User.tenant_id == tenant_id, User.id == id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.role == "owner":
        active_owner_count = db.query(User).filter(
            User.tenant_id == tenant_id,
            User.role == "owner",
            User.is_active == True,
        ).count()
        if active_owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last active owner"
            )

    user.is_active = False
    db.commit()
