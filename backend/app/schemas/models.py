"""Pydantic schemas for request/response validation"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator


class TenantCreate(BaseModel):
    """Schema for creating a tenant"""
    name: str = Field(..., min_length=1, max_length=255)
    tier: str = Field(default="starter", pattern="^(starter|pro|enterprise)$")


class TenantResponse(BaseModel):
    """Schema for tenant response"""
    id: UUID
    name: str
    tier: str
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TenantStatusUpdate(BaseModel):
    """Schema for changing the active tenant lifecycle state."""
    status: str = Field(..., pattern="^(active|disabled|suspended)$")


class UserCreate(BaseModel):
    """Schema for creating a user"""
    email: EmailStr
    password: str = Field(..., min_length=12)
    role: str = Field(default="viewer", pattern="^(owner|admin|developer|operator|viewer)$")


class UserInviteRequest(BaseModel):
    """Invite a user into the current tenant with email OTP verification."""
    email: EmailStr
    role: str = Field(default="viewer", pattern="^(owner|admin|developer|operator|viewer)$")


class UserInviteResponse(BaseModel):
    """Tenant user invite response."""
    signup_id: UUID
    email: EmailStr
    tenant_name: str
    invited_role: str
    expires_at: datetime
    delivery: str
    next_resend_at: datetime
    dev_otp: Optional[str] = None


class UserResponse(BaseModel):
    """Schema for user response"""
    id: UUID
    email: str
    role: str
    mfa_enabled: bool
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreate(BaseModel):
    """Schema for creating an API key"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scopes: List[str] = Field(default=["read"], min_items=1)
    expires_in_days: int = Field(default=90, ge=1, le=365)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: List[str]) -> List[str]:
        allowed = {"read", "write", "admin"}
        normalized = sorted({scope.strip().lower() for scope in value if scope and scope.strip()})
        invalid = sorted(set(normalized) - allowed)
        if invalid:
            raise ValueError(f"Unsupported API key scopes: {', '.join(invalid)}")
        if not normalized:
            raise ValueError("At least one API key scope is required")
        return normalized


class APIKeyRotate(BaseModel):
    """Schema for rotating an API key into a new secret."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    scopes: Optional[List[str]] = None
    expires_in_days: int = Field(default=90, ge=1, le=365)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        return APIKeyCreate.validate_scopes(value)


class APIKeyResponse(BaseModel):
    """Schema for API key response (doesn't include the actual key)"""
    id: UUID
    name: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None
    last_used_ip: Optional[str] = None
    last_used_request_id: Optional[str] = None
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    rotated_from_id: Optional[UUID] = None

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    """Schema for creating a policy"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    policy_yaml: str = Field(..., min_length=10)
    activate: bool = True


class PolicyResponse(BaseModel):
    """Schema for policy response"""
    id: UUID
    name: str
    version: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyDetailResponse(BaseModel):
    """Schema for detailed policy response with yaml"""
    id: UUID
    name: str
    description: Optional[str] = None
    policy_yaml: str
    version: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True



class GatewayConfigCreate(BaseModel):
    """Schema for gateway configuration"""
    name: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(..., pattern="^(openai|anthropic|cohere|azure_openai|gemini)$")
    endpoint: str = Field(..., min_length=1, max_length=512)
    model_whitelist: Optional[List[str]] = None
    redaction_strategy: str = Field(default="mask", pattern="^(mask|hash|synthetic)$")
    redaction_token_retention_days: int = Field(default=90, ge=1, le=3650)


class GatewayConfigResponse(BaseModel):
    """Schema for gateway config response"""
    id: UUID
    name: str
    provider: str
    endpoint: str
    redaction_strategy: str
    redaction_token_retention_days: int = 90
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyValidationRequest(BaseModel):
    """Validate policy YAML before activation."""
    policy_yaml: str = Field(..., min_length=1)


class PolicyValidationResponse(BaseModel):
    valid: bool
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []
    normalized_policy: Optional[Dict[str, Any]] = None
    stats: Optional[Dict[str, Any]] = None


class PolicySimulationRequest(BaseModel):
    """Dry-run a policy decision without changing active policy state."""
    policy_yaml: Optional[str] = None
    policy_id: Optional[UUID] = None
    model: str = Field(..., min_length=1, max_length=255)
    route: str = Field(default="/v1/chat/completions", max_length=512)
    prompts: List[str] = Field(default_factory=list)
    topics: List[str] = Field(default_factory=list)
    rate_limit_exceeded: bool = False


class PolicySimulationResponse(BaseModel):
    decision: str
    allow: bool
    reason: str
    policy_id: Optional[UUID] = None
    policy_version: Optional[int] = None
    policy_name: Optional[str] = None
    explanations: List[Dict[str, Any]]
    matched_rules: List[Dict[str, Any]]
    validation: PolicyValidationResponse


class PolicyRollbackRequest(BaseModel):
    """Activate an older policy version."""
    policy_id: Optional[UUID] = None
    version: Optional[int] = Field(default=None, ge=1)


class ProviderCredentialCreate(BaseModel):
    """Create or rotate a model provider credential."""
    provider: str = Field(..., pattern="^(openai|anthropic|cohere|azure_openai|gemini)$")
    display_name: str = Field(..., min_length=1, max_length=255)
    api_key: str = Field(..., min_length=8)
    endpoint: Optional[str] = Field(default=None, max_length=512)


class ProviderCredentialResponse(BaseModel):
    """Provider credential metadata. Raw secret is never returned."""
    id: UUID
    provider: str
    display_name: str
    endpoint: Optional[str] = None
    auth_scheme: str
    status: str
    version: int = 1
    last_verified_at: Optional[datetime] = None
    created_at: datetime
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    rotated_from_id: Optional[UUID] = None

    class Config:
        from_attributes = True


class OnboardingSignupRequest(BaseModel):
    """Start Lite self-service onboarding by sending an email OTP."""
    email: EmailStr
    tenant_name: str = Field(..., min_length=2, max_length=255)


class OnboardingSignupResponse(BaseModel):
    """Signup OTP request response."""
    signup_id: UUID
    email: EmailStr
    tenant_name: str
    expires_at: datetime
    delivery: str
    next_resend_at: datetime
    dev_otp: Optional[str] = None


class OnboardingResendRequest(BaseModel):
    """Resend an existing pending signup OTP."""
    signup_id: UUID


class OnboardingResendResponse(BaseModel):
    """OTP resend response."""
    signup_id: UUID
    email: EmailStr
    expires_at: datetime
    delivery: str
    next_resend_at: datetime
    dev_otp: Optional[str] = None


class OnboardingVerifyRequest(BaseModel):
    """Verify email OTP and bootstrap the first tenant."""
    signup_id: UUID
    otp: str = Field(..., min_length=6, max_length=6)
    password: str = Field(..., min_length=12, max_length=256)


class OnboardingChecklistResponse(BaseModel):
    """Tenant onboarding checklist state."""
    email_verified: bool
    tenant_created: bool
    api_key_issued: bool
    provider_key_saved: bool
    route_created: bool
    policy_created: bool
    snippet_viewed: bool
    current_step: str


class OnboardingVerifyResponse(BaseModel):
    """Verified signup response including the first AuthClaw gateway key."""
    tenant_id: UUID
    tenant_name: str
    user_id: UUID
    email: EmailStr
    role: str
    api_key: str
    gateway_url: str
    provider: str
    model: str
    checklist: OnboardingChecklistResponse
    powershell_snippet: str
    curl_snippet: str


class RedactionTokenMapResponse(BaseModel):
    """Schema for redaction token mapping response"""
    id: UUID
    token_value: str
    token_hash: str
    original_value: str
    strategy: str
    entity_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    purged_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogMetadataResponse(BaseModel):
    """Schema for audit log metadata response"""
    id: UUID
    record_id: UUID
    actor_id: Optional[UUID] = None
    action: str
    frameworks_affected: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    """Standard error response"""
    detail: str
    status_code: int
    error_type: Optional[str] = None
