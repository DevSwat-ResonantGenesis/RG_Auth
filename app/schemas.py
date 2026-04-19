"""
Pydantic request/response models for the Auth service.
Extracted from routers.py for shared use across all router modules.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


# ============================================
# Auth - Register / Login / Token
# ============================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    username: Optional[str] = None
    full_name: Optional[str] = None
    org_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    org_id: Optional[UUID] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    org_id: UUID
    role: str
    plan: Optional[str] = None
    user: Optional[dict] = None
    requires_email_verification: Optional[bool] = None
    message: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[dict] = None


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VerifyRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    status: str
    is_active: bool
    is_superuser: bool
    default_org_id: Optional[UUID] = None
    org_id: Optional[UUID] = None
    role: Optional[str] = None
    crypto_hash: Optional[str] = None
    user_hash: Optional[str] = None


# Dev-only user creation request (local testing, no billing)
class DevCreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    org_name: Optional[str] = None


# ============================================
# Org API Keys
# ============================================

class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    prefix: str
    scopes: List[str]
    auth_method: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime] = None
    token: Optional[str] = None


class ApiKeyVerifyRequest(BaseModel):
    api_key: str


class ApiKeyVerifyResponse(BaseModel):
    valid: bool
    user_id: Optional[str] = None
    org_id: Optional[str] = None
    role: Optional[str] = None
    plan: Optional[str] = None
    scopes: List[str] = []
    auth_method: str = "api_key"


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    scopes: List[str] = Field(default_factory=list)
    expires_in_days: Optional[int] = Field(default=None, gt=0, le=365)
    auth_method: str = Field(default="api_key")


class RevokeApiKeyRequest(BaseModel):
    api_key_id: UUID


# ============================================
# Identity & Mnemonic
# ============================================

class UserIdentityResponse(BaseModel):
    """User cryptographic identity response."""
    crypto_hash: Optional[str] = None
    user_hash: Optional[str] = None
    universe_id: Optional[str] = None


class MnemonicRequest(BaseModel):
    """Request to retrieve mnemonic with password verification."""
    password: str


class MnemonicResponse(BaseModel):
    """Mnemonic phrase response."""
    mnemonic: str
    universe_id: str


# ============================================
# User API Keys (BYOK - Bring Your Own Key)
# ============================================

class UserApiKeyCreate(BaseModel):
    provider: str  # 'openai', 'anthropic', 'google', 'mistral', 'groq'
    api_key: str
    name: Optional[str] = None


class UserApiKeyResponse(BaseModel):
    id: str
    provider: str
    name: str
    key_prefix: str  # First 8 chars for display
    is_valid: bool
    is_primary: bool = False
    last_used: Optional[str] = None
    created_at: str


class ValidateApiKeyRequest(BaseModel):
    provider: str
    api_key: str


class ValidateApiKeyResponse(BaseModel):
    valid: bool
    provider: str
    error: Optional[str] = None
    models: Optional[List[str]] = None


class TrialStatusResponse(BaseModel):
    is_trial_user: bool
    trial_start_date: Optional[str] = None
    trial_end_date: Optional[str] = None
    days_remaining: int
    is_expired: bool
    has_api_key: bool
    can_use_services: bool
    requires_upgrade: bool
    current_plan: str


class ServiceAccessResponse(BaseModel):
    can_access: bool
    reason: Optional[str] = None
    action: Optional[str] = None  # 'add-api-key', 'upgrade-plan', 'none'


class AvailableProvidersResponse(BaseModel):
    providers: List[str]
    has_user_keys: bool
    user_key_providers: List[str]


# ============================================
# MFA
# ============================================

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    provisioning_uri: str
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    code: str
    secret: Optional[str] = None  # Required during setup, not after


class MFADisableRequest(BaseModel):
    password: str
    code: Optional[str] = None  # Either TOTP code or backup code


# ============================================
# SSO / OAuth
# ============================================

class SSOInitiateRequest(BaseModel):
    provider: str
    redirect_uri: Optional[str] = None  # Frontend redirect after auth


class SSOCallbackRequest(BaseModel):
    provider: str
    code: str
    state: str


class SSOCallbackQueryParams(BaseModel):
    """Query params from OAuth callback (GET request)."""
    code: str
    state: str
    error: Optional[str] = None
    error_description: Optional[str] = None


class SAMLInitiateRequest(BaseModel):
    org_id: str
    redirect_uri: Optional[str] = None


# ============================================
# Password Management
# ============================================

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    mfa_code: Optional[str] = None  # Required if MFA is enabled


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# ============================================
# Email Verification
# ============================================

class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


# ============================================
# Agent Settings
# ============================================

class AgentCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    system_prompt: Optional[str] = None
    personality_config: Optional[dict] = None
    isolate_anchors: bool = True


class AgentUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    system_prompt: Optional[str] = None
    personality_config: Optional[dict] = None
    enabled_patches: Optional[List[int]] = None
    patch_config: Optional[dict] = None
    memory_config: Optional[dict] = None
    anchor_config: Optional[dict] = None
    isolate_anchors: Optional[bool] = None
    status: Optional[str] = None


class AgentApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scopes: Optional[List[str]] = None
    rate_limit: Optional[int] = Field(default=100, ge=1, le=10000)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)


class AgentApiKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: List[str]
    rate_limit: int
    expires_at: Optional[str]
    created_at: str
    last_used_at: Optional[str]
    is_active: bool


class AgentRestrictionsRequest(BaseModel):
    blocked_topics: Optional[List[str]] = None
    allowed_domains: Optional[List[str]] = None
    blocked_domains: Optional[List[str]] = None
    max_tokens_per_message: Optional[int] = None
    max_messages_per_hour: Optional[int] = None
    allowed_tools: Optional[List[str]] = None
    blocked_tools: Optional[List[str]] = None
    content_filter_level: Optional[str] = None  # none, low, medium, high
