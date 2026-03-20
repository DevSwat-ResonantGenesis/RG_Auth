"""
Auth Routers - Full old backend compatibility.
Ported from ResonantGraphAIV0.1 backend with:
- Multi-tenant (Organization) support
- Role-based access control
- HttpOnly cookie authentication
- Refresh token DB storage
- Identity-based JWT tokens
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID, uuid4
import re
import secrets
import hashlib
import hmac
import logging
import urllib.parse
import httpx

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

from .config import settings
from .db import get_db
from .models import Agent, ApiKey, Organization, OrgMembership, PasswordResetToken, RefreshToken, User, UserApiKey
from .identity import Identity
from .security import (
    create_access_token,
    decode_access_token,
    validate_access_token,
    generate_api_key,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from .economic_integration import create_user_economic_state, EconomicIntegrationError
from .crypto import encrypt_api_key, decrypt_api_key
from .rate_limit import (
    rate_limit,
    login_rate_limit,
    register_rate_limit,
    password_reset_rate_limit,
    refresh_token_rate_limit,
)
from .audit import log_audit_event, AuditEventType, get_client_info


router = APIRouter()

ACCESS_COOKIE = settings.ACCESS_COOKIE
REFRESH_COOKIE = settings.REFRESH_COOKIE


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _generate_slug(name: str) -> str:
    """Generate a URL-safe slug from organization name."""
    slug = name.lower().replace(" ", "-")
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = slug[:50]  # Limit length
    # Add random suffix to ensure uniqueness
    suffix = secrets.token_hex(4)
    return f"{slug}-{suffix}"


# ============================================
# Request/Response Models
# ============================================

def validate_password_strength(password: str) -> str:
    """
    Validate password meets security requirements.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    
    Returns the password if valid, raises ValueError with message if not.
    """
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("one lowercase letter")
    if not re.search(r'\d', password):
        errors.append("one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        errors.append("one special character (!@#$%^&*)")
    
    if errors:
        raise ValueError(f"Password must contain: {', '.join(errors)}")
    return password


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    username: Optional[str] = None
    full_name: Optional[str] = None
    org_name: Optional[str] = None


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


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    org_id: Optional[UUID] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: dict
    token_type: str = "bearer"
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
# Cookie Helpers
# ============================================

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, user_email: str = None, user_role: str = None, org_id: str = None):
    """Set HttpOnly auth cookies with proper security settings."""
    is_dev = settings.ENVIRONMENT == "development"
    
    # Security settings based on environment
    # Production: Secure=True (HTTPS required), SameSite=lax
    # Development: Secure=False (HTTP allowed), SameSite=lax
    secure_value = settings.COOKIE_SECURE if not is_dev else False
    samesite_value = "lax"
    
    # Cookie domain - None means browser will use the request origin
    # Using None for same-origin cookies (no cross-subdomain needed)
    cookie_domain = None
    if not is_dev and getattr(settings, "COOKIE_DOMAIN", None):
        cookie_domain = settings.COOKIE_DOMAIN
    
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        httponly=True,
        secure=secure_value,
        samesite=samesite_value,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
        domain=cookie_domain,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        httponly=True,
        secure=secure_value,
        samesite=samesite_value,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/",
        domain=cookie_domain,
    )
    
    # Set session cookie for frontend (NOT HttpOnly so JS can read user info)
    if user_email and user_role and org_id:
        import json
        session_data = json.dumps({
            "email": user_email,
            "role": user_role,
            "org": org_id,
            "userId": user_email
        })
        session_data = urllib.parse.quote(session_data, safe="")
        response.set_cookie(
            "rg_session",
            session_data,
            httponly=False,  # Frontend needs to read this
            secure=secure_value,
            samesite=samesite_value,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            path="/",
            domain=cookie_domain,
        )


def _clear_auth_cookies(response: Response):
    """Clear auth cookies."""
    is_dev = settings.ENVIRONMENT == "development"
    domains = [None]
    if not is_dev and getattr(settings, "COOKIE_DOMAIN", None):
        domains.append(settings.COOKIE_DOMAIN)

    for domain in domains:
        response.delete_cookie(ACCESS_COOKIE, path="/", domain=domain)
        response.delete_cookie(REFRESH_COOKIE, path="/", domain=domain)
        response.delete_cookie("rg_session", path="/", domain=domain)


def _generate_crypto_identity(user_id: UUID, email: str) -> tuple[str, str, str]:
    """Generate cryptographic identity for a user.
    
    Returns:
        tuple: (crypto_hash, user_hash, universe_id)
    """
    # Generate deterministic crypto hash from user_id + email + timestamp
    seed_data = f"{user_id}:{email}:{_utcnow().isoformat()}:{secrets.token_hex(16)}"
    crypto_hash = hashlib.sha256(seed_data.encode()).hexdigest()
    
    # Generate user hash (Hash Sphere semantic identity)
    user_hash_data = f"user:{user_id}:{email}"
    user_hash = hashlib.sha256(user_hash_data.encode()).hexdigest()
    
    # Generate universe ID (first 32 chars of a derived hash)
    universe_data = f"universe:{crypto_hash}:{user_hash}"
    universe_id = hashlib.sha256(universe_data.encode()).hexdigest()[:32]
    
    return crypto_hash, user_hash, universe_id


# ============================================
# Helper Functions
# ============================================

async def _resolve_membership(
    db: AsyncSession, 
    user_id: UUID, 
    org_id: Optional[UUID]
) -> OrgMembership:
    """Resolve user's organization membership."""
    stmt = select(OrgMembership).where(
        OrgMembership.user_id == user_id,
        OrgMembership.status == "active",
    )
    result = await db.execute(stmt)
    memberships = result.scalars().all()
    
    if not memberships:
        raise HTTPException(status_code=403, detail="No active organizations")

    if org_id:
        for membership in memberships:
            if membership.org_id == org_id:
                return membership
        raise HTTPException(status_code=403, detail="Org access denied")

    # Return first active membership
    if memberships:
        return memberships[0]

    raise HTTPException(status_code=403, detail="Org access denied")


async def _issue_refresh_token(
    db: AsyncSession,
    identity: Identity,
    request: Request,
) -> str:
    """Issue and store a refresh token."""
    refresh_plain, refresh_hash = generate_refresh_token()
    refresh = RefreshToken(
        user_id=identity.user_id,
        org_id=identity.org_id,
        token_hash=refresh_hash,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=_utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh)
    await db.commit()
    return refresh_plain


async def _get_identity_from_request(
    request: Request,
    db: AsyncSession,
) -> Identity:
    """Extract Identity from access token in cookie or Authorization header."""
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        decoded = decode_access_token(token)
        identity = Identity.from_claims(decoded)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not identity.org_id:
        raise HTTPException(status_code=401, detail="Invalid identity")

    # Optional: verify user/org are still active
    user_result = await db.execute(select(User).where(User.id == identity.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")

    return identity


# ============================================
# Auth Endpoints
# ============================================

@router.post("/auth/register", response_model=LoginResponse)
@register_rate_limit()
async def register(
    request: Request,
    payload: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user with organization.
    
    Creates:
    1. Organization (with name or default)
    2. User (with email, password, full_name)
    3. OrgMembership (user -> org, role=owner)
    4. JWT tokens with Identity claims
    5. HttpOnly cookies
    """
    # Validate password strength
    try:
        validate_password_strength(payload.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Check for duplicate email
    result = await db.execute(select(User).where(User.email == payload.email))
    existing = result.scalar_one_or_none()
    if existing:
        if settings.REQUIRE_EMAIL_VERIFICATION and not existing.email_verified:
            from .email_verification import resend_verification_email

            membership_result = await db.execute(
                select(OrgMembership).where(
                    OrgMembership.user_id == existing.id,
                    OrgMembership.status == "active",
                )
            )
            membership = membership_result.scalar_one_or_none()
            if not membership or not membership.org_id:
                raise HTTPException(status_code=403, detail="No active organizations")

            try:
                success, message = await resend_verification_email(existing, db)
                if success:
                    logger.info(f"Verification email resent to {existing.email}")
                else:
                    logger.warning(f"Failed to resend verification email to {existing.email}: {message}")
            except Exception as e:
                logger.error(f"Error resending verification email: {e}")
                message = "Verification email sent. Please check your inbox."

            return LoginResponse(
                access_token="",
                org_id=membership.org_id,
                role=membership.role,
                user={
                    "id": str(existing.id),
                    "email": existing.email,
                    "username": existing.username,
                    "full_name": existing.full_name,
                    "email_verified": existing.email_verified,
                },
                requires_email_verification=True,
                message=message,
            )

        raise HTTPException(status_code=400, detail="Email already registered")

    # Create organization
    org_name = payload.org_name or f"{payload.email.split('@')[0]}'s Organization"
    org = Organization(
        name=org_name,
        slug=_generate_slug(org_name),
        is_active=True,
    )
    db.add(org)
    await db.flush()  # Get org.id

    # Create user (email_verified=False by default)
    # 1-WEEK UNLIMITED TRIAL: every new user gets unlimited credits for 7 days
    trial_end = _utcnow() + timedelta(days=7)
    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name or payload.username or payload.email.split('@')[0],
        password_hash=hash_password(payload.password),
        is_active=True,
        is_superuser=False,
        unlimited_credits=True,
        trial_expires_at=trial_end,
        default_org_id=org.id,
        status="active",
        email_verified=False,
    )
    logger.info(f"🎁 New user trial: unlimited access until {trial_end.isoformat()}")
    db.add(user)
    await db.flush()  # Get user.id
    
    # Generate cryptographic identity
    crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, payload.email)
    user.crypto_hash = crypto_hash
    user.user_hash = user_hash
    user.universe_id = universe_id
    
    # ============================================
    # LAYER 3: Hash Sphere Anchor Creation
    # ============================================
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            hash_sphere_response = await client.post(
                f"{settings.HASH_SPHERE_URL}/anchors/create",
                json={
                    "user_id": str(user.id),
                    "user_hash": user_hash,
                    "universe_id": universe_id,
                    "content": f"User registration: {payload.email}",
                    "metadata": {
                        "type": "user_registration",
                        "email": payload.email,
                        "timestamp": _utcnow().isoformat(),
                    }
                }
            )
            if hash_sphere_response.status_code == 200:
                logger.info(f"Hash Sphere anchor created for user: {user_hash[:16]}...")
            else:
                logger.warning(f"Hash Sphere anchor creation failed: {hash_sphere_response.status_code}")
    except Exception as e:
        logger.error(f"Hash Sphere anchor creation error: {e}")
        # Don't fail registration if Hash Sphere is down
    
    # ============================================
    # LAYER 4: Blockchain DSID Registration
    # ============================================
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            blockchain_response = await client.post(
                f"{settings.BLOCKCHAIN_SERVICE_URL}/identity/register",
                json={
                    "user_id": str(user.id),
                    "crypto_hash": crypto_hash,
                    "user_hash": user_hash,
                    "universe_id": universe_id,
                    "email": payload.email,
                }
            )
            if blockchain_response.status_code == 200:
                logger.info(f"Blockchain identity registered for user: {crypto_hash[:16]}...")
            else:
                logger.warning(f"Blockchain identity registration failed: {blockchain_response.status_code}")
    except Exception as e:
        logger.error(f"Blockchain identity registration error: {e}")
        # Don't fail registration if blockchain is down

    # Create membership (owner role)
    membership = OrgMembership(
        user_id=user.id,
        org_id=org.id,
        role="owner",
        status="active",
    )
    db.add(membership)
    
    # ============================================
    # CRITICAL: Create UserEconomicState in billing_service
    # ============================================
    # TODO: Re-enable when billing service has /economic-state/ endpoint
    # try:
    #     economic_state = await create_user_economic_state(
    #         user_id=user.id,
    #         org_id=org.id,
    #         tier="developer",  # Default tier
    #         subscription_source="internal",
    #         is_dev_override=False,
    #     )
    # except EconomicIntegrationError as e:
    #     # CRITICAL: Rollback the transaction if economic state creation fails
    #     await db.rollback()
    #     raise HTTPException(
    #         status_code=503,
    #         detail=f"Registration failed: could not create economic state. {e}"
    #     )
    # ============================================
    
    await db.commit()
    
    # Send verification email
    from .email_verification import create_verification_token, send_verification_email
    try:
        plain_token = await create_verification_token(user, db)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://dev-swat.com')
        verification_url = f"{frontend_url}/verify-email?token={plain_token}"
        email_sent = await send_verification_email(user.email, verification_url, user.full_name)
        if email_sent:
            logger.info(f"Verification email sent to {user.email}")
        else:
            logger.error(f"Failed to send verification email to {user.email}")
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")
        # Don't fail registration if email fails - user can resend later
    
    # Log registration
    ip_address, user_agent = get_client_info(request)
    await log_audit_event(
        db, AuditEventType.REGISTRATION,
        user_id=user.id,
        org_id=org.id,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"email": user.email},
        success=True,
    )
    await db.commit()

    if settings.REQUIRE_EMAIL_VERIFICATION:
        return LoginResponse(
            access_token="",
            org_id=org.id,
            role="owner",
            user={
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "full_name": user.full_name,
                "email_verified": user.email_verified,
            },
            requires_email_verification=True,
            message="Verification email sent. Please verify your email before logging in.",
        )

    # Create Identity
    identity = Identity(
        user_id=user.id,
        org_id=org.id,
        role="owner",
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    # Create tokens
    access_token = create_access_token(identity, user.token_version)
    refresh_plain = await _issue_refresh_token(db, identity, request)
    
    # Set cookies (including rg_session for frontend)
    _set_auth_cookies(
        response, 
        access_token, 
        refresh_plain,
        user_email=user.email,
        user_role="owner",
        org_id=str(org.id)
    )

    return LoginResponse(
        access_token=access_token,
        org_id=org.id,
        role="owner",
        user={
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "email_verified": user.email_verified,
        }
    )


@router.post("/auth/signup", response_model=LoginResponse)
@register_rate_limit()
async def signup(
    request: Request,
    payload: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Alias for register endpoint - for backwards compatibility."""
    return await register(request, payload, response, db)


@router.post("/auth/dev-create-user", response_model=LoginResponse, include_in_schema=False)
async def dev_create_user(
    request: Request,
    payload: DevCreateUserRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Create a local dev user + org and return login tokens.

    This endpoint is intended *only* for local development. It bypasses
    billing and plan selection so that developers can sign in quickly.
    
    SECURITY: This endpoint is completely disabled in production.
    It will return 404 and not appear in OpenAPI docs.
    """

    # Hard safety check: never allow this outside development
    # Multiple checks for defense in depth
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found")
    
    if settings.ENV not in ("dev", "development", "local"):
        raise HTTPException(status_code=404, detail="Not found")

    # Normalize inputs
    email = payload.email
    full_name = payload.full_name or "Dev User"
    org_name = payload.org_name or "Dev Organization"

    # Check if user already exists
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        user = existing_user
        # Ensure password is usable for local testing
        user.password_hash = hash_password(payload.password)
        db.add(user)
        await db.commit()

        # Ensure there is at least one active membership
        membership_result = await db.execute(
            select(OrgMembership).where(
                OrgMembership.user_id == user.id,
                OrgMembership.status == "active",
            )
        )
        membership = membership_result.scalar_one_or_none()
        if not membership:
            org_result = await db.execute(select(Organization))
            org = org_result.scalars().first()
            if not org:
                org = Organization(
                    name=org_name,
                    slug=_generate_slug(org_name),
                    is_active=True,
                )
                db.add(org)
                await db.commit()
                await db.refresh(org)
            membership = OrgMembership(
                user_id=user.id,
                org_id=org.id,
                role="owner",
                status="active",
            )
            db.add(membership)
            await db.commit()
    else:
        # Create org with unlimited plan for dev mode
        org = Organization(
            name=org_name,
            slug=_generate_slug(org_name),
            is_active=True,
            plan="unlimited",  # Dev mode gets full access
        )
        db.add(org)
        await db.commit()
        await db.refresh(org)

        # Create user
        user = User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(payload.password),
            is_active=True,
            is_superuser=False,
            default_org_id=org.id,
            status="active",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        # Generate cryptographic identity
        crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, email)
        user.crypto_hash = crypto_hash
        user.user_hash = user_hash
        user.universe_id = universe_id
        await db.commit()

        # Create membership
        membership = OrgMembership(
            user_id=user.id,
            org_id=org.id,
            role="owner",
            status="active",
        )
        db.add(membership)
        await db.commit()

    identity = Identity(
        user_id=user.id,
        org_id=membership.org_id,
        role=membership.role,
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    access_token = create_access_token(identity, user.token_version)
    refresh_plain = await _issue_refresh_token(db, identity, request)
    _set_auth_cookies(response, access_token, refresh_plain)

    return LoginResponse(
        access_token=access_token,
        org_id=identity.org_id,
        role=identity.role,
        user={
            "id": str(user.id),
            "email": user.email,
            "username": getattr(user, "username", None),
            "full_name": user.full_name,
        },
    )


# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


async def _check_and_update_lockout(user: User, db: AsyncSession, success: bool) -> None:
    """Check account lockout status and update failed attempts."""
    now = _utcnow()
    
    if success:
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_failed_login_at = None
    else:
        # Increment failed attempts
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        user.last_failed_login_at = now
        
        # Lock account if max attempts exceeded
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    
    await db.commit()


def _is_account_locked(user: User) -> tuple[bool, Optional[int]]:
    """Check if account is locked. Returns (is_locked, minutes_remaining)."""
    if not user.locked_until:
        return False, None
    
    now = _utcnow()
    if user.locked_until > now:
        remaining = (user.locked_until - now).total_seconds() / 60
        return True, int(remaining) + 1
    
    return False, None


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Login user and return JWT tokens.
    """
    # Find active user
    result = await db.execute(
        select(User).where(
            User.email == payload.email,
            User.status == "active",
        )
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # CRITICAL: Check if email is verified
    if settings.REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
        raise HTTPException(
            status_code=403, 
            detail="Email not verified. Please check your inbox for the verification link or request a new one."
        )

    # CRITICAL: Check if cryptographic identity exists, create if missing
    if not user.crypto_hash or not user.user_hash or not user.universe_id:
        logger.info(f"Generating missing cryptographic identity for user on login: {user.email}")
        crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, user.email)
        user.crypto_hash = crypto_hash
        user.user_hash = user_hash
        user.universe_id = universe_id
        
        # Create Hash Sphere anchor
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{settings.HASH_SPHERE_URL}/anchors/create",
                    json={
                        "user_id": str(user.id),
                        "user_hash": user_hash,
                        "universe_id": universe_id,
                        "content": f"User login crypto identity creation: {user.email}",
                        "metadata": {
                            "type": "login_crypto_identity_creation",
                            "email": user.email,
                            "timestamp": _utcnow().isoformat(),
                        }
                    }
                )
        except Exception as e:
            logger.error(f"Hash Sphere anchor creation error: {e}")
        
        # Register blockchain identity
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{settings.BLOCKCHAIN_SERVICE_URL}/identity/register",
                    json={
                        "user_id": str(user.id),
                        "crypto_hash": crypto_hash,
                        "user_hash": user_hash,
                        "universe_id": universe_id,
                        "email": user.email,
                    }
                )
        except Exception as e:
            logger.error(f"Blockchain identity registration error: {e}")
        
        await db.commit()

    # Resolve membership
    result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == user.id,
            OrgMembership.status == "active",
        )
    )
    memberships = result.scalars().all()
    if not memberships:
        raise HTTPException(status_code=403, detail="No active organizations")
    
    # Use specified org or first membership
    membership = None
    if payload.org_id:
        for m in memberships:
            if m.org_id == payload.org_id:
                membership = m
                break
        if not membership:
            raise HTTPException(status_code=403, detail="Org access denied")
    else:
        membership = memberships[0]
    
    # Create identity
    identity = Identity(
        user_id=user.id,
        org_id=membership.org_id,
        role=membership.role,
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    # Create tokens
    access_token = create_access_token(identity, user.token_version)
    
    # Generate refresh token
    refresh_plain, refresh_hash = generate_refresh_token()
    refresh = RefreshToken(
        user_id=identity.user_id,
        org_id=identity.org_id,
        token_hash=refresh_hash,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=_utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh)
    await db.commit()
    
    # Set cookies (including rg_session for frontend)
    _set_auth_cookies(
        response, 
        access_token, 
        refresh_plain,
        user_email=user.email,
        user_role=identity.role,
        org_id=str(identity.org_id)
    )

    # Plan comes from subscription, not from superuser flag
    plan = "developer"
    
    return LoginResponse(
        access_token=access_token,
        org_id=identity.org_id,
        role=identity.role,
        plan=plan,
        user={
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
        }
    )


@router.post("/auth/refresh", response_model=RefreshResponse)
@refresh_token_rate_limit()
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token from cookie or body.
    
    1. Validate refresh token
    2. Revoke old token
    3. Issue new tokens
    4. Set new cookies
    """
    # Get refresh token from cookie
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    # Find token record
    token_hash = hash_token(refresh_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
        )
    )
    record = result.scalar_one_or_none()
    
    if not record or record.expires_at < _utcnow():
        raise HTTPException(status_code=401, detail="Expired refresh token")

    # Verify user
    user_result = await db.execute(select(User).where(User.id == record.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")

    # Verify membership
    membership_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == record.user_id,
            OrgMembership.org_id == record.org_id,
            OrgMembership.status == "active",
        )
    )
    membership = membership_result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Org membership inactive")

    # Revoke old token
    record.revoked_at = _utcnow()
    await db.commit()

    # Create new Identity
    identity = Identity(
        user_id=record.user_id,
        org_id=record.org_id,
        role=membership.role,
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    # Issue new tokens
    access_token = create_access_token(identity, user.token_version)
    new_refresh = await _issue_refresh_token(db, identity, request)
    
    # Set cookies
    _set_auth_cookies(response, access_token, new_refresh)

    return RefreshResponse(access_token=access_token)


@router.post("/auth/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Logout user by revoking refresh token and clearing cookies.
    """
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    access_token = request.cookies.get(ACCESS_COOKIE)
    if not refresh_token and not access_token:
        response.status_code = 204
        return response

    if refresh_token:
        token_hash = hash_token(refresh_token)
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
            )
        )
        record = result.scalar_one_or_none()
        if record:
            record.revoked_at = _utcnow()
            await db.commit()
    
    _clear_auth_cookies(response)
    response.status_code = 204
    return response


@router.post("/auth/verify")
async def verify(payload: VerifyRequest, db: AsyncSession = Depends(get_db)):
    """Verify an access token."""
    try:
        # Use secure validation with token_version check
        decoded = await validate_access_token(payload.token, db)
        role = decoded.get("role", "user")
        user_id = decoded.get("user_id")
        
        # Check user flags from DB
        is_superuser = False
        unlimited_credits = False
        if user_id:
            result = await db.execute(
                select(User).where(User.id == UUID(user_id))
            )
            user = result.scalar_one_or_none()
            if user:
                is_superuser = user.is_superuser
                unlimited_credits = getattr(user, 'unlimited_credits', False) or False
                
                # AUTO-EXPIRE 1-WEEK TRIAL: if trial has ended, revoke unlimited
                trial_end = getattr(user, 'trial_expires_at', None)
                if trial_end and unlimited_credits and not is_superuser:
                    if _utcnow() > trial_end:
                        user.unlimited_credits = False
                        user.trial_expires_at = None
                        unlimited_credits = False
                        await db.commit()
                        logger.info(f"⏰ Trial expired for user {user_id}, reverted to free tier")
        
        def _normalize_role(raw_role: str, *, is_superuser: bool) -> str:
            if not raw_role:
                return "user"

            mapping = {
                "admin": "org_admin",
                "security": "compliance",
                "analyst": "user",
            }
            mapped = mapping.get(raw_role, raw_role)

            if mapped == "system":
                return "platform_dev" if is_superuser else "user"

            allowed = {
                "viewer",
                "user",
                "platform_owner",
                "owner",
                "org_admin",
                "platform_dev",
                "finance",
                "compliance",
                "ml_engineer",
            }
            return mapped if mapped in allowed else "user"

        normalized_role = _normalize_role(role, is_superuser=is_superuser)

        # Determine plan from billing_service (authoritative) with safe fallback.
        # Returned plan must match canonical tiers used across services: developer/plus/enterprise.
        # Only platform_dev role gets auto-enterprise, NOT is_superuser (superuser is for owner dashboard only)
        plan: Optional[str] = "enterprise" if normalized_role in ("platform_dev", "platform_owner") else None

        if plan is None and user_id:
            try:
                billing_base = getattr(settings, "BILLING_URL", "http://billing_service:8000").rstrip("/")
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(f"{billing_base}/economic-state/{user_id}/headers")
                if resp.status_code == 200:
                    data = resp.json() or {}
                    headers = data.get("headers", {}) if isinstance(data, dict) else {}
                    tier = (headers.get("X-Subscription-Tier") or "").strip().lower()
                    if tier in {"developer", "plus", "enterprise"}:
                        plan = tier
            except Exception:
                plan = None

        if plan is None:
            raw_plan = (decoded.get("plan") or "").strip().lower()
            if raw_plan in {"developer", "plus", "enterprise"}:
                plan = raw_plan
            elif raw_plan in {"free", "starter"}:
                plan = "developer"
            elif raw_plan in {"pro"}:
                plan = "plus"
            else:
                plan = "developer"
        
        # Role is determined by OrgMembership, NOT by is_superuser flag.
        # is_superuser only grants owner dashboard access (validated in owner_auth.py).
        # platform_owner role must be explicitly assigned in OrgMembership.
        effective_role = normalized_role
        
        # Trial info for frontend display
        trial_active = False
        trial_expires_iso = None
        if user:
            te = getattr(user, 'trial_expires_at', None)
            if te and unlimited_credits:
                trial_active = True
                trial_expires_iso = te.isoformat()

        return {
            "valid": True,
            "user_id": user_id,
            "org_id": decoded.get("org_id"),
            "role": effective_role,
            "plan": plan,
            "is_superuser": is_superuser,
            "unlimited_credits": unlimited_credits or is_superuser,
            "trial_active": trial_active,
            "trial_expires_at": trial_expires_iso,
            "crypto_hash": getattr(user, "crypto_hash", None) if user else None,
            "user_hash": getattr(user, "user_hash", None) if user else None,
            "universe_id": getattr(user, "universe_id", None) if user else None,
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.get("/auth/me", response_model=UserResponse)
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get current authenticated user information."""
    # Get token from cookie or header
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        decoded = decode_access_token(token)
        identity = Identity.from_claims(decoded)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not identity.user_id:
        raise HTTPException(status_code=401, detail="Invalid identity")

    # Get user
    result = await db.execute(select(User).where(User.id == identity.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get membership
    membership_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == identity.user_id,
            OrgMembership.org_id == identity.org_id,
            OrgMembership.status == "active",
        )
    )
    membership = membership_result.scalar_one_or_none()

    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        status=user.status,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        default_org_id=user.default_org_id,
        org_id=identity.org_id,
        role=membership.role if membership else None,
        crypto_hash=user.crypto_hash,
        user_hash=user.user_hash,
    )


@router.get("/auth/desktop-callback")
async def desktop_callback(request: Request):
    """Desktop app auth callback.
    Reads rg_access_token from HttpOnly cookie server-side.
    If logged in: redirects to Electron's localhost callback with token.
    If not logged in: shows page prompting user to log in first."""
    from fastapi.responses import HTMLResponse, RedirectResponse
    import urllib.parse

    port = request.query_params.get("port")
    if not port or not port.isdigit():
        return HTMLResponse("<h2>Invalid request</h2>", status_code=400)

    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        try:
            decoded = decode_access_token(token)
            identity = Identity.from_claims(decoded)
            if identity.user_id:
                # Valid session — redirect token to Electron's localhost server
                callback = f"http://localhost:{port}/auth-callback?token={urllib.parse.quote(token)}"
                return RedirectResponse(callback)
        except Exception:
            pass

    # Not logged in — redirect straight to the existing login page
    # After login, redirect back here so the cookie check succeeds
    return_url = urllib.parse.quote(f"/auth/desktop-callback?port={port}")
    return RedirectResponse(f"/login?redirect={return_url}")


@router.get("/auth/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the current organization."""
    identity = await _get_identity_from_request(request, db)

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.org_id == identity.org_id)
        .order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        ApiKeyResponse(
            id=key.id,
            name=key.name,
            prefix=key.prefix,
            scopes=key.scopes or [],
            auth_method=key.auth_method,
            created_at=key.created_at,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
        )
        for key in keys
    ]


@router.post("/auth/api-keys", response_model=ApiKeyResponse, status_code=201)
async def create_api_key_endpoint(
    request: Request,
    payload: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key for the current organization."""
    identity = await _get_identity_from_request(request, db)

    # Generate plaintext API key and hashed form
    api_key_plain, prefix, hashed = generate_api_key()

    expires_at: Optional[datetime] = None
    if payload.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days)

    record = ApiKey(
        name=payload.name,
        prefix=prefix,
        hashed_key=hashed,
        org_id=identity.org_id,
        scopes=list(payload.scopes or []),
        auth_method=payload.auth_method,
        expires_at=expires_at,
        created_by_user_id=identity.user_id,
        is_global=False,
    )

    db.add(record)
    await db.commit()
    await db.refresh(record)

    return ApiKeyResponse(
        id=record.id,
        name=record.name,
        prefix=record.prefix,
        scopes=record.scopes or [],
        auth_method=record.auth_method,
        created_at=record.created_at,
        expires_at=record.expires_at,
        last_used_at=record.last_used_at,
        token=api_key_plain,
    )


@router.post("/auth/api-keys/revoke", status_code=204)
async def revoke_api_key_endpoint(
    request: Request,
    payload: RevokeApiKeyRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) an API key for the current organization."""
    identity = await _get_identity_from_request(request, db)

    record = await db.get(ApiKey, payload.api_key_id)
    if not record or record.org_id != identity.org_id:
        raise HTTPException(status_code=404, detail="API key not found")

    await db.delete(record)
    await db.commit()

    return Response(status_code=204)


@router.post("/auth/api-keys/verify", response_model=ApiKeyVerifyResponse)
async def verify_org_api_key(
    payload: ApiKeyVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """Verify an org API key and return identity context.

    This is used by the gateway to support paid API access without JWT.
    """
    api_key = (payload.api_key or "").strip()
    if not api_key.startswith("RG-"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    if "." not in api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        key_body = api_key.split("RG-", 1)[1]
        prefix = key_body.split(".", 1)[0]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not prefix:
        raise HTTPException(status_code=401, detail="Invalid API key")

    hashed = hash_token(api_key)

    result = await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not hmac.compare_digest(str(record.hashed_key or ""), str(hashed or "")):
        raise HTTPException(status_code=401, detail="Invalid API key")

    if record.expires_at and record.expires_at < _utcnow():
        raise HTTPException(status_code=401, detail="API key expired")

    # Update last_used timestamp
    record.last_used_at = _utcnow()
    await db.commit()

    org_id = str(record.org_id)

    resolved_user_id: Optional[str] = str(record.created_by_user_id) if record.created_by_user_id else None
    resolved_role: Optional[str] = None

    if not resolved_user_id:
        membership_result = await db.execute(
            select(OrgMembership)
            .where(OrgMembership.org_id == record.org_id, OrgMembership.status == "active")
            .order_by(OrgMembership.created_at.asc())
        )
        memberships = membership_result.scalars().all()
        if memberships:
            # Prefer owner/admin if present.
            owner = next((m for m in memberships if (m.role or "").lower() == "owner"), None)
            admin = next((m for m in memberships if (m.role or "").lower() in {"admin", "org_admin"}), None)
            chosen = owner or admin or memberships[0]
            resolved_user_id = str(chosen.user_id)
            resolved_role = chosen.role
    else:
        membership_result = await db.execute(
            select(OrgMembership)
            .where(
                OrgMembership.org_id == record.org_id,
                OrgMembership.user_id == UUID(resolved_user_id),
                OrgMembership.status == "active",
            )
        )
        membership = membership_result.scalar_one_or_none()
        resolved_role = membership.role if membership else None

    # Resolve plan from billing_service economic state headers (authoritative)
    plan: Optional[str] = None
    if resolved_user_id:
        try:
            billing_base = getattr(settings, "BILLING_URL", "http://billing_service:8000").rstrip("/")
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{billing_base}/economic-state/{resolved_user_id}/headers")
            if resp.status_code == 200:
                data = resp.json() or {}
                headers = data.get("headers", {}) if isinstance(data, dict) else {}
                tier = (headers.get("X-Subscription-Tier") or "").strip().lower()
                if tier in {"developer", "plus", "enterprise"}:
                    plan = tier
        except Exception:
            plan = None

    if plan is None:
        plan = "developer"

    return ApiKeyVerifyResponse(
        valid=True,
        user_id=resolved_user_id,
        org_id=org_id,
        role=resolved_role or "user",
        plan=plan,
        scopes=list(record.scopes or []),
        auth_method=record.auth_method or "api_key",
    )


@router.get("/auth/health")
async def health():
    """Health check endpoint."""
    return {"service": "auth", "status": "ok"}


# ============================================
# Identity & Mnemonic Endpoints (Ported from old backend)
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


@router.get("/auth/identity", response_model=UserIdentityResponse)
async def get_user_identity(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get user's cryptographic identity information."""
    identity = await _get_identity_from_request(request, db)
    
    user = await db.get(User, identity.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserIdentityResponse(
        crypto_hash=getattr(user, "crypto_hash", None),
        user_hash=getattr(user, "user_hash", None),
        universe_id=getattr(user, "universe_id", None),
    )


@router.post("/auth/mnemonic", response_model=MnemonicResponse)
async def get_mnemonic(
    request: Request,
    payload: MnemonicRequest,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve user's mnemonic phrase with password verification.
    
    This endpoint requires password confirmation for security.
    The mnemonic is decrypted from the user's anchor_seed.
    """
    from .seed_manager import seed_manager
    
    identity = await _get_identity_from_request(request, db)
    
    user = await db.get(User, identity.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify password
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Check if user has anchor_seed
    anchor_seed = getattr(user, "anchor_seed", None)
    if not anchor_seed:
        raise HTTPException(status_code=404, detail="No mnemonic found for this user")
    
    # Decrypt the anchor_seed using SeedManager
    try:
        decrypted_mnemonic = seed_manager.decrypt_seed(anchor_seed)
    except Exception as e:
        # If decryption fails, the seed might not be encrypted
        decrypted_mnemonic = anchor_seed
    
    universe_id = getattr(user, "universe_id", "") or ""
    
    return MnemonicResponse(
        mnemonic=decrypted_mnemonic,
        universe_id=universe_id,
    )


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


# Compatibility endpoint for chat_service internal calls
@router.get("/api-keys/user/{user_id}")
async def get_api_keys_by_user_id(
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get API keys for a specific user (internal service call).
    
    This endpoint is called by chat_service to retrieve user's API keys
    for BYOK (Bring Your Own Key) functionality.
    """
    try:
        result = await db.execute(
            select(UserApiKey).where(UserApiKey.user_id == user_id)
        )
        user_keys = result.scalars().all()
        
        keys = []
        for key in user_keys:
            keys.append({
                "id": str(key.id),
                "provider": key.provider,
                "name": key.name,
                "decrypted_key": decrypt_api_key(key.encrypted_key),
                "is_valid": key.is_valid,
            })
        
        return {"keys": keys}
    except Exception as e:
        return {"keys": []}


@router.get("/auth/user/api-keys")
async def get_user_api_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get all API keys for the current user (masked)."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.user_id == identity.user_id)
    )
    user_keys = result.scalars().all()
    
    keys = []
    for key in user_keys:
        keys.append({
            "id": str(key.id),
            "provider": key.provider,
            "name": key.name or f"{key.provider} Key",
            "key_prefix": key.key_prefix or "***",
            "is_valid": key.is_valid,
            "created_at": key.created_at.isoformat() if key.created_at else None,
        })
    
    return {"keys": keys}


@router.post("/auth/user/api-keys")
async def add_user_api_key(
    request: Request,
    payload: UserApiKeyCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add a new API key for the user."""
    identity = await _get_identity_from_request(request, db)
    
    # Validate the key format
    key_prefix = payload.api_key[:8] if len(payload.api_key) > 8 else payload.api_key[:4] + "..."
    
    # Check if key for this provider already exists
    existing = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == payload.provider.lower()
        )
    )
    existing_key = existing.scalar_one_or_none()
    
    if existing_key:
        # Update existing key
        existing_key.encrypted_key = encrypt_api_key(payload.api_key)
        existing_key.key_prefix = key_prefix
        existing_key.is_valid = True
        existing_key.name = payload.name or existing_key.name
        await db.commit()
        await db.refresh(existing_key)
        
        return UserApiKeyResponse(
            id=str(existing_key.id),
            provider=existing_key.provider,
            name=existing_key.name or f"{existing_key.provider} Key",
            key_prefix=key_prefix,
            is_valid=True,
            created_at=existing_key.created_at.isoformat() if existing_key.created_at else _utcnow().isoformat(),
        )
    
    # Create new key
    new_key = UserApiKey(
        user_id=identity.user_id,
        provider=payload.provider.lower(),
        name=payload.name or f"{payload.provider} Key",
        encrypted_key=encrypt_api_key(payload.api_key),
        key_prefix=key_prefix,
        is_valid=True,
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return UserApiKeyResponse(
        id=str(new_key.id),
        provider=new_key.provider,
        name=new_key.name,
        key_prefix=key_prefix,
        is_valid=True,
        created_at=new_key.created_at.isoformat() if new_key.created_at else _utcnow().isoformat(),
    )


@router.post("/auth/user/api-keys/validate")
async def validate_user_api_key(
    payload: ValidateApiKeyRequest,
):
    """Validate an API key before adding."""
    # Basic format validation
    provider = payload.provider.lower()
    api_key = payload.api_key.strip()
    
    valid = False
    error = None
    models = []
    
    if provider == "openai":
        valid = api_key.startswith("sk-") and len(api_key) > 20
        if valid:
            models = ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]
        else:
            error = "Invalid OpenAI API key format. Should start with 'sk-'"
    elif provider == "anthropic":
        valid = api_key.startswith("sk-ant-") and len(api_key) > 20
        if valid:
            models = ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"]
        else:
            error = "Invalid Anthropic API key format. Should start with 'sk-ant-'"
    elif provider == "google":
        valid = api_key.startswith("AIza") and len(api_key) > 20
        if valid:
            models = ["gemini-pro", "gemini-pro-vision"]
        else:
            error = "Invalid Google API key format. Should start with 'AIza'"
    elif provider == "mistral":
        valid = len(api_key) > 20
        if valid:
            models = ["mistral-large", "mistral-medium", "mistral-small"]
        else:
            error = "Invalid Mistral API key"
    elif provider == "groq":
        valid = api_key.startswith("gsk_") and len(api_key) > 20
        if valid:
            models = ["llama-3.1-70b", "mixtral-8x7b"]
        else:
            error = "Invalid Groq API key format. Should start with 'gsk_'"
    else:
        valid = len(api_key) > 10
        if not valid:
            error = "Invalid API key"
    
    return ValidateApiKeyResponse(
        valid=valid,
        provider=provider,
        error=error,
        models=models if valid else None,
    )


@router.delete("/auth/user/api-keys/{key_id}")
async def delete_user_api_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a user API key."""
    identity = await _get_identity_from_request(request, db)
    
    # Find the key
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.id == key_uuid,
            UserApiKey.user_id == identity.user_id
        )
    )
    key = result.scalar_one_or_none()
    
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Delete the key
    await db.delete(key)
    await db.commit()
    
    return {"success": True, "deleted": key_id, "provider": key.provider}


@router.delete("/auth/user/api-keys/by-provider/{provider}")
async def delete_user_api_key_by_provider(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a user API key by provider name (e.g. 'openai', 'anthropic')."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == provider.lower()
        )
    )
    key = result.scalar_one_or_none()
    
    if not key:
        raise HTTPException(status_code=404, detail=f"No key found for provider: {provider}")
    
    await db.delete(key)
    await db.commit()
    
    return {"success": True, "deleted": True, "provider": provider}


@router.get("/auth/user/trial-status")
async def get_trial_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get trial status for current user."""
    identity = await _get_identity_from_request(request, db)
    
    # Get user
    user_result = await db.execute(select(User).where(User.id == identity.user_id))
    user = user_result.scalar_one_or_none()
    
    # Default to free trial
    is_trial = True
    days_remaining = 14
    is_expired = False
    current_plan = "free-trial"
    
    return TrialStatusResponse(
        is_trial_user=is_trial,
        trial_start_date=user.created_at.isoformat() if user and user.created_at else None,
        trial_end_date=None,
        days_remaining=days_remaining,
        is_expired=is_expired,
        has_api_key=False,  # Would check user_api_keys table
        can_use_services=True,
        requires_upgrade=False,
        current_plan=current_plan,
    )


@router.get("/auth/user/service-access")
async def check_service_access(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Check if user can access services."""
    identity = await _get_identity_from_request(request, db)
    
    return ServiceAccessResponse(
        can_access=True,
        reason=None,
        action="none",
    )


@router.get("/auth/user/available-providers")
async def get_available_providers(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get available AI providers based on user's API keys."""
    identity = await _get_identity_from_request(request, db)
    
    # Default providers available to all users
    default_providers = ["openai", "anthropic", "google", "mistral", "groq"]
    
    # Get user's configured API keys
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.user_id == identity.user_id)
    )
    user_keys = result.scalars().all()
    
    user_key_providers = [key.provider for key in user_keys if key.is_valid]
    has_user_keys = len(user_key_providers) > 0
    
    return AvailableProvidersResponse(
        providers=default_providers,
        has_user_keys=has_user_keys,
        user_key_providers=user_key_providers,
    )


@router.get("/auth/internal/user-api-keys/{user_id}")
async def get_user_api_keys_internal(
    user_id: str,
    request: Request,
    provider: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Internal endpoint for services to fetch user's decrypted API keys.
    This should only be called by internal services (IDE, chat, etc).
    
    Protected by internal service header check.
    Returns the actual API key for making LLM requests on behalf of the user.
    Supports both UUID and email as user identifier.
    """
    # Verify internal service call - check for internal header or localhost
    internal_key = request.headers.get("x-internal-service-key")
    is_internal = (
        internal_key == settings.INTERNAL_SERVICE_KEY or
        request.headers.get("x-forwarded-for", "").startswith("10.") or
        request.headers.get("x-forwarded-for", "").startswith("172.") or
        (request.client and request.client.host in ["127.0.0.1", "localhost"])
    )
    
    if not is_internal and settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=403, detail="Internal endpoint - access denied")
    
    user_uuid = None
    
    # Try to parse as UUID first
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        # Not a UUID, might be an email - look up user by email
        if "@" in user_id:
            user_result = await db.execute(
                select(User).where(User.email == user_id)
            )
            user = user_result.scalar_one_or_none()
            if user:
                user_uuid = user.id
            else:
                raise HTTPException(status_code=404, detail="User not found")
        else:
            raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Build query
    query = select(UserApiKey).where(
        UserApiKey.user_id == user_uuid,
        UserApiKey.is_valid == True
    )
    
    if provider:
        query = query.where(UserApiKey.provider == provider.lower())
    
    result = await db.execute(query)
    user_keys = result.scalars().all()
    
    # Return decrypted keys for internal service use
    keys = []
    for key in user_keys:
        try:
            decrypted_key = decrypt_api_key(key.encrypted_key)
        except Exception:
            decrypted_key = key.encrypted_key  # Fallback for legacy unencrypted keys
        
        keys.append({
            "provider": key.provider,
            "api_key": decrypted_key,
            "name": key.name or f"{key.provider} Key",
        })
    
    return {"keys": keys, "user_id": user_id}


# ============================================
# Organization Management
# ============================================

@router.get("/auth/orgs")
async def list_orgs(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List organizations for current user."""
    identity = await _get_identity_from_request(request, db)
    
    # Get user's memberships
    stmt = select(OrgMembership).where(
        OrgMembership.user_id == identity.user_id,
        OrgMembership.status == "active",
    )
    result = await db.execute(stmt)
    memberships = result.scalars().all()
    
    orgs = []
    for membership in memberships:
        org_result = await db.execute(select(Organization).where(Organization.id == membership.org_id))
        org = org_result.scalar_one_or_none()
        if org:
            orgs.append({
                "id": str(org.id),
                "name": org.name,
                "slug": org.slug,
                "role": membership.role,
            })
    
    return {"organizations": orgs}

@router.post("/auth/orgs/invite")
async def invite_to_org(
    request: Request,
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    """Invite a user to organization."""
    identity = await _get_identity_from_request(request, db)
    
    # CRITICAL: Check if user's tier allows team members
    from ..billing_service.app.models import UserEconomicState, SubscriptionTier
    result = await db.execute(
        select(UserEconomicState).where(UserEconomicState.user_id == identity.user_id)
    )
    economic_state = result.scalar_one_or_none()
    
    if economic_state and economic_state.subscription_tier in [SubscriptionTier.DEVELOPER, SubscriptionTier.PLUS]:
        raise HTTPException(
            status_code=403,
            detail=f"Team invites not available on {economic_state.subscription_tier.value} tier. Upgrade to Enterprise for team features."
        )
    
    email = payload.get("email")
    role = payload.get("role", "member")
    
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    # In production, send invitation email
    return {"success": True, "message": f"Invitation sent to {email}"}


# ============================================
# Settings Management - Agent CRUD
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


@router.get("/auth/settings/agents")
async def list_agents(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all agents for user."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.user_id == identity.user_id).order_by(Agent.created_at.desc())
    )
    agents = result.scalars().all()
    
    return [
        {
            "id": str(agent.id),
            "name": agent.name,
            "description": agent.description,
            "agent_hash": agent.agent_hash,
            "system_prompt": agent.system_prompt,
            "personality_config": agent.personality_config or {},
            "enabled_patches": agent.enabled_patches or [],
            "patch_config": agent.patch_config or {},
            "memory_config": agent.memory_config or {},
            "anchor_config": agent.anchor_config or {},
            "isolate_anchors": agent.isolate_anchors,
            "status": agent.status,
            "is_template": agent.is_template,
            "template_id": str(agent.template_id) if agent.template_id else None,
            "is_shared": agent.is_shared,
            "is_public": agent.is_public,
            "is_imported": agent.is_imported,
            "created_at": agent.created_at.isoformat() if agent.created_at else None,
        }
        for agent in agents
    ]


@router.post("/auth/settings/agents")
async def create_agent(
    request: Request,
    body: AgentCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new agent."""
    identity = await _get_identity_from_request(request, db)
    
    # Generate agent hash
    import hashlib
    hash_input = f"{identity.user_id}:{body.name}:{datetime.now().isoformat()}"
    agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    agent = Agent(
        user_id=identity.user_id,
        org_id=identity.org_id,
        name=body.name,
        description=body.description,
        system_prompt=body.system_prompt,
        personality_config=body.personality_config or {},
        isolate_anchors=body.isolate_anchors,
        agent_hash=agent_hash,
        status="active",
    )
    
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    
    return {
        "id": str(agent.id),
        "name": agent.name,
        "description": agent.description,
        "agent_hash": agent.agent_hash,
        "system_prompt": agent.system_prompt,
        "personality_config": agent.personality_config or {},
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
        "memory_config": agent.memory_config or {},
        "anchor_config": agent.anchor_config or {},
        "isolate_anchors": agent.isolate_anchors,
        "status": agent.status,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


@router.get("/auth/settings/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "id": str(agent.id),
        "name": agent.name,
        "description": agent.description,
        "agent_hash": agent.agent_hash,
        "system_prompt": agent.system_prompt,
        "personality_config": agent.personality_config or {},
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
        "memory_config": agent.memory_config or {},
        "anchor_config": agent.anchor_config or {},
        "isolate_anchors": agent.isolate_anchors,
        "status": agent.status,
        "is_template": agent.is_template,
        "template_id": str(agent.template_id) if agent.template_id else None,
        "is_shared": agent.is_shared,
        "is_public": agent.is_public,
        "is_imported": agent.is_imported,
        "share_secret": agent.share_secret if not agent.is_imported else None,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


@router.put("/auth/settings/agents/{agent_id}")
async def update_agent(
    agent_id: str,
    request: Request,
    body: AgentUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.is_imported:
        raise HTTPException(status_code=403, detail="Cannot edit imported agent")
    
    # Update fields
    if body.name is not None:
        agent.name = body.name
    if body.description is not None:
        agent.description = body.description
    if body.system_prompt is not None:
        agent.system_prompt = body.system_prompt
    if body.personality_config is not None:
        agent.personality_config = body.personality_config
    if body.enabled_patches is not None:
        agent.enabled_patches = body.enabled_patches
    if body.patch_config is not None:
        agent.patch_config = body.patch_config
    if body.memory_config is not None:
        agent.memory_config = body.memory_config
    if body.anchor_config is not None:
        agent.anchor_config = body.anchor_config
    if body.isolate_anchors is not None:
        agent.isolate_anchors = body.isolate_anchors
    if body.status is not None:
        agent.status = body.status
    
    await db.commit()
    await db.refresh(agent)
    
    return {
        "id": str(agent.id),
        "name": agent.name,
        "description": agent.description,
        "agent_hash": agent.agent_hash,
        "system_prompt": agent.system_prompt,
        "personality_config": agent.personality_config or {},
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
        "memory_config": agent.memory_config or {},
        "anchor_config": agent.anchor_config or {},
        "isolate_anchors": agent.isolate_anchors,
        "status": agent.status,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


@router.delete("/auth/settings/agents/{agent_id}")
async def delete_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    await db.delete(agent)
    await db.commit()
    
    return {"status": "deleted", "id": agent_id}


@router.get("/auth/settings/providers")
async def get_provider_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get provider settings for user."""
    identity = await _get_identity_from_request(request, db)
    return {
        "default_provider": "openai",
        "providers": {
            "openai": {"enabled": True},
            "anthropic": {"enabled": True},
            "google": {"enabled": True},
        }
    }


# ============================================
# MFA Endpoints - TOTP Implementation
# ============================================

from .mfa import MFAManager, encrypt_mfa_secret, decrypt_mfa_secret, verify_totp_code, verify_backup_code

_mfa_manager = MFAManager()


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


@router.get("/auth/mfa/status")
async def get_mfa_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get MFA status for current user."""
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "enabled": user.mfa_enabled,
        "method": "totp" if user.mfa_enabled else None,
        "verified": user.mfa_verified_at is not None,
        "verified_at": user.mfa_verified_at.isoformat() if user.mfa_verified_at else None,
        "available": True,
        "backup_codes_remaining": len(user.mfa_backup_codes) if user.mfa_backup_codes else 0,
    }


@router.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Setup MFA for current user.
    
    Returns TOTP secret, QR code, and backup codes.
    User must verify with /auth/mfa/verify to enable MFA.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first to reconfigure."
        )
    
    # Generate MFA credentials
    secret, uri, qr_url, backup_codes, backup_hashes = _mfa_manager.setup_mfa(user.email)
    
    # Store encrypted secret and hashed backup codes (but don't enable yet)
    user.mfa_secret = encrypt_mfa_secret(secret)
    user.mfa_backup_codes = backup_hashes
    await db.commit()
    
    return MFASetupResponse(
        secret=secret,
        qr_code_url=qr_url,
        provisioning_uri=uri,
        backup_codes=backup_codes,
    )


@router.post("/auth/mfa/verify")
async def verify_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify MFA code and enable MFA.
    
    During initial setup, verifies the code matches the secret.
    After setup, this endpoint can be used to verify codes for testing.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_secret:
        raise HTTPException(
            status_code=400,
            detail="MFA not set up. Call /auth/mfa/setup first."
        )
    
    # Decrypt the stored secret
    secret = decrypt_mfa_secret(user.mfa_secret)
    
    # Verify the TOTP code
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Enable MFA if not already enabled
    if not user.mfa_enabled:
        user.mfa_enabled = True
        user.mfa_verified_at = _utcnow()
        user.token_version += 1  # Invalidate existing sessions
        await db.commit()
        
        return {
            "verified": True,
            "mfa_enabled": True,
            "message": "MFA has been enabled successfully.",
        }
    
    return {
        "verified": True,
        "mfa_enabled": True,
        "message": "MFA code verified.",
    }


@router.post("/auth/mfa/disable")
async def disable_mfa(
    payload: MFADisableRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Disable MFA for current user.
    
    Requires password confirmation and optionally a valid MFA code.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    # Verify password
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Optionally verify MFA code if provided
    if payload.code and user.mfa_secret:
        secret = decrypt_mfa_secret(user.mfa_secret)
        if not verify_totp_code(secret, payload.code):
            # Try backup code
            valid, idx = verify_backup_code(payload.code, user.mfa_backup_codes or [])
            if not valid:
                raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    user.mfa_verified_at = None
    user.token_version += 1  # Invalidate existing sessions
    await db.commit()
    
    return {
        "mfa_enabled": False,
        "message": "MFA has been disabled successfully.",
    }


@router.post("/auth/mfa/backup-codes/regenerate")
async def regenerate_backup_codes(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Regenerate backup codes for MFA.
    
    Invalidates all existing backup codes and generates new ones.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    from .mfa import generate_backup_codes
    backup_codes, backup_hashes = generate_backup_codes()
    
    user.mfa_backup_codes = backup_hashes
    await db.commit()
    
    return {
        "backup_codes": backup_codes,
        "message": "New backup codes generated. Store them securely.",
    }


@router.post("/auth/mfa/verify-backup")
async def verify_backup_code_endpoint(
    payload: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify and consume a backup code.
    
    Used when user doesn't have access to their authenticator app.
    Each backup code can only be used once.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    if not user.mfa_backup_codes:
        raise HTTPException(status_code=400, detail="No backup codes available")
    
    # Verify backup code
    valid, idx = verify_backup_code(payload.code, user.mfa_backup_codes)
    
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid backup code")
    
    # Remove used backup code
    user.mfa_backup_codes = [
        code for i, code in enumerate(user.mfa_backup_codes) if i != idx
    ]
    await db.commit()
    
    return {
        "verified": True,
        "backup_codes_remaining": len(user.mfa_backup_codes),
        "message": "Backup code verified and consumed.",
    }


# ============================================
# SSO Endpoints - OAuth2 Implementation
# ============================================

from .oauth import OAuthManager, OAuthError, get_available_providers, is_provider_configured

_oauth_manager = OAuthManager()


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


@router.get("/auth/sso/providers")
async def get_sso_providers():
    """Get list of available SSO providers."""
    return {
        "providers": _oauth_manager.get_providers(),
        "oauth_enabled": len(get_available_providers()) > 0,
        "saml_enabled": False,  # SAML not yet implemented
    }


@router.get("/oauth/google/login")
async def google_oauth_login(request: Request):
    """Google OAuth login - redirects to Google authorization."""
    if not is_provider_configured("google"):
        raise HTTPException(status_code=501, detail="Google OAuth is not configured")
    
    try:
        # Use /auth/oauth/callback to match Google OAuth app settings
        callback_path = "/auth/oauth/callback"
        auth_url, state = _oauth_manager.initiate("google", callback_path)
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=auth_url)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/oauth/github/login")
async def github_oauth_login(request: Request):
    """GitHub OAuth login - redirects to GitHub authorization."""
    if not is_provider_configured("github"):
        raise HTTPException(status_code=501, detail="GitHub OAuth is not configured")
    
    try:
        # Use /auth/oauth/callback to match GitHub OAuth app settings
        callback_path = "/auth/oauth/callback"
        auth_url, state = _oauth_manager.initiate("github", callback_path)
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=auth_url)
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/auth/sso/oauth/initiate")
async def initiate_oauth(
    payload: SSOInitiateRequest,
    request: Request,
):
    """
    Initiate OAuth flow with provider.
    
    Returns authorization URL to redirect user to.
    """
    provider = payload.provider.lower()
    
    if not is_provider_configured(provider):
        available = get_available_providers()
        if not available:
            raise HTTPException(
                status_code=501,
                detail="No OAuth providers are configured. Set GOOGLE_CLIENT_ID/SECRET, GITHUB_CLIENT_ID/SECRET, or MICROSOFT_CLIENT_ID/SECRET environment variables."
            )
        raise HTTPException(
            status_code=400,
            detail=f"OAuth provider '{provider}' is not configured. Available providers: {', '.join(available)}"
        )
    
    try:
        # Use actual backend callback path with provider (matches registered OAuth callback)
        callback_path = "/auth/oauth/callback"
        auth_url, state = _oauth_manager.initiate(
            provider,
            callback_path,
            extra_data={"frontend_redirect": payload.redirect_uri},
        )
        
        # Debug: Log the exact redirect_uri being sent
        import urllib.parse
        parsed = urllib.parse.urlparse(auth_url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_uri = params.get('redirect_uri', ['NOT_FOUND'])[0]
        logger.info(f"OAuth initiate for {provider}: redirect_uri={redirect_uri}")
        
        return {
            "authorization_url": auth_url,
            "state": state,
            "provider": provider,
        }
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/auth/sso/oauth/callback/{provider}")
async def oauth_callback_get(
    provider: str,
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    """
    Handle OAuth callback (GET request from provider redirect).
    
    This endpoint receives the callback from the OAuth provider,
    exchanges the code for tokens, and creates/logs in the user.
    """
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"OAuth error: {error}. {error_description or ''}"
        )
    
    return await _handle_oauth_callback(provider, code, state, request, response, db)


@router.get("/auth/oauth/callback")
async def oauth_callback_compatibility(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    """
    Compatibility OAuth callback endpoint at /auth/oauth/callback.
    This matches the registered OAuth app callback URLs for Google and GitHub.
    Provider is extracted from the state parameter.
    """
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"OAuth error: {error}. {error_description or ''}"
        )
    
    # Extract provider from state (stored in Redis)
    from .oauth_redis import get_oauth_state
    state_data = get_oauth_state(state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    
    provider = state_data.get("provider", "google")  # Default to google
    return await _handle_oauth_callback(provider, code, state, request, response, db)


@router.get("/auth/sso/oauth/callback")
async def oauth_callback_get_no_provider(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    error: Optional[str] = None,
    error_description: Optional[str] = None,
):
    """
    Handle OAuth callback without provider in path (GET request from provider redirect).
    Provider is extracted from the state parameter.
    """
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"OAuth error: {error}. {error_description or ''}"
        )
    
    # Extract provider from state (stored in Redis)
    from .oauth_redis import get_oauth_state
    state_data = get_oauth_state(state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    
    provider = state_data.get("provider", "google")  # Default to google
    return await _handle_oauth_callback(provider, code, state, request, response, db)


@router.post("/auth/sso/oauth/callback")
async def oauth_callback_post(
    payload: SSOCallbackRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle OAuth callback (POST request from frontend).
    
    Frontend receives the callback, extracts code/state, and posts here.
    """
    return await _handle_oauth_callback(
        payload.provider, payload.code, payload.state, request, response, db
    )


async def _handle_oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession,
):
    """
    Common OAuth callback handler.
    
    1. Validates state (CSRF protection)
    2. Exchanges code for tokens
    3. Gets user info from provider
    4. Creates or finds existing user
    5. Issues JWT tokens
    """
    provider = provider.lower()
    callback_path = f"/auth/sso/oauth/callback/{provider}"
    
    try:
        # Get user info from OAuth provider
        user_info = await _oauth_manager.handle_callback(
            provider, code, state, callback_path
        )
    except OAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    email = user_info.get("email")
    if not email:
        raise HTTPException(
            status_code=400,
            detail="OAuth provider did not return an email address"
        )
    
    # Find or create user
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    if user:
        # Existing user - update last login
        user.last_login_at = _utcnow()
        
        # Update name if not set
        if not user.full_name and user_info.get("name"):
            user.full_name = user_info["name"]
        
        # CRITICAL: Check if cryptographic identity exists, create if missing
        if not user.crypto_hash or not user.user_hash or not user.universe_id:
            logger.info(f"Generating missing cryptographic identity for existing user: {user.email}")
            crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, email)
            user.crypto_hash = crypto_hash
            user.user_hash = user_hash
            user.universe_id = universe_id
            
            # Create Hash Sphere anchor
            try:
                import httpx
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{settings.HASH_SPHERE_URL}/anchors/create",
                        json={
                            "user_id": str(user.id),
                            "user_hash": user_hash,
                            "universe_id": universe_id,
                            "content": f"User OAuth login: {email}",
                            "metadata": {
                                "type": "oauth_crypto_identity_creation",
                                "email": email,
                                "timestamp": _utcnow().isoformat(),
                            }
                        }
                    )
            except Exception as e:
                logger.error(f"Hash Sphere anchor creation error: {e}")
            
            # Register blockchain identity
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{settings.BLOCKCHAIN_SERVICE_URL}/identity/register",
                        json={
                            "user_id": str(user.id),
                            "crypto_hash": crypto_hash,
                            "user_hash": user_hash,
                            "universe_id": universe_id,
                            "email": email,
                        }
                    )
            except Exception as e:
                logger.error(f"Blockchain identity registration error: {e}")
        
        await db.commit()
    else:
        # New user - create account
        org_name = f"{email.split('@')[0]}'s Organization"
        org = Organization(
            name=org_name,
            slug=_generate_slug(org_name),
            is_active=True,
        )
        db.add(org)
        await db.flush()
        
        # Create user with 1-WEEK UNLIMITED TRIAL
        oauth_trial_end = _utcnow() + timedelta(days=7)
        user = User(
            email=email,
            username=user_info.get("username") or email.split('@')[0],
            full_name=user_info.get("name") or email.split('@')[0],
            password_hash=None,  # OAuth users don't have password
            is_active=True,
            is_superuser=False,
            unlimited_credits=True,
            trial_expires_at=oauth_trial_end,
            default_org_id=org.id,
            status="active",
        )
        logger.info(f"🎁 OAuth new user trial: unlimited access until {oauth_trial_end.isoformat()}")
        db.add(user)
        await db.flush()
        
        # Generate cryptographic identity
        crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, email)
        user.crypto_hash = crypto_hash
        user.user_hash = user_hash
        user.universe_id = universe_id
        
        # Create Hash Sphere anchor
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{settings.HASH_SPHERE_URL}/anchors/create",
                    json={
                        "user_id": str(user.id),
                        "user_hash": user_hash,
                        "universe_id": universe_id,
                        "content": f"OAuth new user registration: {email}",
                        "metadata": {
                            "type": "oauth_new_user_registration",
                            "email": email,
                            "provider": provider,
                            "timestamp": _utcnow().isoformat(),
                        }
                    }
                )
        except Exception as e:
            logger.error(f"Hash Sphere anchor creation error: {e}")
        
        # Register blockchain identity
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{settings.BLOCKCHAIN_SERVICE_URL}/identity/register",
                    json={
                        "user_id": str(user.id),
                        "crypto_hash": crypto_hash,
                        "user_hash": user_hash,
                        "universe_id": universe_id,
                        "email": email,
                    }
                )
        except Exception as e:
            logger.error(f"Blockchain identity registration error: {e}")
        
        # Create membership
        membership = OrgMembership(
            user_id=user.id,
            org_id=org.id,
            role="owner",
            status="active",
        )
        db.add(membership)
        await db.commit()
    
    # Get membership for token
    membership_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == user.id,
            OrgMembership.status == "active",
        )
    )
    membership = membership_result.scalar_one_or_none()
    
    if not membership:
        raise HTTPException(status_code=500, detail="User has no active membership")
    
    # Log OAuth login
    ip_address, user_agent = get_client_info(request)
    await log_audit_event(
        db, AuditEventType.SSO_LOGIN,
        user_id=user.id,
        org_id=membership.org_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"provider": provider, "is_new_user": user.created_at == user.updated_at},
        success=True,
    )
    await db.commit()
    
    # Create Identity
    identity = Identity(
        user_id=user.id,
        org_id=membership.org_id,
        role=membership.role,
        scopes=[],
        api_key_id=None,
        auth_method="oauth",
    )
    
    # Create tokens
    access_token = create_access_token(identity, user.token_version)
    refresh_plain = await _issue_refresh_token(db, identity, request)
    
    # Return HTML with JavaScript to handle OAuth callback
    # Google redirects browser to this URL, so we need HTML not JSON
    from fastapi.responses import HTMLResponse
    import json
    
    frontend_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "https://dev-swat.com"
    dashboard_url = f"{frontend_url}/dashboard"
    
    # Prepare auth data for frontend
    auth_data = {
        "access_token": access_token,
        "org_id": str(membership.org_id),
        "role": membership.role,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "username": user.username or user.email.split("@")[0],
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
        }
    }
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting...</title>
        <meta charset="utf-8">
    </head>
    <body>
        <script>
            try {{
                // Store auth data for frontend
                const authData = {json.dumps(auth_data)};
                localStorage.setItem('auth_data', JSON.stringify(authData));
                localStorage.setItem('user', JSON.stringify(authData.user));
                localStorage.setItem('authenticated', 'true');
                
                // Immediate redirect
                window.location.replace('{dashboard_url}');
            }} catch (e) {{
                console.error('OAuth callback error:', e);
                // Fallback: just redirect
                window.location.replace('{dashboard_url}');
            }}
        </script>
    </body>
    </html>
    """
    
    html_response = HTMLResponse(content=html_content, status_code=200)
    
    # Set cookies on HTML response
    _set_auth_cookies(
        html_response, 
        access_token, 
        refresh_plain,
        user_email=user.email,
        user_role=membership.role,
        org_id=str(membership.org_id)
    )
    
    return html_response


class SAMLInitiateRequest(BaseModel):
    org_id: str
    redirect_uri: Optional[str] = None


@router.post("/auth/sso/saml/initiate")
async def initiate_saml(
    payload: SAMLInitiateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Initiate SAML SSO flow for enterprise customers.
    
    Requires SAML to be configured for the organization.
    """
    from .saml import is_saml_enabled, get_saml_config, initiate_saml_login
    
    if not is_saml_enabled():
        raise HTTPException(
            status_code=501,
            detail="SAML SSO is not enabled. Contact support to enable enterprise SSO."
        )
    
    try:
        org_id = UUID(payload.org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID")
    
    # Check if org exists and has SAML configured
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    config = get_saml_config(org_id)
    if not config:
        raise HTTPException(
            status_code=400,
            detail="SAML is not configured for this organization. Contact your administrator."
        )
    
    try:
        redirect_url, request_id = await initiate_saml_login(
            org_id=org_id,
            relay_state=payload.redirect_uri,
        )
        
        return {
            "redirect_url": redirect_url,
            "request_id": request_id,
        }
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML initiation failed: {str(e)}")


@router.post("/auth/sso/saml/callback")
async def saml_callback(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Handle SAML callback from IdP.
    
    Processes the SAML response and creates/updates user session.
    """
    from .saml import is_saml_enabled, process_saml_response
    
    if not is_saml_enabled():
        raise HTTPException(
            status_code=501,
            detail="SAML SSO is not enabled."
        )
    
    # Get SAML response from form data
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")
    relay_state = form_data.get("RelayState")
    
    if not saml_response:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")
    
    # Extract org_id from relay_state or session
    # In production, this would be stored in a secure session
    org_id_str = form_data.get("org_id") or relay_state
    if not org_id_str:
        raise HTTPException(status_code=400, detail="Missing organization context")
    
    try:
        org_id = UUID(org_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID")
    
    try:
        user, is_new = await process_saml_response(
            saml_response=saml_response,
            org_id=org_id,
            db=db,
        )
        
        # Create session for user
        membership = await _resolve_membership(db, user.id, org_id)
        
        identity = Identity(
            user_id=user.id,
            org_id=membership.org_id,
            role=membership.role,
            scopes=[],
            api_key_id=None,
            auth_method="saml",
        )
        
        access_token = create_access_token(identity, user.token_version)
        refresh_plain = await _issue_refresh_token(db, identity, request)
        _set_auth_cookies(response, access_token, refresh_plain)
        
        # Log SAML login
        ip_address, user_agent = get_client_info(request)
        await log_audit_event(
            db, AuditEventType.SSO_LOGIN,
            user_id=user.id,
            org_id=org_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"provider": "saml", "is_new_user": is_new},
            success=True,
        )
        await db.commit()
        
        # Redirect to frontend
        frontend_redirect = relay_state or settings.FRONTEND_URL
        return {
            "success": True,
            "access_token": access_token,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
            },
            "is_new_user": is_new,
            "redirect_uri": frontend_redirect,
        }
        
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML authentication failed: {str(e)}")


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


@router.post("/auth/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Change password for current user. Requires MFA if enabled."""
    from .mfa_enforcement import verify_mfa_for_operation
    
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check MFA requirement
    if user.mfa_enabled:
        success, message = await verify_mfa_for_operation(
            user, "password_change", payload.mfa_code, db
        )
        if not success:
            raise HTTPException(
                status_code=403 if "required" in message.lower() else 401,
                detail=message
            )
    
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    # Validate new password strength
    try:
        validate_password_strength(payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    user.password_hash = hash_password(payload.new_password)
    user.token_version += 1  # Invalidate all existing sessions
    
    # Log password change
    ip_address, user_agent = get_client_info(request)
    await log_audit_event(
        db, AuditEventType.PASSWORD_CHANGE,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True,
    )
    await db.commit()
    
    return {"success": True, "message": "Password changed successfully"}


@router.post("/auth/forgot-password")
@password_reset_rate_limit()
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Request password reset email.
    
    Generates a secure token, stores it in DB, and would send email in production.
    Always returns success to prevent email enumeration attacks.
    """
    # Find user by email (don't reveal if user exists)
    result = await db.execute(
        select(User).where(User.email == payload.email, User.status == "active")
    )
    user = result.scalar_one_or_none()
    
    if user:
        # Invalidate any existing reset tokens for this user
        existing_tokens = await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at == None,
            )
        )
        for token in existing_tokens.scalars().all():
            token.used_at = _utcnow()
        
        # Generate new reset token
        reset_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        # Store token in DB (expires in 1 hour)
        password_reset = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=_utcnow() + timedelta(hours=1),
        )
        db.add(password_reset)
        await db.commit()
        
        # Build reset URL
        frontend_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "https://dev-swat.com"
        reset_url = f"{frontend_url}/reset-password?token={reset_token}"
        
        # Send password reset email
        from .email_service import send_password_reset_email
        try:
            email_sent = await send_password_reset_email(
                to=user.email,
                reset_url=reset_url,
                name=user.full_name
            )
            if email_sent:
                logger.info(f"Password reset email sent to {user.email}")
            else:
                logger.error(f"Failed to send password reset email to {user.email}")
        except Exception as e:
            logger.error(f"Error sending password reset email: {e}")
        
        # Log the reset URL for development
        if settings.ENVIRONMENT == "development":
            print(f"\n{'='*60}")
            print(f"PASSWORD RESET LINK (DEV MODE)")
            print(f"Email: {payload.email}")
            print(f"Reset URL: {reset_url}")
            print(f"Token: {reset_token}")
            print(f"Expires: {password_reset.expires_at}")
            print(f"{'='*60}\n")
    
    # Always return success to prevent email enumeration
    return {
        "success": True,
        "message": "If an account exists with this email, a reset link has been sent.",
    }


@router.post("/auth/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Reset password with token.
    
    Verifies the token is valid and not expired, then updates the password.
    """
    # Validate password strength
    try:
        validate_password_strength(payload.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Hash the provided token to look up in DB
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    
    # Find the reset token
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at == None,
        )
    )
    reset_token = result.scalar_one_or_none()
    
    if not reset_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token. Please request a new password reset."
        )
    
    # Check if token is expired
    if reset_token.expires_at < _utcnow():
        raise HTTPException(
            status_code=400,
            detail="Reset token has expired. Please request a new password reset."
        )
    
    # Get the user
    user = await db.get(User, reset_token.user_id)
    if not user or user.status != "active":
        raise HTTPException(
            status_code=400,
            detail="User account not found or inactive."
        )
    
    # Update password
    user.password_hash = hash_password(payload.new_password)
    user.token_version += 1  # Invalidate all existing sessions
    
    # Mark token as used
    reset_token.used_at = _utcnow()
    
    await db.commit()
    
    return {
        "success": True,
        "message": "Password has been reset successfully. You can now log in with your new password.",
    }


# ============================================
# Email Verification Endpoints
# ============================================

class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


@router.post("/auth/verify-email")
async def verify_email(
    payload: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    """Verify email address with token."""
    from .email_verification import verify_email_token
    
    success, user, message = await verify_email_token(payload.token, db)
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return {
        "success": True,
        "message": message,
        "email_verified": True,
    }


@router.post("/auth/resend-verification")
@password_reset_rate_limit()  # Reuse rate limit to prevent spam
async def resend_verification(
    request: Request,
    payload: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Resend verification email."""
    from .email_verification import resend_verification_email
    
    # Find user
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if email exists
        return {
            "success": True,
            "message": "If an account exists with this email, a verification link has been sent.",
        }
    
    success, message = await resend_verification_email(user, db)
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return {
        "success": True,
        "message": "Verification email sent. Please check your inbox.",
    }


@router.get("/auth/email-status")
async def get_email_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get email verification status for current user."""
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "email": user.email,
        "email_verified": user.email_verified,
        "email_verified_at": user.email_verified_at.isoformat() if user.email_verified_at else None,
    }


# ============================================
# Session Management Endpoints
# ============================================

@router.get("/auth/sessions")
async def list_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all active sessions for the current user."""
    from .sessions import get_active_sessions
    from .security import hash_token
    
    identity = await _get_identity_from_request(request, db)
    
    # Get current session token hash
    current_token = request.cookies.get(REFRESH_COOKIE)
    current_hash = hash_token(current_token) if current_token else None
    
    sessions = await get_active_sessions(identity.user_id, db, current_hash)
    
    return {
        "sessions": sessions,
        "count": len(sessions),
    }


@router.delete("/auth/sessions/{session_id}")
async def revoke_session_endpoint(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Revoke a specific session."""
    from .sessions import revoke_session
    
    identity = await _get_identity_from_request(request, db)
    
    try:
        session_uuid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID")
    
    success, message = await revoke_session(identity.user_id, session_uuid, db)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    # Log session revocation
    ip_address, user_agent = get_client_info(request)
    await log_audit_event(
        db, AuditEventType.LOGOUT,
        user_id=identity.user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"session_id": session_id, "action": "revoke_single"},
        success=True,
    )
    await db.commit()
    
    return {"success": True, "message": message}


@router.post("/auth/sessions/revoke-all")
async def revoke_all_sessions_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Revoke all sessions except the current one."""
    from .sessions import revoke_all_sessions
    from .security import hash_token
    
    identity = await _get_identity_from_request(request, db)
    
    # Get current session to exclude
    current_token = request.cookies.get(REFRESH_COOKIE)
    current_session_id = None
    
    if current_token:
        current_hash = hash_token(current_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == current_hash)
        )
        current_session = result.scalar_one_or_none()
        if current_session:
            current_session_id = current_session.id
    
    count = await revoke_all_sessions(identity.user_id, db, current_session_id)
    
    # Log session revocation
    ip_address, user_agent = get_client_info(request)
    await log_audit_event(
        db, AuditEventType.LOGOUT,
        user_id=identity.user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"action": "revoke_all", "count": count},
        success=True,
    )
    await db.commit()
    
    return {
        "success": True,
        "message": f"Revoked {count} session(s)",
        "revoked_count": count,
    }


# ============================================
# Trusted Device Endpoints
# ============================================

@router.get("/auth/trusted-devices")
async def list_trusted_devices(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all trusted devices for MFA bypass."""
    from .sessions import get_trusted_devices
    
    identity = await _get_identity_from_request(request, db)
    devices = await get_trusted_devices(identity.user_id, db)
    
    return {
        "devices": devices,
        "count": len(devices),
    }


@router.post("/auth/trusted-devices")
async def trust_current_device(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Mark the current device as trusted for MFA bypass."""
    from .sessions import trust_device
    
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user or not user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA must be enabled to trust devices"
        )
    
    ip_address, user_agent = get_client_info(request)
    device_info = await trust_device(identity.user_id, user_agent, ip_address, db)
    
    return {
        "success": True,
        "message": "Device trusted successfully",
        "device": device_info,
    }


@router.delete("/auth/trusted-devices/{device_id}")
async def revoke_trusted_device_endpoint(
    device_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Remove a device from trusted devices."""
    from .sessions import revoke_trusted_device
    
    identity = await _get_identity_from_request(request, db)
    
    try:
        device_uuid = UUID(device_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid device ID")
    
    success, message = await revoke_trusted_device(identity.user_id, device_uuid, db)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    return {"success": True, "message": message}


@router.post("/auth/trusted-devices/revoke-all")
async def revoke_all_trusted_devices_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Remove all trusted devices."""
    from .sessions import revoke_all_trusted_devices
    
    identity = await _get_identity_from_request(request, db)
    count = await revoke_all_trusted_devices(identity.user_id, db)
    
    return {
        "success": True,
        "message": f"Removed {count} trusted device(s)",
        "removed_count": count,
    }


# ============================================
# Agent Settings - Extended Endpoints
# ============================================

@router.get("/auth/settings/agents/templates")
async def list_agent_templates(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List available agent templates."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.is_template == True, Agent.is_public == True)
    )
    templates = result.scalars().all()
    
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "description": t.description,
            "system_prompt": t.system_prompt,
            "personality_config": t.personality_config or {},
        }
        for t in templates
    ]


@router.get("/auth/settings/agents/shared")
async def list_shared_agents(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List agents shared with current user."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.is_shared == True, Agent.is_public == True)
    )
    shared = result.scalars().all()
    
    return [
        {
            "id": str(a.id),
            "name": a.name,
            "description": a.description,
            "owner_id": str(a.user_id),
        }
        for a in shared
    ]


@router.post("/auth/settings/agents/from-template/{template_id}")
async def create_agent_from_template(
    template_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new agent from a template."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(template_id), Agent.is_template == True)
    )
    template = result.scalar_one_or_none()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Create new agent from template
    import hashlib
    hash_input = f"{identity.user_id}:{template.name}:{datetime.now().isoformat()}"
    agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    new_agent = Agent(
        user_id=identity.user_id,
        org_id=identity.org_id,
        name=f"{template.name} (Copy)",
        description=template.description,
        system_prompt=template.system_prompt,
        personality_config=template.personality_config,
        enabled_patches=template.enabled_patches,
        patch_config=template.patch_config,
        memory_config=template.memory_config,
        anchor_config=template.anchor_config,
        isolate_anchors=template.isolate_anchors,
        agent_hash=agent_hash,
        template_id=template.id,
        status="active",
    )
    
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)
    
    return {
        "id": str(new_agent.id),
        "name": new_agent.name,
        "agent_hash": new_agent.agent_hash,
        "template_id": str(template.id),
    }


@router.post("/auth/settings/agents/import")
async def import_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Import an agent from export data."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    import hashlib
    hash_input = f"{identity.user_id}:{body.get('name', 'Imported')}:{datetime.now().isoformat()}"
    agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    new_agent = Agent(
        user_id=identity.user_id,
        org_id=identity.org_id,
        name=body.get("name", "Imported Agent"),
        description=body.get("description"),
        system_prompt=body.get("system_prompt"),
        personality_config=body.get("personality_config", {}),
        enabled_patches=body.get("enabled_patches", []),
        patch_config=body.get("patch_config", {}),
        memory_config=body.get("memory_config", {}),
        anchor_config=body.get("anchor_config", {}),
        isolate_anchors=body.get("isolate_anchors", True),
        agent_hash=agent_hash,
        is_imported=True,
        status="active",
    )
    
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)
    
    return {
        "id": str(new_agent.id),
        "name": new_agent.name,
        "agent_hash": new_agent.agent_hash,
        "imported": True,
    }


@router.post("/auth/settings/agents/{agent_id}/export")
async def export_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Export an agent's configuration."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "name": agent.name,
        "description": agent.description,
        "system_prompt": agent.system_prompt,
        "personality_config": agent.personality_config or {},
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
        "memory_config": agent.memory_config or {},
        "anchor_config": agent.anchor_config or {},
        "isolate_anchors": agent.isolate_anchors,
        "exported_at": datetime.now().isoformat(),
    }


@router.post("/auth/settings/agents/{agent_id}/share")
async def share_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Share an agent with others."""
    import secrets
    
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    share_secret = secrets.token_urlsafe(16)
    agent.is_shared = True
    agent.share_secret = share_secret
    await db.commit()
    
    return {
        "shared": True,
        "share_url": f"/agents/shared/{share_secret}",
        "share_secret": share_secret,
    }


@router.post("/auth/settings/agents/{agent_id}/save-template")
async def save_agent_as_template(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Save an agent as a template."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.is_template = True
    await db.commit()
    
    return {
        "template_id": str(agent.id),
        "is_template": True,
    }


@router.post("/auth/settings/agents/{agent_id}/hash")
async def regenerate_agent_hash(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Regenerate agent's hash."""
    import hashlib
    
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    hash_input = f"{identity.user_id}:{agent.name}:{datetime.now().isoformat()}"
    new_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    agent.agent_hash = new_hash
    await db.commit()
    
    return {
        "agent_hash": new_hash,
        "regenerated_at": datetime.now().isoformat(),
    }


@router.get("/auth/settings/agents/{agent_id}/anchors")
async def get_agent_anchors(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get anchors for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Return anchor config or empty list
    return agent.anchor_config.get("anchors", []) if agent.anchor_config else []


@router.delete("/auth/settings/agents/{agent_id}/anchors/{anchor_id}")
async def delete_agent_anchor(
    agent_id: str,
    anchor_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an anchor from an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Remove anchor from config
    if agent.anchor_config and "anchors" in agent.anchor_config:
        agent.anchor_config["anchors"] = [
            a for a in agent.anchor_config["anchors"] if a.get("id") != anchor_id
        ]
        await db.commit()
    
    return {"deleted": True, "anchor_id": anchor_id}


# Import AgentApiKey model
from .models import AgentApiKey


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


@router.get("/auth/settings/agents/{agent_id}/api-keys")
async def get_agent_api_keys(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get API keys for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists and belongs to user
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Get all API keys for this agent
    keys_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    keys = keys_result.scalars().all()
    
    return {
        "keys": [
            {
                "id": str(k.id),
                "name": k.name,
                "prefix": k.prefix,
                "scopes": k.scopes or [],
                "rate_limit": k.rate_limit,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "is_active": k.is_active,
            }
            for k in keys
        ],
        "count": len(keys),
    }


@router.post("/auth/settings/agents/{agent_id}/api-keys")
async def create_agent_api_key(
    agent_id: str,
    payload: AgentApiKeyCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Create an API key for an agent.
    
    Returns the full API key ONCE - it cannot be retrieved again.
    Store it securely.
    """
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists and belongs to user
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check for duplicate name
    existing = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.name == payload.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"API key with name '{payload.name}' already exists")
    
    # Generate API key
    key_plain = f"rga_{secrets.token_urlsafe(32)}"
    key_prefix = key_plain[:12]
    key_hash = hashlib.sha256(key_plain.encode()).hexdigest()
    
    # Calculate expiration
    expires_at = None
    if payload.expires_in_days:
        expires_at = _utcnow() + timedelta(days=payload.expires_in_days)
    
    # Create API key record
    api_key = AgentApiKey(
        agent_id=UUID(agent_id),
        user_id=identity.user_id,
        name=payload.name,
        prefix=key_prefix,
        hashed_key=key_hash,
        scopes=payload.scopes or ["chat", "query"],
        rate_limit=payload.rate_limit or 100,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key": key_plain,  # Only returned once!
        "prefix": key_prefix,
        "scopes": api_key.scopes,
        "rate_limit": api_key.rate_limit,
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "created_at": api_key.created_at.isoformat(),
        "warning": "Store this key securely. It will not be shown again.",
    }


@router.delete("/auth/settings/agents/{agent_id}/api-keys/{key_id}")
async def delete_agent_api_key(
    agent_id: str,
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists and belongs to user
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Find the API key
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    key_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.id == key_uuid,
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    api_key = key_result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Delete the key
    await db.delete(api_key)
    await db.commit()
    
    return {
        "deleted": True,
        "key_id": key_id,
        "name": api_key.name,
    }


@router.put("/auth/settings/agents/{agent_id}/api-keys/{key_id}")
async def update_agent_api_key(
    agent_id: str,
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update an API key for an agent (name, scopes, rate_limit, is_active)."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    # Verify agent exists and belongs to user
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Find the API key
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    key_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.id == key_uuid,
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    api_key = key_result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Update fields
    if "name" in body:
        api_key.name = body["name"]
    if "scopes" in body:
        api_key.scopes = body["scopes"]
    if "rate_limit" in body:
        api_key.rate_limit = body["rate_limit"]
    if "is_active" in body:
        api_key.is_active = body["is_active"]
    
    await db.commit()
    await db.refresh(api_key)
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "prefix": api_key.prefix,
        "scopes": api_key.scopes,
        "rate_limit": api_key.rate_limit,
        "is_active": api_key.is_active,
        "updated": True,
    }


@router.get("/auth/settings/agents/{agent_id}/memory")
async def get_agent_memory(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get memory configuration for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return agent.memory_config or {}


@router.put("/auth/settings/agents/{agent_id}/memory")
async def update_agent_memory(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update memory configuration for an agent."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.memory_config = body
    await db.commit()
    
    return agent.memory_config


@router.get("/auth/settings/agents/{agent_id}/metrics")
async def get_agent_metrics(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get metrics for an agent.
    
    Returns placeholder metrics - real metrics tracking is not yet implemented.
    """
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "total_messages": 0,
        "total_tokens": 0,
        "average_response_time_ms": 0,
        "success_rate": 1.0,
        "last_active": None,
        "message": "Agent metrics tracking is not yet implemented. These are placeholder values.",
    }


@router.get("/auth/settings/agents/{agent_id}/patches")
async def get_agent_patches(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get enabled patches for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
    }


class AgentRestrictionsRequest(BaseModel):
    blocked_topics: Optional[List[str]] = None
    allowed_domains: Optional[List[str]] = None
    blocked_domains: Optional[List[str]] = None
    max_tokens_per_message: Optional[int] = None
    max_messages_per_hour: Optional[int] = None
    allowed_tools: Optional[List[str]] = None
    blocked_tools: Optional[List[str]] = None
    content_filter_level: Optional[str] = None  # none, low, medium, high


DEFAULT_RESTRICTIONS = {
    "blocked_topics": [],
    "allowed_domains": [],
    "blocked_domains": [],
    "max_tokens_per_message": 4096,
    "max_messages_per_hour": 100,
    "allowed_tools": [],
    "blocked_tools": [],
    "content_filter_level": "medium",
}


@router.get("/auth/settings/agents/{agent_id}/restrictions")
async def get_agent_restrictions(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get restrictions for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Merge stored restrictions with defaults
    restrictions = {**DEFAULT_RESTRICTIONS, **(agent.restrictions or {})}
    
    return restrictions


@router.put("/auth/settings/agents/{agent_id}/restrictions")
async def update_agent_restrictions(
    agent_id: str,
    payload: AgentRestrictionsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update restrictions for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    # Verify agent exists
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Get current restrictions or defaults
    current = agent.restrictions or {}
    
    # Update only provided fields
    updates = payload.model_dump(exclude_none=True)
    new_restrictions = {**current, **updates}
    
    # Validate content_filter_level
    if new_restrictions.get("content_filter_level") not in (None, "none", "low", "medium", "high"):
        raise HTTPException(status_code=400, detail="Invalid content_filter_level. Must be: none, low, medium, high")
    
    # Validate max values
    if new_restrictions.get("max_tokens_per_message", 0) > 32000:
        raise HTTPException(status_code=400, detail="max_tokens_per_message cannot exceed 32000")
    
    if new_restrictions.get("max_messages_per_hour", 0) > 10000:
        raise HTTPException(status_code=400, detail="max_messages_per_hour cannot exceed 10000")
    
    agent.restrictions = new_restrictions
    await db.commit()
    
    return {
        "success": True,
        "message": "Agent restrictions updated",
        "restrictions": {**DEFAULT_RESTRICTIONS, **new_restrictions},
    }
