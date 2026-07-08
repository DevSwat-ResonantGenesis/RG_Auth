"""Auth Routers - Core authentication endpoints.

Ported from ResonantGraphAIV0.1 backend with:
- Multi-tenant (Organization) support
- Role-based access control
- HttpOnly cookie authentication
- Refresh token DB storage
- Identity-based JWT tokens

Domain routers extracted to separate files:
- mfa_routes.py        — MFA TOTP + backup codes
- password_routes.py   — change/forgot/reset password
- email_routes.py      — email verification
- sessions_routes.py   — sessions + trusted devices
- byok_routes.py       — user BYOK API keys
- api_keys_routes.py   — org-level API keys
- agent_settings.py    — agent settings extended endpoints
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
import logging
import urllib.parse
import httpx

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

from .config import settings
from .db import get_db
from .economic_integration import create_user_economic_state, EconomicIntegrationError
from .models import Agent, Organization, OrgMembership, RefreshToken, User, UserApiKey
from .identity import Identity
from .security import (
    create_access_token,
    decode_access_token,
    validate_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from .crypto import encrypt_api_key, decrypt_api_key
from .rate_limit import (
    register_rate_limit,
    refresh_token_rate_limit,
)
from .audit import log_audit_event, AuditEventType, get_client_info

# Shared helpers and schemas
from .deps import (
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    _utcnow,
    _generate_slug,
    _generate_crypto_identity,
    _internal_headers,
    _set_auth_cookies,
    _clear_auth_cookies,
    _resolve_membership,
    _issue_refresh_token,
    _get_identity_from_request,
    validate_password_strength,
)
from .schemas import (
    AgentCreateRequest,
    AgentUpdateRequest,
    DevCreateUserRequest,
    LoginRequest,
    LoginResponse,
    MnemonicRequest,
    MnemonicResponse,
    RefreshResponse,
    RegisterRequest,
    SSOCallbackRequest,
    SSOCallbackQueryParams,
    SSOInitiateRequest,
    SAMLInitiateRequest,
    UserIdentityResponse,
    UserResponse,
    VerifyRequest,
)

router = APIRouter()


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
                headers=_internal_headers(),
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
    try:
        await create_user_economic_state(
            user_id=user.id,
            org_id=org.id,
            tier="developer",  # Default tier
            subscription_source="internal",
            is_dev_override=False,
        )
    except EconomicIntegrationError as e:
        # Non-fatal: the 7-day unlimited_credits trial + CreditManager's
        # lazy-create-on-first-deduction fallback both still work without this
        # row, so don't block signup on billing_service being unreachable.
        # It just means /auth/verify's plan-tier lookup falls back to a
        # default plan until this succeeds (e.g. on next login retry).
        logger.error(f"Failed to create economic state for user {user.id}: {e}")
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
                    headers=_internal_headers(),
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
    plan = "free"
    
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
                plan = "free"
            elif raw_plan in {"pro"}:
                plan = "plus"
            else:
                plan = "free"
        
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
    refresh = request.cookies.get(REFRESH_COOKIE)
    if token:
        try:
            decoded = decode_access_token(token)
            identity = Identity.from_claims(decoded)
            if identity.user_id:
                # Valid session — redirect token to Electron's localhost server
                callback = f"http://localhost:{port}/auth-callback?token={urllib.parse.quote(token)}"
                if refresh:
                    callback += f"&refresh_token={urllib.parse.quote(refresh)}"
                return RedirectResponse(callback)
        except Exception:
            pass

    # Not logged in — set a cookie so OAuth callback can redirect token to IDE
    # This survives the Google/GitHub OAuth multi-step flow
    return_url = urllib.parse.quote(f"/auth/desktop-callback?port={port}")
    resp = RedirectResponse(f"/login?redirect={return_url}")
    is_dev = settings.ENVIRONMENT == "development"
    resp.set_cookie(
        "rg_desktop_port",
        port,
        httponly=True,
        secure=not is_dev,
        samesite="lax",
        max_age=600,  # 10 minutes — enough for OAuth flow
        path="/",
    )
    return resp


@router.get("/auth/health")
async def health():
    """Health check endpoint."""
    return {"service": "auth", "status": "ok"}


# ============================================
# Identity & Mnemonic Endpoints (Ported from old backend)
# ============================================

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
# SSO Endpoints - OAuth2 Implementation
# ============================================

from .oauth import OAuthManager, OAuthError, get_available_providers, is_provider_configured

_oauth_manager = OAuthManager()


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

    If the state indicates a SERVICE CONNECTION (Drive/Calendar/Gmail), handle it
    here directly instead of treating it as a login.
    """
    from fastapi.responses import RedirectResponse as _Redirect
    from .oauth_redis import get_oauth_state

    frontend_url = _oauth_manager.frontend_url  # e.g. https://dev-swat.com

    if error:
        return _Redirect(
            url=f"{frontend_url}/connect-profiles?status=error&message={error}",
            status_code=302,
        )

    state_data = get_oauth_state(state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    extra = state_data.get("extra_data", {})

    # ── SERVICE CONNECTION (Drive / Calendar / Gmail) ──────────────────
    if extra.get("service_connection"):
        service = extra.get("service", "")
        stored_user_id = extra.get("user_id")
        logger.info("Service connection callback: service=%s user=%s", service, stored_user_id)

        # Don't consume state yet — validate_oauth_state does that
        from .oauth import validate_oauth_state, OAUTH_PROVIDERS, is_provider_configured
        validate_oauth_state(state)  # consume + verify expiry

        if not is_provider_configured("google"):
            return _Redirect(
                url=f"{frontend_url}/connect-profiles?service={service}&status=error&message=Google+OAuth+not+configured",
                status_code=302,
            )

        google_config = OAUTH_PROVIDERS["google"]
        redirect_uri = state_data.get("redirect_uri", "")

        # Exchange code for tokens
        import httpx as _httpx
        try:
            async with _httpx.AsyncClient(timeout=15.0) as client:
                token_resp = await client.post(
                    google_config.token_url,
                    data={
                        "client_id": google_config.client_id,
                        "client_secret": google_config.client_secret,
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "grant_type": "authorization_code",
                    },
                    headers={"Accept": "application/json"},
                )
                token_resp.raise_for_status()
                tokens = token_resp.json()
        except Exception as e:
            logger.error("Service connection token exchange failed: %s", e)
            return _Redirect(
                url=f"{frontend_url}/connect-profiles?service={service}&status=error&message=Token+exchange+failed",
                status_code=302,
            )

        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        if not access_token:
            return _Redirect(
                url=f"{frontend_url}/connect-profiles?service={service}&status=error&message=No+access+token",
                status_code=302,
            )

        token_to_store = refresh_token or access_token
        key_prefix = f"g_{service.replace('google-', '')[:8]}"
        friendly_name = f"Google {service.replace('google-', '').replace('-', ' ').title()}"

        # Resolve user — use stored_user_id from the state (the user who initiated)
        from uuid import UUID as _UUID
        try:
            user_uuid = _UUID(stored_user_id) if stored_user_id else None
        except (ValueError, TypeError):
            user_uuid = None

        if not user_uuid:
            return _Redirect(
                url=f"{frontend_url}/connect-profiles?service={service}&status=error&message=Invalid+user",
                status_code=302,
            )

        from .crypto import encrypt_api_key
        existing = await db.execute(
            select(UserApiKey).where(
                UserApiKey.user_id == user_uuid,
                UserApiKey.provider == service,
            )
        )
        existing_key = existing.scalar_one_or_none()

        if existing_key:
            existing_key.encrypted_key = encrypt_api_key(token_to_store)
            existing_key.key_prefix = key_prefix
            existing_key.is_valid = True
            existing_key.name = friendly_name
        else:
            new_key = UserApiKey(
                user_id=user_uuid,
                provider=service,
                name=friendly_name,
                encrypted_key=encrypt_api_key(token_to_store),
                key_prefix=key_prefix,
                is_valid=True,
            )
            db.add(new_key)

        await db.commit()
        logger.info(
            "Service connected via GET callback: service=%s user=%s has_refresh=%s",
            service, stored_user_id, bool(refresh_token),
        )

        return _Redirect(
            url=f"{frontend_url}/connect-profiles?service={service}&status=connected",
            status_code=302,
        )

    # ── REGULAR LOGIN ──────────────────────────────────────────────────
    provider = state_data.get("provider", "google")
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
                        headers=_internal_headers(),
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
                    headers=_internal_headers(),
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
    
    # ── Desktop IDE callback: if rg_desktop_port cookie exists, redirect
    #    the token directly to the IDE's localhost server instead of /dashboard.
    #    This cookie is set by /auth/desktop-callback when the user wasn't
    #    logged in yet and had to go through Google/GitHub OAuth.
    desktop_port = request.cookies.get("rg_desktop_port")
    if desktop_port and desktop_port.isdigit():
        import urllib.parse
        from fastapi.responses import RedirectResponse as _Redir
        callback_url = f"http://localhost:{desktop_port}/auth-callback?token={urllib.parse.quote(access_token)}&refresh_token={urllib.parse.quote(refresh_plain)}"
        logger.info(f"OAuth desktop redirect: sending token + refresh to localhost:{desktop_port}")
        ide_resp = _Redir(callback_url)
        # Set auth cookies so the website is also logged in
        _set_auth_cookies(
            ide_resp,
            access_token,
            refresh_plain,
            user_email=user.email,
            user_role=membership.role,
            org_id=str(membership.org_id),
        )
        # Clear the desktop port cookie
        ide_resp.delete_cookie("rg_desktop_port", path="/")
        return ide_resp
    
    # Return HTML with JavaScript to handle OAuth callback
    # Google redirects browser to this URL, so we need HTML not JSON
    from fastapi.responses import HTMLResponse
    import json
    
    frontend_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "https://dev-swat.com"
    dashboard_url = f"{frontend_url}/"
    
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

