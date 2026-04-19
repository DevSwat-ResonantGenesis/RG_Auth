"""
Shared dependencies, helpers, and constants used across all auth routers.
Extracted from routers.py to avoid circular imports.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID
import re
import secrets
import hashlib
import logging
import urllib.parse

from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .identity import Identity
from .models import OrgMembership, RefreshToken, User
from .security import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    verify_password,
)

logger = logging.getLogger(__name__)

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


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, user_email: str = None, user_role: str = None, org_id: str = None):
    """Set HttpOnly auth cookies with proper security settings."""
    is_dev = settings.ENVIRONMENT == "development"
    
    # Security settings based on environment
    secure_value = settings.COOKIE_SECURE if not is_dev else False
    samesite_value = "lax"
    
    # Cookie domain
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


def _internal_headers() -> dict:
    """Build headers for internal service-to-service calls."""
    return {"X-Internal-Key": settings.INTERNAL_SERVICE_KEY} if settings.INTERNAL_SERVICE_KEY else {}


def _generate_crypto_identity(user_id: UUID, email: str) -> tuple[str, str, str]:
    """Generate cryptographic identity for a user.
    
    Returns:
        tuple: (crypto_hash, user_hash, universe_id)
    """
    seed_data = f"{user_id}:{email}:{_utcnow().isoformat()}:{secrets.token_hex(16)}"
    crypto_hash = hashlib.sha256(seed_data.encode()).hexdigest()
    
    user_hash_data = f"user:{user_id}:{email}"
    user_hash = hashlib.sha256(user_hash_data.encode()).hexdigest()
    
    universe_data = f"universe:{crypto_hash}:{user_hash}"
    universe_id = hashlib.sha256(universe_data.encode()).hexdigest()[:32]
    
    return crypto_hash, user_hash, universe_id


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
