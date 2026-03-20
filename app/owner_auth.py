"""
Owner Authentication Module
Separate authentication for platform owner dashboard access.
Uses environment variables for owner credentials - no database storage.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import jwt
import os
import secrets
import hashlib

from .config import settings

router = APIRouter(prefix="/owner/auth", tags=["Owner Authentication"])
security = HTTPBearer()

# Owner credentials from environment variables
# These MUST be set in production via environment variables
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "")
OWNER_PASSWORD_HASH = os.getenv("OWNER_PASSWORD_HASH", "")  # Pre-hashed password
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "")  # Plain password (will be hashed)
OWNER_JWT_SECRET = os.getenv("OWNER_JWT_SECRET", settings.JWT_SECRET_KEY + "_owner")
OWNER_TOKEN_EXPIRE_HOURS = int(os.getenv("OWNER_TOKEN_EXPIRE_HOURS", "24"))


def hash_password(password: str) -> str:
    """Hash password with SHA-256 and salt."""
    salt = OWNER_JWT_SECRET[:16]
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return hash_password(plain_password) == hashed_password


def get_owner_password_hash() -> str:
    """Get the owner password hash - either pre-hashed or hash the plain password."""
    if OWNER_PASSWORD_HASH:
        return OWNER_PASSWORD_HASH
    if OWNER_PASSWORD:
        return hash_password(OWNER_PASSWORD)
    return ""


class OwnerLoginRequest(BaseModel):
    email: EmailStr
    password: str


class OwnerTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class OwnerValidateResponse(BaseModel):
    valid: bool
    email: str
    role: str = "owner"
    expires_at: str


@router.post("/login", response_model=OwnerTokenResponse)
async def owner_login(request: OwnerLoginRequest, response: Response):
    """
    Authenticate platform owner and return JWT token.
    Also sets owner_token cookie for nginx auth check on V8 routes.
    
    Owner credentials are configured via environment variables:
    - OWNER_EMAIL: Owner's email address
    - OWNER_PASSWORD: Owner's password (plain text, will be hashed)
    - OWNER_PASSWORD_HASH: Pre-hashed password (alternative to OWNER_PASSWORD)
    - OWNER_JWT_SECRET: Secret key for JWT signing
    """
    # Check if owner credentials are configured
    if not OWNER_EMAIL:
        raise HTTPException(
            status_code=500,
            detail="Owner authentication not configured. Set OWNER_EMAIL environment variable."
        )
    
    password_hash = get_owner_password_hash()
    if not password_hash:
        raise HTTPException(
            status_code=500,
            detail="Owner password not configured. Set OWNER_PASSWORD or OWNER_PASSWORD_HASH environment variable."
        )
    
    # Verify credentials
    if request.email.lower() != OWNER_EMAIL.lower():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(request.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    expires_at = datetime.utcnow() + timedelta(hours=OWNER_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": OWNER_EMAIL,
        "role": "owner",
        "type": "owner_access",
        "iat": datetime.utcnow(),
        "exp": expires_at,
        "jti": secrets.token_hex(16),  # Unique token ID
    }
    
    token = jwt.encode(payload, OWNER_JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    
    # Set owner_token cookie for nginx auth check on V8 routes
    response.set_cookie(
        key="owner_token",
        value=token,
        max_age=OWNER_TOKEN_EXPIRE_HOURS * 3600,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    
    return OwnerTokenResponse(
        access_token=token,
        expires_in=OWNER_TOKEN_EXPIRE_HOURS * 3600
    )


@router.get("/validate", response_model=OwnerValidateResponse)
async def validate_owner_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Validate owner JWT token OR session token for superusers.
    Returns token details if valid, raises 401 if invalid.
    """
    token = credentials.credentials
    
    # First try owner token
    try:
        payload = jwt.decode(
            token,
            OWNER_JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        # Verify this is an owner token
        if payload.get("role") == "owner" and payload.get("type") == "owner_access":
            return OwnerValidateResponse(
                valid=True,
                email=payload.get("sub", ""),
                role="owner",
                expires_at=datetime.fromtimestamp(payload.get("exp", 0)).isoformat()
            )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        pass  # Try session token next
    
    # Try session token for superusers
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        # Check if user is superuser or platform_owner
        is_superuser = payload.get("is_superuser", False)
        role = payload.get("role", "")
        
        if is_superuser or role == "platform_owner":
            return OwnerValidateResponse(
                valid=True,
                email=payload.get("sub", payload.get("email", "")),
                role="owner",
                expires_at=datetime.fromtimestamp(payload.get("exp", 0)).isoformat()
            )
        else:
            raise HTTPException(status_code=403, detail="Not authorized for owner dashboard")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


@router.post("/logout")
async def owner_logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Logout owner session.
    Note: JWT tokens are stateless, so this just validates the token.
    Client should delete the token from storage.
    """
    # Validate token first
    await validate_owner_token(credentials)
    
    return {"message": "Logged out successfully"}


@router.get("/status")
async def owner_auth_status():
    """
    Check if owner authentication is properly configured.
    Does not reveal credentials, only configuration status.
    """
    return {
        "configured": bool(OWNER_EMAIL and get_owner_password_hash()),
        "email_set": bool(OWNER_EMAIL),
        "password_set": bool(get_owner_password_hash()),
        "jwt_secret_set": bool(OWNER_JWT_SECRET),
        "token_expire_hours": OWNER_TOKEN_EXPIRE_HOURS,
    }


# ============================================
# OWNER DASHBOARD DATA ENDPOINTS
# ============================================

@router.get("/dashboard/stats")
async def get_dashboard_stats(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get platform statistics for owner dashboard."""
    await validate_owner_token(credentials)
    
    # Query real data from database
    from .db import SessionLocal
    from .models import User, Organization
    from sqlalchemy import select, func
    import httpx
    
    async with SessionLocal() as session:
        # Get user counts
        total_users_result = await session.execute(select(func.count(User.id)))
        total_users = total_users_result.scalar() or 0

        active_users_result = await session.execute(
            select(func.count(User.id)).where(
                User.last_login_at.isnot(None),
                User.last_login_at > datetime.utcnow() - timedelta(hours=24),
            )
        )
        active_users = active_users_result.scalar() or 0
        
        # Get org counts
        total_orgs_result = await session.execute(select(func.count(Organization.id)))
        total_orgs = total_orgs_result.scalar() or 0

    total_revenue = None
    mrr = None
    credits_consumed = None
    paying_users = None

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            billing_resp = await client.get("http://billing_service:8000/billing/admin/stats")
            if billing_resp.status_code == 200:
                billing_data = billing_resp.json()
                total_revenue = billing_data.get("total_revenue")
                credits_consumed = billing_data.get("total_credits_used")
                paying_users = billing_data.get("paying_users")

            subs_resp = await client.get("http://billing_service:8000/billing/subscriptions/stats")
            if subs_resp.status_code == 200:
                subs_data = subs_resp.json()
                mrr = subs_data.get("mrr")
    except Exception:
        pass

    conversion_rate = round((paying_users / total_users) * 100, 1) if total_users > 0 and paying_users is not None else None
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_organizations": total_orgs,
        "total_revenue": total_revenue,
        "mrr": mrr,
        "credits_consumed": credits_consumed,
        "api_calls": None,
        "conversion_rate": conversion_rate,
    }


@router.get("/dashboard/users")
async def get_dashboard_users(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    limit: int = 500,
    offset: int = 0
):
    """Get users list for owner dashboard with full details."""
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User
    from sqlalchemy import select, func
    
    async with SessionLocal() as session:
        # Get total count
        count_result = await session.execute(select(func.count(User.id)))
        total_count = count_result.scalar() or 0
        
        # Get users
        result = await session.execute(
            select(User)
            .order_by(User.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        users = result.scalars().all()
        
        user_list = []
        for user in users:
            user_list.append({
                "id": str(user.id),
                "email": user.email,
                "username": user.username or "",
                "full_name": user.full_name or "",
                "status": user.status or "active",
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "mfa_enabled": user.mfa_enabled,
                "email_verified": user.email_verified,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            })
    
    return {"users": user_list, "total": total_count}


# ============================================
# OWNER SETTINGS ENDPOINTS
# ============================================

# In-memory settings storage (in production, use database or config service)
_platform_settings = {
    "credit_rate": 0.001,
    "developer_credits": 1000,
    "plus_credits": 50000,
    "plus_price": 49,
    "topup_price": 8,
    "topup_amount": 10000,
    "maintenance_mode": False,
    "signups_enabled": True,
}

@router.get("/settings")
async def get_platform_settings(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get current platform settings."""
    await validate_owner_token(credentials)
    return _platform_settings

@router.post("/settings")
async def save_platform_settings(
    settings: dict,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Save platform settings."""
    await validate_owner_token(credentials)
    
    # Update settings
    for key, value in settings.items():
        if key in _platform_settings:
            _platform_settings[key] = value
    
    return {"status": "saved", "settings": _platform_settings}


# ============================================
# ADMIN USER MANAGEMENT ENDPOINTS
# ============================================

@router.post("/admin/reset-password/{user_id}")
async def admin_reset_password(
    user_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Send password reset email to a user (admin action).
    Only platform owner can trigger this.
    """
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User, PasswordResetToken
    from uuid import UUID
    import secrets
    from datetime import datetime, timedelta
    
    async with SessionLocal() as session:
        from sqlalchemy import select
        
        # Find the user
        result = await session.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate reset token
        plain_token = secrets.token_urlsafe(32)
        from .security import hash_token
        hashed_token = hash_token(plain_token)
        
        # Create reset token record
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=hashed_token,
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        session.add(reset_token)
        await session.commit()
        
        # Send reset email
        try:
            import os
            frontend_url = os.getenv("AUTH_FRONTEND_URL", "https://resonantgenesis.xyz")
            reset_url = f"{frontend_url}/reset-password?token={plain_token}"
            
            # Try to send email via notification service or direct SMTP
            import httpx
            notification_url = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification_service:8000")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{notification_url}/email/send",
                    json={
                        "to": user.email,
                        "subject": "Password Reset Request - ResonantGenesis",
                        "template": "password_reset",
                        "data": {
                            "reset_url": reset_url,
                            "user_name": user.full_name or user.email.split("@")[0],
                            "expires_hours": 24,
                        }
                    }
                )
        except Exception as e:
            # Log but don't fail - token is created, user can use it
            import logging
            logging.warning(f"Failed to send reset email: {e}")
        
        return {
            "status": "success",
            "message": f"Password reset email sent to {user.email}",
            "user_email": user.email,
        }


@router.post("/admin/set-password/{user_id}")
async def admin_set_password(
    user_id: str,
    new_password: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Directly set a user's password (admin action).
    Only platform owner can do this.
    """
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User
    from .security import hash_password
    from uuid import UUID
    
    async with SessionLocal() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Set new password
        user.password_hash = hash_password(new_password)
        user.token_version = (user.token_version or 0) + 1  # Invalidate existing tokens
        await session.commit()
        
        return {
            "status": "success",
            "message": f"Password updated for {user.email}",
            "user_email": user.email,
        }


@router.post("/admin/block-user/{user_id}")
async def admin_block_user(
    user_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Block a user from accessing the platform (admin action).
    Sets is_active=False and increments token_version to invalidate sessions.
    """
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User
    from uuid import UUID
    
    async with SessionLocal() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Block user
        user.is_active = False
        user.status = "blocked"
        user.token_version = (user.token_version or 0) + 1  # Invalidate existing tokens
        await session.commit()
        
        return {
            "status": "success",
            "message": f"User {user.email} has been blocked",
            "user_email": user.email,
        }


@router.post("/admin/unblock-user/{user_id}")
async def admin_unblock_user(
    user_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Unblock a user and restore platform access (admin action).
    """
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User
    from uuid import UUID
    
    async with SessionLocal() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Unblock user
        user.is_active = True
        user.status = "active"
        await session.commit()
        
        return {
            "status": "success",
            "message": f"User {user.email} has been unblocked",
            "user_email": user.email,
        }


@router.delete("/admin/delete-user/{user_id}")
async def admin_delete_user(
    user_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Permanently delete a user account (admin action).
    This is irreversible - use with caution.
    """
    await validate_owner_token(credentials)
    
    from .db import SessionLocal
    from .models import User
    from uuid import UUID
    
    async with SessionLocal() as session:
        from sqlalchemy import select
        
        result = await session.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_email = user.email
        await session.delete(user)
        await session.commit()
        
        return {
            "status": "success",
            "message": f"User {user_email} has been permanently deleted",
            "user_email": user_email,
        }


# Dependency for protecting owner-only endpoints
async def require_owner(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Dependency to require owner authentication for endpoints.
    
    Usage:
        @router.get("/protected")
        async def protected_endpoint(owner: dict = Depends(require_owner)):
            return {"owner_email": owner["email"]}
    """
    result = await validate_owner_token(credentials)
    return {"email": result.email, "role": result.role}
