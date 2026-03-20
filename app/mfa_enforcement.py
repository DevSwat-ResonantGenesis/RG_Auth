"""
MFA enforcement module for sensitive operations.

Requires MFA verification for:
- Password changes
- API key creation/deletion
- Account deletion
- MFA disable
- Email change
"""
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User


# Operations that require MFA verification
SENSITIVE_OPERATIONS = {
    "password_change",
    "api_key_create",
    "api_key_delete",
    "mfa_disable",
    "email_change",
    "account_delete",
    "byok_key_add",
    "byok_key_delete",
}

# How long MFA verification is valid (5 minutes)
MFA_VERIFICATION_WINDOW_MINUTES = 5


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


async def check_mfa_required(
    user: User,
    operation: str,
    db: AsyncSession,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Check if MFA verification is required for an operation.
    
    Skips MFA if device is trusted.
    
    Returns:
        Tuple of (mfa_required, reason)
    """
    # If user doesn't have MFA enabled, no verification needed
    if not user.mfa_enabled:
        return False, None
    
    # Check if operation requires MFA
    if operation not in SENSITIVE_OPERATIONS:
        return False, None
    
    # Check if device is trusted (skip MFA for trusted devices)
    if user_agent or ip_address:
        from .sessions import is_device_trusted
        if await is_device_trusted(user.id, user_agent, ip_address, db):
            return False, None
    
    # Check if MFA was recently verified
    if user.mfa_verified_at:
        window = timedelta(minutes=MFA_VERIFICATION_WINDOW_MINUTES)
        if _utcnow() - user.mfa_verified_at < window:
            return False, None
    
    return True, f"MFA verification required for {operation.replace('_', ' ')}"


async def verify_mfa_for_operation(
    user: User,
    operation: str,
    mfa_code: Optional[str],
    db: AsyncSession,
) -> tuple[bool, str]:
    """
    Verify MFA code for a sensitive operation.
    
    Returns:
        Tuple of (success, message)
    """
    from .mfa import verify_totp_code
    
    # Check if MFA is required
    mfa_required, reason = await check_mfa_required(user, operation, db)
    
    if not mfa_required:
        return True, "MFA not required"
    
    if not mfa_code:
        return False, reason or "MFA code required"
    
    # Verify the code
    if not user.mfa_secret:
        return False, "MFA not properly configured"
    
    if verify_totp_code(user.mfa_secret, mfa_code):
        # Update verification timestamp
        user.mfa_verified_at = _utcnow()
        await db.commit()
        return True, "MFA verified"
    
    return False, "Invalid MFA code"


def require_mfa(operation: str):
    """
    Decorator to require MFA verification for sensitive operations.
    
    Usage:
        @require_mfa("password_change")
        async def change_password(...):
            ...
    
    The endpoint must accept an optional `mfa_code` parameter in the request body.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get request and db from kwargs
            request = kwargs.get('request')
            db = kwargs.get('db')
            
            if not request or not db:
                # Can't enforce MFA without request/db
                return await func(*args, **kwargs)
            
            # Get user from request
            from .routers import _get_identity_from_request
            try:
                identity = await _get_identity_from_request(request, db)
                user = await db.get(User, identity.user_id)
            except HTTPException:
                # Not authenticated, let the endpoint handle it
                return await func(*args, **kwargs)
            
            if not user:
                return await func(*args, **kwargs)
            
            # Check if MFA is required
            mfa_required, reason = await check_mfa_required(user, operation, db)
            
            if mfa_required:
                # Try to get MFA code from request body
                mfa_code = None
                try:
                    body = await request.json()
                    mfa_code = body.get('mfa_code')
                except:
                    pass
                
                if not mfa_code:
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": {
                                "code": "MFA_REQUIRED",
                                "message": reason,
                                "mfa_required": True,
                                "operation": operation,
                            }
                        }
                    )
                
                # Verify MFA
                success, message = await verify_mfa_for_operation(user, operation, mfa_code, db)
                if not success:
                    raise HTTPException(
                        status_code=401,
                        detail={
                            "error": {
                                "code": "MFA_INVALID",
                                "message": message,
                            }
                        }
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


class MFARequiredResponse:
    """Response model for MFA required errors."""
    
    @staticmethod
    def create(operation: str) -> dict:
        return {
            "error": {
                "code": "MFA_REQUIRED",
                "message": f"MFA verification required for {operation.replace('_', ' ')}",
                "mfa_required": True,
                "operation": operation,
            }
        }
