"""
Password management routes — change, forgot, reset.
Extracted from routers.py.
"""
from __future__ import annotations

from datetime import timedelta
import hashlib
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .deps import _get_identity_from_request, _utcnow, validate_password_strength
from .models import PasswordResetToken, User
from .security import hash_password, verify_password
from .audit import log_audit_event, AuditEventType, get_client_info
from .rate_limit import password_reset_rate_limit
from .schemas import ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordRequest

logger = logging.getLogger(__name__)

router = APIRouter()


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
