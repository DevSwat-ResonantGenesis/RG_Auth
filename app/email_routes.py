"""
Email verification routes.
Extracted from routers.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_db
from .deps import _get_identity_from_request
from .models import User
from .rate_limit import password_reset_rate_limit
from .schemas import VerifyEmailRequest, ResendVerificationRequest

router = APIRouter()


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
