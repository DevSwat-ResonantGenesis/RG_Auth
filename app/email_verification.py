"""
Email verification module for the auth service.

Handles:
- Generating verification tokens
- Sending verification emails (stub for now)
- Verifying email tokens
"""
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User
from .config import settings


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def generate_verification_token() -> Tuple[str, str]:
    """
    Generate a verification token.
    
    Returns:
        Tuple of (plain_token, hashed_token)
    """
    plain_token = secrets.token_urlsafe(32)
    hashed_token = hashlib.sha256(plain_token.encode()).hexdigest()
    return plain_token, hashed_token


async def send_verification_email(
    email: str,
    verification_url: str,
    user_name: Optional[str] = None,
) -> bool:
    """
    Send verification email to user.
    
    Uses the email_service module which supports SendGrid in production
    and console output in development.
    
    Returns:
        True if email was sent successfully
    """
    from .email_service import send_verification_email as _send_email
    return await _send_email(
        to=email,
        verification_url=verification_url,
        name=user_name,
    )


async def create_verification_token(
    user: User,
    db: AsyncSession,
) -> str:
    """
    Create and store a verification token for a user.
    
    Returns:
        The plain token to send to user
    """
    plain_token, hashed_token = generate_verification_token()
    
    user.email_verification_token = hashed_token
    user.email_verification_sent_at = _utcnow()
    await db.commit()
    
    return plain_token


async def verify_email_token(
    token: str,
    db: AsyncSession,
) -> Tuple[bool, Optional[User], str]:
    """
    Verify an email verification token.
    
    Returns:
        Tuple of (success, user, message)
    """
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    
    # Find user with this token
    result = await db.execute(
        select(User).where(User.email_verification_token == hashed_token)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return False, None, "Invalid or expired verification token"
    
    # Check if already verified
    if user.email_verified:
        return True, user, "Email already verified"
    
    # Check token expiration (24 hours)
    if user.email_verification_sent_at:
        expiry = user.email_verification_sent_at + timedelta(hours=24)
        if _utcnow() > expiry:
            return False, user, "Verification token has expired. Please request a new one."
    
    # Mark email as verified
    user.email_verified = True
    user.email_verified_at = _utcnow()
    user.email_verification_token = None  # Clear token after use
    await db.commit()
    
    return True, user, "Email verified successfully"


async def resend_verification_email(
    user: User,
    db: AsyncSession,
) -> Tuple[bool, str]:
    """
    Resend verification email to user.
    
    Returns:
        Tuple of (success, message)
    """
    if user.email_verified:
        return False, "Email is already verified"
    
    # Rate limit: only allow resend every 60 seconds
    if user.email_verification_sent_at:
        cooldown = user.email_verification_sent_at + timedelta(seconds=60)
        if _utcnow() < cooldown:
            remaining = int((cooldown - _utcnow()).total_seconds())
            return False, f"Please wait {remaining} seconds before requesting another email"
    
    # Generate new token
    plain_token = await create_verification_token(user, db)
    
    # Build verification URL
    frontend_url = getattr(settings, 'FRONTEND_URL', 'https://dev-swat.com')
    verification_url = f"{frontend_url}/verify-email?token={plain_token}"
    
    # Send email
    await send_verification_email(
        email=user.email,
        verification_url=verification_url,
        user_name=user.full_name,
    )
    
    return True, "Verification email sent"
