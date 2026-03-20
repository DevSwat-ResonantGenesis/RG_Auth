"""
Login notification module for the auth service.

Sends email notifications when:
- Login from a new device
- Login from a new location
- Login after account was locked
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import RefreshToken, User
from .sessions import parse_device_info, get_location_from_ip, generate_device_fingerprint
from .config import settings


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


async def check_new_device_login(
    user_id,
    user_agent: Optional[str],
    ip_address: Optional[str],
    db: AsyncSession,
) -> tuple[bool, Optional[str]]:
    """
    Check if this is a login from a new device.
    
    Returns:
        Tuple of (is_new_device, device_name)
    """
    if not user_agent:
        return False, None
    
    device_name, _ = parse_device_info(user_agent)
    
    # Check if we've seen this device before
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.user_agent == user_agent,
        ).limit(1)
    )
    existing = result.scalar_one_or_none()
    
    return existing is None, device_name


async def check_new_location_login(
    user_id,
    ip_address: Optional[str],
    db: AsyncSession,
) -> tuple[bool, Optional[str]]:
    """
    Check if this is a login from a new location.
    
    Returns:
        Tuple of (is_new_location, location_name)
    """
    if not ip_address:
        return False, None
    
    # Skip for local IPs
    if ip_address.startswith(("127.", "10.", "172.", "192.168.", "::1")):
        return False, None
    
    location = get_location_from_ip(ip_address)
    
    # Check if we've seen this IP before
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.ip_address == ip_address,
        ).limit(1)
    )
    existing = result.scalar_one_or_none()
    
    return existing is None, location


async def send_login_notification(
    user: User,
    device_name: str,
    ip_address: Optional[str],
    location: Optional[str],
    is_new_device: bool,
    is_new_location: bool,
) -> bool:
    """
    Send login notification email.
    
    Uses the email_service module which supports SendGrid in production
    and console output in development.
    """
    if not is_new_device and not is_new_location:
        return False
    
    from .email_service import send_login_notification_email
    return await send_login_notification_email(
        to=user.email,
        device_name=device_name,
        location=location,
        ip_address=ip_address,
        name=user.full_name,
    )


async def process_login_notification(
    user: User,
    user_agent: Optional[str],
    ip_address: Optional[str],
    db: AsyncSession,
) -> None:
    """
    Process login and send notification if needed.
    
    Called after successful login.
    """
    # Check for new device
    is_new_device, device_name = await check_new_device_login(
        user.id, user_agent, ip_address, db
    )
    
    # Check for new location
    is_new_location, location = await check_new_location_login(
        user.id, ip_address, db
    )
    
    # Send notification if new device or location
    if is_new_device or is_new_location:
        await send_login_notification(
            user=user,
            device_name=device_name or "Unknown Device",
            ip_address=ip_address,
            location=location,
            is_new_device=is_new_device,
            is_new_location=is_new_location,
        )
