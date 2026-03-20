"""
Session management module for the auth service.

Provides:
- List active sessions
- Revoke specific sessions
- Revoke all sessions except current
- Device parsing from user agent
- Location lookup from IP (stub)
"""
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import RefreshToken, TrustedDevice, User
from .config import settings


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def parse_device_info(user_agent: Optional[str]) -> Tuple[str, str]:
    """
    Parse device name and type from user agent string.
    
    Returns:
        Tuple of (device_name, device_type)
    """
    if not user_agent:
        return "Unknown Device", "unknown"
    
    ua_lower = user_agent.lower()
    
    # Detect device type
    if any(x in ua_lower for x in ["mobile", "android", "iphone", "ipad"]):
        if "ipad" in ua_lower or "tablet" in ua_lower:
            device_type = "tablet"
        else:
            device_type = "mobile"
    else:
        device_type = "desktop"
    
    # Parse browser name
    browser = "Unknown Browser"
    if "chrome" in ua_lower and "edg" not in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "opera" in ua_lower or "opr" in ua_lower:
        browser = "Opera"
    
    # Parse OS
    os_name = "Unknown OS"
    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macos" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower and "android" not in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    
    device_name = f"{browser} on {os_name}"
    return device_name, device_type


def get_location_from_ip(ip_address: Optional[str]) -> Optional[str]:
    """
    Get location from IP address synchronously (for non-async contexts).
    
    For async contexts, use geoip.get_location_from_ip() directly.
    """
    if not ip_address:
        return None
    
    # Local/private IPs
    if ip_address.startswith(("127.", "10.", "172.", "192.168.", "::1")):
        return "Local Network"
    
    # For sync contexts, return None - async callers should use geoip module
    return None


async def get_location_from_ip_async(ip_address: Optional[str]) -> Optional[str]:
    """
    Get location from IP address asynchronously using GeoIP service.
    """
    from .geoip import get_location_from_ip as geoip_lookup
    return await geoip_lookup(ip_address)


def generate_device_fingerprint(
    user_agent: Optional[str],
    ip_address: Optional[str],
) -> str:
    """
    Generate a fingerprint for device identification.
    
    Uses user agent as the primary identifier.
    """
    data = f"{user_agent or 'unknown'}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


async def get_active_sessions(
    user_id: UUID,
    db: AsyncSession,
    current_token_hash: Optional[str] = None,
) -> List[dict]:
    """
    Get all active sessions for a user.
    
    Returns list of session info dicts.
    """
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > _utcnow(),
        ).order_by(RefreshToken.created_at.desc())
    )
    tokens = result.scalars().all()
    
    sessions = []
    for token in tokens:
        device_name, device_type = parse_device_info(token.user_agent)
        
        sessions.append({
            "id": str(token.id),
            "device_name": token.device_name or device_name,
            "device_type": token.device_type or device_type,
            "ip_address": token.ip_address,
            "location": token.location or get_location_from_ip(token.ip_address),
            "created_at": token.created_at.isoformat() if token.created_at else None,
            "last_active_at": (token.last_active_at or token.created_at).isoformat() if (token.last_active_at or token.created_at) else None,
            "is_current": current_token_hash and token.token_hash == current_token_hash,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        })
    
    return sessions


async def revoke_session(
    user_id: UUID,
    session_id: UUID,
    db: AsyncSession,
) -> Tuple[bool, str]:
    """
    Revoke a specific session.
    
    Returns:
        Tuple of (success, message)
    """
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.id == session_id,
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    token = result.scalar_one_or_none()
    
    if not token:
        return False, "Session not found or already revoked"
    
    token.revoked_at = _utcnow()
    await db.commit()
    
    return True, "Session revoked successfully"


async def revoke_all_sessions(
    user_id: UUID,
    db: AsyncSession,
    except_session_id: Optional[UUID] = None,
) -> int:
    """
    Revoke all sessions for a user, optionally except one.
    
    Returns:
        Number of sessions revoked
    """
    query = select(RefreshToken).where(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    )
    
    if except_session_id:
        query = query.where(RefreshToken.id != except_session_id)
    
    result = await db.execute(query)
    tokens = result.scalars().all()
    
    count = 0
    for token in tokens:
        token.revoked_at = _utcnow()
        count += 1
    
    await db.commit()
    return count


async def update_session_activity(
    token_hash: str,
    db: AsyncSession,
) -> None:
    """Update last_active_at for a session."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token = result.scalar_one_or_none()
    
    if token:
        token.last_active_at = _utcnow()
        await db.commit()


# ============================================
# Trusted Device Management
# ============================================

TRUSTED_DEVICE_DURATION_DAYS = 30


async def is_device_trusted(
    user_id: UUID,
    user_agent: Optional[str],
    ip_address: Optional[str],
    db: AsyncSession,
) -> bool:
    """Check if the current device is trusted for MFA bypass."""
    fingerprint = generate_device_fingerprint(user_agent, ip_address)
    
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == fingerprint,
            TrustedDevice.trusted_until > _utcnow(),
        )
    )
    device = result.scalar_one_or_none()
    
    if device:
        # Update last used
        device.last_used_at = _utcnow()
        await db.commit()
        return True
    
    return False


async def trust_device(
    user_id: UUID,
    user_agent: Optional[str],
    ip_address: Optional[str],
    db: AsyncSession,
) -> dict:
    """
    Mark current device as trusted for MFA bypass.
    
    Returns device info dict.
    """
    fingerprint = generate_device_fingerprint(user_agent, ip_address)
    device_name, device_type = parse_device_info(user_agent)
    
    # Check if already trusted
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == fingerprint,
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Extend trust period
        existing.trusted_until = _utcnow() + timedelta(days=TRUSTED_DEVICE_DURATION_DAYS)
        existing.last_used_at = _utcnow()
        await db.commit()
        
        return {
            "id": str(existing.id),
            "device_name": existing.device_name,
            "trusted_until": existing.trusted_until.isoformat(),
        }
    
    # Create new trusted device
    device = TrustedDevice(
        user_id=user_id,
        device_fingerprint=fingerprint,
        device_name=device_name,
        device_type=device_type,
        user_agent=user_agent[:500] if user_agent else None,
        ip_address=ip_address,
        trusted_until=_utcnow() + timedelta(days=TRUSTED_DEVICE_DURATION_DAYS),
        last_used_at=_utcnow(),
    )
    db.add(device)
    await db.commit()
    
    return {
        "id": str(device.id),
        "device_name": device_name,
        "trusted_until": device.trusted_until.isoformat(),
    }


async def get_trusted_devices(
    user_id: UUID,
    db: AsyncSession,
) -> List[dict]:
    """Get all trusted devices for a user."""
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.trusted_until > _utcnow(),
        ).order_by(TrustedDevice.last_used_at.desc())
    )
    devices = result.scalars().all()
    
    return [
        {
            "id": str(d.id),
            "device_name": d.device_name,
            "device_type": d.device_type,
            "ip_address": d.ip_address,
            "trusted_until": d.trusted_until.isoformat() if d.trusted_until else None,
            "last_used_at": d.last_used_at.isoformat() if d.last_used_at else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        }
        for d in devices
    ]


async def revoke_trusted_device(
    user_id: UUID,
    device_id: UUID,
    db: AsyncSession,
) -> Tuple[bool, str]:
    """Revoke trust for a specific device."""
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.id == device_id,
            TrustedDevice.user_id == user_id,
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        return False, "Device not found"
    
    await db.delete(device)
    await db.commit()
    
    return True, "Device removed from trusted devices"


async def revoke_all_trusted_devices(
    user_id: UUID,
    db: AsyncSession,
) -> int:
    """Revoke all trusted devices for a user."""
    result = await db.execute(
        select(TrustedDevice).where(TrustedDevice.user_id == user_id)
    )
    devices = result.scalars().all()
    
    count = len(devices)
    for device in devices:
        await db.delete(device)
    
    await db.commit()
    return count
