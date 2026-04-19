"""
Session management + trusted device routes.
Extracted from routers.py.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .deps import _get_identity_from_request, REFRESH_COOKIE
from .models import RefreshToken, User
from .security import hash_token
from .audit import log_audit_event, AuditEventType, get_client_info

router = APIRouter()


# ============================================
# Session Management
# ============================================

@router.get("/auth/sessions")
async def list_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all active sessions for the current user."""
    from .sessions import get_active_sessions
    
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
