"""
MFA (Multi-Factor Authentication) routes — TOTP, backup codes.
Extracted from routers.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_db
from .deps import _get_identity_from_request, _utcnow
from .models import User
from .security import verify_password
from .crypto import encrypt_api_key, decrypt_api_key
from .mfa import MFAManager, encrypt_mfa_secret, decrypt_mfa_secret, verify_totp_code, verify_backup_code
from .schemas import MFASetupResponse, MFAVerifyRequest, MFADisableRequest

router = APIRouter()

_mfa_manager = MFAManager()


@router.get("/auth/mfa/status")
async def get_mfa_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get MFA status for current user."""
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "enabled": user.mfa_enabled,
        "method": "totp" if user.mfa_enabled else None,
        "verified": user.mfa_verified_at is not None,
        "verified_at": user.mfa_verified_at.isoformat() if user.mfa_verified_at else None,
        "available": True,
        "backup_codes_remaining": len(user.mfa_backup_codes) if user.mfa_backup_codes else 0,
    }


@router.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Setup MFA for current user.
    
    Returns TOTP secret, QR code, and backup codes.
    User must verify with /auth/mfa/verify to enable MFA.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first to reconfigure."
        )
    
    # Generate MFA credentials
    secret, uri, qr_url, backup_codes, backup_hashes = _mfa_manager.setup_mfa(user.email)
    
    # Store encrypted secret and hashed backup codes (but don't enable yet)
    user.mfa_secret = encrypt_mfa_secret(secret)
    user.mfa_backup_codes = backup_hashes
    await db.commit()
    
    return MFASetupResponse(
        secret=secret,
        qr_code_url=qr_url,
        provisioning_uri=uri,
        backup_codes=backup_codes,
    )


@router.post("/auth/mfa/verify")
async def verify_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify MFA code and enable MFA.
    
    During initial setup, verifies the code matches the secret.
    After setup, this endpoint can be used to verify codes for testing.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_secret:
        raise HTTPException(
            status_code=400,
            detail="MFA not set up. Call /auth/mfa/setup first."
        )
    
    # Decrypt the stored secret
    secret = decrypt_mfa_secret(user.mfa_secret)
    
    # Verify the TOTP code
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Enable MFA if not already enabled
    if not user.mfa_enabled:
        user.mfa_enabled = True
        user.mfa_verified_at = _utcnow()
        user.token_version += 1  # Invalidate existing sessions
        await db.commit()
        
        return {
            "verified": True,
            "mfa_enabled": True,
            "message": "MFA has been enabled successfully.",
        }
    
    return {
        "verified": True,
        "mfa_enabled": True,
        "message": "MFA code verified.",
    }


@router.post("/auth/mfa/disable")
async def disable_mfa(
    payload: MFADisableRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Disable MFA for current user.
    
    Requires password confirmation and optionally a valid MFA code.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    # Verify password
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Optionally verify MFA code if provided
    if payload.code and user.mfa_secret:
        secret = decrypt_mfa_secret(user.mfa_secret)
        if not verify_totp_code(secret, payload.code):
            # Try backup code
            valid, idx = verify_backup_code(payload.code, user.mfa_backup_codes or [])
            if not valid:
                raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    user.mfa_verified_at = None
    user.token_version += 1  # Invalidate existing sessions
    await db.commit()
    
    return {
        "mfa_enabled": False,
        "message": "MFA has been disabled successfully.",
    }


@router.post("/auth/mfa/backup-codes/regenerate")
async def regenerate_backup_codes(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Regenerate backup codes for MFA.
    
    Invalidates all existing backup codes and generates new ones.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    from .mfa import generate_backup_codes
    backup_codes, backup_hashes = generate_backup_codes()
    
    user.mfa_backup_codes = backup_hashes
    await db.commit()
    
    return {
        "backup_codes": backup_codes,
        "message": "New backup codes generated. Store them securely.",
    }


@router.post("/auth/mfa/verify-backup")
async def verify_backup_code_endpoint(
    payload: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify and consume a backup code.
    
    Used when user doesn't have access to their authenticator app.
    Each backup code can only be used once.
    """
    identity = await _get_identity_from_request(request, db)
    user = await db.get(User, identity.user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    if not user.mfa_backup_codes:
        raise HTTPException(status_code=400, detail="No backup codes available")
    
    # Verify backup code
    valid, idx = verify_backup_code(payload.code, user.mfa_backup_codes)
    
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid backup code")
    
    # Remove used backup code
    user.mfa_backup_codes = [
        code for i, code in enumerate(user.mfa_backup_codes) if i != idx
    ]
    await db.commit()
    
    return {
        "verified": True,
        "backup_codes_remaining": len(user.mfa_backup_codes),
        "message": "Backup code verified and consumed.",
    }
