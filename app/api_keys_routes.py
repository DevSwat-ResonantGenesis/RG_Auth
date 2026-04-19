"""
Org-level API key routes — list, create, revoke, verify.
Extracted from routers.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
import hmac
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .deps import _get_identity_from_request, _utcnow
from .models import ApiKey, OrgMembership
from .security import generate_api_key, hash_token
from .schemas import (
    ApiKeyCreateRequest,
    ApiKeyResponse,
    ApiKeyVerifyRequest,
    ApiKeyVerifyResponse,
    RevokeApiKeyRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/auth/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the current organization."""
    identity = await _get_identity_from_request(request, db)

    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.org_id == identity.org_id)
        .order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        ApiKeyResponse(
            id=key.id,
            name=key.name,
            prefix=key.prefix,
            scopes=key.scopes or [],
            auth_method=key.auth_method,
            created_at=key.created_at,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
        )
        for key in keys
    ]


@router.post("/auth/api-keys", response_model=ApiKeyResponse, status_code=201)
async def create_api_key_endpoint(
    request: Request,
    payload: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key for the current organization."""
    identity = await _get_identity_from_request(request, db)

    # Generate plaintext API key and hashed form
    api_key_plain, prefix, hashed = generate_api_key()

    expires_at: Optional[datetime] = None
    if payload.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days)

    record = ApiKey(
        name=payload.name,
        prefix=prefix,
        hashed_key=hashed,
        org_id=identity.org_id,
        scopes=list(payload.scopes or []),
        auth_method=payload.auth_method,
        expires_at=expires_at,
        created_by_user_id=identity.user_id,
        is_global=False,
    )

    db.add(record)
    await db.commit()
    await db.refresh(record)

    return ApiKeyResponse(
        id=record.id,
        name=record.name,
        prefix=record.prefix,
        scopes=record.scopes or [],
        auth_method=record.auth_method,
        created_at=record.created_at,
        expires_at=record.expires_at,
        last_used_at=record.last_used_at,
        token=api_key_plain,
    )


@router.post("/auth/api-keys/revoke", status_code=204)
async def revoke_api_key_endpoint(
    request: Request,
    payload: RevokeApiKeyRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) an API key for the current organization."""
    identity = await _get_identity_from_request(request, db)

    record = await db.get(ApiKey, payload.api_key_id)
    if not record or record.org_id != identity.org_id:
        raise HTTPException(status_code=404, detail="API key not found")

    await db.delete(record)
    await db.commit()

    return Response(status_code=204)


@router.post("/auth/api-keys/verify", response_model=ApiKeyVerifyResponse)
async def verify_org_api_key(
    payload: ApiKeyVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """Verify an org API key and return identity context.

    This is used by the gateway to support paid API access without JWT.
    """
    api_key = (payload.api_key or "").strip()
    if not api_key.startswith("RG-"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    if "." not in api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        key_body = api_key.split("RG-", 1)[1]
        prefix = key_body.split(".", 1)[0]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not prefix:
        raise HTTPException(status_code=401, detail="Invalid API key")

    hashed = hash_token(api_key)

    result = await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not hmac.compare_digest(str(record.hashed_key or ""), str(hashed or "")):
        raise HTTPException(status_code=401, detail="Invalid API key")

    if record.expires_at and record.expires_at < _utcnow():
        raise HTTPException(status_code=401, detail="API key expired")

    # Update last_used timestamp
    record.last_used_at = _utcnow()
    await db.commit()

    org_id = str(record.org_id)

    resolved_user_id: Optional[str] = str(record.created_by_user_id) if record.created_by_user_id else None
    resolved_role: Optional[str] = None

    if not resolved_user_id:
        membership_result = await db.execute(
            select(OrgMembership)
            .where(OrgMembership.org_id == record.org_id, OrgMembership.status == "active")
            .order_by(OrgMembership.created_at.asc())
        )
        memberships = membership_result.scalars().all()
        if memberships:
            # Prefer owner/admin if present.
            owner = next((m for m in memberships if (m.role or "").lower() == "owner"), None)
            admin = next((m for m in memberships if (m.role or "").lower() in {"admin", "org_admin"}), None)
            chosen = owner or admin or memberships[0]
            resolved_user_id = str(chosen.user_id)
            resolved_role = chosen.role
    else:
        membership_result = await db.execute(
            select(OrgMembership)
            .where(
                OrgMembership.org_id == record.org_id,
                OrgMembership.user_id == UUID(resolved_user_id),
                OrgMembership.status == "active",
            )
        )
        membership = membership_result.scalar_one_or_none()
        resolved_role = membership.role if membership else None

    # Resolve plan from billing_service economic state headers (authoritative)
    plan: Optional[str] = None
    if resolved_user_id:
        try:
            billing_base = getattr(settings, "BILLING_URL", "http://billing_service:8000").rstrip("/")
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{billing_base}/economic-state/{resolved_user_id}/headers")
            if resp.status_code == 200:
                data = resp.json() or {}
                headers = data.get("headers", {}) if isinstance(data, dict) else {}
                tier = (headers.get("X-Subscription-Tier") or "").strip().lower()
                if tier in {"developer", "plus", "enterprise"}:
                    plan = tier
        except Exception:
            plan = None

    if plan is None:
        plan = "developer"

    return ApiKeyVerifyResponse(
        valid=True,
        user_id=resolved_user_id,
        org_id=org_id,
        role=resolved_role or "user",
        plan=plan,
        scopes=list(record.scopes or []),
        auth_method=record.auth_method or "api_key",
    )
