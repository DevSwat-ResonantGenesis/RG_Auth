"""Scoped workspace access tokens (RGW- prefix) - see WorkspaceAccessToken's
docstring in models.py for why these are a distinct type from the org-level
RG- API keys in api_keys_routes.py.
"""
from __future__ import annotations

from datetime import datetime
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .deps import _get_identity_from_request
from .models import Workspace, WorkspaceAccessToken
from .security import generate_workspace_token, hash_token

router = APIRouter()


@router.post("/auth/user/workspaces/{workspace_id}/token")
async def mint_workspace_token(workspace_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Mint a fresh RGW- token for a workspace the caller owns. Called by
    RG_Terminal_Sandbox (via Gateway) when creating that workspace's
    container, not directly by the browser - shown to the user once via
    the terminal's connect banner, never persisted client-side in plaintext.
    """
    identity = await _get_identity_from_request(request, db)
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if not workspace or workspace.user_id != identity.user_id:
        raise HTTPException(status_code=404, detail="Workspace not found")

    token, prefix, hashed = generate_workspace_token()
    record = WorkspaceAccessToken(
        user_id=identity.user_id,
        workspace_id=workspace.id,
        prefix=prefix,
        hashed_secret=hashed,
        scopes=["agents:*", "builder:*"],
    )
    db.add(record)
    await db.commit()
    return {"token": token, "scopes": record.scopes}


class WorkspaceTokenVerifyRequest(BaseModel):
    token: str


class InternalMintRequest(BaseModel):
    user_id: str
    workspace_id: str


def _require_internal(request: Request) -> None:
    internal_key = request.headers.get("x-internal-service-key")
    client_host = request.client.host if request.client else ""
    forwarded_for = request.headers.get("x-forwarded-for", "")
    is_internal = (
        internal_key == settings.INTERNAL_SERVICE_KEY or
        forwarded_for.startswith("10.") or
        forwarded_for.startswith("172.") or
        client_host in ["127.0.0.1", "localhost"] or
        client_host.startswith("10.") or
        client_host.startswith("172.")
    )
    if not is_internal and settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=403, detail="Internal endpoint - access denied")


@router.post("/auth/internal/workspace-tokens/mint")
async def mint_workspace_token_internal(
    payload: InternalMintRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called by RG_Terminal_Sandbox when it creates a workspace's
    container (docker_manager.create_container), so RG_WORKSPACE_TOKEN can
    be injected as an env var. Mints a fresh token each time rather than
    trying to reuse a prior one - the plaintext secret only ever exists at
    mint time (only its hash is stored), so there's nothing to "reuse".
    """
    _require_internal(request)

    token, prefix, hashed = generate_workspace_token()
    record = WorkspaceAccessToken(
        user_id=payload.user_id,
        workspace_id=payload.workspace_id,
        prefix=prefix,
        hashed_secret=hashed,
        scopes=["agents:*", "builder:*"],
    )
    db.add(record)
    await db.commit()
    return {"token": token, "scopes": record.scopes}


@router.post("/auth/internal/workspace-tokens/verify")
async def verify_workspace_token(
    payload: WorkspaceTokenVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Called by RG_Gateway on every request bearing an RGW- token."""
    _require_internal(request)

    token = (payload.token or "").strip()
    if not token.startswith("RGW-") or "." not in token:
        raise HTTPException(status_code=401, detail="Invalid workspace token")

    try:
        prefix = token.split("RGW-", 1)[1].split(".", 1)[0]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid workspace token")
    if not prefix:
        raise HTTPException(status_code=401, detail="Invalid workspace token")

    hashed = hash_token(token)
    result = await db.execute(select(WorkspaceAccessToken).where(WorkspaceAccessToken.prefix == prefix))
    record = result.scalar_one_or_none()
    if not record or not hmac.compare_digest(str(record.hashed_secret or ""), str(hashed or "")):
        raise HTTPException(status_code=401, detail="Invalid workspace token")
    if record.expires_at and record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Workspace token expired")

    return {
        "user_id": str(record.user_id),
        "workspace_id": str(record.workspace_id),
        "scopes": record.scopes or [],
    }
