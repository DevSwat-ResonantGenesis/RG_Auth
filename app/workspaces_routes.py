"""Workspaces - a persistent, titled project identity shared across the
IDE, sandboxed terminal, Builder, and Agent OS. See Workspace's docstring
in models.py for why this exists (today's project_id is an unminted UUID
with no backing row anywhere).
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_db
from .deps import _get_identity_from_request
from .models import Workspace

router = APIRouter()


class WorkspaceCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)


class WorkspaceUpdate(BaseModel):
    title: str | None = None
    touch: bool = False  # bump last_active_at without changing anything else


def _to_response(w: Workspace) -> dict:
    return {
        "id": str(w.id),
        "title": w.title,
        "created_at": w.created_at.isoformat() if w.created_at else None,
        "last_active_at": w.last_active_at.isoformat() if w.last_active_at else None,
    }


@router.get("/auth/user/workspaces")
async def list_workspaces(request: Request, db: AsyncSession = Depends(get_db)):
    identity = await _get_identity_from_request(request, db)
    result = await db.execute(
        select(Workspace).where(Workspace.user_id == identity.user_id).order_by(Workspace.last_active_at.desc())
    )
    return {"workspaces": [_to_response(w) for w in result.scalars().all()]}


@router.post("/auth/user/workspaces")
async def create_workspace(
    request: Request,
    payload: WorkspaceCreate,
    db: AsyncSession = Depends(get_db),
):
    identity = await _get_identity_from_request(request, db)
    workspace = Workspace(user_id=identity.user_id, title=payload.title)
    db.add(workspace)
    await db.commit()
    await db.refresh(workspace)
    return _to_response(workspace)


async def _get_owned_workspace(workspace_id: str, identity, db: AsyncSession) -> Workspace:
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if not workspace or workspace.user_id != identity.user_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspace


@router.patch("/auth/user/workspaces/{workspace_id}")
async def update_workspace(
    workspace_id: str,
    request: Request,
    payload: WorkspaceUpdate,
    db: AsyncSession = Depends(get_db),
):
    identity = await _get_identity_from_request(request, db)
    workspace = await _get_owned_workspace(workspace_id, identity, db)
    if payload.title:
        workspace.title = payload.title
    if payload.touch or payload.title:
        workspace.last_active_at = datetime.utcnow()
    await db.commit()
    await db.refresh(workspace)
    return _to_response(workspace)


@router.delete("/auth/user/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    identity = await _get_identity_from_request(request, db)
    workspace = await _get_owned_workspace(workspace_id, identity, db)
    await db.delete(workspace)
    await db.commit()
    return {"deleted": True}
