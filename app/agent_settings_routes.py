"""
Agent settings extended routes — templates, sharing, import/export, anchors,
agent API keys, memory, metrics, patches, restrictions.
Extracted from routers.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from .db import get_db
from .deps import _get_identity_from_request, _utcnow
from .models import Agent, AgentApiKey
from .schemas import (
    AgentApiKeyCreateRequest,
    AgentApiKeyResponse,
    AgentRestrictionsRequest,
)

router = APIRouter()


DEFAULT_RESTRICTIONS = {
    "blocked_topics": [],
    "allowed_domains": [],
    "blocked_domains": [],
    "max_tokens_per_message": 4096,
    "max_messages_per_hour": 100,
    "allowed_tools": [],
    "blocked_tools": [],
    "content_filter_level": "medium",
}


@router.get("/auth/settings/agents/templates")
async def list_agent_templates(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List available agent templates."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.is_template == True, Agent.is_public == True)
    )
    templates = result.scalars().all()
    
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "description": t.description,
            "system_prompt": t.system_prompt,
            "personality_config": t.personality_config or {},
        }
        for t in templates
    ]


@router.get("/auth/settings/agents/shared")
async def list_shared_agents(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List agents shared with current user."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.is_shared == True, Agent.is_public == True)
    )
    shared = result.scalars().all()
    
    return [
        {
            "id": str(a.id),
            "name": a.name,
            "description": a.description,
            "owner_id": str(a.user_id),
        }
        for a in shared
    ]


@router.post("/auth/settings/agents/from-template/{template_id}")
async def create_agent_from_template(
    template_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new agent from a template."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(template_id), Agent.is_template == True)
    )
    template = result.scalar_one_or_none()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    hash_input = f"{identity.user_id}:{template.name}:{datetime.now().isoformat()}"
    agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    new_agent = Agent(
        user_id=identity.user_id,
        org_id=identity.org_id,
        name=f"{template.name} (Copy)",
        description=template.description,
        system_prompt=template.system_prompt,
        personality_config=template.personality_config,
        enabled_patches=template.enabled_patches,
        patch_config=template.patch_config,
        memory_config=template.memory_config,
        anchor_config=template.anchor_config,
        isolate_anchors=template.isolate_anchors,
        agent_hash=agent_hash,
        template_id=template.id,
        status="active",
    )
    
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)
    
    return {
        "id": str(new_agent.id),
        "name": new_agent.name,
        "agent_hash": new_agent.agent_hash,
        "template_id": str(template.id),
    }


@router.post("/auth/settings/agents/import")
async def import_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Import an agent from export data."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    hash_input = f"{identity.user_id}:{body.get('name', 'Imported')}:{datetime.now().isoformat()}"
    agent_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    new_agent = Agent(
        user_id=identity.user_id,
        org_id=identity.org_id,
        name=body.get("name", "Imported Agent"),
        description=body.get("description"),
        system_prompt=body.get("system_prompt"),
        personality_config=body.get("personality_config", {}),
        enabled_patches=body.get("enabled_patches", []),
        patch_config=body.get("patch_config", {}),
        memory_config=body.get("memory_config", {}),
        anchor_config=body.get("anchor_config", {}),
        isolate_anchors=body.get("isolate_anchors", True),
        agent_hash=agent_hash,
        is_imported=True,
        status="active",
    )
    
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)
    
    return {
        "id": str(new_agent.id),
        "name": new_agent.name,
        "agent_hash": new_agent.agent_hash,
        "imported": True,
    }


@router.post("/auth/settings/agents/{agent_id}/export")
async def export_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Export an agent's configuration."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "name": agent.name,
        "description": agent.description,
        "system_prompt": agent.system_prompt,
        "personality_config": agent.personality_config or {},
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
        "memory_config": agent.memory_config or {},
        "anchor_config": agent.anchor_config or {},
        "isolate_anchors": agent.isolate_anchors,
        "exported_at": datetime.now().isoformat(),
    }


@router.post("/auth/settings/agents/{agent_id}/share")
async def share_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Share an agent with others."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    share_secret = secrets.token_urlsafe(16)
    agent.is_shared = True
    agent.share_secret = share_secret
    await db.commit()
    
    return {
        "shared": True,
        "share_url": f"/agents/shared/{share_secret}",
        "share_secret": share_secret,
    }


@router.post("/auth/settings/agents/{agent_id}/save-template")
async def save_agent_as_template(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Save an agent as a template."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.is_template = True
    await db.commit()
    
    return {
        "template_id": str(agent.id),
        "is_template": True,
    }


@router.post("/auth/settings/agents/{agent_id}/hash")
async def regenerate_agent_hash(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Regenerate agent's hash."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    hash_input = f"{identity.user_id}:{agent.name}:{datetime.now().isoformat()}"
    new_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
    
    agent.agent_hash = new_hash
    await db.commit()
    
    return {
        "agent_hash": new_hash,
        "regenerated_at": datetime.now().isoformat(),
    }


@router.get("/auth/settings/agents/{agent_id}/anchors")
async def get_agent_anchors(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get anchors for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return agent.anchor_config.get("anchors", []) if agent.anchor_config else []


@router.delete("/auth/settings/agents/{agent_id}/anchors/{anchor_id}")
async def delete_agent_anchor(
    agent_id: str,
    anchor_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an anchor from an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.anchor_config and "anchors" in agent.anchor_config:
        agent.anchor_config["anchors"] = [
            a for a in agent.anchor_config["anchors"] if a.get("id") != anchor_id
        ]
        await db.commit()
    
    return {"deleted": True, "anchor_id": anchor_id}


@router.get("/auth/settings/agents/{agent_id}/api-keys")
async def get_agent_api_keys(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get API keys for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    keys_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    keys = keys_result.scalars().all()
    
    return {
        "keys": [
            {
                "id": str(k.id),
                "name": k.name,
                "prefix": k.prefix,
                "scopes": k.scopes or [],
                "rate_limit": k.rate_limit,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "is_active": k.is_active,
            }
            for k in keys
        ],
        "count": len(keys),
    }


@router.post("/auth/settings/agents/{agent_id}/api-keys")
async def create_agent_api_key(
    agent_id: str,
    payload: AgentApiKeyCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Create an API key for an agent.
    
    Returns the full API key ONCE - it cannot be retrieved again.
    Store it securely.
    """
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    existing = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.name == payload.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"API key with name '{payload.name}' already exists")
    
    key_plain = f"rga_{secrets.token_urlsafe(32)}"
    key_prefix = key_plain[:12]
    key_hash = hashlib.sha256(key_plain.encode()).hexdigest()
    
    expires_at = None
    if payload.expires_in_days:
        expires_at = _utcnow() + timedelta(days=payload.expires_in_days)
    
    api_key = AgentApiKey(
        agent_id=UUID(agent_id),
        user_id=identity.user_id,
        name=payload.name,
        prefix=key_prefix,
        hashed_key=key_hash,
        scopes=payload.scopes or ["chat", "query"],
        rate_limit=payload.rate_limit or 100,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key": key_plain,
        "prefix": key_prefix,
        "scopes": api_key.scopes,
        "rate_limit": api_key.rate_limit,
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "created_at": api_key.created_at.isoformat(),
        "warning": "Store this key securely. It will not be shown again.",
    }


@router.delete("/auth/settings/agents/{agent_id}/api-keys/{key_id}")
async def delete_agent_api_key(
    agent_id: str,
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    key_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.id == key_uuid,
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    api_key = key_result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    await db.delete(api_key)
    await db.commit()
    
    return {
        "deleted": True,
        "key_id": key_id,
        "name": api_key.name,
    }


@router.put("/auth/settings/agents/{agent_id}/api-keys/{key_id}")
async def update_agent_api_key(
    agent_id: str,
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update an API key for an agent (name, scopes, rate_limit, is_active)."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    key_result = await db.execute(
        select(AgentApiKey).where(
            AgentApiKey.id == key_uuid,
            AgentApiKey.agent_id == UUID(agent_id),
            AgentApiKey.user_id == identity.user_id,
        )
    )
    api_key = key_result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    if "name" in body:
        api_key.name = body["name"]
    if "scopes" in body:
        api_key.scopes = body["scopes"]
    if "rate_limit" in body:
        api_key.rate_limit = body["rate_limit"]
    if "is_active" in body:
        api_key.is_active = body["is_active"]
    
    await db.commit()
    await db.refresh(api_key)
    
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "prefix": api_key.prefix,
        "scopes": api_key.scopes,
        "rate_limit": api_key.rate_limit,
        "is_active": api_key.is_active,
        "updated": True,
    }


@router.get("/auth/settings/agents/{agent_id}/memory")
async def get_agent_memory(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get memory configuration for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return agent.memory_config or {}


@router.put("/auth/settings/agents/{agent_id}/memory")
async def update_agent_memory(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update memory configuration for an agent."""
    identity = await _get_identity_from_request(request, db)
    body = await request.json()
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.memory_config = body
    await db.commit()
    
    return agent.memory_config


@router.get("/auth/settings/agents/{agent_id}/metrics")
async def get_agent_metrics(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get metrics for an agent.
    
    Returns placeholder metrics - real metrics tracking is not yet implemented.
    """
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "total_messages": 0,
        "total_tokens": 0,
        "average_response_time_ms": 0,
        "success_rate": 1.0,
        "last_active": None,
        "message": "Agent metrics tracking is not yet implemented. These are placeholder values.",
    }


@router.get("/auth/settings/agents/{agent_id}/patches")
async def get_agent_patches(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get enabled patches for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "enabled_patches": agent.enabled_patches or [],
        "patch_config": agent.patch_config or {},
    }


@router.get("/auth/settings/agents/{agent_id}/restrictions")
async def get_agent_restrictions(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get restrictions for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    restrictions = {**DEFAULT_RESTRICTIONS, **(agent.restrictions or {})}
    
    return restrictions


@router.put("/auth/settings/agents/{agent_id}/restrictions")
async def update_agent_restrictions(
    agent_id: str,
    payload: AgentRestrictionsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update restrictions for an agent."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(Agent).where(Agent.id == UUID(agent_id), Agent.user_id == identity.user_id)
    )
    agent = result.scalar_one_or_none()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    current = agent.restrictions or {}
    
    updates = payload.model_dump(exclude_none=True)
    new_restrictions = {**current, **updates}
    
    if new_restrictions.get("content_filter_level") not in (None, "none", "low", "medium", "high"):
        raise HTTPException(status_code=400, detail="Invalid content_filter_level. Must be: none, low, medium, high")
    
    if new_restrictions.get("max_tokens_per_message", 0) > 32000:
        raise HTTPException(status_code=400, detail="max_tokens_per_message cannot exceed 32000")
    
    if new_restrictions.get("max_messages_per_hour", 0) > 10000:
        raise HTTPException(status_code=400, detail="max_messages_per_hour cannot exceed 10000")
    
    agent.restrictions = new_restrictions
    await db.commit()
    
    return {
        "success": True,
        "message": "Agent restrictions updated",
        "restrictions": {**DEFAULT_RESTRICTIONS, **new_restrictions},
    }
