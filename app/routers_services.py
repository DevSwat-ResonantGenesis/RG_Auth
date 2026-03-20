"""
Google Service Connection Endpoints (Drive, Calendar, Gmail)
============================================================
Separate from SSO login — these endpoints let users grant their agents
access to Google services by storing OAuth refresh tokens.

This file is isolated from routers.py so that ANY failure here
can NEVER take down the core auth/login endpoints.
"""
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_db
from .models import UserApiKey
from .crypto import encrypt_api_key
from .oauth import (
    OAuthManager,
    OAUTH_PROVIDERS,
    generate_oauth_state,
    validate_oauth_state,
    is_provider_configured,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["google-services"])

_oauth_manager = OAuthManager()

# ── helpers ────────────────────────────────────────────────────────────

GOOGLE_SERVICE_SCOPES: Dict[str, list] = {
    "google-drive": [
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/drive.file",
    ],
    "google-calendar": [
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/calendar.events",
    ],
    "gmail": [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
    ],
}


async def _get_identity(request: Request, db: AsyncSession):
    """Re-use the identity extraction from the main routers module."""
    from .routers import _get_identity_from_request
    return await _get_identity_from_request(request, db)


# ── request / response models ─────────────────────────────────────────

class GoogleServiceInitiateRequest(BaseModel):
    service: str  # google-drive, google-calendar, gmail
    redirect_uri: Optional[str] = None


class GoogleServiceCallbackRequest(BaseModel):
    code: str
    state: str
    service: str


# ── endpoints ──────────────────────────────────────────────────────────

@router.post("/auth/services/google/initiate")
async def google_service_initiate(
    payload: GoogleServiceInitiateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate Google OAuth for service connection (Drive/Calendar/Gmail).
    Returns an authorization URL the frontend redirects the user to.
    """
    identity = await _get_identity(request, db)

    service = payload.service.lower()
    if service not in GOOGLE_SERVICE_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown service '{service}'. Supported: {', '.join(GOOGLE_SERVICE_SCOPES.keys())}",
        )

    if not is_provider_configured("google"):
        raise HTTPException(status_code=501, detail="Google OAuth is not configured on this platform.")

    google_config = OAUTH_PROVIDERS["google"]

    scopes = ["openid", "email", "profile"] + GOOGLE_SERVICE_SCOPES[service]

    # Reuse the SAME registered callback URL as login
    callback_url = payload.redirect_uri or (
        _oauth_manager.frontend_url + "/auth/oauth/callback"
    )

    state = generate_oauth_state(
        provider="google",
        redirect_uri=callback_url,
        extra_data={
            "service_connection": True,
            "service": service,
            "user_id": str(identity.user_id),
        },
    )

    params = {
        "client_id": google_config.client_id,
        "redirect_uri": callback_url,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }

    authorization_url = f"{google_config.authorize_url}?{urlencode(params)}"

    logger.info(
        "Google service connection initiated: service=%s user=%s",
        service, identity.user_id,
    )

    return {
        "authorization_url": authorization_url,
        "state": state,
        "provider": f"google-service-{service}",
        "service": service,
    }


@router.post("/auth/services/google/callback")
async def google_service_callback(
    payload: GoogleServiceCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google OAuth callback for service connections.
    Exchanges the code for tokens and stores the refresh_token
    in user_api_keys for the agent to use.
    """
    identity = await _get_identity(request, db)

    state_data = validate_oauth_state(payload.state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    extra = state_data.get("extra_data", {})
    if not extra.get("service_connection"):
        raise HTTPException(status_code=400, detail="Not a service connection state")

    service = extra.get("service", payload.service)
    stored_user_id = extra.get("user_id")

    if stored_user_id and str(identity.user_id) != stored_user_id:
        raise HTTPException(status_code=403, detail="User mismatch in OAuth state")

    if not is_provider_configured("google"):
        raise HTTPException(status_code=501, detail="Google OAuth is not configured")

    google_config = OAUTH_PROVIDERS["google"]
    redirect_uri = state_data.get("redirect_uri", "")

    # Exchange code for tokens
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                google_config.token_url,
                data={
                    "client_id": google_config.client_id,
                    "client_secret": google_config.client_secret,
                    "code": payload.code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()
    except httpx.HTTPError as e:
        logger.error("Google token exchange failed: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to exchange code: {e}")

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="No access token from Google")

    token_to_store = refresh_token or access_token
    key_prefix = f"g_{service.replace('google-', '')[:8]}"

    existing = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == service,
        )
    )
    existing_key = existing.scalar_one_or_none()

    friendly_name = f"Google {service.replace('google-', '').replace('-', ' ').title()}"

    if existing_key:
        existing_key.encrypted_key = encrypt_api_key(token_to_store)
        existing_key.key_prefix = key_prefix
        existing_key.is_valid = True
        existing_key.name = friendly_name
        await db.commit()
        key_id = str(existing_key.id)
    else:
        new_key = UserApiKey(
            user_id=identity.user_id,
            provider=service,
            name=friendly_name,
            encrypted_key=encrypt_api_key(token_to_store),
            key_prefix=key_prefix,
            is_valid=True,
        )
        db.add(new_key)
        await db.commit()
        await db.refresh(new_key)
        key_id = str(new_key.id)

    logger.info(
        "Google service connected: service=%s user=%s has_refresh=%s",
        service, identity.user_id, bool(refresh_token),
    )

    return {
        "status": "connected",
        "service": service,
        "key_id": key_id,
        "has_refresh_token": bool(refresh_token),
    }


# ── Slack service connection ──────────────────────────────────────────

SLACK_BOT_SCOPES = [
    "channels:read", "channels:history", "chat:write",
    "users:read", "users:read.email", "im:write",
]


class SlackServiceInitiateRequest(BaseModel):
    redirect_uri: Optional[str] = None


class SlackServiceCallbackRequest(BaseModel):
    code: str
    state: str


@router.post("/auth/services/slack/initiate")
async def slack_service_initiate(
    payload: SlackServiceInitiateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Initiate Slack OAuth for service connection (bot token for agents)."""
    identity = await _get_identity(request, db)

    if not is_provider_configured("slack"):
        raise HTTPException(status_code=501, detail="Slack OAuth is not configured on this platform.")

    slack_config = OAUTH_PROVIDERS["slack"]

    callback_url = payload.redirect_uri or (
        _oauth_manager.frontend_url + "/auth/oauth/callback"
    )

    state = generate_oauth_state(
        provider="slack",
        redirect_uri=callback_url,
        extra_data={
            "service_connection": True,
            "service": "slack",
            "user_id": str(identity.user_id),
        },
    )

    params = {
        "client_id": slack_config.client_id,
        "redirect_uri": callback_url,
        "scope": ",".join(SLACK_BOT_SCOPES),
        "state": state,
    }

    authorization_url = f"{slack_config.authorize_url}?{urlencode(params)}"

    logger.info("Slack service connection initiated: user=%s", identity.user_id)

    return {
        "authorization_url": authorization_url,
        "state": state,
        "provider": "slack",
    }


@router.post("/auth/services/slack/callback")
async def slack_service_callback(
    payload: SlackServiceCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Slack OAuth callback — store bot access token for agent use."""
    identity = await _get_identity(request, db)

    state_data = validate_oauth_state(payload.state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    extra = state_data.get("extra_data", {})
    if not extra.get("service_connection"):
        raise HTTPException(status_code=400, detail="Not a service connection state")

    stored_user_id = extra.get("user_id")
    if stored_user_id and str(identity.user_id) != stored_user_id:
        raise HTTPException(status_code=403, detail="User mismatch in OAuth state")

    if not is_provider_configured("slack"):
        raise HTTPException(status_code=501, detail="Slack OAuth is not configured")

    slack_config = OAUTH_PROVIDERS["slack"]
    redirect_uri = state_data.get("redirect_uri", "")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                slack_config.token_url,
                data={
                    "client_id": slack_config.client_id,
                    "client_secret": slack_config.client_secret,
                    "code": payload.code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()
    except httpx.HTTPError as e:
        logger.error("Slack token exchange failed: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to exchange code: {e}")

    if not tokens.get("ok"):
        raise HTTPException(status_code=400, detail=f"Slack error: {tokens.get('error', 'unknown')}")

    access_token = tokens.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="No access token from Slack")

    team_name = tokens.get("team", {}).get("name", "Slack")
    key_prefix = f"xoxb-{access_token[5:13]}..." if len(access_token) > 13 else "xoxb-..."

    existing = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == "slack",
        )
    )
    existing_key = existing.scalar_one_or_none()

    friendly_name = f"Slack ({team_name})"

    if existing_key:
        existing_key.encrypted_key = encrypt_api_key(access_token)
        existing_key.key_prefix = key_prefix
        existing_key.is_valid = True
        existing_key.name = friendly_name
        await db.commit()
        key_id = str(existing_key.id)
    else:
        new_key = UserApiKey(
            user_id=identity.user_id,
            provider="slack",
            name=friendly_name,
            encrypted_key=encrypt_api_key(access_token),
            key_prefix=key_prefix,
            is_valid=True,
        )
        db.add(new_key)
        await db.commit()
        await db.refresh(new_key)
        key_id = str(new_key.id)

    logger.info("Slack service connected: user=%s team=%s", identity.user_id, team_name)

    return {
        "status": "connected",
        "service": "slack",
        "key_id": key_id,
        "team_name": team_name,
    }


# ── Phase 2.3: Unified Integration Hub Status ─────────────────────────

INTEGRATION_CATALOG = [
    {"id": "google-drive", "name": "Google Drive", "icon": "google-drive", "category": "storage", "provider": "google"},
    {"id": "google-calendar", "name": "Google Calendar", "icon": "calendar", "category": "productivity", "provider": "google"},
    {"id": "gmail", "name": "Gmail", "icon": "mail", "category": "communication", "provider": "google"},
    {"id": "slack", "name": "Slack", "icon": "slack", "category": "communication", "provider": "slack"},
    {"id": "github", "name": "GitHub", "icon": "github", "category": "development", "provider": "github"},
    {"id": "openai", "name": "OpenAI", "icon": "openai", "category": "ai_provider", "provider": "openai"},
    {"id": "anthropic", "name": "Anthropic", "icon": "anthropic", "category": "ai_provider", "provider": "anthropic"},
    {"id": "groq", "name": "Groq", "icon": "groq", "category": "ai_provider", "provider": "groq"},
    {"id": "google-ai", "name": "Google AI (Gemini)", "icon": "google", "category": "ai_provider", "provider": "google"},
    {"id": "mistral", "name": "Mistral AI", "icon": "mistral", "category": "ai_provider", "provider": "mistral"},
]


@router.get("/auth/integrations")
async def list_integrations(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Unified Integration Hub — list all integrations and their connection status for the user."""
    identity = await _get_identity(request, db)

    # Get user's connected services (API keys)
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.is_valid == True,
        )
    )
    connected_keys = {k.provider: k for k in result.scalars().all()}

    # Get available OAuth providers
    from .oauth import get_available_providers
    oauth_providers = get_available_providers()

    integrations = []
    for item in INTEGRATION_CATALOG:
        provider = item["provider"]
        item_id = item["id"]

        connected = item_id in connected_keys or provider in connected_keys
        key_obj = connected_keys.get(item_id) or connected_keys.get(provider)

        can_connect = (
            provider in oauth_providers
            or item["category"] == "ai_provider"
        )

        integrations.append({
            "id": item_id,
            "name": item["name"],
            "icon": item["icon"],
            "category": item["category"],
            "connected": connected,
            "can_connect": can_connect,
            "key_name": key_obj.name if key_obj else None,
            "connected_at": key_obj.created_at.isoformat() if key_obj and key_obj.created_at else None,
        })

    return {
        "integrations": integrations,
        "connected_count": sum(1 for i in integrations if i["connected"]),
        "available_count": len(integrations),
    }


@router.get("/auth/integrations/{integration_id}/status")
async def integration_status(
    integration_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed status for a specific integration."""
    identity = await _get_identity(request, db)

    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == integration_id,
        )
    )
    key = result.scalar_one_or_none()

    if not key:
        return {
            "integration_id": integration_id,
            "connected": False,
            "message": "Not connected",
        }

    return {
        "integration_id": integration_id,
        "connected": True,
        "is_valid": key.is_valid,
        "name": key.name,
        "key_prefix": key.key_prefix,
        "created_at": key.created_at.isoformat() if key.created_at else None,
        "last_validated": key.last_validated_at.isoformat() if key.last_validated_at else None,
    }
