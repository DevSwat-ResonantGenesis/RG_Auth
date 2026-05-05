"""
User BYOK (Bring Your Own Key) API key routes — add, list, validate, delete provider keys.
Extracted from routers.py.
"""
from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .deps import _get_identity_from_request, _utcnow
from .models import User, UserApiKey
from .crypto import encrypt_api_key, decrypt_api_key
from .schemas import (
    AvailableProvidersResponse,
    ServiceAccessResponse,
    TrialStatusResponse,
    UserApiKeyCreate,
    UserApiKeyResponse,
    ValidateApiKeyRequest,
    ValidateApiKeyResponse,
)

router = APIRouter()


# Compatibility endpoint for chat_service internal calls
@router.get("/api-keys/user/{user_id}")
async def get_api_keys_by_user_id(
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get API keys for a specific user (internal service call).
    
    This endpoint is called by chat_service to retrieve user's API keys
    for BYOK (Bring Your Own Key) functionality.
    """
    try:
        result = await db.execute(
            select(UserApiKey).where(UserApiKey.user_id == user_id)
        )
        user_keys = result.scalars().all()
        
        keys = []
        for key in user_keys:
            keys.append({
                "id": str(key.id),
                "provider": key.provider,
                "name": key.name,
                "decrypted_key": decrypt_api_key(key.encrypted_key),
                "is_valid": key.is_valid,
            })
        
        return {"keys": keys}
    except Exception as e:
        return {"keys": []}


@router.get("/auth/user/api-keys")
async def get_user_api_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get all API keys for the current user (masked)."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.user_id == identity.user_id)
    )
    user_keys = result.scalars().all()
    
    keys = []
    for key in user_keys:
        keys.append({
            "id": str(key.id),
            "provider": key.provider,
            "name": key.name or f"{key.provider} Key",
            "key_prefix": key.key_prefix or "***",
            "is_valid": key.is_valid,
            "is_primary": getattr(key, 'is_primary', False),
            "created_at": key.created_at.isoformat() if key.created_at else None,
        })
    
    return {"keys": keys}


@router.post("/auth/user/api-keys")
async def add_user_api_key(
    request: Request,
    payload: UserApiKeyCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add a new API key for the user."""
    identity = await _get_identity_from_request(request, db)
    
    # Validate the key format
    key_prefix = payload.api_key[:8] if len(payload.api_key) > 8 else payload.api_key[:4] + "..."
    
    # Check how many keys exist for this provider
    existing = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == payload.provider.lower()
        )
    )
    existing_keys = existing.scalars().all()
    
    # First key for this provider becomes primary automatically
    is_first_key = len(existing_keys) == 0
    
    # Create new key (always — multiple keys per provider allowed)
    new_key = UserApiKey(
        user_id=identity.user_id,
        provider=payload.provider.lower(),
        name=payload.name or f"{payload.provider} Key {len(existing_keys) + 1}",
        encrypted_key=encrypt_api_key(payload.api_key),
        key_prefix=key_prefix,
        is_valid=True,
        is_primary=is_first_key,
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return UserApiKeyResponse(
        id=str(new_key.id),
        provider=new_key.provider,
        name=new_key.name,
        key_prefix=key_prefix,
        is_valid=True,
        is_primary=new_key.is_primary,
        created_at=new_key.created_at.isoformat() if new_key.created_at else _utcnow().isoformat(),
    )


@router.post("/auth/user/api-keys/validate")
async def validate_user_api_key(
    payload: ValidateApiKeyRequest,
):
    """Validate an API key before adding."""
    # Basic format validation
    provider = payload.provider.lower()
    api_key = payload.api_key.strip()
    
    valid = False
    error = None
    models = []
    
    if provider == "openai":
        valid = api_key.startswith("sk-") and len(api_key) > 20
        if valid:
            models = ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]
        else:
            error = "Invalid OpenAI API key format. Should start with 'sk-'"
    elif provider == "anthropic":
        valid = api_key.startswith("sk-ant-") and len(api_key) > 20
        if valid:
            models = ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"]
        else:
            error = "Invalid Anthropic API key format. Should start with 'sk-ant-'"
    elif provider == "google":
        valid = api_key.startswith("AIza") and len(api_key) > 20
        if valid:
            models = ["gemini-pro", "gemini-pro-vision"]
        else:
            error = "Invalid Google API key format. Should start with 'AIza'"
    elif provider == "mistral":
        valid = len(api_key) > 20
        if valid:
            models = ["mistral-large", "mistral-medium", "mistral-small"]
        else:
            error = "Invalid Mistral API key"
    elif provider == "groq":
        valid = api_key.startswith("gsk_") and len(api_key) > 20
        if valid:
            models = ["llama-3.1-70b", "mixtral-8x7b"]
        else:
            error = "Invalid Groq API key format. Should start with 'gsk_'"
    elif provider == "openrouter":
        valid = api_key.startswith("sk-or-") and len(api_key) > 20
        if valid:
            models = ["auto", "openai/gpt-4o", "anthropic/claude-3.5-sonnet"]
        else:
            error = "Invalid OpenRouter API key format. Should start with 'sk-or-'"
    elif provider == "deepseek":
        valid = api_key.startswith("sk-") and len(api_key) > 20
        if valid:
            models = ["deepseek-chat", "deepseek-coder"]
        else:
            error = "Invalid DeepSeek API key format. Should start with 'sk-'"
    elif provider == "tokenrouter":
        valid = api_key.startswith("sk-") and len(api_key) > 20
        if valid:
            models = ["google/gemini-3-flash-preview", "google/gemini-3.1-pro-preview", "openai/gpt-5.5", "anthropic/claude-opus-4.7", "deepseek/deepseek-v4-flash", "z-ai/glm-5.1", "qwen/qwen3.6-plus"]
        else:
            error = "Invalid TokenRouter API key format. Should start with 'sk-'"
    elif provider == "grok":
        valid = api_key.startswith("xai-") and len(api_key) > 20
        if valid:
            models = ["grok-2", "grok-2-mini"]
        else:
            error = "Invalid Grok API key format. Should start with 'xai-'"
    elif provider == "bedrock":
        valid = len(api_key) > 20
        if valid:
            models = ["anthropic.claude-3-5-sonnet-20241022-v2:0", "anthropic.claude-3-haiku-20240307-v1:0", "meta.llama3-1-70b-instruct-v1:0", "amazon.nova-pro-v1:0", "amazon.nova-lite-v1:0"]
        else:
            error = "Invalid AWS Bedrock API key"
    elif provider in ("together", "fireworks", "cohere", "perplexity", "huggingface", "replicate", "stability", "elevenlabs", "kimi", "metaai", "copilot", "glm"):
        valid = len(api_key) > 10
        if valid:
            models = []
        else:
            error = f"Invalid {provider} API key"
    else:
        valid = len(api_key) > 10
        if not valid:
            error = "Invalid API key"
    
    return ValidateApiKeyResponse(
        valid=valid,
        provider=provider,
        error=error,
        models=models if valid else None,
    )


@router.delete("/auth/user/api-keys/{key_id}")
async def delete_user_api_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a user API key."""
    identity = await _get_identity_from_request(request, db)
    
    # Find the key
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.id == key_uuid,
            UserApiKey.user_id == identity.user_id
        )
    )
    key = result.scalar_one_or_none()
    
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Delete the key
    await db.delete(key)
    await db.commit()
    
    return {"success": True, "deleted": key_id, "provider": key.provider}


@router.delete("/auth/user/api-keys/by-provider/{provider}")
async def delete_user_api_key_by_provider(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete ALL user API keys for a given provider."""
    identity = await _get_identity_from_request(request, db)
    
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == provider.lower()
        )
    )
    keys = result.scalars().all()
    
    if not keys:
        raise HTTPException(status_code=404, detail=f"No keys found for provider: {provider}")
    
    for key in keys:
        await db.delete(key)
    await db.commit()
    
    return {"success": True, "deleted": len(keys), "provider": provider}


@router.put("/auth/user/api-keys/{key_id}/set-primary")
async def set_primary_api_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Set a specific key as primary for its provider."""
    identity = await _get_identity_from_request(request, db)
    
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key ID format")
    
    # Find the target key
    result = await db.execute(
        select(UserApiKey).where(
            UserApiKey.id == key_uuid,
            UserApiKey.user_id == identity.user_id
        )
    )
    target_key = result.scalar_one_or_none()
    if not target_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Unset primary on all other keys for same provider
    siblings = await db.execute(
        select(UserApiKey).where(
            UserApiKey.user_id == identity.user_id,
            UserApiKey.provider == target_key.provider
        )
    )
    for k in siblings.scalars().all():
        k.is_primary = (k.id == target_key.id)
    
    await db.commit()
    return {"success": True, "primary_key_id": key_id, "provider": target_key.provider}


@router.get("/auth/user/trial-status")
async def get_trial_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get trial status for current user."""
    identity = await _get_identity_from_request(request, db)
    
    # Get user
    user_result = await db.execute(select(User).where(User.id == identity.user_id))
    user = user_result.scalar_one_or_none()
    
    # Default to free trial
    is_trial = True
    days_remaining = 14
    is_expired = False
    current_plan = "free-trial"
    
    return TrialStatusResponse(
        is_trial_user=is_trial,
        trial_start_date=user.created_at.isoformat() if user and user.created_at else None,
        trial_end_date=None,
        days_remaining=days_remaining,
        is_expired=is_expired,
        has_api_key=False,  # Would check user_api_keys table
        can_use_services=True,
        requires_upgrade=False,
        current_plan=current_plan,
    )


@router.get("/auth/user/service-access")
async def check_service_access(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Check if user can access services."""
    identity = await _get_identity_from_request(request, db)
    
    return ServiceAccessResponse(
        can_access=True,
        reason=None,
        action="none",
    )


@router.get("/auth/user/available-providers")
async def get_available_providers(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get available AI providers based on user's API keys."""
    identity = await _get_identity_from_request(request, db)
    
    # Default providers available to all users
    default_providers = ["tokenrouter", "openai", "anthropic", "google", "mistral", "groq"]
    
    # Get user's configured API keys
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.user_id == identity.user_id)
    )
    user_keys = result.scalars().all()
    
    user_key_providers = [key.provider for key in user_keys if key.is_valid]
    has_user_keys = len(user_key_providers) > 0
    
    return AvailableProvidersResponse(
        providers=default_providers,
        has_user_keys=has_user_keys,
        user_key_providers=user_key_providers,
    )


@router.get("/auth/internal/user-api-keys/{user_id}")
async def get_user_api_keys_internal(
    user_id: str,
    request: Request,
    provider: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Internal endpoint for services to fetch user's decrypted API keys.
    This should only be called by internal services (IDE, chat, etc).
    
    Protected by internal service header check.
    Returns the actual API key for making LLM requests on behalf of the user.
    Supports both UUID and email as user identifier.
    """
    # Verify internal service call - check for internal header or localhost
    internal_key = request.headers.get("x-internal-service-key")
    is_internal = (
        internal_key == settings.INTERNAL_SERVICE_KEY or
        request.headers.get("x-forwarded-for", "").startswith("10.") or
        request.headers.get("x-forwarded-for", "").startswith("172.") or
        (request.client and request.client.host in ["127.0.0.1", "localhost"])
    )
    
    if not is_internal and settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=403, detail="Internal endpoint - access denied")
    
    user_uuid = None
    
    # Try to parse as UUID first
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        # Not a UUID, might be an email - look up user by email
        if "@" in user_id:
            user_result = await db.execute(
                select(User).where(User.email == user_id)
            )
            user = user_result.scalar_one_or_none()
            if user:
                user_uuid = user.id
            else:
                raise HTTPException(status_code=404, detail="User not found")
        else:
            raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Build query
    query = select(UserApiKey).where(
        UserApiKey.user_id == user_uuid,
        UserApiKey.is_valid == True
    )
    
    if provider:
        query = query.where(UserApiKey.provider == provider.lower())
    
    result = await db.execute(query)
    user_keys = result.scalars().all()
    
    # Return decrypted keys for internal service use
    # Sort so primary keys come first per provider
    keys = []
    for key in sorted(user_keys, key=lambda k: (k.provider, not getattr(k, 'is_primary', False))):
        try:
            decrypted_key = decrypt_api_key(key.encrypted_key)
        except Exception:
            decrypted_key = key.encrypted_key  # Fallback for legacy unencrypted keys
        
        keys.append({
            "provider": key.provider,
            "api_key": decrypted_key,
            "name": key.name or f"{key.provider} Key",
            "is_primary": getattr(key, 'is_primary', False),
            "key_id": str(key.id),
        })
    
    return {"keys": keys, "user_id": user_id}
