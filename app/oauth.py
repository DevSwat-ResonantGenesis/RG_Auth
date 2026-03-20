"""
OAuth2 SSO module for auth_service.

Implements OAuth2 authentication with multiple providers:
- Google
- GitHub
- Microsoft

Uses httpx for async HTTP requests instead of external OAuth libraries
for better control and fewer dependencies.
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import os

import httpx

from .config import settings
from .oauth_redis import store_oauth_state, get_oauth_state, delete_oauth_state


# OAuth State expiration (10 minutes)
OAUTH_STATE_EXPIRY_SECONDS = 600

# OAuth states stored in Redis for production reliability
# _oauth_states: Dict[str, Dict[str, Any]] = {}  # No longer used - using Redis


@dataclass
class OAuthProvider:
    """OAuth2 provider configuration."""
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: List[str]
    # Optional: some providers need extra params
    extra_authorize_params: Dict[str, str] = None
    
    def __post_init__(self):
        if self.extra_authorize_params is None:
            self.extra_authorize_params = {}


# Provider configurations
OAUTH_PROVIDERS: Dict[str, OAuthProvider] = {}


def _init_providers():
    """Initialize OAuth providers from environment variables."""
    global OAUTH_PROVIDERS
    
    # Google OAuth2
    google_client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    if google_client_id and google_client_secret:
        OAUTH_PROVIDERS["google"] = OAuthProvider(
            name="google",
            client_id=google_client_id,
            client_secret=google_client_secret,
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://www.googleapis.com/oauth2/v3/userinfo",
            scopes=["openid", "email", "profile"],
            extra_authorize_params={"access_type": "offline", "prompt": "consent"},
        )
    
    # GitHub OAuth2
    github_client_id = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET", "")
    if github_client_id and github_client_secret:
        OAUTH_PROVIDERS["github"] = OAuthProvider(
            name="github",
            client_id=github_client_id,
            client_secret=github_client_secret,
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user",
            scopes=["user:email", "read:user"],
        )
    
    # Microsoft OAuth2 (Azure AD)
    microsoft_client_id = os.getenv("MICROSOFT_CLIENT_ID", "")
    microsoft_client_secret = os.getenv("MICROSOFT_CLIENT_SECRET", "")
    microsoft_tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
    if microsoft_client_id and microsoft_client_secret:
        OAUTH_PROVIDERS["microsoft"] = OAuthProvider(
            name="microsoft",
            client_id=microsoft_client_id,
            client_secret=microsoft_client_secret,
            authorize_url=f"https://login.microsoftonline.com/{microsoft_tenant}/oauth2/v2.0/authorize",
            token_url=f"https://login.microsoftonline.com/{microsoft_tenant}/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/v1.0/me",
            scopes=["openid", "email", "profile", "User.Read"],
        )
    
    # Slack OAuth2
    slack_client_id = os.getenv("SLACK_CLIENT_ID", "")
    slack_client_secret = os.getenv("SLACK_CLIENT_SECRET", "")
    if slack_client_id and slack_client_secret:
        OAUTH_PROVIDERS["slack"] = OAuthProvider(
            name="slack",
            client_id=slack_client_id,
            client_secret=slack_client_secret,
            authorize_url="https://slack.com/oauth/v2/authorize",
            token_url="https://slack.com/api/oauth.v2.access",
            userinfo_url="https://slack.com/api/users.identity",
            scopes=["channels:read", "channels:history", "chat:write", "users:read", "users:read.email"],
        )


# Initialize on module load
_init_providers()


def get_available_providers() -> List[str]:
    """Get list of configured OAuth providers."""
    return list(OAUTH_PROVIDERS.keys())


def is_provider_configured(provider: str) -> bool:
    """Check if a provider is configured."""
    return provider.lower() in OAUTH_PROVIDERS


def generate_oauth_state(
    provider: str,
    redirect_uri: str,
    extra_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate and store OAuth state for CSRF protection.
    
    Args:
        provider: OAuth provider name
        redirect_uri: Where to redirect after OAuth
        extra_data: Optional extra data to store with state
        
    Returns:
        State token string
    """
    state = secrets.token_urlsafe(32)
    
    store_oauth_state(state, {
        "provider": provider,
        "redirect_uri": redirect_uri,
        "created_at": time.time(),
        "extra_data": extra_data or {},
    })
    
    # Redis handles expiration automatically with TTL
    
    return state


def validate_oauth_state(state: str) -> Optional[Dict[str, Any]]:
    """
    Validate and consume OAuth state.
    
    Args:
        state: State token to validate
        
    Returns:
        State data if valid, None otherwise
    """
    state_data = get_oauth_state(state)
    if not state_data:
        return None
    
    delete_oauth_state(state)
    
    # Check expiration
    if time.time() - state_data["created_at"] > OAUTH_STATE_EXPIRY_SECONDS:
        return None
    
    return state_data


def _cleanup_expired_states():
    """Remove expired OAuth states - Redis handles this automatically with TTL."""
    # No longer needed - Redis automatically expires keys after TTL
    pass


def build_authorization_url(
    provider: str,
    redirect_uri: str,
    state: str,
) -> str:
    """
    Build OAuth authorization URL.
    
    Args:
        provider: OAuth provider name
        redirect_uri: Callback URL
        state: CSRF state token
        
    Returns:
        Full authorization URL
        
    Raises:
        ValueError: If provider not configured
    """
    if provider not in OAUTH_PROVIDERS:
        raise ValueError(f"Provider '{provider}' not configured")
    
    config = OAUTH_PROVIDERS[provider]
    
    params = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(config.scopes),
        "state": state,
        **config.extra_authorize_params,
    }
    
    return f"{config.authorize_url}?{urlencode(params)}"


async def exchange_code_for_tokens(
    provider: str,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    """
    Exchange authorization code for access tokens.
    
    Args:
        provider: OAuth provider name
        code: Authorization code from callback
        redirect_uri: Same redirect_uri used in authorization
        
    Returns:
        Token response dict with access_token, etc.
        
    Raises:
        ValueError: If provider not configured
        httpx.HTTPError: If token exchange fails
    """
    if provider not in OAUTH_PROVIDERS:
        raise ValueError(f"Provider '{provider}' not configured")
    
    config = OAUTH_PROVIDERS[provider]
    
    data = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    
    headers = {"Accept": "application/json"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            config.token_url,
            data=data,
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()


async def get_user_info(
    provider: str,
    access_token: str,
) -> Dict[str, Any]:
    """
    Get user info from OAuth provider.
    
    Args:
        provider: OAuth provider name
        access_token: Access token from token exchange
        
    Returns:
        User info dict (structure varies by provider)
        
    Raises:
        ValueError: If provider not configured
        httpx.HTTPError: If userinfo request fails
    """
    if provider not in OAUTH_PROVIDERS:
        raise ValueError(f"Provider '{provider}' not configured")
    
    config = OAUTH_PROVIDERS[provider]
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            config.userinfo_url,
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()
        user_info = response.json()
        
        # GitHub requires separate request for email
        if provider == "github" and not user_info.get("email"):
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers=headers,
                timeout=10.0,
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next(
                    (e["email"] for e in emails if e.get("primary")),
                    emails[0]["email"] if emails else None
                )
                user_info["email"] = primary_email
        
        return user_info


def normalize_user_info(provider: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize user info from different providers to a common format.
    
    Args:
        provider: OAuth provider name
        user_info: Raw user info from provider
        
    Returns:
        Normalized user info with: email, name, picture, provider_id
    """
    if provider == "google":
        return {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "first_name": user_info.get("given_name"),
            "last_name": user_info.get("family_name"),
            "picture": user_info.get("picture"),
            "provider_id": user_info.get("sub"),
            "email_verified": user_info.get("email_verified", False),
        }
    
    elif provider == "github":
        name = user_info.get("name") or user_info.get("login", "")
        name_parts = name.split(" ", 1)
        return {
            "email": user_info.get("email"),
            "name": name,
            "first_name": name_parts[0] if name_parts else "",
            "last_name": name_parts[1] if len(name_parts) > 1 else "",
            "picture": user_info.get("avatar_url"),
            "provider_id": str(user_info.get("id")),
            "email_verified": True,  # GitHub verifies emails
            "username": user_info.get("login"),
        }
    
    elif provider == "microsoft":
        name = user_info.get("displayName", "")
        return {
            "email": user_info.get("mail") or user_info.get("userPrincipalName"),
            "name": name,
            "first_name": user_info.get("givenName", ""),
            "last_name": user_info.get("surname", ""),
            "picture": None,  # Microsoft Graph requires separate call for photo
            "provider_id": user_info.get("id"),
            "email_verified": True,  # Microsoft verifies emails
        }
    
    elif provider == "slack":
        user = user_info.get("user", {})
        name = user.get("name", "")
        name_parts = name.split(" ", 1)
        return {
            "email": user.get("email"),
            "name": name,
            "first_name": name_parts[0] if name_parts else "",
            "last_name": name_parts[1] if len(name_parts) > 1 else "",
            "picture": user.get("image_72"),
            "provider_id": user.get("id"),
            "email_verified": True,
        }
    
    else:
        # Generic fallback
        return {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "first_name": user_info.get("first_name", ""),
            "last_name": user_info.get("last_name", ""),
            "picture": user_info.get("picture"),
            "provider_id": user_info.get("id") or user_info.get("sub"),
            "email_verified": user_info.get("email_verified", False),
        }


class OAuthError(Exception):
    """OAuth-related error."""
    pass


class OAuthManager:
    """
    High-level OAuth management class.
    
    Usage:
        manager = OAuthManager(frontend_url="http://localhost:5175")
        
        # Initiate OAuth
        url, state = manager.initiate("google", "/oauth/callback")
        # Redirect user to url
        
        # Handle callback
        user_info = await manager.handle_callback("google", code, state, "/oauth/callback")
    """
    
    def __init__(self, frontend_url: str = None):
        self.frontend_url = frontend_url or os.getenv("FRONTEND_URL", os.getenv("AUTH_FRONTEND_URL", "https://dev-swat.com"))
    
    def get_providers(self) -> List[Dict[str, Any]]:
        """Get list of available OAuth providers with display info."""
        providers = []
        
        provider_info = {
            "google": {"display_name": "Google", "icon": "google"},
            "github": {"display_name": "GitHub", "icon": "github"},
            "microsoft": {"display_name": "Microsoft", "icon": "microsoft"},
            "slack": {"display_name": "Slack", "icon": "slack"},
        }
        
        for name in get_available_providers():
            info = provider_info.get(name, {"display_name": name.title(), "icon": name})
            providers.append({
                "id": name,  # Frontend expects 'id' field
                "name": info["display_name"],  # Frontend expects 'name' field
                "type": "oauth2",  # Frontend expects 'type' field
                "icon": info["icon"],
                "enabled": True,  # Frontend expects 'enabled' field
            })
        
        return providers
    
    def initiate(
        self,
        provider: str,
        callback_path: str,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """
        Initiate OAuth flow.
        
        Args:
            provider: OAuth provider name
            callback_path: Path for OAuth callback (e.g., "/auth/sso/oauth/callback")
            extra_data: Optional data to pass through OAuth flow
            
        Returns:
            Tuple of (authorization_url, state)
            
        Raises:
            OAuthError: If provider not configured
        """
        provider = provider.lower()
        
        if not is_provider_configured(provider):
            raise OAuthError(f"OAuth provider '{provider}' is not configured")
        
        # Build callback URL
        redirect_uri = f"{self.frontend_url}{callback_path}"
        
        # Generate state
        state = generate_oauth_state(provider, redirect_uri, extra_data)
        
        # Build authorization URL
        auth_url = build_authorization_url(provider, redirect_uri, state)
        
        return auth_url, state
    
    async def handle_callback(
        self,
        provider: str,
        code: str,
        state: str,
        callback_path: str,
    ) -> Dict[str, Any]:
        """
        Handle OAuth callback.
        
        Args:
            provider: OAuth provider name
            code: Authorization code from callback
            state: State token from callback
            callback_path: Path for OAuth callback
            
        Returns:
            Normalized user info
            
        Raises:
            OAuthError: If state invalid or OAuth fails
        """
        provider = provider.lower()
        
        # Validate state
        state_data = validate_oauth_state(state)
        if not state_data:
            raise OAuthError("Invalid or expired OAuth state")
        
        if state_data["provider"] != provider:
            raise OAuthError("Provider mismatch in OAuth state")

        redirect_uri = state_data.get("redirect_uri") or f"{self.frontend_url}{callback_path}"
        
        try:
            # Exchange code for tokens
            tokens = await exchange_code_for_tokens(provider, code, redirect_uri)
            access_token = tokens.get("access_token")
            
            if not access_token:
                raise OAuthError("No access token in OAuth response")
            
            # Get user info
            user_info = await get_user_info(provider, access_token)
            
            # Normalize user info
            normalized = normalize_user_info(provider, user_info)
            normalized["provider"] = provider
            normalized["extra_data"] = state_data.get("extra_data", {})
            
            return normalized
            
        except httpx.HTTPError as e:
            raise OAuthError(f"OAuth request failed: {e}")
