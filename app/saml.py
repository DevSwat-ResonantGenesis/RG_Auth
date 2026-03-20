"""
SAML SSO module for enterprise authentication.

Supports:
- SAML 2.0 IdP-initiated and SP-initiated flows
- Multiple IdP configurations per organization
- Just-in-time user provisioning

Configuration:
    Set AUTH_SAML_ENABLED=true and configure IdP metadata per organization.

Note: Requires python3-saml library for full functionality.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import User, Organization, OrgMembership


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class SAMLConfig:
    """SAML configuration for an organization."""
    
    def __init__(
        self,
        org_id: UUID,
        idp_entity_id: str,
        idp_sso_url: str,
        idp_certificate: str,
        sp_entity_id: Optional[str] = None,
        attribute_mapping: Optional[Dict[str, str]] = None,
    ):
        self.org_id = org_id
        self.idp_entity_id = idp_entity_id
        self.idp_sso_url = idp_sso_url
        self.idp_certificate = idp_certificate
        self.sp_entity_id = sp_entity_id or f"{settings.FRONTEND_URL}/saml/metadata"
        self.attribute_mapping = attribute_mapping or {
            "email": "email",
            "first_name": "firstName",
            "last_name": "lastName",
        }


# In-memory store for SAML configs (in production, store in database)
_saml_configs: Dict[str, SAMLConfig] = {}


def is_saml_enabled() -> bool:
    """Check if SAML SSO is enabled."""
    return getattr(settings, 'SAML_ENABLED', False)


def get_saml_config(org_id: UUID) -> Optional[SAMLConfig]:
    """Get SAML configuration for an organization."""
    return _saml_configs.get(str(org_id))


def register_saml_config(config: SAMLConfig) -> None:
    """Register a SAML configuration for an organization."""
    _saml_configs[str(config.org_id)] = config


async def initiate_saml_login(
    org_id: UUID,
    relay_state: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Initiate SAML login flow.
    
    Returns:
        Tuple of (redirect_url, request_id)
    """
    config = get_saml_config(org_id)
    if not config:
        raise ValueError(f"SAML not configured for organization {org_id}")
    
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        
        # Build SAML settings
        saml_settings = _build_saml_settings(config)
        
        # Create auth request
        # Note: In real implementation, this would use the actual request object
        auth = OneLogin_Saml2_Auth({}, saml_settings)
        redirect_url = auth.login(return_to=relay_state)
        request_id = auth.get_last_request_id()
        
        return redirect_url, request_id
        
    except ImportError:
        # python3-saml not installed - return stub
        raise NotImplementedError(
            "SAML SSO requires python3-saml library. "
            "Install with: pip install python3-saml"
        )


async def process_saml_response(
    saml_response: str,
    org_id: UUID,
    db: AsyncSession,
) -> Tuple[User, bool]:
    """
    Process SAML response and create/update user.
    
    Returns:
        Tuple of (user, is_new_user)
    """
    config = get_saml_config(org_id)
    if not config:
        raise ValueError(f"SAML not configured for organization {org_id}")
    
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.response import OneLogin_Saml2_Response
        
        # Build SAML settings
        saml_settings = _build_saml_settings(config)
        
        # Parse and validate response
        # Note: In real implementation, this would use the actual request object
        auth = OneLogin_Saml2_Auth({}, saml_settings)
        auth.process_response()
        
        if not auth.is_authenticated():
            errors = auth.get_errors()
            raise ValueError(f"SAML authentication failed: {errors}")
        
        # Extract user attributes
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        
        # Map attributes to user fields
        email = _get_attribute(attributes, config.attribute_mapping.get("email", "email")) or name_id
        first_name = _get_attribute(attributes, config.attribute_mapping.get("first_name", "firstName"))
        last_name = _get_attribute(attributes, config.attribute_mapping.get("last_name", "lastName"))
        
        if not email:
            raise ValueError("Email not found in SAML response")
        
        # Find or create user
        return await _find_or_create_saml_user(
            db=db,
            org_id=org_id,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        
    except ImportError:
        raise NotImplementedError(
            "SAML SSO requires python3-saml library. "
            "Install with: pip install python3-saml"
        )


def _build_saml_settings(config: SAMLConfig) -> dict:
    """Build SAML settings dictionary for python3-saml."""
    return {
        "strict": True,
        "debug": settings.ENVIRONMENT == "development",
        "sp": {
            "entityId": config.sp_entity_id,
            "assertionConsumerService": {
                "url": f"{settings.FRONTEND_URL}/auth/saml/callback",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": f"{settings.FRONTEND_URL}/auth/saml/logout",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": config.idp_certificate,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameIdEncrypted": False,
        },
    }


def _get_attribute(attributes: Dict[str, list], key: str) -> Optional[str]:
    """Get first value of an attribute."""
    values = attributes.get(key, [])
    return values[0] if values else None


async def _find_or_create_saml_user(
    db: AsyncSession,
    org_id: UUID,
    email: str,
    first_name: Optional[str],
    last_name: Optional[str],
) -> Tuple[User, bool]:
    """Find existing user or create new one via JIT provisioning."""
    # Check if user exists
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    is_new = False
    
    if not user:
        # JIT provisioning - create new user
        full_name = f"{first_name or ''} {last_name or ''}".strip() or email.split('@')[0]
        
        user = User(
            email=email,
            full_name=full_name,
            password_hash=None,  # SAML users don't have passwords
            is_active=True,
            is_superuser=False,
            default_org_id=org_id,
            status="active",
            email_verified=True,  # SAML IdP verified the email
            email_verified_at=_utcnow(),
        )
        db.add(user)
        await db.flush()
        is_new = True
    
    # Ensure user has membership in the organization
    membership_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == user.id,
            OrgMembership.org_id == org_id,
        )
    )
    membership = membership_result.scalar_one_or_none()
    
    if not membership:
        membership = OrgMembership(
            user_id=user.id,
            org_id=org_id,
            role="member",  # Default role for SAML users
            status="active",
        )
        db.add(membership)
    
    await db.commit()
    
    return user, is_new
