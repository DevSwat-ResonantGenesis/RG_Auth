from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSON
import uuid

from .db import Base


class User(Base):
    """User model with full old backend compatibility."""
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)  # Renamed from hashed_password
    status = Column(String(50), default="active", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    unlimited_credits = Column(Boolean, default=False, nullable=False)  # Bypass billing only, no role elevation
    trial_expires_at = Column(DateTime(timezone=True), nullable=True)  # 1-week unlimited trial expiry
    default_org_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    token_version = Column(Integer, default=1, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # MFA (Multi-Factor Authentication) fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(500), nullable=True)  # Encrypted TOTP secret
    mfa_backup_codes = Column(JSON, nullable=True)  # Hashed backup codes
    mfa_verified_at = Column(DateTime(timezone=True), nullable=True)  # When MFA was first verified
    
    # Account lockout fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_failed_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Email verification fields
    email_verified = Column(Boolean, default=False, nullable=False)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    email_verification_token = Column(String(128), nullable=True)
    email_verification_sent_at = Column(DateTime(timezone=True), nullable=True)
    
    # Deterministic Anchor Universes (Phase 1)
    anchor_seed = Column(String(500), nullable=True)  # Encrypted BIP-39 seed
    universe_id = Column(String(32), nullable=True, index=True)  # Derived universe ID
    seed_encrypted = Column(Boolean, default=False)
    
    # Cryptographic Hash (for blockchain/NFT/ownership)
    crypto_hash = Column(String(64), nullable=True, index=True)
    user_hash = Column(String(64), nullable=True, index=True)  # Hash Sphere hash
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class ApiKey(Base):
    """API key model for service and external access (ported from old backend)."""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    prefix = Column(String(12), nullable=False, index=True)
    hashed_key = Column(String(128), nullable=False)
    auth_method = Column(String(50), default="api_key", nullable=False)
    scopes = Column(JSON, nullable=False, default=list)

    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_by_user_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    is_global = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class Organization(Base):
    """Organization model for multi-tenant support."""
    __tablename__ = "organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_organizations_slug"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), index=True, nullable=False)
    slug = Column(String(128), index=True, nullable=False)
    plan = Column(String(50), default="developer", nullable=False)  # developer, plus, enterprise
    status = Column(String(50), default="active", nullable=False)
    meta = Column(JSON, default=dict, nullable=False)
    settings = Column(JSON, default=dict, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class OrgMembership(Base):
    """Organization membership - links users to organizations with roles."""
    __tablename__ = "org_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_memberships_user_org"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    role = Column(String(50), default="viewer", nullable=False)  # owner, admin, viewer
    status = Column(String(50), default="active", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class RefreshToken(Base):
    """Refresh token storage for secure token management."""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    token_hash = Column(String(128), nullable=False, index=True)
    user_agent = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    auth_method = Column(String(50), default="jwt", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Session metadata for session management
    device_name = Column(String(255), nullable=True)  # Parsed from user agent
    device_type = Column(String(50), nullable=True)  # desktop, mobile, tablet
    location = Column(String(255), nullable=True)  # City, Country (from IP)
    last_active_at = Column(DateTime(timezone=True), nullable=True)
    is_current = Column(Boolean, default=False, nullable=False)  # Mark current session


class TrustedDevice(Base):
    """Trusted devices for MFA bypass (remember this device)."""
    __tablename__ = "trusted_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint", name="uq_trusted_devices_user_device"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    device_fingerprint = Column(String(128), nullable=False, index=True)  # Hash of device info
    device_name = Column(String(255), nullable=True)
    device_type = Column(String(50), nullable=True)
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(64), nullable=True)
    trusted_until = Column(DateTime(timezone=True), nullable=False)  # 30 days by default
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class UserApiKey(Base):
    """User API keys for BYOK (Bring Your Own Key) functionality.
    
    Stores user-provided API keys for external AI providers like OpenAI, Anthropic, etc.
    Keys are stored encrypted for security.
    """
    __tablename__ = "user_api_keys"
    __table_args__ = (
        UniqueConstraint("user_id", "provider", name="uq_user_api_keys_user_provider"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # openai, anthropic, google, groq, mistral
    name = Column(String(255), nullable=True)  # User-friendly name
    encrypted_key = Column(Text, nullable=False)  # Encrypted API key
    key_prefix = Column(String(12), nullable=True)  # First few chars for display (e.g., "sk-abc...")
    is_valid = Column(Boolean, default=True, nullable=False)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class PasswordResetToken(Base):
    """Password reset token storage for secure password recovery."""
    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    token_hash = Column(String(128), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Agent(Base):
    """Agent model for user-created AI agents."""
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    agent_hash = Column(String(64), nullable=True, index=True)
    system_prompt = Column(Text, nullable=True)
    personality_config = Column(JSON, default=dict, nullable=False)
    enabled_patches = Column(JSON, default=list, nullable=False)
    patch_config = Column(JSON, default=dict, nullable=False)
    memory_config = Column(JSON, default=dict, nullable=False)
    anchor_config = Column(JSON, default=dict, nullable=False)
    isolate_anchors = Column(Boolean, default=True, nullable=False)
    status = Column(String(50), default="active", nullable=False)
    is_template = Column(Boolean, default=False, nullable=False)
    template_id = Column(UUID(as_uuid=True), nullable=True)
    is_shared = Column(Boolean, default=False, nullable=False)
    is_public = Column(Boolean, default=False, nullable=False)
    is_imported = Column(Boolean, default=False, nullable=False)
    share_secret = Column(String(255), nullable=True)
    
    # Agent restrictions
    restrictions = Column(JSON, default=dict, nullable=False)  # Custom restrictions config
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AgentApiKey(Base):
    """API keys specific to agents for programmatic access."""
    __tablename__ = "agent_api_keys"
    __table_args__ = (
        UniqueConstraint("agent_id", "name", name="uq_agent_api_keys_agent_name"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)  # Owner of the agent
    name = Column(String(255), nullable=False)
    prefix = Column(String(16), nullable=False, index=True)  # e.g., "rga_xxxx"
    hashed_key = Column(String(128), nullable=False)
    scopes = Column(JSON, default=list, nullable=False)  # Allowed operations
    rate_limit = Column(Integer, default=100, nullable=False)  # Requests per minute
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
