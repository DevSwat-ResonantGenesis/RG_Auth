"""
Audit logging module for the auth service.

Logs all security-relevant events for compliance and debugging:
- Login attempts (success/failure)
- Registration
- Password changes
- MFA changes
- API key operations
- Account lockouts
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, String, Text, Index
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSON
from sqlalchemy.ext.asyncio import AsyncSession

from .db import Base
from .config import settings


class AuditEventType(str, Enum):
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    
    # Registration events
    REGISTRATION = "registration"
    EMAIL_VERIFICATION = "email_verification"
    EMAIL_VERIFICATION_RESENT = "email_verification_resent"
    
    # Password events
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    
    # MFA events
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFY_SUCCESS = "mfa_verify_success"
    MFA_VERIFY_FAILURE = "mfa_verify_failure"
    MFA_BACKUP_CODE_USED = "mfa_backup_code_used"
    MFA_BACKUP_CODES_REGENERATED = "mfa_backup_codes_regenerated"
    
    # Account events
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_SUSPENDED = "account_suspended"
    ACCOUNT_REACTIVATED = "account_reactivated"
    
    # API key events
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"
    
    # BYOK events
    BYOK_KEY_ADDED = "byok_key_added"
    BYOK_KEY_REMOVED = "byok_key_removed"
    
    # SSO events
    SSO_LOGIN = "sso_login"
    SSO_LINK = "sso_link"
    
    # Admin events
    ADMIN_USER_SUSPEND = "admin_user_suspend"
    ADMIN_USER_REACTIVATE = "admin_user_reactivate"
    ADMIN_ROLE_CHANGE = "admin_role_change"


class AuditLog(Base):
    """Audit log model for security events."""
    __tablename__ = "audit_logs"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(PGUUID(as_uuid=True), nullable=True, index=True)
    org_id = Column(PGUUID(as_uuid=True), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)
    details = Column(JSON, nullable=True)
    success = Column(String(10), nullable=False, default="true")  # true/false/partial
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


async def log_audit_event(
    db: AsyncSession,
    event_type: AuditEventType,
    user_id: Optional[UUID] = None,
    org_id: Optional[UUID] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    error_message: Optional[str] = None,
) -> AuditLog:
    """
    Log an audit event to the database.
    
    Args:
        db: Database session
        event_type: Type of event
        user_id: User ID (if applicable)
        org_id: Organization ID (if applicable)
        ip_address: Client IP address
        user_agent: Client user agent
        details: Additional event details
        success: Whether the operation succeeded
        error_message: Error message if failed
    
    Returns:
        The created AuditLog record
    """
    # Sanitize details to remove sensitive data
    safe_details = _sanitize_details(details) if details else None
    
    audit_log = AuditLog(
        event_type=event_type.value,
        user_id=user_id,
        org_id=org_id,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
        details=safe_details,
        success="true" if success else "false",
        error_message=error_message,
    )
    
    db.add(audit_log)
    
    # Don't commit here - let the caller handle the transaction
    # This allows audit logs to be part of the same transaction as the operation
    
    # Also log to console in development
    if settings.ENVIRONMENT == "development":
        _log_to_console(audit_log)
    
    return audit_log


def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive data from audit details."""
    sensitive_keys = {
        "password", "new_password", "current_password", "old_password",
        "token", "secret", "api_key", "key", "mfa_secret",
        "backup_codes", "refresh_token", "access_token",
    }
    
    sanitized = {}
    for key, value in details.items():
        if key.lower() in sensitive_keys:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_details(value)
        else:
            sanitized[key] = value
    
    return sanitized


def _log_to_console(audit_log: AuditLog) -> None:
    """Log audit event to console for development."""
    status = "✓" if audit_log.success == "true" else "✗"
    print(f"[AUDIT] {status} {audit_log.event_type} | user={audit_log.user_id} | ip={audit_log.ip_address}")


def get_client_info(request) -> tuple[Optional[str], Optional[str]]:
    """Extract client IP and user agent from request."""
    ip_address = None
    user_agent = None
    
    if request:
        # Get IP from X-Forwarded-For header (for proxied requests) or client
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        elif request.client:
            ip_address = request.client.host
        
        user_agent = request.headers.get("user-agent")
    
    return ip_address, user_agent
