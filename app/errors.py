"""
Standardized error responses for the auth service.

Provides consistent error format across all endpoints:
{
    "error": {
        "code": "ERROR_CODE",
        "message": "Human readable message",
        "details": {...}  # Optional additional details
    }
}
"""
from typing import Any, Dict, Optional
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Standard error response format."""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Wrapper for error responses."""
    error: ErrorDetail


# Error codes
class AuthErrorCodes:
    # Authentication errors (401)
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_INVALID = "MFA_INVALID"
    
    # Authorization errors (403)
    ACCESS_DENIED = "ACCESS_DENIED"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    ORG_ACCESS_DENIED = "ORG_ACCESS_DENIED"
    
    # Account errors (400, 423)
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_INACTIVE = "ACCOUNT_INACTIVE"
    ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
    EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS"
    USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS"
    
    # Validation errors (400)
    VALIDATION_ERROR = "VALIDATION_ERROR"
    PASSWORD_TOO_WEAK = "PASSWORD_TOO_WEAK"
    INVALID_EMAIL = "INVALID_EMAIL"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED_RESET = "TOKEN_EXPIRED_RESET"
    
    # Resource errors (404)
    USER_NOT_FOUND = "USER_NOT_FOUND"
    ORG_NOT_FOUND = "ORG_NOT_FOUND"
    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    API_KEY_NOT_FOUND = "API_KEY_NOT_FOUND"
    
    # Rate limiting (429)
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    
    # Server errors (500)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class AuthError(HTTPException):
    """Custom auth exception with standardized format."""
    
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.code = code
        self.error_message = message
        self.details = details
        super().__init__(
            status_code=status_code,
            detail={
                "error": {
                    "code": code,
                    "message": message,
                    "details": details,
                }
            }
        )


# Pre-defined error factories
def invalid_credentials() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.INVALID_CREDENTIALS,
        message="Invalid email or password",
    )


def not_authenticated() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.NOT_AUTHENTICATED,
        message="Authentication required",
    )


def token_expired() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.TOKEN_EXPIRED,
        message="Token has expired. Please log in again.",
    )


def token_invalid() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.TOKEN_INVALID,
        message="Invalid token",
    )


def account_locked(minutes_remaining: int) -> AuthError:
    return AuthError(
        status_code=423,
        code=AuthErrorCodes.ACCOUNT_LOCKED,
        message=f"Account is locked due to too many failed login attempts. Try again in {minutes_remaining} minutes.",
        details={"minutes_remaining": minutes_remaining},
    )


def account_inactive() -> AuthError:
    return AuthError(
        status_code=403,
        code=AuthErrorCodes.ACCOUNT_INACTIVE,
        message="Account is inactive. Please contact support.",
    )


def email_already_exists() -> AuthError:
    return AuthError(
        status_code=400,
        code=AuthErrorCodes.EMAIL_ALREADY_EXISTS,
        message="An account with this email already exists",
    )


def password_too_weak(reason: str) -> AuthError:
    return AuthError(
        status_code=400,
        code=AuthErrorCodes.PASSWORD_TOO_WEAK,
        message=reason,
        details={
            "requirements": [
                "Minimum 8 characters",
                "At least one uppercase letter",
                "At least one lowercase letter",
                "At least one digit",
                "At least one special character",
            ]
        },
    )


def user_not_found() -> AuthError:
    return AuthError(
        status_code=404,
        code=AuthErrorCodes.USER_NOT_FOUND,
        message="User not found",
    )


def org_not_found() -> AuthError:
    return AuthError(
        status_code=404,
        code=AuthErrorCodes.ORG_NOT_FOUND,
        message="Organization not found",
    )


def agent_not_found() -> AuthError:
    return AuthError(
        status_code=404,
        code=AuthErrorCodes.AGENT_NOT_FOUND,
        message="Agent not found",
    )


def api_key_not_found() -> AuthError:
    return AuthError(
        status_code=404,
        code=AuthErrorCodes.API_KEY_NOT_FOUND,
        message="API key not found",
    )


def access_denied(reason: str = "Access denied") -> AuthError:
    return AuthError(
        status_code=403,
        code=AuthErrorCodes.ACCESS_DENIED,
        message=reason,
    )


def org_access_denied() -> AuthError:
    return AuthError(
        status_code=403,
        code=AuthErrorCodes.ORG_ACCESS_DENIED,
        message="You do not have access to this organization",
    )


def rate_limit_exceeded(retry_after: int = 60) -> AuthError:
    return AuthError(
        status_code=429,
        code=AuthErrorCodes.RATE_LIMIT_EXCEEDED,
        message="Too many requests. Please try again later.",
        details={"retry_after_seconds": retry_after},
    )


def mfa_required() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.MFA_REQUIRED,
        message="Multi-factor authentication required",
    )


def mfa_invalid() -> AuthError:
    return AuthError(
        status_code=401,
        code=AuthErrorCodes.MFA_INVALID,
        message="Invalid MFA code",
    )


def validation_error(message: str, details: Optional[Dict] = None) -> AuthError:
    return AuthError(
        status_code=400,
        code=AuthErrorCodes.VALIDATION_ERROR,
        message=message,
        details=details,
    )


def reset_token_expired() -> AuthError:
    return AuthError(
        status_code=400,
        code=AuthErrorCodes.TOKEN_EXPIRED_RESET,
        message="Reset token has expired. Please request a new password reset.",
    )


def reset_token_invalid() -> AuthError:
    return AuthError(
        status_code=400,
        code=AuthErrorCodes.INVALID_TOKEN,
        message="Invalid or expired reset token. Please request a new password reset.",
    )


# Exception handler for FastAPI
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    """Handle AuthError exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
    )
