import os
import secrets
from pydantic_settings import BaseSettings


def _get_required_secret(env_var: str, default_dev: str) -> str:
    """Get a secret from environment, fail in production if not set."""
    value = os.getenv(env_var)
    if value:
        return value
    
    # In production, secrets MUST be set via environment
    env = os.getenv("AUTH_ENVIRONMENT", "development")
    if env == "production":
        raise ValueError(f"CRITICAL: {env_var} must be set in production environment!")
    
    # In development, use default but warn
    print(f"[WARNING] Using default {env_var} - set via environment for production!")
    return default_dev


class Settings(BaseSettings):
    APP_NAME: str = "Auth Service"
    ENV: str = "dev"
    ENVIRONMENT: str = "development"  # development | staging | production

    DB_HOST: str = "auth_db"
    DB_PORT: int = 5432
    DB_USER: str = "auth_user"
    DB_PASSWORD: str = "auth_pass"
    DB_NAME: str = "auth_db"

    # SECURITY: These MUST be set via environment variables in production
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 60 minutes (1 hour) - prevents frequent logouts
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # API Key salt for hashing tokens
    API_KEY_SALT: str = ""
    
    # Cookie settings
    ACCESS_COOKIE: str = "rg_access_token"
    REFRESH_COOKIE: str = "rg_refresh_token"
    COOKIE_DOMAIN: str = ""  # Set to ".yourdomain.com" in production for cross-subdomain; empty = same-origin
    COOKIE_SECURE: bool = True  # Always True in production (HTTPS required)
    
    # Internal service key for service-to-service auth
    INTERNAL_SERVICE_KEY: str = ""
    
    # Email service configuration
    # Option 1: SMTP (Google Workspace, etc.)
    SMTP_HOST: str = ""  # smtp.gmail.com for Google Workspace
    SMTP_PORT: int = 587
    SMTP_USER: str = ""  # info@dev-swat.com
    SMTP_PASSWORD: str = ""  # App password from Google
    
    # Option 2: SendGrid API
    SENDGRID_API_KEY: str = ""
    
    # Email sender settings
    EMAIL_FROM_ADDRESS: str = "info@dev-swat.com"
    EMAIL_FROM_NAME: str = "DevSwat"
    
    # Frontend URL for email links and OAuth callbacks
    FRONTEND_URL: str = os.getenv("AUTH_FRONTEND_URL", "https://dev-swat.com")

    REQUIRE_EMAIL_VERIFICATION: bool = True
    
    # Service URLs
    HASH_SPHERE_URL: str = os.getenv("HASH_SPHERE_URL", "http://hash_sphere:8000")
    BLOCKCHAIN_SERVICE_URL: str = os.getenv("BLOCKCHAIN_SERVICE_URL", "http://blockchain_service:8000")
    
    # GeoIP service (MaxMind)
    MAXMIND_LICENSE_KEY: str = ""
    MAXMIND_ACCOUNT_ID: str = ""
    
    # Error monitoring (Sentry)
    SENTRY_DSN: str = ""

    class Config:
        env_prefix = "AUTH_"
        case_sensitive = False


# Initialize settings
settings = Settings()

# Validate and set secrets with proper defaults for dev
if not settings.JWT_SECRET_KEY:
    settings.JWT_SECRET_KEY = _get_required_secret(
        "AUTH_JWT_SECRET_KEY", 
        "dev-secret-change-me-" + secrets.token_hex(8)
    )

if not settings.API_KEY_SALT:
    settings.API_KEY_SALT = _get_required_secret(
        "AUTH_API_KEY_SALT",
        "dev-api-key-salt-" + secrets.token_hex(8)
    )

if not settings.INTERNAL_SERVICE_KEY:
    settings.INTERNAL_SERVICE_KEY = _get_required_secret(
        "AUTH_INTERNAL_SERVICE_KEY",
        "internal-service-key-" + secrets.token_hex(8)
    )


def get_database_url() -> str:
    # Use dedicated AUTH_DATABASE_URL if available, otherwise fall back to constructed URL
    auth_db_url = os.getenv("AUTH_DATABASE_URL")
    if auth_db_url:
        # Convert to asyncpg format if needed
        return auth_db_url.replace("postgresql://", "postgresql+asyncpg://").replace("?sslmode=", "?ssl=")
    
    return (
        f"postgresql+asyncpg://{settings.DB_USER}:{settings.DB_PASSWORD}"
        f"@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
    )
