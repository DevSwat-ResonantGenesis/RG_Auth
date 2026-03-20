from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4
import secrets

import hashlib
import hmac
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .identity import Identity


# Use argon2 for production-grade password hashing (bcrypt has issues with passlib)
pwd_context = CryptContext(schemes=["argon2", "sha256_crypt"], deprecated="auto")

ALGORITHM = "HS256"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    if not hashed_password:
        return False
    # Support both old SHA256 and new argon2/bcrypt hashes
    if hashed_password.startswith("$2") or hashed_password.startswith("$argon2"):
        return pwd_context.verify(plain_password, hashed_password)
    else:
        # Legacy SHA256 hash
        computed = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(computed, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password using argon2."""
    password_bytes = password.encode('utf-8')[:72]
    return pwd_context.hash(password_bytes.decode('utf-8', errors='ignore'))


# Alias for backwards compatibility
get_password_hash = hash_password


def _salted_hash(value: str, salt: str) -> str:
    """Create a salted SHA256 hash."""
    digest = hashlib.sha256()
    digest.update(salt.encode("utf-8"))
    digest.update(value.encode("utf-8"))
    return digest.hexdigest()


def hash_token(token: str) -> str:
    """Hash a token for secure storage."""
    return _salted_hash(token, settings.API_KEY_SALT)


def generate_refresh_token() -> Tuple[str, str]:
    """Generate a refresh token and its hash."""
    token = secrets.token_urlsafe(48)
    return token, hash_token(token)


def generate_api_key() -> Tuple[str, str, str]:
    """Generate an API key with prefix and hash."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    api_key = f"RG-{prefix}.{secret}"
    return api_key, prefix, hash_token(api_key)


def create_access_token(identity: Identity, token_version: int, user_crypto_data: dict = None) -> str:
    """Create a JWT access token with Identity claims and crypto hashes."""
    expire = _utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: Dict[str, Any] = {
        "exp": expire,
        "iat": _utcnow(),
        "jti": uuid4().hex,
        "type": "access",
        "token_version": token_version,
        **identity.to_claims(),
    }
    
    # Add crypto identity fields if provided
    if user_crypto_data:
        if user_crypto_data.get("crypto_hash"):
            payload["crypto_hash"] = user_crypto_data["crypto_hash"]
        if user_crypto_data.get("user_hash"):
            payload["user_hash"] = user_crypto_data["user_hash"]
        if user_crypto_data.get("universe_id"):
            payload["universe_id"] = user_crypto_data["universe_id"]
    
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate an access token, returning full claims."""
    decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[ALGORITHM])
    if decoded.get("type") != "access":
        raise JWTError("Invalid token type")
    return decoded


async def validate_access_token(token: str, db: AsyncSession) -> Dict[str, Any]:
    """Decode and validate an access token with server-side token_version check."""
    # First decode the token
    decoded = decode_access_token(token)
    
    # Extract user_id and token_version from token
    user_id = decoded.get("user_id")
    token_version = decoded.get("token_version")
    
    if not user_id or token_version is None:
        raise JWTError("Invalid token claims")
    
    # Look up user and validate token_version
    from sqlalchemy import select
    from .models import User
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise JWTError("User not found")
    
    if user.token_version != token_version:
        raise JWTError("Token version mismatch - token invalidated")
    
    return decoded
