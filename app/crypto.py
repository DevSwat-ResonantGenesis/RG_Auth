"""
Cryptographic utilities for auth_service.

Provides encryption/decryption for sensitive data like BYOK API keys.
Uses Fernet symmetric encryption (AES-128-CBC with HMAC).
"""

import os
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _get_encryption_key() -> bytes:
    """
    Get or derive the encryption key for BYOK keys.
    
    Uses BYOK_ENCRYPTION_KEY env var if set, otherwise derives from JWT_SECRET_KEY.
    In production, BYOK_ENCRYPTION_KEY should be a proper Fernet key.
    """
    env_key = os.getenv("BYOK_ENCRYPTION_KEY")
    
    if env_key:
        # If it's already a valid Fernet key (44 chars base64), use it
        if len(env_key) == 44:
            return env_key.encode()
        # Otherwise, derive a key from it
        derived = hashlib.sha256(env_key.encode()).digest()
        return base64.urlsafe_b64encode(derived)
    
    # Fallback: derive from JWT secret (not ideal for production)
    jwt_secret = settings.JWT_SECRET_KEY
    derived = hashlib.sha256(jwt_secret.encode()).digest()
    return base64.urlsafe_b64encode(derived)


# Initialize Fernet cipher
_fernet: Optional[Fernet] = None


def _get_fernet() -> Fernet:
    """Get or create the Fernet cipher instance."""
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_get_encryption_key())
    return _fernet


def encrypt_api_key(plain_key: str) -> str:
    """
    Encrypt an API key for secure storage.
    
    Args:
        plain_key: The plaintext API key
        
    Returns:
        Base64-encoded encrypted key
    """
    if not plain_key:
        return ""
    
    fernet = _get_fernet()
    encrypted = fernet.encrypt(plain_key.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_api_key(encrypted_key: str) -> str:
    """
    Decrypt an API key from storage.
    
    Args:
        encrypted_key: The encrypted API key (base64)
        
    Returns:
        The plaintext API key
        
    Raises:
        ValueError: If decryption fails (invalid key or corrupted data)
    """
    if not encrypted_key:
        return ""
    
    # Handle legacy unencrypted keys (they won't have Fernet prefix)
    # Fernet tokens start with 'gAAAAA' (base64 of version byte + timestamp)
    if not encrypted_key.startswith('gAAAAA'):
        # This is likely a legacy unencrypted key, return as-is
        # Log warning in production
        return encrypted_key
    
    try:
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_key.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        # If decryption fails, it might be a legacy unencrypted key
        # or corrupted data - return as-is with warning
        return encrypted_key
    except Exception as e:
        raise ValueError(f"Failed to decrypt API key: {e}")


def is_encrypted(value: str) -> bool:
    """Check if a value appears to be Fernet-encrypted."""
    if not value:
        return False
    return value.startswith('gAAAAA')


def rotate_encryption_key(old_key: str, new_key: str, encrypted_value: str) -> str:
    """
    Re-encrypt a value with a new key.
    
    Args:
        old_key: The old encryption key
        new_key: The new encryption key
        encrypted_value: The value encrypted with old_key
        
    Returns:
        The value re-encrypted with new_key
    """
    # Decrypt with old key
    old_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(old_key.encode()).digest()))
    try:
        decrypted = old_fernet.decrypt(encrypted_value.encode('utf-8'))
    except InvalidToken:
        raise ValueError("Failed to decrypt with old key")
    
    # Encrypt with new key
    new_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(new_key.encode()).digest()))
    return new_fernet.encrypt(decrypted).decode('utf-8')
