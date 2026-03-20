"""
Multi-Factor Authentication (MFA) module for auth_service.

Implements TOTP (Time-based One-Time Password) authentication using pyotp.
Supports:
- TOTP secret generation
- QR code generation for authenticator apps
- TOTP code verification
- Backup codes for recovery
"""

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from typing import List, Optional, Tuple

from .crypto import encrypt_api_key, decrypt_api_key


# TOTP Configuration
TOTP_INTERVAL = 30  # Seconds per code
TOTP_DIGITS = 6     # Number of digits in code
TOTP_ALGORITHM = "sha1"  # HMAC algorithm
TOTP_VALID_WINDOW = 1    # Allow codes from adjacent intervals (±30s)

# Backup codes configuration
BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 8  # Characters per code


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret.
    
    Returns:
        Base32-encoded secret string (32 characters)
    """
    # Generate 20 random bytes (160 bits) as recommended by RFC 4226
    random_bytes = secrets.token_bytes(20)
    # Encode as base32 for compatibility with authenticator apps
    return base64.b32encode(random_bytes).decode('utf-8')


def _get_totp_counter(timestamp: Optional[float] = None) -> int:
    """Get the current TOTP counter value."""
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp // TOTP_INTERVAL)


def _hotp(secret: str, counter: int) -> str:
    """
    Generate HOTP code (RFC 4226).
    
    Args:
        secret: Base32-encoded secret
        counter: Counter value
        
    Returns:
        6-digit HOTP code as string
    """
    # Decode base32 secret
    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        raise ValueError("Invalid base32 secret")
    
    # Pack counter as 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)
    
    # Calculate HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation (RFC 4226)
    offset = hmac_hash[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_hash[offset:offset + 4])[0]
    truncated &= 0x7FFFFFFF  # Clear top bit
    
    # Generate code
    code = truncated % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def generate_totp_code(secret: str, timestamp: Optional[float] = None) -> str:
    """
    Generate current TOTP code.
    
    Args:
        secret: Base32-encoded secret
        timestamp: Optional timestamp (defaults to current time)
        
    Returns:
        6-digit TOTP code as string
    """
    counter = _get_totp_counter(timestamp)
    return _hotp(secret, counter)


def verify_totp_code(secret: str, code: str, valid_window: int = TOTP_VALID_WINDOW) -> bool:
    """
    Verify a TOTP code.
    
    Args:
        secret: Base32-encoded secret
        code: 6-digit code to verify
        valid_window: Number of intervals to check before/after current
        
    Returns:
        True if code is valid, False otherwise
    """
    if not code or len(code) != TOTP_DIGITS:
        return False
    
    if not code.isdigit():
        return False
    
    current_counter = _get_totp_counter()
    
    # Check current and adjacent intervals
    for offset in range(-valid_window, valid_window + 1):
        expected_code = _hotp(secret, current_counter + offset)
        if hmac.compare_digest(code, expected_code):
            return True
    
    return False


def generate_provisioning_uri(
    secret: str,
    email: str,
    issuer: str = "ResonantGenesis"
) -> str:
    """
    Generate otpauth:// URI for authenticator apps.
    
    Args:
        secret: Base32-encoded secret
        email: User's email address
        issuer: Application name
        
    Returns:
        otpauth:// URI string
    """
    # URL-encode special characters
    from urllib.parse import quote
    
    label = quote(f"{issuer}:{email}", safe="")
    params = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}"
    
    return f"otpauth://totp/{label}?{params}"


def generate_qr_code_data_url(uri: str) -> str:
    """
    Generate QR code as base64 data URL.
    
    Uses a simple QR code implementation without external dependencies.
    For production, consider using the 'qrcode' library for better QR codes.
    
    Args:
        uri: The otpauth:// URI to encode
        
    Returns:
        Data URL string (data:image/svg+xml;base64,...)
    """
    # Simple SVG-based QR code placeholder
    # In production, use: pip install qrcode[pil]
    # For now, return the URI in a format the frontend can use
    
    try:
        # Try to use qrcode library if available
        import qrcode
        from qrcode.image.svg import SvgImage
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Generate SVG
        img = qr.make_image(image_factory=SvgImage)
        buffer = io.BytesIO()
        img.save(buffer)
        svg_data = buffer.getvalue()
        
        return f"data:image/svg+xml;base64,{base64.b64encode(svg_data).decode()}"
    except ImportError:
        # Fallback: return URI directly (frontend can generate QR)
        return f"otpauth-uri:{uri}"


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> Tuple[List[str], List[str]]:
    """
    Generate backup codes for MFA recovery.
    
    Args:
        count: Number of backup codes to generate
        
    Returns:
        Tuple of (plain_codes, hashed_codes)
        - plain_codes: Show to user once
        - hashed_codes: Store in database
    """
    plain_codes = []
    hashed_codes = []
    
    for _ in range(count):
        # Generate random code (e.g., "A1B2-C3D4")
        code_bytes = secrets.token_bytes(BACKUP_CODE_LENGTH // 2)
        code = code_bytes.hex().upper()
        # Format as XXXX-XXXX
        formatted = f"{code[:4]}-{code[4:]}"
        plain_codes.append(formatted)
        
        # Hash for storage
        code_hash = hashlib.sha256(formatted.encode()).hexdigest()
        hashed_codes.append(code_hash)
    
    return plain_codes, hashed_codes


def verify_backup_code(code: str, hashed_codes: List[str]) -> Tuple[bool, Optional[int]]:
    """
    Verify a backup code.
    
    Args:
        code: Backup code to verify (with or without hyphen)
        hashed_codes: List of hashed backup codes from database
        
    Returns:
        Tuple of (is_valid, index_of_used_code)
        - index_of_used_code is None if not valid
    """
    # Normalize code (remove hyphens, uppercase)
    normalized = code.replace("-", "").upper()
    if len(normalized) == BACKUP_CODE_LENGTH:
        # Re-add hyphen for hashing
        formatted = f"{normalized[:4]}-{normalized[4:]}"
    else:
        formatted = code.upper()
    
    code_hash = hashlib.sha256(formatted.encode()).hexdigest()
    
    for i, stored_hash in enumerate(hashed_codes):
        if hmac.compare_digest(code_hash, stored_hash):
            return True, i
    
    return False, None


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt MFA secret for database storage."""
    return encrypt_api_key(secret)


def decrypt_mfa_secret(encrypted_secret: str) -> str:
    """Decrypt MFA secret from database."""
    return decrypt_api_key(encrypted_secret)


class MFAManager:
    """
    High-level MFA management class.
    
    Usage:
        manager = MFAManager()
        
        # Setup MFA
        secret, uri, qr_url, backup_codes, backup_hashes = manager.setup_mfa("user@example.com")
        # Store: encrypt_mfa_secret(secret), backup_hashes in database
        # Show: qr_url, backup_codes to user
        
        # Verify code
        is_valid = manager.verify_code(decrypt_mfa_secret(stored_secret), user_code)
    """
    
    def __init__(self, issuer: str = "ResonantGenesis"):
        self.issuer = issuer
    
    def setup_mfa(self, email: str) -> Tuple[str, str, str, List[str], List[str]]:
        """
        Setup MFA for a user.
        
        Args:
            email: User's email address
            
        Returns:
            Tuple of (secret, uri, qr_data_url, backup_codes, backup_hashes)
        """
        secret = generate_totp_secret()
        uri = generate_provisioning_uri(secret, email, self.issuer)
        qr_url = generate_qr_code_data_url(uri)
        backup_codes, backup_hashes = generate_backup_codes()
        
        return secret, uri, qr_url, backup_codes, backup_hashes
    
    def verify_code(self, secret: str, code: str) -> bool:
        """Verify a TOTP code."""
        return verify_totp_code(secret, code)
    
    def verify_backup(self, code: str, hashed_codes: List[str]) -> Tuple[bool, Optional[int]]:
        """Verify a backup code."""
        return verify_backup_code(code, hashed_codes)
