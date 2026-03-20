"""
Keypair Generation - Layer 5

Generates Ed25519 keypairs for message signing and verification.
Derives keypairs deterministically from crypto_hash for reproducibility.
"""

import hashlib
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def derive_keypair_from_crypto_hash(crypto_hash: str) -> Tuple[bytes, bytes]:
    """
    Derive Ed25519 keypair from crypto_hash (deterministic).
    
    WARNING: This is for DSID identity and message signing only.
    NOT for securing funds or critical cryptographic operations.
    For production, consider using HSM, KMS, or secure key storage.
    
    Args:
        crypto_hash: The user's crypto_hash (64-char hex string)
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library not installed")
    
    # Use crypto_hash as seed for deterministic key generation
    seed = hashlib.sha256(crypto_hash.encode()).digest()
    
    # Generate Ed25519 keypair from seed
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
    public_key = private_key.public_key()
    
    # Serialize to bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return (private_bytes, public_bytes)


def sign_message(private_key_bytes: bytes, message: str) -> bytes:
    """
    Sign a message with the private key.
    
    Args:
        private_key_bytes: 32-byte private key
        message: Message to sign
    
    Returns:
        64-byte signature
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library not installed")
    
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(message.encode())
    return signature


def verify_signature(public_key_bytes: bytes, message: str, signature: bytes) -> bool:
    """
    Verify a message signature.
    
    Args:
        public_key_bytes: 32-byte public key
        message: Original message
        signature: 64-byte signature
    
    Returns:
        True if signature is valid
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library not installed")
    
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message.encode())
        return True
    except Exception:
        return False


def get_public_key_hex(crypto_hash: str) -> str:
    """
    Get the public key as hex string for a given crypto_hash.
    
    This can be stored in the database or shared publicly.
    """
    _, public_bytes = derive_keypair_from_crypto_hash(crypto_hash)
    return public_bytes.hex()


# Example usage for future implementation:
"""
# During registration:
private_key, public_key = derive_keypair_from_crypto_hash(crypto_hash)
user.public_key = public_key.hex()  # Store in database

# When signing a message:
signature = sign_message(private_key, "Hello, world!")

# When verifying:
is_valid = verify_signature(public_key, "Hello, world!", signature)
"""
