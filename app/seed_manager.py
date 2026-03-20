"""
Seed Management Service
Handles BIP-39 seed generation, encryption, and derivation
Ported from ResonantGraphAIV0.1 backend
"""
from __future__ import annotations

import hashlib
import os
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# Try to import BIP-39 library
try:
    from mnemonic import Mnemonic
    BIP39_AVAILABLE = True
except ImportError:
    BIP39_AVAILABLE = False
    logger.warning("BIP-39 library not installed. Install with: pip install mnemonic")

# Try to import encryption library
try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning("cryptography library not installed. Install with: pip install cryptography")


class SeedManager:
    """
    Seed Management Service
    
    Handles:
    - BIP-39 seed generation
    - Seed encryption/decryption
    - Universe ID derivation
    """
    
    def __init__(self):
        """Initialize seed manager"""
        if BIP39_AVAILABLE:
            self.mn = Mnemonic("english")
        else:
            self.mn = None
            logger.warning("BIP-39 not available - using fallback seed generation")
        
        # Get encryption key from environment
        encryption_key = os.getenv("SEED_ENCRYPTION_KEY")
        if encryption_key and CRYPTOGRAPHY_AVAILABLE:
            try:
                self.cipher = Fernet(encryption_key.encode())
                self.encryption_enabled = True
            except Exception as e:
                logger.warning(f"Failed to initialize encryption: {e}")
                self.cipher = None
                self.encryption_enabled = False
        else:
            self.cipher = None
            self.encryption_enabled = False
            if not encryption_key:
                logger.warning("SEED_ENCRYPTION_KEY not set - seeds will not be encrypted")
    
    def generate_seed(self, strength: int = 128) -> Tuple[str, str]:
        """
        Generate BIP-39 seed
        
        Args:
            strength: Entropy strength in bits (128, 160, 192, 224, or 256)
        
        Returns:
            (mnemonic_phrase, seed_hex)
            - mnemonic_phrase: Human-readable 12/15/18/21/24 word phrase
            - seed_hex: Hexadecimal seed for cryptographic operations
        """
        if not BIP39_AVAILABLE:
            # Fallback: Generate deterministic seed from random bytes
            logger.warning("Using fallback seed generation (BIP-39 not available)")
            import secrets
            entropy = secrets.token_bytes(strength // 8)
            seed_hex = entropy.hex()
            # Create simple mnemonic-like representation (not BIP-39 compliant)
            mnemonic = f"fallback-seed-{seed_hex[:16]}"
            return mnemonic, seed_hex
        
        try:
            # Generate entropy
            import secrets
            entropy = secrets.token_bytes(strength // 8)
            
            # Generate BIP-39 mnemonic
            mnemonic = self.mn.to_mnemonic(entropy)
            
            # Generate seed from mnemonic
            seed = self.mn.to_seed(mnemonic)
            seed_hex = seed.hex()
            
            logger.info(f"Generated BIP-39 seed: {strength} bits, {len(mnemonic.split())} words")
            
            return mnemonic, seed_hex
        
        except Exception as e:
            logger.error(f"Error generating BIP-39 seed: {e}", exc_info=True)
            # Fallback
            import secrets
            entropy = secrets.token_bytes(strength // 8)
            seed_hex = entropy.hex()
            mnemonic = f"fallback-seed-{seed_hex[:16]}"
            return mnemonic, seed_hex
    
    def encrypt_seed(self, seed: str) -> str:
        """
        Encrypt seed for storage
        
        Args:
            seed: Seed to encrypt (hex string or mnemonic)
        
        Returns:
            Encrypted seed (base64 string)
        """
        if not self.encryption_enabled or not self.cipher:
            logger.warning("Encryption not available - returning seed as-is (NOT SECURE)")
            return seed
        
        try:
            encrypted = self.cipher.encrypt(seed.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Error encrypting seed: {e}", exc_info=True)
            raise ValueError(f"Failed to encrypt seed: {e}")
    
    def decrypt_seed(self, encrypted_seed: str) -> str:
        """
        Decrypt seed for use
        
        Args:
            encrypted_seed: Encrypted seed (base64 string)
        
        Returns:
            Decrypted seed (original string)
        """
        if not self.encryption_enabled or not self.cipher:
            # Assume it's not encrypted
            return encrypted_seed
        
        try:
            decrypted = self.cipher.decrypt(encrypted_seed.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting seed: {e}", exc_info=True)
            raise ValueError(f"Failed to decrypt seed: {e}")
    
    def derive_universe_id(self, seed: str) -> str:
        """
        Derive universe identifier from seed
        
        This is deterministic: same seed → same universe_id
        
        Args:
            seed: Seed (hex string or mnemonic)
        
        Returns:
            Universe ID (16-character hex string)
        """
        # Use SHA-256 for deterministic derivation
        universe_hash = hashlib.sha256(seed.encode()).hexdigest()
        universe_id = universe_hash[:16]  # First 16 characters (64 bits)
        
        return universe_id
    
    def validate_mnemonic(self, mnemonic: str) -> bool:
        """
        Validate BIP-39 mnemonic phrase
        
        Args:
            mnemonic: Mnemonic phrase to validate
        
        Returns:
            True if valid, False otherwise
        """
        if not BIP39_AVAILABLE:
            return False
        
        try:
            return self.mn.check(mnemonic)
        except Exception:
            return False
    
    def mnemonic_to_seed(self, mnemonic: str) -> str:
        """
        Convert mnemonic phrase to seed
        
        Args:
            mnemonic: BIP-39 mnemonic phrase
        
        Returns:
            Seed hex string
        """
        if not BIP39_AVAILABLE:
            raise ValueError("BIP-39 not available")
        
        if not self.validate_mnemonic(mnemonic):
            raise ValueError("Invalid mnemonic phrase")
        
        seed = self.mn.to_seed(mnemonic)
        return seed.hex()


# Singleton instance
seed_manager = SeedManager()
