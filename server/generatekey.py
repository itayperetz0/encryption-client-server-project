# owner Itay Pretz
"""
Cryptographic Key Generator

This module provides secure key generation functionality using Python's secrets module.
It generates cryptographically strong random values for:
- UUIDs (128-bit)
- AES keys (256-bit)
- Nonces (64-bit)

The secrets module is used instead of random to ensure cryptographic security
for all generated values.
"""

import secrets

class Key_generator:
    """
    Generates cryptographically secure random values for various cryptographic purposes.
    
    This class provides methods to generate random UUIDs, AES keys, and nonces using
    Python's secrets module, which is designed for generating cryptographically strong
    random numbers suitable for managing secrets such as account authentication,
    tokens, and similar.
    """
    
    def generate_random_uuid(self):
        """
        Generate a cryptographically secure random UUID.
        
        Returns:
            bytes: A 16-byte (128-bit) random UUID suitable for unique identification.
                  This provides sufficient randomness for avoiding collisions in
                  distributed systems.
        """
        random_uuid = secrets.token_bytes(16)
        return random_uuid
    
    def generate_AES_key(self):
        """
        Generate a cryptographically secure AES-256 key.
        
        Returns:
            bytes: A 32-byte (256-bit) random key suitable for AES-256 encryption.
                  Uses secrets.token_bytes to ensure cryptographic security.
        """
        key_len = 32  # 256 bits = 32 bytes for AES-256
        bytes_key = secrets.token_bytes(key_len)
        return bytes_key
    
    def generate_random_nonce(self):
        """
        Generate a cryptographically secure random nonce.
        
        Returns:
            bytes: An 8-byte (64-bit) random nonce suitable for use in cryptographic
                  protocols to ensure message freshness and prevent replay attacks.
        """
        random_nonce = secrets.token_bytes(8)
        return random_nonce
