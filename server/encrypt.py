# owner Itay Pretz
"""
Encryption and Decryption Implementation

This module provides encryption and decryption functionality using both symmetric (AES-CBC)
and asymmetric (RSA-OAEP) cryptography. It handles:
- AES-CBC encryption/decryption with PKCS7 padding
- RSA encryption using PKCS1_OAEP padding scheme

Security Notes:
- Uses a zero IV for AES-CBC mode (this should be reviewed for production use)
- Implements PKCS7 padding for AES operations
- Uses RSA with OAEP padding for asymmetric encryption
"""

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class Encrypt:
    """
    Provides encryption and decryption operations using AES and RSA.
    
    This class implements both symmetric (AES-CBC) and asymmetric (RSA) encryption
    operations. AES is used for bulk data encryption, while RSA is used for
    key exchange and small data encryption.
    """
    
    def __init__(self):
        """Initialize the encryption handler."""
        pass
    
    def encrypt_aes_cbc(self, key, to_encrypt):
        """
        Encrypt data using AES in CBC mode with PKCS7 padding.
        
        Args:
            key (bytes): The AES key (should be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
            to_encrypt (bytes): The data to encrypt
            
        Returns:
            bytes: The encrypted data
            
        Notes:
            - Uses a zero IV (this should be reviewed for production use)
            - Implements PKCS7 padding to handle data of any length
        """
        iv = b'\x00' * 16  # Zero IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        to_encrypt = pad(to_encrypt, AES.block_size)
        cipher_server_key = cipher.encrypt(to_encrypt)
        return cipher_server_key
    
    def decrypt_aes_cbc(self, key, encrypted_data):
        """
        Decrypt data using AES in CBC mode with PKCS7 padding.
        
        Args:
            key (bytes): The AES key (should be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
            encrypted_data (bytes): The data to decrypt
            
        Returns:
            bytes: The decrypted data with padding removed
            
        Notes:
            - Uses a zero IV (must match encryption)
            - Removes PKCS7 padding after decryption
        """
        iv = bytes([0] * AES.block_size)  # Zero IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_data)
        return unpad(decrypted_text, AES.block_size)
    
    def encrypt_rsa_public(self, public_key_bytes, data):
        """
        Encrypt data using RSA with OAEP padding.
        
        Args:
            public_key_bytes (bytes): The RSA public key in binary format
            data (bytes): The data to encrypt (must be smaller than the RSA key size
                         minus padding overhead)
            
        Returns:
            bytes: The encrypted data
            
        Notes:
            - Uses PKCS1_OAEP padding which is secure against chosen-ciphertext attacks
            - The size of data that can be encrypted is limited by the RSA key size
        """
        # Load the RSA public key
        rsa_key = RSA.import_key(public_key_bytes)
        # Create a cipher object for encryption using OAEP padding
        cipher = PKCS1_OAEP.new(rsa_key)
        # Encrypt the data
        ciphertext = cipher.encrypt(data)
        return ciphertext
