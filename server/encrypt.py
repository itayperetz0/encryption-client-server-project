# owner Itay Pretz
# ID 207007329

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class Encrypt:
    
    
    
    def __init__(self):
        pass
    
  
    def encrypt_aes_cbc(self, key, to_encrypt):  
        
        iv = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        to_encrypt = pad(to_encrypt, AES.block_size)
        cipher_server_key = cipher.encrypt(to_encrypt)
        return cipher_server_key
    
    
    def decrypt_aes_cbc(self, key, encrypted_data):
        iv = bytes([0] * AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_data)
        return unpad(decrypted_text, AES.block_size)

    
    
    # def decrypt_aes_cbc(self, key, encrypted_data):
       
    #     iv = b'\x00' * 16
    #     cipher = AES.new(key, AES.MODE_CBC, iv)
    #     decrypted_data = cipher.decrypt(encrypted_data)
    #     # decrypted_data = unpad(decrypted_data, AES.block_size)
    #     decrypted_data = decrypted_data.decode()
    #     return decrypted_data
    
    def encrypt_rsa_public(self, public_key_bytes, data):
       
        # Load the RSA public key
        rsa_key = RSA.import_key(public_key_bytes)

        # Create a cipher object for encryption
        cipher = PKCS1_OAEP.new(rsa_key)

        # Encrypt the data
        ciphertext = cipher.encrypt(data)

        return ciphertext