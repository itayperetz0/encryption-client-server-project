# owner Itay Pretz
# ID 207007329

import secrets



class Key_generator:

    def generate_random_uuid(self):
        # Generate 16 bytes (128 bits) of random uuid
        random_uuid = secrets.token_bytes(16)
        return random_uuid

    def generate_AES_key(self):
        # Generate a random 256 bit key using secrets.token_bytes
        key_len = 32
        bytes_key = secrets.token_bytes(key_len)
        return bytes_key


    def generate_random_nonce(self):
        random_nounce = secrets.token_bytes(8)
        return random_nounce
       
    
    
   