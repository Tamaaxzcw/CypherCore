# Author: Tamaaxzcw
# GitHub: https://github.com/Tamaaxzcw

import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

# Constants for compatibility
SALT_SIZE = 16
IV_SIZE = 12  # GCM standard IV size
TAG_SIZE = 16
KEY_SIZE = 32 # 256 bits
ITERATIONS = 250000

def encrypt(plain_text: str, secret: str) -> str:
    """Enkripsi teks menggunakan AES-256-GCM dengan derivasi kunci PBKDF2."""
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(secret, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA512)
    
    cipher = AES.new(key, AES.MODE_GCM)
    iv = cipher.nonce # GCM nonce (IV)
    
    cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    
    # Format: salt:iv:tag:ciphertext, all encoded in Base64
    encrypted_payload = base64.b64encode(salt + iv + tag + cipher_text)
    return encrypted_payload.decode('utf-8')

def decrypt(encrypted_payload: str, secret: str) -> str:
    """Dekripsi payload terenkripsi."""
    try:
        data = base64.b64decode(encrypted_payload)
        
        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE : SALT_SIZE + IV_SIZE]
        tag = data[SALT_SIZE + IV_SIZE : SALT_SIZE + IV_SIZE + TAG_SIZE]
        cipher_text = data[SALT_SIZE + IV_SIZE + TAG_SIZE:]

        key = PBKDF2(secret, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA512)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        decrypted_text = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted_text.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise Exception("Decryption failed. Data may be corrupted or key is incorrect.")

# Example usage
if __name__ == "__main__":
    secret_key = "tamaaxzcw-key"
    original_text = "Pesan ini akan dienkripsi di Python."

    encrypted = encrypt(original_text, secret_key)
    decrypted = decrypt(encrypted, secret_key)
    
    print(f"Original : {original_text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
