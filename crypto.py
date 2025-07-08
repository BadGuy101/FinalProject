# utils/crypto.py

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def hash_file(file_path: str, algorithm: str = "sha256") -> str:
    """
    Returns the hash of a file.
    """
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES CBC mode with a random IV.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    padding = 16 - len(data) % 16
    data += bytes([padding]) * padding
    ciphertext = cipher.encrypt(data)
    return base64.b64encode(cipher.iv + ciphertext)

def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts AES CBC encrypted data.
    """
    raw = base64.b64decode(ciphertext)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ct)
    padding = plaintext[-1]
    return plaintext[:-padding]
