from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Example: Use a fixed key/iv for demo; in production, use secure key management!
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for AES-256
IV = b'abcdef9876543210'                   # 16 bytes for AES CBC

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt_bytes(data):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(data)
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct

def aes_decrypt_bytes(data):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    return unpad(padded)