from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from Crypto.Cipher import DES, ChaCha20
from Crypto.Random import get_random_bytes

# For demo: use a fixed key. In production, use secure key management!
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for AES-256

# DES key must be 8 bytes
DES_KEY = b'8bytekey'

def aes_encrypt(plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()

def aes_encrypt_bytes(data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct

def aes_decrypt_bytes(data):
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

# --- DES ---
def des_encrypt(plaintext):
    iv = get_random_bytes(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    pad_len = 8 - (len(plaintext.encode()) % 8)
    padded = plaintext.encode() + bytes([pad_len] * pad_len)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct).decode()

def des_decrypt(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pad_len = padded[-1]
    return padded[:-pad_len].decode()

def des_encrypt_bytes(data):
    iv = get_random_bytes(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    pad_len = 8 - (len(data) % 8)
    padded = data + bytes([pad_len] * pad_len)
    ct = cipher.encrypt(padded)
    return iv + ct

def des_decrypt_bytes(data):
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pad_len = padded[-1]
    return padded[:-pad_len]

# --- ChaCha20 ---
CHACHA_KEY = get_random_bytes(32)

def chacha20_encrypt(plaintext):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=CHACHA_KEY, nonce=nonce)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(nonce + ct).decode()

def chacha20_decrypt(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    ct = data[12:]
    cipher = ChaCha20.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt(ct)
    return pt.decode()

def chacha20_encrypt_bytes(data):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=CHACHA_KEY, nonce=nonce)
    ct = cipher.encrypt(data)
    return nonce + ct

def chacha20_decrypt_bytes(data):
    nonce = data[:12]
    ct = data[12:]
    cipher = ChaCha20.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt(ct)
    return pt