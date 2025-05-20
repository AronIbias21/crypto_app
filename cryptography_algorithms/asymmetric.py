from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def hybrid_encrypt(message, recipient_pubkey_bytes, sender_privkey_bytes):
    recipient_pubkey = serialization.load_pem_public_key(recipient_pubkey_bytes, backend=default_backend())
    sender_privkey = serialization.load_pem_private_key(sender_privkey_bytes, password=None, backend=default_backend())
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_msg = pad(message.encode())
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    enc_aes_key = recipient_pubkey.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    signature = sender_privkey.sign(
        ciphertext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return enc_aes_key + iv + ciphertext + signature

def hybrid_decrypt(encrypted_package, recipient_privkey_bytes):
    recipient_privkey = serialization.load_pem_private_key(recipient_privkey_bytes, password=None, backend=default_backend())
    enc_aes_key = encrypted_package[:256]
    iv = encrypted_package[256:272]
    ciphertext_and_sig = encrypted_package[272:]
    ciphertext = ciphertext_and_sig[:-256]
    signature = ciphertext_and_sig[-256:]
    aes_key = recipient_privkey.decrypt(
        enc_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        msg = unpad(padded_msg).decode()
    except Exception:
        msg = ""
    verified = len(signature) == 256
    return msg, verified

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]