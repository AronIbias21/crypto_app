from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def rsa_encrypt(plaintext):
    # Encrypt with session public key (PEM, base64)
    from flask import session
    pubkey_pem = base64.b64decode(session['public_key'])
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_public_key(pubkey_pem)
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext_b64):
    # Decrypt with session private key (PEM, base64)
    from flask import session
    privkey_pem = base64.b64decode(session['private_key'])
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(privkey_pem, password=None)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def rsa_encrypt_bytes(data):
    from flask import session
    pubkey_pem = base64.b64decode(session['public_key'])
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_public_key(pubkey_pem)
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt_bytes(data):
    from flask import session
    privkey_pem = base64.b64decode(session['private_key'])
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(privkey_pem, password=None)
    plaintext = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def hybrid_encrypt(message, recipient_pubkey, sender_privkey):
    # Placeholder for secure chat
    raise NotImplementedError("hybrid_encrypt not implemented yet.")

def hybrid_decrypt(encrypted_package, private_key):
    # Placeholder for secure chat
    raise NotImplementedError("hybrid_decrypt not implemented yet.")