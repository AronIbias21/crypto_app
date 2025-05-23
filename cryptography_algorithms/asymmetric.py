from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Random import get_random_bytes
import base64
import math

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
    from flask import session
    pubkey_pem = base64.b64decode(session['public_key'])
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_public_key(pubkey_pem)
    plaintext_bytes = plaintext.encode()
    key_size = public_key.key_size // 8
    max_chunk = key_size - 2 * hashes.SHA256().digest_size - 2
    if len(plaintext_bytes) > max_chunk:
        return "Error: Message too long for RSA encryption. Use file mode for large data."
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext_b64):
    from flask import session
    privkey_pem = base64.b64decode(session['private_key'])
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(privkey_pem, password=None)
    ciphertext = base64.b64decode(ciphertext_b64)
    key_size = private_key.key_size // 8
    if len(ciphertext) > key_size:
        return "Error: Ciphertext too large for RSA decryption. Use file mode for large data."
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
    key_size = public_key.key_size // 8
    max_chunk = key_size - 2 * hashes.SHA256().digest_size - 2
    chunks = [data[i:i+max_chunk] for i in range(0, len(data), max_chunk)]
    encrypted = b''
    for chunk in chunks:
        encrypted += public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return encrypted

def rsa_decrypt_bytes(data):
    from flask import session
    privkey_pem = base64.b64decode(session['private_key'])
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(privkey_pem, password=None)
    key_size = private_key.key_size // 8
    chunks = [data[i:i+key_size] for i in range(0, len(data), key_size)]
    decrypted = b''
    for chunk in chunks:
        decrypted += private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return decrypted

def hybrid_encrypt(message, recipient_pubkey, sender_privkey):
    # Placeholder for secure chat
    raise NotImplementedError("hybrid_encrypt not implemented yet.")

def hybrid_decrypt(encrypted_package, private_key):
    # Placeholder for secure chat
    raise NotImplementedError("hybrid_decrypt not implemented yet.")