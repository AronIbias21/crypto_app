import hashlib

def sha256_hash(input_text):
    return hashlib.sha256(input_text.encode()).hexdigest()

def sha3_512_hash(input_text):
    return hashlib.sha3_512(input_text.encode()).hexdigest()
