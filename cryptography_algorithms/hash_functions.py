import hashlib

def sha256_hash(input_text):
    return hashlib.sha256(input_text.encode()).hexdigest()

def sha3_512_hash(input_text):
    return hashlib.sha3_512(input_text.encode()).hexdigest()

def sha1_hash(input_text):
    return hashlib.sha1(input_text.encode()).hexdigest()

def blake2b_hash(input_text):
    return hashlib.blake2b(input_text.encode()).hexdigest()

def sha256_hash_file(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def sha3_512_hash_file(file_bytes):
    return hashlib.sha3_512(file_bytes).hexdigest()

def sha1_hash_file(file_bytes):
    return hashlib.sha1(file_bytes).hexdigest()

def blake2b_hash_file(file_bytes):
    return hashlib.blake2b(file_bytes).hexdigest()
