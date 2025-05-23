from flask import Flask, render_template, request, session, send_file, redirect, url_for
from cryptography_algorithms import symmetric, asymmetric, hash_functions
import base64
import os
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Needed for session

ALGORITHM_INFO = {
    "aes": {
        "name": "AES (Advanced Encryption Standard)",
        "type": "Symmetric",
        "history": "AES was established as the encryption standard by NIST in 2001, replacing DES.",
        "description": "AES is a block cipher that encrypts data in 128-bit blocks using 128, 192, or 256-bit keys.",
        "use_cases": "Used for secure data storage, file encryption, and secure communications."
    },
    "des": {
        "name": "DES (Data Encryption Standard)",
        "type": "Symmetric",
        "history": "DES was adopted as a federal standard in 1977 but is now considered insecure.",
        "description": "DES encrypts data in 64-bit blocks using a 56-bit key.",
        "use_cases": "Legacy systems, replaced by AES for most applications."
    },
    "chacha20": {
        "name": "ChaCha20",
        "type": "Symmetric",
        "history": "ChaCha20 was designed by Daniel J. Bernstein as a faster, more secure alternative to Salsa20.",
        "description": "A stream cipher known for speed and security, often used in TLS and VPNs.",
        "use_cases": "TLS, VPNs, disk encryption."
    },
    "rsa": {
        "name": "RSA",
        "type": "Asymmetric",
        "history": "RSA was invented in 1977 by Rivest, Shamir, and Adleman.",
        "description": "RSA uses a pair of keys for encryption and decryption, based on the difficulty of factoring large numbers.",
        "use_cases": "Secure key exchange, digital signatures, email encryption."
    },
    "sha256": {
        "name": "SHA-256",
        "type": "Hash",
        "history": "SHA-256 is part of the SHA-2 family, published by NIST in 2001.",
        "description": "Produces a 256-bit hash value, widely used for data integrity.",
        "use_cases": "Digital signatures, certificates, file integrity."
    },
    "sha3_512": {
        "name": "SHA3-512",
        "type": "Hash",
        "history": "SHA-3 was standardized in 2015 as an alternative to SHA-2.",
        "description": "Produces a 512-bit hash using the Keccak algorithm.",
        "use_cases": "Data integrity, blockchain, digital signatures."
    },
    "sha1": {
        "name": "SHA-1",
        "type": "Hash",
        "history": "SHA-1 was designed by the NSA in 1995, now considered weak.",
        "description": "Produces a 160-bit hash, deprecated for most security uses.",
        "use_cases": "Legacy systems, not recommended for new applications."
    },
    "blake2b": {
        "name": "BLAKE2b",
        "type": "Hash",
        "history": "BLAKE2 was designed in 2012 as a faster, more secure alternative to MD5 and SHA-1.",
        "description": "Produces variable-length hashes, optimized for speed and security.",
        "use_cases": "File integrity, password hashing, digital signatures."
    }
}

@app.route('/', methods=['GET', 'POST'])
def home():
    crypto_result = None
    crypto_operation = None
    crypto_input = None
    chat_result = None
    crypto_file = False
    input_mode = request.form.get('input_mode', 'text')

    # Generate RSA key pair for the session if not present
    if 'private_key' not in session or 'public_key' not in session:
        priv, pub = asymmetric.generate_rsa_keypair()
        session['private_key'] = base64.b64encode(priv).decode()
        session['public_key'] = base64.b64encode(pub).decode()

    # Initialize chat history if not present
    if 'chat_history' not in session:
        session['chat_history'] = []

    # Handle crypto tool form
    if request.method == 'POST' and request.form.get('form_type') == 'crypto_tool':
        crypto_operation = request.form['operation']
        input_mode = request.form.get('input_mode', 'text')
        crypto_input = request.form.get('input_text', '')

        # Handle file input
        file_data = None
        filename = None
        if input_mode == 'file' and 'input_file' in request.files:
            file = request.files['input_file']
            if file and file.filename:
                filename = file.filename
                if not filename.lower().endswith('.txt'):
                    crypto_result = "Error: Only .txt files are supported for file operations."
                    file_data = None
                else:
                    file_data = file.read()

        try:
            # Text mode
            if input_mode == 'text':
                if crypto_operation == 'aes_encrypt':
                    crypto_result = symmetric.aes_encrypt(crypto_input)
                elif crypto_operation == 'aes_decrypt':
                    crypto_result = symmetric.aes_decrypt(crypto_input)
                elif crypto_operation == 'des_encrypt':
                    crypto_result = symmetric.des_encrypt(crypto_input)
                elif crypto_operation == 'des_decrypt':
                    crypto_result = symmetric.des_decrypt(crypto_input)
                elif crypto_operation == 'chacha20_encrypt':
                    crypto_result = symmetric.chacha20_encrypt(crypto_input)
                elif crypto_operation == 'chacha20_decrypt':
                    crypto_result = symmetric.chacha20_decrypt(crypto_input)
                elif crypto_operation == 'rsa_encrypt':
                    crypto_result = asymmetric.rsa_encrypt(crypto_input)
                elif crypto_operation == 'rsa_decrypt':
                    crypto_result = asymmetric.rsa_decrypt(crypto_input)
                elif crypto_operation == 'sha256_hash':
                    crypto_result = hash_functions.sha256_hash(crypto_input)
                elif crypto_operation == 'sha3_512_hash':
                    crypto_result = hash_functions.sha3_512_hash(crypto_input)
                elif crypto_operation == 'sha1_hash':
                    crypto_result = hash_functions.sha1_hash(crypto_input)
                elif crypto_operation == 'blake2b_hash':
                    crypto_result = hash_functions.blake2b_hash(crypto_input)
                else:
                    crypto_result = "Invalid operation selected."
            # File mode
            elif input_mode == 'file' and file_data is not None:
                if crypto_operation == 'aes_encrypt':
                    result_bytes = symmetric.aes_encrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename + '.enc'
                    crypto_result = "File encrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'aes_decrypt':
                    result_bytes = symmetric.aes_decrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename.replace('.enc', '') + '.dec'
                    crypto_result = "File decrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'des_encrypt':
                    result_bytes = symmetric.des_encrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename + '.des'
                    crypto_result = "File encrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'des_decrypt':
                    result_bytes = symmetric.des_decrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename.replace('.des', '') + '.dec'
                    crypto_result = "File decrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'chacha20_encrypt':
                    result_bytes = symmetric.chacha20_encrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename + '.chacha'
                    crypto_result = "File encrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'chacha20_decrypt':
                    result_bytes = symmetric.chacha20_decrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename.replace('.chacha', '') + '.dec'
                    crypto_result = "File decrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'rsa_encrypt':
                    result_bytes = asymmetric.rsa_encrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename + '.rsa'
                    crypto_result = "File encrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'rsa_decrypt':
                    result_bytes = asymmetric.rsa_decrypt_bytes(file_data)
                    session['crypto_file_data'] = base64.b64encode(result_bytes).decode()
                    session['crypto_file_name'] = filename.replace('.rsa', '') + '.dec'
                    crypto_result = "File decrypted. Click download."
                    crypto_file = True
                elif crypto_operation == 'sha256_hash':
                    crypto_result = hash_functions.sha256_hash_file(file_data)
                elif crypto_operation == 'sha3_512_hash':
                    crypto_result = hash_functions.sha3_512_hash_file(file_data)
                elif crypto_operation == 'sha1_hash':
                    crypto_result = hash_functions.sha1_hash_file(file_data)
                elif crypto_operation == 'blake2b_hash':
                    crypto_result = hash_functions.blake2b_hash_file(file_data)
                else:
                    crypto_result = "File mode only supports AES/DES/ChaCha20/RSA encrypt/decrypt and file hashing."
            else:
                crypto_result = "No input provided."
        except Exception as e:
            crypto_result = f"An error occurred: {str(e)}"

    # Handle secure chat encrypt form
    if request.method == 'POST' and request.form.get('form_type') == 'secure_chat_encrypt':
        recipient_pubkey_b64 = request.form['recipient_pubkey']
        message = request.form['message']
        try:
            recipient_pubkey = base64.b64decode(recipient_pubkey_b64)
            sender_privkey = base64.b64decode(session['private_key'])
            encrypted_package = asymmetric.hybrid_encrypt(
                message, recipient_pubkey, sender_privkey
            )
            chat_result = base64.b64encode(encrypted_package).decode()
            # Store sent message in chat history
            history = session['chat_history']
            history.append({'type': 'sent', 'content': message, 'encrypted': chat_result})
            session['chat_history'] = history
        except Exception as e:
            chat_result = f"Encryption error: {str(e)}"

    # Handle secure chat decrypt form
    if request.method == 'POST' and request.form.get('form_type') == 'secure_chat_decrypt':
        encrypted_package_b64 = request.form['encrypted_package']
        private_key_b64 = session.get('private_key')
        try:
            encrypted_package = base64.b64decode(encrypted_package_b64)
            private_key = base64.b64decode(private_key_b64)
            decrypted_message, verified = asymmetric.hybrid_decrypt(
                encrypted_package, private_key
            )
            if verified:
                chat_result = f"Verified message: {decrypted_message}"
                # Store received message in chat history
                history = session['chat_history']
                history.append({'type': 'received', 'content': decrypted_message, 'encrypted': encrypted_package_b64})
                session['chat_history'] = history
            else:
                chat_result = "Message integrity/authenticity could not be verified."
        except Exception as e:
            chat_result = f"Decryption error: {str(e)}"

    return render_template(
        'home.html',
        crypto_result=crypto_result,
        crypto_operation=crypto_operation,
        crypto_input=crypto_input,
        public_key=session['public_key'],
        chat_result=chat_result,
        chat_history=session.get('chat_history', []),
        crypto_file=crypto_file,
        input_mode=input_mode,
        algorithm_info=ALGORITHM_INFO
    )

@app.route('/download_crypto_file')
def download_crypto_file():
    data = session.get('crypto_file_data')
    filename = session.get('crypto_file_name', 'result.bin')
    if not data:
        return redirect(url_for('home'))
    file_bytes = base64.b64decode(data)
    return send_file(BytesIO(file_bytes), as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)