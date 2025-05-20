# Cryptographic Application

**Course Name:** [Applied Cryptography - CSAC 329]  
**Date:** [May 24 2025]

## Group Members
- Aron V. Ibias (@AronIbias21)
- Jester Tapit (@bobgithub)
- Ma. Angela Matubis (@carolgithub)

---

## Introduction

This project is a web-based cryptographic application built with Python and Flask. It allows users to experiment with various cryptographic algorithms, including symmetric, asymmetric, and hash functions, and demonstrates the importance of cryptography in secure communications.

---

## Project Objectives

1. Implement and demonstrate core cryptographic algorithms (AES, RSA, SHA).
2. Provide a user-friendly interface for encryption, decryption, and hashing.
3. Enable secure, end-to-end encrypted chat between users.

---

## Application Architecture & UI

- **Backend:** Python Flask
- **Frontend:** HTML5, Bootstrap
- **Session Management:** Flask sessions for user keys and chat history
- **UI:** Tabbed interface for crypto tools and secure chat

---

## Cryptographic Algorithms

### AES (Advanced Encryption Standard)
- **Type:** Symmetric
- **History:** Standardized by NIST in 2001, replacing DES.
- **Description:** Block cipher operating on 128-bit blocks with 128/192/256-bit keys. Uses rounds of substitution, permutation, and mixing.
- **Pseudocode:**
    ```
    KeyExpansion(key)
    AddRoundKey(state, roundKey)
    for each round:
        SubBytes(state)
        ShiftRows(state)
        MixColumns(state)
        AddRoundKey(state, roundKey)
    ```
- **Library:** `cryptography`
- **Integration:** Used for text and file encryption/decryption.

### RSA (Rivest–Shamir–Adleman)
- **Type:** Asymmetric
- **History:** Invented in 1977, one of the first public-key cryptosystems.
- **Description:** Uses a public/private key pair for encryption and decryption. Based on the difficulty of factoring large integers.
- **Pseudocode:**
    ```
    Choose primes p, q
    Compute n = p * q
    Compute φ(n) = (p-1)*(q-1)
    Choose e such that 1 < e < φ(n), gcd(e, φ(n)) = 1
    Compute d ≡ e⁻¹ mod φ(n)
    Public key: (e, n), Private key: (d, n)
    Encryption: c = m^e mod n
    ```
- **Library:** `cryptography`
- **Integration:** Used for text and file encryption/decryption, and for secure chat.

### SHA-256 / SHA3-512
- **Type:** Hash
- **History:** SHA-2 (2001), SHA-3 (2015, Keccak).
- **Description:** One-way hash functions producing 256/512-bit digests.
- **Pseudocode:**
    ```
    Initialize hash values (H0-H7)
    Process message in 512-bit blocks:
        Prepare message schedule array
        Initialize working variables
        for 64 rounds:
            Perform bitwise operations and modular additions
        Add working variables to hash values
    ```
- **Library:** `cryptography`
- **Integration:** Used for hashing text input.

---

## How to Run

1. **Install requirements:**  
   ```
   pip install -r requirements.txt
   ```
2. **Run the app:**  
   ```
   python app.py
   ```
3. **Open in browser:**  
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Contribution Guidelines

- Each member must use their own GitHub account.
- Make regular, meaningful commits with clear messages.
- Use branches for new features; submit pull requests for review.
- Review and comment on teammates’ pull requests.
- Document major changes in commit messages.

---

## License

[MIT License](LICENSE)  <!-- Or your chosen license -->