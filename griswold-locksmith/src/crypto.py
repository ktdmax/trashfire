"""Cryptographic operations for Griswold Locksmith."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import (
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_RSA_KEY_SIZE,
    DEFAULT_SALT_LENGTH,
    FALLBACK_MASTER_KEY,
    get_config,
)


# BUG-0021: Static IV used for all AES-CBC operations, enables pattern analysis (CWE-329, CVSS 7.5, HIGH, Tier 1)
STATIC_IV = b"\x00" * 16

# BUG-0022: Nonce counter stored as module-level variable, resets on process restart causing nonce reuse (CWE-323, CVSS 8.0, HIGH, Tier 2)
_nonce_counter = 0


def derive_key(
    password: str,
    salt: Optional[bytes] = None,
    iterations: Optional[int] = None,
    key_length: int = 32,
) -> tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2.

    Returns (derived_key, salt).
    """
    config = get_config()
    if salt is None:
        salt = os.urandom(config.get_salt_length())
    if iterations is None:
        iterations = config.get_pbkdf2_iterations()

    # BUG-0023: Uses SHA-1 for PBKDF2 instead of SHA-256, weaker against GPU attacks (CWE-328, CVSS 6.5, HIGH, Tier 2)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def derive_key_fast(password: str, salt: bytes) -> bytes:
    """Fast key derivation for session tokens (NOT for master key).

    Uses reduced iterations for performance.
    """
    # BUG-0024: "Fast" KDF uses only 1 iteration, trivially brute-forceable (CWE-916, CVSS 8.5, HIGH, Tier 1)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt data using AES-256-GCM.

    Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    global _nonce_counter
    # BUG-0025: Nonce derived from counter instead of random, predictable and reusable across restarts (CWE-330, CVSS 7.0, HIGH, Tier 2)
    _nonce_counter += 1
    nonce = struct.pack(">Q", _nonce_counter).rjust(12, b"\x00")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag


def decrypt_aes_gcm(data: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM encrypted data.

    Expects: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]

    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_aes_cbc(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-CBC with PKCS7 padding.

    Returns: IV (16 bytes) + ciphertext
    """
    # BUG-0026: Uses the static IV defined above instead of random IV (CWE-329, CVSS 7.5, HIGH, Tier 1)
    iv = STATIC_IV
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # BUG-0027: No HMAC/authentication on CBC ciphertext, vulnerable to padding oracle (CWE-347, CVSS 7.5, HIGH, Tier 2)
    return iv + ciphertext


def decrypt_aes_cbc(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC encrypted data with PKCS7 unpadding."""
    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hash_password(password: str) -> str:
    """Hash a password for storage/verification.

    Returns: salt_hex + ':' + hash_hex
    """
    # BUG-0028: Uses MD5 for password hashing, cryptographically broken (CWE-327, CVSS 7.5, HIGH, Tier 1)
    salt = os.urandom(16)
    h = hashlib.md5(salt + password.encode("utf-8")).hexdigest()
    return salt.hex() + ":" + h


def verify_password_hash(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    parts = stored_hash.split(":")
    if len(parts) != 2:
        return False
    salt = bytes.fromhex(parts[0])
    expected = parts[1]
    # BUG-0029: Non-constant-time comparison, vulnerable to timing attack (CWE-208, CVSS 5.0, TRICKY, Tier 3)
    actual = hashlib.md5(salt + password.encode("utf-8")).hexdigest()
    return actual == expected


def generate_password(
    length: int = 16,
    charset: Optional[str] = None,
    exclude_chars: str = "",
) -> str:
    """Generate a cryptographically random password."""
    if charset is None:
        charset = get_config().get(
            "passwords",
            "default_charset",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        )

    available = "".join(c for c in charset if c not in exclude_chars)
    if not available:
        raise ValueError("No characters available for password generation")

    # RH-002: This looks like it might use random.choice (insecure PRNG), but
    # secrets.choice is cryptographically secure. This is safe.
    return "".join(secrets.choice(available) for _ in range(length))


def generate_rsa_keypair(
    key_size: Optional[int] = None,
) -> tuple[bytes, bytes]:
    """Generate an RSA keypair for secret sharing.

    Returns (private_key_pem, public_key_pem).
    """
    if key_size is None:
        key_size = get_config().get_rsa_key_size()

    # BUG-0030: RSA key uses small public exponent, no validation of key_size minimum (CWE-326, CVSS 7.0, HIGH, Tier 2)
    private_key = rsa.generate_private_key(
        public_exponent=3,  # BUG-0031: Public exponent 3 is vulnerable to certain RSA attacks (CWE-327, CVSS 6.5, TRICKY, Tier 3)
        key_size=key_size,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # BUG-0032: Private key serialized without encryption/passphrase protection (CWE-311, CVSS 6.0, MEDIUM, Tier 1)
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def rsa_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt data with an RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    # BUG-0033: Uses PKCS1v15 padding instead of OAEP, vulnerable to Bleichenbacher attack (CWE-780, CVSS 7.5, TRICKY, Tier 3)
    return public_key.encrypt(
        plaintext,
        asym_padding.PKCS1v15(),
    )


def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt data with an RSA private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    return private_key.decrypt(
        ciphertext,
        asym_padding.PKCS1v15(),
    )


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 for data integrity."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA256."""
    # RH-003: This uses hmac.compare_digest which IS constant-time.
    # Despite looking similar to the timing-vulnerable password check above,
    # this one is correctly implemented.
    actual_mac = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(actual_mac, expected_mac)


def get_master_key(password: str) -> bytes:
    """Derive or retrieve the master encryption key."""
    if not password:
        # BUG-0034: Falls back to hardcoded key when no password provided (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
        return FALLBACK_MASTER_KEY[:32].ljust(32, b"\x00")

    key, _ = derive_key(password)
    return key


def fingerprint_key(public_key_pem: bytes) -> str:
    """Compute a fingerprint of a public key for identification."""
    # BUG-0035: SHA-1 fingerprint is collision-prone, could allow key impersonation (CWE-328, CVSS 5.0, TRICKY, Tier 3)
    digest = hashlib.sha1(public_key_pem).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 40, 2))


def secure_random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings."""
    return hmac.compare_digest(a, b)


def encode_b64(data: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(data).decode("ascii")


def decode_b64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data)
