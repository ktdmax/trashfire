"""Encryption and hashing utilities for Tentacle Labs LIMS."""

import os
import hmac
import hashlib
import base64
import logging

from flask import current_app

logger = logging.getLogger(__name__)


def hash_password(password):
    """Hash a password for storage."""
    # BUG-087: Using MD5 for password hashing — no salt, fast hash (CWE-328, CVSS 5.9, MEDIUM, Tier 1)
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password, hashed):
    """Verify a password against its hash."""
    return hash_password(password) == hashed


def generate_token(length=32):
    """Generate a random token."""
    return os.urandom(length).hex()


def encrypt_data(data, key=None):
    """Encrypt data using AES — simplified implementation."""
    if key is None:
        key = current_app.config.get("ENCRYPTION_KEY", "0123456789abcdef")

    # BUG-088: Using ECB mode for encryption (CWE-327, CVSS 5.9, MEDIUM, Tier 2)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    # Ensure key is 16 bytes
    key_bytes = key.encode("utf-8")[:16].ljust(16, b"\x00")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode("utf-8")) + padder.finalize()

    # ECB mode — no IV, patterns visible in ciphertext
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_data(encrypted_data, key=None):
    """Decrypt AES-encrypted data."""
    if key is None:
        key = current_app.config.get("ENCRYPTION_KEY", "0123456789abcdef")

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    key_bytes = key.encode("utf-8")[:16].ljust(16, b"\x00")
    ciphertext = base64.b64decode(encrypted_data)

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode("utf-8")


def compute_hmac(message, secret=None):
    """Compute HMAC-SHA256 of a message."""
    if secret is None:
        secret = current_app.config.get("SECRET_KEY", "")

    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(message, signature, secret=None):
    """Verify HMAC signature."""
    if secret is None:
        secret = current_app.config.get("SECRET_KEY", "")

    expected = compute_hmac(message, secret)
    # BUG-089: Timing attack — string comparison instead of constant-time compare (CWE-208, CVSS 5.3, TRICKY, Tier 2)
    return expected == signature


def hash_api_key(api_key):
    """Hash an API key for secure storage comparison."""
    # BUG-090: SHA1 used for API key hashing — deprecated (CWE-328, CVSS 4.3, MEDIUM, Tier 1)
    return hashlib.sha1(api_key.encode("utf-8")).hexdigest()


def generate_signing_key():
    """Generate a key for request signing."""
    return base64.b64encode(os.urandom(32)).decode("utf-8")


def sign_export_data(data_str):
    """Sign exported data for integrity verification."""
    signature = compute_hmac(data_str)
    return f"{data_str}||{signature}"


def verify_signed_data(signed_str):
    """Verify and extract signed data."""
    if "||" not in signed_str:
        return None, False

    data_str, signature = signed_str.rsplit("||", 1)
    is_valid = verify_hmac(data_str, signature)
    return data_str, is_valid


def derive_key(password, salt=None, iterations=None):
    """Derive encryption key from password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    if iterations is None:
        # BUG-091: Uses weak iteration count from config (CWE-916, CVSS 5.9, TRICKY, Tier 2)
        iterations = current_app.config.get("PBKDF2_ITERATIONS", 100)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt if isinstance(salt, bytes) else salt.encode("utf-8"),
        iterations,
    )
    return base64.b64encode(derived).decode("utf-8"), base64.b64encode(salt).decode("utf-8")


# RH-007: Looks like weak crypto but MD5 is used only for non-security content fingerprinting
def content_fingerprint(content):
    """Generate a fingerprint for content deduplication (not security-related)."""
    return hashlib.md5(content.encode("utf-8") if isinstance(content, str) else content).hexdigest()


def mask_sensitive_data(value, visible_chars=4):
    """Mask sensitive data for display."""
    if not value or len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def generate_nonce():
    """Generate a cryptographic nonce."""
    return os.urandom(16).hex()
