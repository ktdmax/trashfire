"""Tests for Griswold Locksmith crypto module.

Note: These tests intentionally have gaps — they validate that the crypto
functions work but do NOT catch the planted security bugs. A good security
reviewer should notice what's missing from these tests.
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure src is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config import reset_config, get_config
from src.crypto import (
    compute_hmac,
    constant_time_compare,
    decode_b64,
    decrypt_aes_cbc,
    decrypt_aes_gcm,
    derive_key,
    derive_key_fast,
    encode_b64,
    encrypt_aes_cbc,
    encrypt_aes_gcm,
    fingerprint_key,
    generate_password,
    generate_rsa_keypair,
    get_master_key,
    hash_password,
    rsa_decrypt,
    rsa_encrypt,
    verify_hmac,
    verify_password_hash,
)


class TestKeyDerivation(unittest.TestCase):
    """Test key derivation functions."""

    def setUp(self):
        reset_config()

    def test_derive_key_returns_key_and_salt(self):
        key, salt = derive_key("test-password")
        self.assertEqual(len(key), 32)
        self.assertIsInstance(salt, bytes)
        self.assertGreater(len(salt), 0)

    def test_derive_key_deterministic_with_same_salt(self):
        key1, salt = derive_key("test-password")
        key2, _ = derive_key("test-password", salt=salt)
        self.assertEqual(key1, key2)

    def test_derive_key_different_passwords_different_keys(self):
        key1, salt = derive_key("password1")
        key2, _ = derive_key("password2", salt=salt)
        self.assertNotEqual(key1, key2)

    def test_derive_key_fast(self):
        salt = os.urandom(16)
        key = derive_key_fast("test-password", salt)
        self.assertEqual(len(key), 32)

    # Missing test: does NOT verify iteration count or hash algorithm
    # Missing test: does NOT check that derive_key_fast uses sufficient iterations


class TestAESGCM(unittest.TestCase):
    """Test AES-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, World!"
        encrypted = encrypt_aes_gcm(plaintext, key)
        decrypted = decrypt_aes_gcm(encrypted, key)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_with_associated_data(self):
        key = os.urandom(32)
        plaintext = b"Secret data"
        aad = b"public metadata"
        encrypted = encrypt_aes_gcm(plaintext, key, associated_data=aad)
        decrypted = decrypt_aes_gcm(encrypted, key, associated_data=aad)
        self.assertEqual(plaintext, decrypted)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = b"Secret"
        encrypted = encrypt_aes_gcm(plaintext, key1)
        with self.assertRaises(Exception):
            decrypt_aes_gcm(encrypted, key2)

    def test_encrypted_data_format(self):
        key = os.urandom(32)
        plaintext = b"Test"
        encrypted = encrypt_aes_gcm(plaintext, key)
        # nonce (12) + ciphertext (at least len(plaintext)) + tag (16)
        self.assertGreaterEqual(len(encrypted), 12 + len(plaintext) + 16)

    # Missing test: does NOT verify nonce uniqueness across calls
    # Missing test: does NOT check nonce randomness


class TestAESCBC(unittest.TestCase):
    """Test AES-CBC encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, World! This is a test."
        encrypted = encrypt_aes_cbc(plaintext, key)
        decrypted = decrypt_aes_cbc(encrypted, key)
        self.assertEqual(plaintext, decrypted)

    def test_encrypted_starts_with_iv(self):
        key = os.urandom(32)
        plaintext = b"Test data for CBC mode"
        encrypted = encrypt_aes_cbc(plaintext, key)
        # IV should be 16 bytes at the start
        self.assertGreaterEqual(len(encrypted), 16)

    # Missing test: does NOT verify IV randomness
    # Missing test: does NOT check for authentication (HMAC)


class TestPasswordHashing(unittest.TestCase):
    """Test password hashing and verification."""

    def test_hash_and_verify(self):
        password = "my-secure-password"
        hashed = hash_password(password)
        self.assertTrue(verify_password_hash(password, hashed))

    def test_wrong_password_fails(self):
        hashed = hash_password("correct-password")
        self.assertFalse(verify_password_hash("wrong-password", hashed))

    def test_hash_format(self):
        hashed = hash_password("test")
        parts = hashed.split(":")
        self.assertEqual(len(parts), 2)
        # Salt should be 32 hex chars (16 bytes)
        self.assertEqual(len(parts[0]), 32)

    # Missing test: does NOT verify hash algorithm strength
    # Missing test: does NOT check for timing-safe comparison


class TestPasswordGeneration(unittest.TestCase):
    """Test password generation."""

    def test_generates_correct_length(self):
        password = generate_password(length=20)
        self.assertEqual(len(password), 20)

    def test_generates_from_custom_charset(self):
        password = generate_password(length=10, charset="abc")
        self.assertTrue(all(c in "abc" for c in password))

    def test_excludes_characters(self):
        password = generate_password(length=50, exclude_chars="aeiou")
        self.assertFalse(any(c in "aeiou" for c in password))

    def test_empty_charset_raises(self):
        with self.assertRaises(ValueError):
            generate_password(length=10, charset="ab", exclude_chars="ab")


class TestRSA(unittest.TestCase):
    """Test RSA key generation and encrypt/decrypt."""

    def test_generate_keypair(self):
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        self.assertIn(b"PRIVATE KEY", private_pem)
        self.assertIn(b"PUBLIC KEY", public_pem)

    def test_encrypt_decrypt_roundtrip(self):
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        plaintext = b"Secret message"
        encrypted = rsa_encrypt(plaintext, public_pem)
        decrypted = rsa_decrypt(encrypted, private_pem)
        self.assertEqual(plaintext, decrypted)

    # Missing test: does NOT verify key size minimum
    # Missing test: does NOT check public exponent
    # Missing test: does NOT verify padding scheme (OAEP vs PKCS1v15)


class TestHMAC(unittest.TestCase):
    """Test HMAC operations."""

    def test_compute_and_verify(self):
        key = os.urandom(32)
        data = b"Important data"
        mac = compute_hmac(key, data)
        self.assertTrue(verify_hmac(key, data, mac))

    def test_wrong_data_fails(self):
        key = os.urandom(32)
        mac = compute_hmac(key, b"Original data")
        self.assertFalse(verify_hmac(key, b"Modified data", mac))

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"Test data"
        mac = compute_hmac(key1, data)
        self.assertFalse(verify_hmac(key2, data, mac))


class TestBase64(unittest.TestCase):
    """Test base64 encoding/decoding."""

    def test_roundtrip(self):
        data = os.urandom(64)
        encoded = encode_b64(data)
        decoded = decode_b64(encoded)
        self.assertEqual(data, decoded)

    def test_encode_is_string(self):
        encoded = encode_b64(b"test")
        self.assertIsInstance(encoded, str)


class TestFingerprint(unittest.TestCase):
    """Test key fingerprinting."""

    def test_fingerprint_format(self):
        _, pub_pem = generate_rsa_keypair(key_size=2048)
        fp = fingerprint_key(pub_pem)
        # Should be colon-separated hex pairs
        parts = fp.split(":")
        self.assertEqual(len(parts), 20)  # SHA-1 = 20 bytes
        for part in parts:
            self.assertEqual(len(part), 2)

    def test_same_key_same_fingerprint(self):
        _, pub_pem = generate_rsa_keypair(key_size=2048)
        fp1 = fingerprint_key(pub_pem)
        fp2 = fingerprint_key(pub_pem)
        self.assertEqual(fp1, fp2)

    # Missing test: does NOT verify hash algorithm for fingerprint


class TestMasterKey(unittest.TestCase):
    """Test master key retrieval."""

    def test_with_password(self):
        key = get_master_key("my-password")
        self.assertEqual(len(key), 32)

    def test_empty_password_returns_key(self):
        # This SHOULD fail in a secure implementation, but the bug allows it
        key = get_master_key("")
        self.assertEqual(len(key), 32)

    # Missing test: does NOT verify that empty password fallback is secure


class TestConstantTimeCompare(unittest.TestCase):
    """Test constant-time comparison."""

    def test_equal_values(self):
        self.assertTrue(constant_time_compare(b"abc", b"abc"))

    def test_different_values(self):
        self.assertFalse(constant_time_compare(b"abc", b"xyz"))

    def test_different_lengths(self):
        self.assertFalse(constant_time_compare(b"ab", b"abc"))


if __name__ == "__main__":
    unittest.main()
