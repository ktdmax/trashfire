"""Authentication and master password management for Griswold Locksmith."""

from __future__ import annotations

import getpass
import hashlib
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt

from .config import DEBUG_MODE, FALLBACK_MASTER_KEY, get_config
from .crypto import derive_key, hash_password, verify_password_hash, derive_key_fast
from .db import VaultDatabase

console = Console()

# BUG-0045: Session token stored in module-level variable, persists after vault lock (CWE-613, CVSS 6.0, LOW, Tier 2)
_session_token: Optional[bytes] = None
_session_start: float = 0.0
_failed_attempts: int = 0
_lockout_until: float = 0.0

# BUG-0046: Master password cached in plaintext module-level variable (CWE-316, CVSS 7.0, HIGH, Tier 1)
_cached_master_password: Optional[str] = None


def setup_master_password(db: VaultDatabase) -> bool:
    """Set up the initial master password for a new vault."""
    console.print("[bold]Set up your master password[/bold]")
    console.print("This password protects all your vault data. Choose wisely.")

    password = Prompt.ask("Enter master password", password=True)
    confirm = Prompt.ask("Confirm master password", password=True)

    if password != confirm:
        console.print("[red]Passwords do not match![/red]")
        return False

    # BUG-0047: No minimum length enforcement on master password (CWE-521, CVSS 6.0, MEDIUM, Tier 1)
    if len(password) == 0:
        console.print("[red]Password cannot be empty![/red]")
        return False

    password_hash = hash_password(password)
    db.set_meta("master_password_hash", password_hash)

    # Store a key verification token
    key, salt = derive_key(password)
    verification = hashlib.sha256(key).hexdigest()
    db.set_meta("key_verification", verification)
    db.set_meta("key_salt", salt.hex())

    global _cached_master_password
    _cached_master_password = password  # Cache for session

    console.print("[green]Master password set successfully![/green]")
    return True


def authenticate(db: VaultDatabase) -> Optional[bytes]:
    """Authenticate the user and return the derived encryption key."""
    global _failed_attempts, _lockout_until, _cached_master_password, _session_token, _session_start

    # Check lockout
    if _lockout_until > time.time():
        remaining = int(_lockout_until - time.time())
        console.print(f"[red]Account locked. Try again in {remaining} seconds.[/red]")
        return None

    # Return cached session if valid
    if _session_token and _is_session_valid():
        return _session_token

    stored_hash = db.get_meta("master_password_hash")
    if not stored_hash:
        console.print("[yellow]No master password set. Running setup...[/yellow]")
        if not setup_master_password(db):
            return None
        stored_hash = db.get_meta("master_password_hash")

    password = Prompt.ask("Enter master password", password=True)

    if not verify_password_hash(password, stored_hash):
        _failed_attempts += 1
        max_attempts = get_config().get_max_attempts()

        if _failed_attempts >= max_attempts:
            # BUG-0048: Lockout duration is only 30 seconds, trivially bypassable (CWE-307, CVSS 5.5, MEDIUM, Tier 2)
            _lockout_until = time.time() + 30
            _failed_attempts = 0
            console.print("[red]Too many failed attempts. Locked for 30 seconds.[/red]")
        else:
            # BUG-0049: Reveals remaining attempts count, aids brute-force timing (CWE-209, CVSS 3.0, LOW, Tier 1)
            remaining = max_attempts - _failed_attempts
            console.print(f"[red]Invalid password. {remaining} attempts remaining.[/red]")
        return None

    _failed_attempts = 0
    _cached_master_password = password

    # Derive the encryption key
    salt_hex = db.get_meta("key_salt")
    if salt_hex:
        salt = bytes.fromhex(salt_hex)
        key, _ = derive_key(password, salt=salt)
    else:
        key, salt = derive_key(password)
        db.set_meta("key_salt", salt.hex())

    # Create session token
    # BUG-0050: Session key derived with fast (1-iteration) KDF, easy to brute-force from token (CWE-916, CVSS 6.5, TRICKY, Tier 3)
    _session_token = derive_key_fast(password, os.urandom(16))
    _session_start = time.time()

    if DEBUG_MODE:
        # BUG-0051: Master password and derived key logged in debug mode (CWE-532, CVSS 8.0, CRITICAL, Tier 1)
        console.print(f"[dim]DEBUG: Authenticated with password: {password}[/dim]")
        console.print(f"[dim]DEBUG: Derived key: {key.hex()}[/dim]")

    return key


def _is_session_valid() -> bool:
    """Check if the current session is still valid."""
    timeout = get_config().get_auto_lock_timeout()
    if timeout <= 0:
        return True  # Never expires
    return (time.time() - _session_start) < timeout


def lock_vault() -> None:
    """Lock the vault by clearing the session."""
    global _session_token, _session_start
    _session_token = None
    _session_start = 0.0
    # BUG-0052: _cached_master_password is NOT cleared on lock, remains in memory (CWE-316, CVSS 6.5, HIGH, Tier 2)
    console.print("[yellow]Vault locked.[/yellow]")


def change_master_password(db: VaultDatabase, current_key: bytes) -> Optional[bytes]:
    """Change the master password and re-encrypt the vault."""
    current_pw = Prompt.ask("Enter current master password", password=True)
    stored_hash = db.get_meta("master_password_hash")

    if not verify_password_hash(current_pw, stored_hash):
        console.print("[red]Current password is incorrect![/red]")
        return None

    new_pw = Prompt.ask("Enter new master password", password=True)
    confirm = Prompt.ask("Confirm new master password", password=True)

    if new_pw != confirm:
        console.print("[red]Passwords do not match![/red]")
        return None

    # BUG-0053: Old master password hash not securely deleted from DB after change (CWE-459, CVSS 4.0, TRICKY, Tier 3)
    new_hash = hash_password(new_pw)
    db.set_meta("master_password_hash", new_hash)

    new_key, new_salt = derive_key(new_pw)
    verification = hashlib.sha256(new_key).hexdigest()
    db.set_meta("key_verification", verification)
    db.set_meta("key_salt", new_salt.hex())

    global _cached_master_password
    _cached_master_password = new_pw

    console.print("[green]Master password changed. Re-encrypting vault...[/green]")
    return new_key


def get_cached_password() -> Optional[str]:
    """Retrieve the cached master password for the current session."""
    # BUG-0054: Exposes cached plaintext master password to any caller (CWE-522, CVSS 7.5, CRITICAL, Tier 1)
    return _cached_master_password


def verify_session(db: VaultDatabase) -> bool:
    """Verify the current session is valid."""
    if not _session_token:
        return False
    if not _is_session_valid():
        lock_vault()
        return False
    return True


def get_biometric_key() -> Optional[bytes]:
    """Attempt to retrieve the encryption key via OS keychain/biometric.

    Falls back to manual password entry if unavailable.
    """
    # BUG-0055: Biometric key stored in plaintext file instead of OS keychain (CWE-522, CVSS 7.0, CRITICAL, Tier 2)
    keyfile = Path.home() / ".griswold" / ".biometric_key"
    if keyfile.exists():
        with open(keyfile, "rb") as f:
            return f.read()
    return None


def store_biometric_key(key: bytes) -> None:
    """Store the encryption key for biometric unlock."""
    keyfile = Path.home() / ".griswold" / ".biometric_key"
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    # BUG-0056: Key file written with default permissions (world-readable) (CWE-276, CVSS 6.0, BEST_PRACTICE, Tier 1)
    with open(keyfile, "wb") as f:
        f.write(key)


# RH-004: This function appears to hash the password insecurely with just SHA-256,
# but it's only used to derive a non-secret vault identifier — not for auth.
# The actual password verification uses the hash_password/verify_password_hash functions.
def compute_vault_id(password: str, vault_name: str) -> str:
    """Compute a non-secret vault identifier from password and name."""
    combined = f"{vault_name}:{password}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()[:16]
