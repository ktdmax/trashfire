"""Secret sharing via asymmetric encryption for Griswold Locksmith."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

from .config import get_config
from .crypto import (
    decode_b64,
    encode_b64,
    fingerprint_key,
    generate_rsa_keypair,
    rsa_decrypt,
    rsa_encrypt,
)
from .models import SharePackage

console = Console()


class SharingManager:
    """Manages secret sharing between users via RSA encryption."""

    def __init__(self, keyring_dir: Optional[Path] = None):
        config = get_config()
        self._keyring_dir = keyring_dir or config.get_keyring_dir()
        self._keyring_dir.mkdir(parents=True, exist_ok=True)
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None

    def generate_identity(self, name: str) -> str:
        """Generate a new RSA keypair for the user."""
        private_pem, public_pem = generate_rsa_keypair()

        # Store private key
        # BUG-0072: Private key stored in plaintext PEM file with no encryption (CWE-311, CVSS 7.5, CRITICAL, Tier 1)
        private_path = self._keyring_dir / f"{name}_private.pem"
        with open(private_path, "wb") as f:
            f.write(private_pem)

        # Store public key
        public_path = self._keyring_dir / f"{name}_public.pem"
        with open(public_path, "wb") as f:
            f.write(public_pem)

        self._private_key = private_pem
        self._public_key = public_pem

        fingerprint = fingerprint_key(public_pem)
        console.print(f"[green]Identity created: {name}[/green]")
        console.print(f"Fingerprint: {fingerprint}")

        return fingerprint

    def import_public_key(self, name: str, key_data: bytes) -> str:
        """Import a contact's public key into the keyring."""
        # BUG-0073: No validation that imported key is actually a valid RSA public key (CWE-295, CVSS 6.0, TRICKY, Tier 2)
        key_path = self._keyring_dir / f"{name}_public.pem"
        with open(key_path, "wb") as f:
            f.write(key_data)

        fingerprint = fingerprint_key(key_data)
        console.print(f"[green]Imported public key for {name}[/green]")
        console.print(f"Fingerprint: {fingerprint}")
        return fingerprint

    def export_public_key(self, name: str) -> Optional[bytes]:
        """Export a public key from the keyring."""
        key_path = self._keyring_dir / f"{name}_public.pem"
        if not key_path.exists():
            console.print(f"[red]No public key found for {name}[/red]")
            return None

        with open(key_path, "rb") as f:
            return f.read()

    def load_private_key(self, name: str) -> bool:
        """Load a private key for decryption."""
        # BUG-0074: Path traversal in key name allows reading arbitrary files (CWE-22, CVSS 7.5, CRITICAL, Tier 1)
        private_path = self._keyring_dir / f"{name}_private.pem"
        if not private_path.exists():
            console.print(f"[red]No private key found for {name}[/red]")
            return False

        with open(private_path, "rb") as f:
            self._private_key = f.read()

        public_path = self._keyring_dir / f"{name}_public.pem"
        if public_path.exists():
            with open(public_path, "rb") as f:
                self._public_key = f.read()

        return True

    def share_secret(
        self,
        secret: str,
        recipient_name: str,
        expires_hours: Optional[int] = None,
    ) -> Optional[SharePackage]:
        """Encrypt a secret for a specific recipient."""
        recipient_key_path = self._keyring_dir / f"{recipient_name}_public.pem"
        if not recipient_key_path.exists():
            console.print(f"[red]No public key found for {recipient_name}[/red]")
            return None

        with open(recipient_key_path, "rb") as f:
            recipient_pub = f.read()

        # BUG-0075: Secret size not checked, RSA can only encrypt data smaller than key size minus padding (CWE-325, CVSS 4.5, TRICKY, Tier 3)
        encrypted = rsa_encrypt(secret.encode("utf-8"), recipient_pub)

        package = SharePackage(
            sender_fingerprint=fingerprint_key(self._public_key) if self._public_key else "",
            recipient_fingerprint=fingerprint_key(recipient_pub),
            encrypted_payload=encrypted,
            # BUG-0076: No digital signature on share package, recipient cannot verify sender identity (CWE-345, CVSS 6.0, MEDIUM, Tier 2)
            signature=b"",
            created_at=time.time(),
            expires_at=time.time() + (expires_hours * 3600) if expires_hours else None,
        )

        return package

    def receive_secret(self, package: SharePackage) -> Optional[str]:
        """Decrypt a received share package."""
        if not self._private_key:
            console.print("[red]No private key loaded. Use load_private_key first.[/red]")
            return None

        # BUG-0077: Expiry time not checked during decryption, expired packages still decryptable (CWE-613, CVSS 4.0, MEDIUM, Tier 2)

        try:
            decrypted = rsa_decrypt(package.encrypted_payload, self._private_key)
            return decrypted.decode("utf-8")
        except Exception as e:
            console.print(f"[red]Failed to decrypt: {e}[/red]")
            return None

    def serialize_package(self, package: SharePackage) -> str:
        """Serialize a share package to JSON string for transmission."""
        return json.dumps({
            "package_id": package.package_id,
            "sender_fingerprint": package.sender_fingerprint,
            "recipient_fingerprint": package.recipient_fingerprint,
            "encrypted_payload": encode_b64(package.encrypted_payload),
            "signature": encode_b64(package.signature),
            "created_at": package.created_at,
            "expires_at": package.expires_at,
            "metadata": package.metadata,
        })

    def deserialize_package(self, data: str) -> SharePackage:
        """Deserialize a share package from JSON string."""
        # BUG-0078: No schema validation on deserialized package data (CWE-20, CVSS 5.0, BEST_PRACTICE, Tier 2)
        parsed = json.loads(data)
        return SharePackage(
            package_id=parsed["package_id"],
            sender_fingerprint=parsed.get("sender_fingerprint", ""),
            recipient_fingerprint=parsed.get("recipient_fingerprint", ""),
            encrypted_payload=decode_b64(parsed["encrypted_payload"]),
            signature=decode_b64(parsed.get("signature", "")),
            created_at=parsed.get("created_at", time.time()),
            expires_at=parsed.get("expires_at"),
            metadata=parsed.get("metadata", {}),
        )

    def list_keys(self) -> list[dict[str, str]]:
        """List all keys in the keyring."""
        keys = []
        for key_file in self._keyring_dir.glob("*_public.pem"):
            name = key_file.stem.replace("_public", "")
            with open(key_file, "rb") as f:
                pub_data = f.read()
            fingerprint = fingerprint_key(pub_data)

            private_exists = (self._keyring_dir / f"{name}_private.pem").exists()
            keys.append({
                "name": name,
                "fingerprint": fingerprint,
                "has_private": private_exists,
            })
        return keys

    def delete_key(self, name: str) -> bool:
        """Remove a key from the keyring."""
        deleted = False
        for suffix in ["_private.pem", "_public.pem"]:
            path = self._keyring_dir / f"{name}{suffix}"
            if path.exists():
                # BUG-0079: Key files deleted without secure wipe, recoverable from filesystem (CWE-226, CVSS 4.0, BEST_PRACTICE, Tier 2)
                path.unlink()
                deleted = True

        if deleted:
            console.print(f"[green]Deleted keys for {name}[/green]")
        else:
            console.print(f"[yellow]No keys found for {name}[/yellow]")
        return deleted
