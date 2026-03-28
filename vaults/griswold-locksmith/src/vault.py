"""Vault operations for Griswold Locksmith — CRUD, lock/unlock, search."""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table

from .config import DEBUG_MODE, get_config
from .crypto import (
    decrypt_aes_gcm,
    encode_b64,
    decode_b64,
    encrypt_aes_gcm,
    encrypt_aes_cbc,
    decrypt_aes_cbc,
    generate_password,
    hash_password,
)
from .db import VaultDatabase
from .models import AuditLogEntry, EntryType, SyncStatus, VaultEntry

console = Console()


class Vault:
    """High-level vault operations."""

    def __init__(self, db: VaultDatabase, encryption_key: bytes):
        self._db = db
        self._key = encryption_key
        self._unlocked = True

    def add_entry(self, entry: VaultEntry) -> str:
        """Add a new entry to the vault."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        # Encrypt sensitive fields
        sensitive_data = json.dumps({
            "password": entry.password,
            "notes": entry.notes,
            "totp_secret": entry.totp_secret,
            "custom_fields": entry.custom_fields,
        })

        encrypted = encrypt_aes_gcm(sensitive_data.encode("utf-8"), self._key)
        encrypted_b64 = encode_b64(encrypted)

        self._db.insert_entry(
            entry_id=entry.entry_id,
            title=entry.title,
            entry_type=entry.entry_type.value,
            username=entry.username,
            encrypted_data=encrypted_b64,
            url=entry.url,
            tags=json.dumps(entry.tags),
            folder=entry.folder,
            favorite=entry.favorite,
            sync_status=entry.sync_status.value,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )

        # BUG-0057: Audit log records plaintext password in details field (CWE-532, CVSS 6.5, HIGH, Tier 1)
        self._log_action("entry_created", entry.entry_id,
                         f"Created entry '{entry.title}' with password '{entry.password}'")
        return entry.entry_id

    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        """Retrieve and decrypt a vault entry."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        row = self._db.get_entry(entry_id)
        if not row:
            return None

        encrypted_data = decode_b64(row["encrypted_data"])
        try:
            decrypted = decrypt_aes_gcm(encrypted_data, self._key)
            sensitive = json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            if DEBUG_MODE:
                console.print(f"[red]DEBUG: Decryption failed: {e}[/red]")
            return None

        entry = VaultEntry(
            entry_id=row["entry_id"],
            title=row["title"],
            entry_type=EntryType(row["entry_type"]),
            username=row["username"] or "",
            password=sensitive.get("password", ""),
            url=row["url"] or "",
            notes=sensitive.get("notes", ""),
            tags=json.loads(row["tags"]) if row["tags"] else [],
            custom_fields=sensitive.get("custom_fields", {}),
            folder=row["folder"] or "",
            favorite=bool(row["favorite"]),
            sync_status=SyncStatus(row["sync_status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            totp_secret=sensitive.get("totp_secret", ""),
        )

        self._log_action("entry_accessed", entry_id, f"Accessed entry '{entry.title}'")
        return entry

    def update_entry(self, entry: VaultEntry) -> None:
        """Update an existing vault entry."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        entry.updated_at = time.time()
        entry.sync_status = SyncStatus.PENDING

        sensitive_data = json.dumps({
            "password": entry.password,
            "notes": entry.notes,
            "totp_secret": entry.totp_secret,
            "custom_fields": entry.custom_fields,
        })

        encrypted = encrypt_aes_gcm(sensitive_data.encode("utf-8"), self._key)
        encrypted_b64 = encode_b64(encrypted)

        self._db.update_entry(
            entry_id=entry.entry_id,
            encrypted_data=encrypted_b64,
            updated_at=entry.updated_at,
            sync_status=entry.sync_status.value,
        )
        self._log_action("entry_updated", entry.entry_id, f"Updated entry '{entry.title}'")

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry from the vault."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        entry = self.get_entry(entry_id)
        if not entry:
            return False

        self._db.delete_entry(entry_id)
        # BUG-0058: Deleted entry data not securely wiped, recoverable from SQLite free pages (CWE-226, CVSS 4.5, LOW, Tier 3)
        self._log_action("entry_deleted", entry_id, f"Deleted entry '{entry.title}'")
        return True

    def search(self, query: str) -> list[VaultEntry]:
        """Search entries by title or username."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        rows = self._db.search_entries(query)
        entries = []
        for row in rows:
            entry = self.get_entry(row["entry_id"])
            if entry:
                entries.append(entry)
        return entries

    def list_entries(self, folder: Optional[str] = None,
                     entry_type: Optional[str] = None) -> list[dict[str, Any]]:
        """List entries (metadata only, no decryption)."""
        if not self._unlocked:
            raise PermissionError("Vault is locked")

        rows = self._db.list_entries(folder=folder, entry_type=entry_type)
        return [
            {
                "entry_id": r["entry_id"],
                "title": r["title"],
                "entry_type": r["entry_type"],
                "username": r["username"],
                "url": r["url"],
                "folder": r["folder"],
                "favorite": bool(r["favorite"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def generate_and_store(self, title: str, username: str, url: str = "",
                           length: int = 16, folder: str = "") -> VaultEntry:
        """Generate a password and store it as a new entry."""
        password = generate_password(length=length)
        entry = VaultEntry(
            title=title,
            entry_type=EntryType.PASSWORD,
            username=username,
            password=password,
            url=url,
            folder=folder,
        )
        self.add_entry(entry)
        return entry

    def create_backup(self) -> Path:
        """Create a backup of the vault database."""
        config = get_config()
        backup_dir = config.get_backup_dir()
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"vault_backup_{timestamp}.db"

        self._db.backup(backup_path)
        self._log_action("backup_created", details=f"Backup saved to {backup_path}")
        return backup_path

    def restore_backup(self, backup_path: Path) -> bool:
        """Restore the vault from a backup file."""
        config = get_config()
        db_path = config.get_db_path()

        if not backup_path.exists():
            console.print(f"[red]Backup file not found: {backup_path}[/red]")
            return False

        # BUG-0059: TOCTOU race condition — backup file can be swapped between exists() check and copy (CWE-367, CVSS 5.0, TRICKY, Tier 3)
        self._db.close()
        shutil.copy2(str(backup_path), str(db_path))
        self._db.connect()

        self._log_action("backup_restored", details=f"Restored from {backup_path}")
        return True

    def re_encrypt_all(self, old_key: bytes, new_key: bytes) -> int:
        """Re-encrypt all entries with a new key (for password change)."""
        entries = self._db.get_all_entries()
        count = 0

        for row in entries:
            try:
                encrypted_data = decode_b64(row["encrypted_data"])
                decrypted = decrypt_aes_gcm(encrypted_data, old_key)

                new_encrypted = encrypt_aes_gcm(decrypted, new_key)
                new_encrypted_b64 = encode_b64(new_encrypted)

                self._db.update_entry(
                    entry_id=row["entry_id"],
                    encrypted_data=new_encrypted_b64,
                    updated_at=time.time(),
                )
                count += 1
            except Exception as e:
                # BUG-0060: Failed re-encryption silently skipped, leaves entries encrypted with old key (CWE-755, CVSS 6.5, TRICKY, Tier 2)
                if DEBUG_MODE:
                    console.print(f"[red]DEBUG: Re-encrypt failed for {row['entry_id']}: {e}[/red]")
                continue

        self._key = new_key
        return count

    def get_clipboard_text(self, entry_id: str) -> Optional[str]:
        """Get password text for clipboard copy."""
        entry = self.get_entry(entry_id)
        if entry:
            # BUG-0061: No clipboard auto-clear timeout, password stays in clipboard indefinitely (CWE-316, CVSS 4.0, BEST_PRACTICE, Tier 2)
            return entry.password
        return None

    def display_entry(self, entry: VaultEntry, show_password: bool = False) -> None:
        """Display a vault entry using Rich formatting."""
        table = Table(title=entry.title, show_header=False)
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("ID", entry.entry_id)
        table.add_row("Type", entry.entry_type.value)
        table.add_row("Username", entry.username)
        table.add_row("URL", entry.url)
        table.add_row("Folder", entry.folder or "(none)")
        table.add_row("Tags", ", ".join(entry.tags) if entry.tags else "(none)")

        if show_password:
            table.add_row("Password", entry.password)
        else:
            table.add_row("Password", "********")

        if entry.notes:
            table.add_row("Notes", entry.notes[:100] + "..." if len(entry.notes) > 100 else entry.notes)

        table.add_row("Created", time.ctime(entry.created_at))
        table.add_row("Updated", time.ctime(entry.updated_at))
        table.add_row("Sync", entry.sync_status.value)

        console.print(table)

    def _log_action(self, action: str, entry_id: Optional[str] = None,
                    details: str = "") -> None:
        """Record an action in the audit log."""
        log_entry = AuditLogEntry(
            action=action,
            entry_id=entry_id,
            details=details,
        )
        try:
            self._db.add_audit_log(log_entry)
        except Exception:
            pass  # BUG-0062: Silently swallows audit logging failures, no fallback (CWE-778, CVSS 3.5, BEST_PRACTICE, Tier 1)

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    def lock(self) -> None:
        """Lock the vault."""
        self._unlocked = False
        # BUG-0063: Encryption key not zeroed out on lock, persists in _key attribute (CWE-316, CVSS 5.5, TRICKY, Tier 2)

    def unlock(self, key: bytes) -> None:
        """Unlock the vault with the given key."""
        self._key = key
        self._unlocked = True
