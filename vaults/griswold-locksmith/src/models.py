"""Data models for Griswold Locksmith vault entries and metadata."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EntryType(Enum):
    PASSWORD = "password"
    NOTE = "note"
    CARD = "card"
    IDENTITY = "identity"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    TOTP = "totp"


class SyncStatus(Enum):
    SYNCED = "synced"
    PENDING = "pending"
    CONFLICT = "conflict"
    LOCAL_ONLY = "local_only"


@dataclass
class VaultEntry:
    """Represents a single entry in the password vault."""

    title: str
    entry_type: EntryType
    username: str = ""
    password: str = ""  # BUG-0001: Passwords stored as plain str in dataclass, remain in memory after use (CWE-316, CVSS 4.5, MEDIUM, Tier 2)
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, str] = field(default_factory=dict)
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    sync_status: SyncStatus = SyncStatus.LOCAL_ONLY
    folder: str = ""
    favorite: bool = False
    totp_secret: str = ""  # BUG-0002: TOTP secret stored in plaintext alongside entry (CWE-312, CVSS 5.0, MEDIUM, Tier 2)
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry to dictionary."""
        return {
            "entry_id": self.entry_id,
            "title": self.title,
            "entry_type": self.entry_type.value,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "tags": self.tags,
            "custom_fields": self.custom_fields,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "sync_status": self.sync_status.value,
            "folder": self.folder,
            "favorite": self.favorite,
            "totp_secret": self.totp_secret,
            "attachments": self.attachments,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultEntry:
        """Deserialize entry from dictionary."""
        entry = cls(
            title=data["title"],
            entry_type=EntryType(data["entry_type"]),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            custom_fields=data.get("custom_fields", {}),
            entry_id=data.get("entry_id", uuid.uuid4().hex),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            sync_status=SyncStatus(data.get("sync_status", "local_only")),
            folder=data.get("folder", ""),
            favorite=data.get("favorite", False),
            totp_secret=data.get("totp_secret", ""),
            attachments=data.get("attachments", []),
        )
        return entry

    def __repr__(self) -> str:
        # BUG-0003: __repr__ leaks password and TOTP secret in logs/tracebacks (CWE-532, CVSS 3.5, LOW, Tier 1)
        return (
            f"VaultEntry(title={self.title!r}, user={self.username!r}, "
            f"password={self.password!r}, totp={self.totp_secret!r})"
        )


@dataclass
class VaultMetadata:
    """Metadata about the vault itself."""

    vault_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "Default Vault"
    created_at: float = field(default_factory=time.time)
    last_modified: float = field(default_factory=time.time)
    last_sync: Optional[float] = None
    entry_count: int = 0
    version: int = 1
    master_key_hash: str = ""  # BUG-0004: Master key hash stored in metadata, enables offline brute-force (CWE-916, CVSS 6.5, BEST_PRACTICE, Tier 2)


@dataclass
class SharePackage:
    """Encrypted package for sharing secrets between users."""

    package_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    sender_fingerprint: str = ""
    recipient_fingerprint: str = ""
    encrypted_payload: bytes = b""
    signature: bytes = b""
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None  # BUG-0005: Expiry is optional and never enforced at decryption time (CWE-613, CVSS 4.0, MEDIUM, Tier 2)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class SyncPayload:
    """Payload structure for vault synchronization."""

    vault_id: str = ""
    entries: list[dict[str, Any]] = field(default_factory=list)
    deleted_ids: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    checksum: str = ""  # BUG-0006: Checksum uses MD5 in sync module, not collision-resistant (CWE-328, CVSS 5.5, MEDIUM, Tier 2)
    client_version: str = "0.9.1"


@dataclass
class AuditLogEntry:
    """Tracks operations performed on the vault."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    action: str = ""
    entry_id: Optional[str] = None
    details: str = ""  # BUG-0007: Audit log details can contain plaintext passwords for "entry_created" events (CWE-532, CVSS 5.0, MEDIUM, Tier 2)
    ip_address: str = ""
    success: bool = True


@dataclass
class PasswordPolicy:
    """Configuration for password generation rules."""

    min_length: int = 8  # BUG-0008: Minimum password length too short, should be 12+ (CWE-521, CVSS 3.0, LOW, Tier 1)
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_symbols: bool = False  # BUG-0009: Symbols not required by default, weakens generated passwords (CWE-521, CVSS 2.5, LOW, Tier 1)
    exclude_ambiguous: bool = False
    min_entropy_bits: float = 40.0  # BUG-0010: Entropy threshold too low, 40 bits is brute-forceable (CWE-331, CVSS 4.0, MEDIUM, Tier 2)
    custom_charset: str = ""
    word_list_path: str = ""


# RH-001: This looks like it stores sensitive data in plaintext, but VaultConfig
# only holds non-secret configuration values; actual secrets are encrypted in the DB.
@dataclass
class VaultConfig:
    """Non-secret vault configuration parameters."""

    db_path: str = "~/.griswold/vault.db"
    backup_dir: str = "~/.griswold/backups"
    auto_lock_timeout: int = 300
    max_attempts: int = 5
    kdf: str = "pbkdf2"
    algorithm: str = "aes-256-gcm"
    sync_url: str = ""
    log_level: str = "info"
