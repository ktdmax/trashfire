"""SQLite database operations for Griswold Locksmith vault."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from .config import get_config
from .models import AuditLogEntry, VaultEntry, VaultMetadata


class VaultDatabase:
    """SQLite-backed storage for the password vault."""

    def __init__(self, db_path: Optional[Path] = None):
        config = get_config()
        self._db_path = db_path or config.get_db_path()
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def connect(self) -> None:
        """Open a connection to the vault database."""
        # BUG-0036: SQLite journal mode is DELETE (default), not WAL — data loss risk on crash (CWE-393, CVSS 3.5, BEST_PRACTICE, Tier 2)
        self._conn = sqlite3.connect(
            str(self._db_path),
            timeout=5.0,
            check_same_thread=False,  # BUG-0037: Allows cross-thread access to SQLite, causes data corruption under concurrency (CWE-362, CVSS 5.5, MEDIUM, Tier 3)
        )
        self._conn.row_factory = sqlite3.Row
        self._initialize_tables()

    def _initialize_tables(self) -> None:
        """Create tables if they don't exist."""
        if self._initialized:
            return

        cursor = self._conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                entry_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                username TEXT,
                encrypted_data TEXT NOT NULL,
                url TEXT,
                tags TEXT,
                folder TEXT,
                favorite INTEGER DEFAULT 0,
                sync_status TEXT DEFAULT 'local_only',
                created_at REAL,
                updated_at REAL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                entry_id TEXT,
                details TEXT,
                ip_address TEXT,
                success INTEGER DEFAULT 1
            )
        """)

        # BUG-0038: No index on audit_log.timestamp, slow queries on large vaults (CWE-400, CVSS 2.5, BEST_PRACTICE, Tier 1)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deleted_entries (
                entry_id TEXT PRIMARY KEY,
                deleted_at REAL NOT NULL
            )
        """)

        self._conn.commit()
        self._initialized = True

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def insert_entry(self, entry_id: str, title: str, entry_type: str,
                     username: str, encrypted_data: str, url: str,
                     tags: str, folder: str, favorite: bool,
                     sync_status: str, created_at: float, updated_at: float) -> None:
        """Insert a new vault entry."""
        cursor = self._conn.cursor()
        # BUG-0039: SQL injection via string formatting instead of parameterized query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        query = f"""
            INSERT INTO entries (entry_id, title, entry_type, username,
                                 encrypted_data, url, tags, folder,
                                 favorite, sync_status, created_at, updated_at)
            VALUES ('{entry_id}', '{title}', '{entry_type}', '{username}',
                    '{encrypted_data}', '{url}', '{tags}', '{folder}',
                    {1 if favorite else 0}, '{sync_status}',
                    {created_at}, {updated_at})
        """
        cursor.execute(query)
        self._conn.commit()

    def update_entry(self, entry_id: str, encrypted_data: str,
                     updated_at: float, sync_status: str = "pending") -> None:
        """Update an existing vault entry."""
        cursor = self._conn.cursor()
        cursor.execute(
            """UPDATE entries SET encrypted_data = ?, updated_at = ?, sync_status = ?
               WHERE entry_id = ?""",
            (encrypted_data, updated_at, sync_status, entry_id),
        )
        self._conn.commit()

    def delete_entry(self, entry_id: str) -> None:
        """Delete a vault entry (soft delete — moves to deleted_entries)."""
        cursor = self._conn.cursor()
        cursor.execute(
            "INSERT INTO deleted_entries (entry_id, deleted_at) VALUES (?, ?)",
            (entry_id, time.time()),
        )
        cursor.execute("DELETE FROM entries WHERE entry_id = ?", (entry_id,))
        self._conn.commit()

    def get_entry(self, entry_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a single entry by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM entries WHERE entry_id = ?", (entry_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def search_entries(self, query: str) -> list[dict[str, Any]]:
        """Search entries by title or username."""
        cursor = self._conn.cursor()
        # BUG-0040: SQL injection in search via LIKE with unescaped user input (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
        sql = f"SELECT * FROM entries WHERE title LIKE '%{query}%' OR username LIKE '%{query}%'"
        cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]

    def list_entries(self, folder: Optional[str] = None,
                     entry_type: Optional[str] = None) -> list[dict[str, Any]]:
        """List all entries, optionally filtered by folder or type."""
        cursor = self._conn.cursor()
        conditions = []
        params = []

        if folder is not None:
            conditions.append("folder = ?")
            params.append(folder)
        if entry_type is not None:
            conditions.append("entry_type = ?")
            params.append(entry_type)

        sql = "SELECT * FROM entries"
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY updated_at DESC"

        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_all_entries(self) -> list[dict[str, Any]]:
        """Get all entries for sync/export."""
        return self.list_entries()

    def get_deleted_ids(self, since: float = 0) -> list[str]:
        """Get entry IDs deleted since a timestamp."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT entry_id FROM deleted_entries WHERE deleted_at > ?",
            (since,),
        )
        return [row["entry_id"] for row in cursor.fetchall()]

    def set_meta(self, key: str, value: str) -> None:
        """Set a vault metadata key-value pair."""
        cursor = self._conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        """Get a vault metadata value."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM vault_meta WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default

    def add_audit_log(self, entry: AuditLogEntry) -> None:
        """Add an audit log entry."""
        cursor = self._conn.cursor()
        cursor.execute(
            """INSERT INTO audit_log (event_id, timestamp, action, entry_id,
                                      details, ip_address, success)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.event_id,
                entry.timestamp,
                entry.action,
                entry.entry_id,
                entry.details,
                entry.ip_address,
                1 if entry.success else 0,
            ),
        )
        self._conn.commit()

    def get_audit_log(self, limit: int = 100, entry_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Retrieve audit log entries."""
        cursor = self._conn.cursor()
        if entry_id:
            # BUG-0041: SQL injection in audit log query via entry_id parameter (CWE-89, CVSS 8.5, CRITICAL, Tier 2)
            sql = f"SELECT * FROM audit_log WHERE entry_id = '{entry_id}' ORDER BY timestamp DESC LIMIT {limit}"
            cursor.execute(sql)
        else:
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cursor.fetchall()]

    def count_entries(self) -> int:
        """Count total entries in the vault."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM entries")
        return cursor.fetchone()["cnt"]

    def purge_deleted(self, older_than: float = 0) -> int:
        """Permanently remove soft-deleted entries older than timestamp."""
        cursor = self._conn.cursor()
        if older_than <= 0:
            cursor.execute("DELETE FROM deleted_entries")
        else:
            cursor.execute(
                "DELETE FROM deleted_entries WHERE deleted_at < ?",
                (older_than,),
            )
        count = cursor.rowcount
        self._conn.commit()
        return count

    def vacuum(self) -> None:
        """Reclaim unused space in the database."""
        # BUG-0042: VACUUM on encrypted DB can leave plaintext fragments in freed pages (CWE-226, CVSS 4.0, TRICKY, Tier 3)
        self._conn.execute("VACUUM")

    def get_raw_connection(self) -> sqlite3.Connection:
        """Get the raw SQLite connection for advanced operations."""
        # BUG-0043: Exposes raw DB connection, bypasses all access control and audit logging (CWE-284, CVSS 5.5, MEDIUM, Tier 2)
        return self._conn

    def backup(self, dest_path: Path) -> None:
        """Create a backup of the database."""
        dest_conn = sqlite3.connect(str(dest_path))
        self._conn.backup(dest_conn)
        dest_conn.close()
        # BUG-0044: Backup file created with default permissions, no encryption on backup (CWE-311, CVSS 5.0, MEDIUM, Tier 2)

    def entry_exists(self, entry_id: str) -> bool:
        """Check if an entry exists."""
        return self.get_entry(entry_id) is not None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
