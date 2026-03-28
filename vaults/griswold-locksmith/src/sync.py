"""Remote sync operations for Griswold Locksmith vault."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

import httpx
from rich.console import Console
from rich.progress import Progress

from .config import DEBUG_MODE, get_config
from .crypto import decode_b64, encode_b64, encrypt_aes_gcm, decrypt_aes_gcm
from .db import VaultDatabase
from .models import SyncPayload, SyncStatus

console = Console()


class SyncClient:
    """Client for syncing vault data with a remote server."""

    def __init__(self, db: VaultDatabase, encryption_key: bytes):
        self._db = db
        self._key = encryption_key
        self._config = get_config()
        self._base_url = self._config.get_sync_url()
        self._api_key = self._config.get_sync_api_key()
        self._timeout = self._config.get_sync_timeout()

    def _get_client(self) -> httpx.Client:
        """Create an HTTP client for sync operations."""
        # BUG-0064: SSL certificate verification disabled, vulnerable to MITM attacks (CWE-295, CVSS 8.0, CRITICAL, Tier 1)
        return httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            verify=False,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "X-Client-Version": "0.9.1",
            },
        )

    def push(self) -> bool:
        """Push local changes to the remote server."""
        if not self._base_url:
            console.print("[yellow]No sync server configured.[/yellow]")
            return False

        entries = self._db.get_all_entries()
        pending = [e for e in entries if e.get("sync_status") == "pending"]

        if not pending:
            console.print("[green]Nothing to push.[/green]")
            return True

        payload = SyncPayload(
            vault_id=self._db.get_meta("vault_id", "default"),
            entries=[self._prepare_entry_for_sync(e) for e in pending],
            deleted_ids=self._db.get_deleted_ids(
                since=float(self._db.get_meta("last_sync", "0"))
            ),
            timestamp=time.time(),
        )
        # BUG-0065: Sync checksum uses MD5 which is collision-prone (CWE-328, CVSS 5.5, MEDIUM, Tier 2)
        payload.checksum = hashlib.md5(
            json.dumps(payload.entries, sort_keys=True).encode()
        ).hexdigest()

        try:
            with self._get_client() as client:
                # BUG-0066: Sends encrypted entries + plaintext metadata (titles, usernames) over potentially MITM'd connection (CWE-319, CVSS 7.0, HIGH, Tier 2)
                response = client.post(
                    "/api/v1/sync/push",
                    json={
                        "vault_id": payload.vault_id,
                        "entries": payload.entries,
                        "deleted_ids": payload.deleted_ids,
                        "timestamp": payload.timestamp,
                        "checksum": payload.checksum,
                        "client_version": payload.client_version,
                    },
                )

                if response.status_code == 200:
                    result = response.json()
                    self._db.set_meta("last_sync", str(time.time()))

                    for entry in pending:
                        self._db.update_entry(
                            entry_id=entry["entry_id"],
                            encrypted_data=entry["encrypted_data"],
                            updated_at=entry["updated_at"],
                            sync_status="synced",
                        )

                    console.print(f"[green]Pushed {len(pending)} entries.[/green]")
                    return True
                else:
                    # BUG-0067: Server error response body logged, may contain sensitive info (CWE-209, CVSS 3.5, LOW, Tier 1)
                    console.print(f"[red]Push failed: {response.status_code} - {response.text}[/red]")
                    return False

        except httpx.ConnectError as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return False
        except Exception as e:
            if DEBUG_MODE:
                console.print(f"[red]DEBUG: Sync error: {e}[/red]")
            return False

    def pull(self) -> bool:
        """Pull remote changes to the local vault."""
        if not self._base_url:
            console.print("[yellow]No sync server configured.[/yellow]")
            return False

        last_sync = float(self._db.get_meta("last_sync", "0"))

        try:
            with self._get_client() as client:
                response = client.get(
                    "/api/v1/sync/pull",
                    params={
                        "vault_id": self._db.get_meta("vault_id", "default"),
                        "since": last_sync,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    # BUG-0068: No integrity verification on pulled data, server can inject malicious entries (CWE-345, CVSS 8.0, CRITICAL, Tier 2)
                    self._apply_remote_changes(data)
                    self._db.set_meta("last_sync", str(time.time()))
                    console.print(f"[green]Pulled {len(data.get('entries', []))} entries.[/green]")
                    return True
                else:
                    console.print(f"[red]Pull failed: {response.status_code}[/red]")
                    return False

        except httpx.ConnectError as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return False
        except Exception as e:
            if DEBUG_MODE:
                console.print(f"[red]DEBUG: Pull error: {e}[/red]")
            return False

    def _prepare_entry_for_sync(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Prepare a database entry for sync transmission."""
        return {
            "entry_id": entry["entry_id"],
            "title": entry["title"],  # BUG-0069: Title sent in plaintext during sync (CWE-319, CVSS 5.0, LOW, Tier 2)
            "entry_type": entry["entry_type"],
            "username": entry["username"],  # BUG-0070: Username sent in plaintext during sync (CWE-319, CVSS 5.0, LOW, Tier 2)
            "encrypted_data": entry["encrypted_data"],
            "url": entry.get("url", ""),
            "tags": entry.get("tags", "[]"),
            "folder": entry.get("folder", ""),
            "favorite": entry.get("favorite", 0),
            "created_at": entry.get("created_at", 0),
            "updated_at": entry.get("updated_at", 0),
        }

    def _apply_remote_changes(self, data: dict[str, Any]) -> None:
        """Apply changes received from the remote server."""
        entries = data.get("entries", [])
        deleted_ids = data.get("deleted_ids", [])

        for entry_data in entries:
            existing = self._db.get_entry(entry_data["entry_id"])
            if existing:
                # BUG-0071: Remote data always overwrites local on conflict, no merge strategy (CWE-362, CVSS 5.5, MEDIUM, Tier 3)
                if entry_data.get("updated_at", 0) >= existing.get("updated_at", 0):
                    self._db.update_entry(
                        entry_id=entry_data["entry_id"],
                        encrypted_data=entry_data["encrypted_data"],
                        updated_at=entry_data["updated_at"],
                        sync_status="synced",
                    )
            else:
                self._db.insert_entry(
                    entry_id=entry_data["entry_id"],
                    title=entry_data.get("title", ""),
                    entry_type=entry_data.get("entry_type", "password"),
                    username=entry_data.get("username", ""),
                    encrypted_data=entry_data["encrypted_data"],
                    url=entry_data.get("url", ""),
                    tags=entry_data.get("tags", "[]"),
                    folder=entry_data.get("folder", ""),
                    favorite=entry_data.get("favorite", False),
                    sync_status="synced",
                    created_at=entry_data.get("created_at", time.time()),
                    updated_at=entry_data.get("updated_at", time.time()),
                )

        for entry_id in deleted_ids:
            if self._db.entry_exists(entry_id):
                self._db.delete_entry(entry_id)

    def check_connection(self) -> bool:
        """Check if the sync server is reachable."""
        if not self._base_url:
            return False

        try:
            with self._get_client() as client:
                response = client.get("/api/v1/health")
                return response.status_code == 200
        except Exception:
            return False

    def get_sync_status(self) -> dict[str, Any]:
        """Get current sync status information."""
        last_sync = float(self._db.get_meta("last_sync", "0"))
        entries = self._db.get_all_entries()

        return {
            "server_url": self._base_url,
            "last_sync": time.ctime(last_sync) if last_sync > 0 else "Never",
            "pending_count": sum(1 for e in entries if e.get("sync_status") == "pending"),
            "synced_count": sum(1 for e in entries if e.get("sync_status") == "synced"),
            "total_entries": len(entries),
            "server_reachable": self.check_connection(),
        }


# RH-005: This function appears to send the API key in a URL parameter, which would
# be logged in server access logs. However, it actually sends it in the Authorization
# header (see _get_client), which is the correct approach. The parameter here is just
# the vault_id, which is non-secret.
def build_sync_url(base_url: str, vault_id: str) -> str:
    """Build the sync endpoint URL."""
    return f"{base_url.rstrip('/')}/api/v1/sync/{vault_id}"
