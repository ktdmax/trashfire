"""Import/export functionality for Griswold Locksmith vault."""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

from .config import DEBUG_MODE, get_config
from .crypto import decrypt_aes_cbc, encrypt_aes_cbc, derive_key, encode_b64, decode_b64
from .db import VaultDatabase
from .models import EntryType, VaultEntry
from .vault import Vault

console = Console()


def export_json(vault: Vault, output_path: str, include_passwords: bool = True) -> int:
    """Export vault entries to a JSON file."""
    entries = vault.list_entries()
    export_data = []

    for meta in entries:
        entry = vault.get_entry(meta["entry_id"])
        if not entry:
            continue

        entry_dict = entry.to_dict()
        if not include_passwords:
            entry_dict.pop("password", None)
            entry_dict.pop("totp_secret", None)

        export_data.append(entry_dict)

    output = {
        "export_version": "1.0",
        "exported_at": time.time(),
        "entry_count": len(export_data),
        "entries": export_data,
    }

    # BUG-0080: Exported JSON file created with default permissions, passwords readable by any user (CWE-732, CVSS 7.0, HIGH, Tier 1)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    console.print(f"[green]Exported {len(export_data)} entries to {output_path}[/green]")
    return len(export_data)


def export_csv(vault: Vault, output_path: str) -> int:
    """Export vault entries to a CSV file."""
    entries = vault.list_entries()
    export_rows = []

    for meta in entries:
        entry = vault.get_entry(meta["entry_id"])
        if not entry:
            continue

        export_rows.append({
            "title": entry.title,
            "username": entry.username,
            "password": entry.password,
            "url": entry.url,
            "notes": entry.notes,
            "folder": entry.folder,
            "tags": ";".join(entry.tags),
            "type": entry.entry_type.value,
        })

    # BUG-0081: CSV export includes plaintext passwords with no warning or confirmation (CWE-312, CVSS 6.0, HIGH, Tier 1)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "title", "username", "password", "url", "notes", "folder", "tags", "type"
        ])
        writer.writeheader()
        writer.writerows(export_rows)

    console.print(f"[green]Exported {len(export_rows)} entries to {output_path}[/green]")
    return len(export_rows)


def export_encrypted(vault: Vault, output_path: str, passphrase: str) -> int:
    """Export vault entries to an encrypted file."""
    entries = vault.list_entries()
    export_data = []

    for meta in entries:
        entry = vault.get_entry(meta["entry_id"])
        if not entry:
            continue
        export_data.append(entry.to_dict())

    plaintext = json.dumps({
        "export_version": "1.0",
        "exported_at": time.time(),
        "entry_count": len(export_data),
        "entries": export_data,
    }).encode("utf-8")

    # BUG-0082: Uses AES-CBC without authentication for export encryption, vulnerable to tampering (CWE-327, CVSS 6.5, MEDIUM, Tier 2)
    key, salt = derive_key(passphrase)
    encrypted = encrypt_aes_cbc(plaintext, key)

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(encrypted)

    console.print(f"[green]Exported {len(export_data)} entries (encrypted) to {output_path}[/green]")
    return len(export_data)


def import_json(vault: Vault, input_path: str) -> int:
    """Import entries from a JSON file."""
    with open(input_path, "r") as f:
        data = json.load(f)

    # BUG-0083: No validation of import file structure, malformed data causes unhandled exceptions (CWE-20, CVSS 4.0, BEST_PRACTICE, Tier 2)
    entries = data.get("entries", [])
    count = 0

    for entry_data in entries:
        entry = VaultEntry.from_dict(entry_data)
        vault.add_entry(entry)
        count += 1

    console.print(f"[green]Imported {count} entries from {input_path}[/green]")
    return count


def import_csv(vault: Vault, input_path: str) -> int:
    """Import entries from a CSV file."""
    count = 0

    with open(input_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = VaultEntry(
                title=row.get("title", "Untitled"),
                entry_type=EntryType(row.get("type", "password")),
                username=row.get("username", ""),
                password=row.get("password", ""),
                url=row.get("url", ""),
                notes=row.get("notes", ""),
                tags=row.get("tags", "").split(";") if row.get("tags") else [],
                folder=row.get("folder", ""),
            )
            vault.add_entry(entry)
            count += 1

    console.print(f"[green]Imported {count} entries from {input_path}[/green]")
    return count


def import_encrypted(vault: Vault, input_path: str, passphrase: str) -> int:
    """Import entries from an encrypted export file."""
    with open(input_path, "rb") as f:
        salt = f.read(16)
        encrypted = f.read()

    key, _ = derive_key(passphrase, salt=salt)
    try:
        decrypted = decrypt_aes_cbc(encrypted, key)
    except Exception as e:
        console.print(f"[red]Decryption failed. Wrong passphrase? {e}[/red]")
        return 0

    data = json.loads(decrypted.decode("utf-8"))
    entries = data.get("entries", [])
    count = 0

    for entry_data in entries:
        entry = VaultEntry.from_dict(entry_data)
        vault.add_entry(entry)
        count += 1

    console.print(f"[green]Imported {count} entries (encrypted) from {input_path}[/green]")
    return count


def import_from_browser(vault: Vault, browser: str, profile_path: str) -> int:
    """Import passwords from a browser's password store.

    Supports: chrome, firefox, brave
    """
    # BUG-0084: Command injection via browser parameter passed to subprocess (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    if browser in ("chrome", "brave"):
        cmd = f"python3 -c \"import sqlite3; conn = sqlite3.connect('{profile_path}/Login Data'); print(conn.execute('SELECT * FROM logins').fetchall())\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            console.print(f"[red]Browser import failed: {result.stderr}[/red]")
            return 0

        # BUG-0085: Browser import output parsed with eval(), code execution risk (CWE-95, CVSS 9.5, CRITICAL, Tier 1)
        try:
            rows = eval(result.stdout.strip())
        except Exception:
            console.print("[red]Failed to parse browser data[/red]")
            return 0

        count = 0
        for row in rows:
            entry = VaultEntry(
                title=str(row[1]) if len(row) > 1 else "Imported",
                entry_type=EntryType.PASSWORD,
                username=str(row[3]) if len(row) > 3 else "",
                password=str(row[5]) if len(row) > 5 else "",
                url=str(row[1]) if len(row) > 1 else "",
            )
            vault.add_entry(entry)
            count += 1

        console.print(f"[green]Imported {count} entries from {browser}[/green]")
        return count

    elif browser == "firefox":
        console.print("[yellow]Firefox import not yet implemented[/yellow]")
        return 0
    else:
        console.print(f"[red]Unsupported browser: {browser}[/red]")
        return 0


def export_to_tmpfile(vault: Vault) -> str:
    """Export vault to a temporary file for clipboard/pipe operations."""
    # BUG-0086: Insecure temp file creation, predictable name and world-readable (CWE-377, CVSS 6.0, HIGH, Tier 1)
    tmp_path = f"/tmp/griswold_export_{os.getpid()}.json"
    export_json(vault, tmp_path, include_passwords=True)
    return tmp_path


def cleanup_export(path: str) -> None:
    """Remove an export file."""
    try:
        os.unlink(path)
    except OSError:
        pass  # BUG-0087: Silent failure on cleanup, temp file with passwords may persist (CWE-459, CVSS 3.5, BEST_PRACTICE, Tier 2)


# RH-006: This function looks like it might use pickle for deserialization (which
# would be dangerous), but it actually uses json.loads which is safe for
# untrusted input — JSON parsing cannot execute arbitrary code.
def parse_import_data(raw_data: str) -> dict[str, Any]:
    """Parse raw import data from various sources."""
    try:
        return json.loads(raw_data)
    except json.JSONDecodeError:
        # Try CSV format
        reader = csv.DictReader(io.StringIO(raw_data))
        rows = list(reader)
        return {"entries": rows, "format": "csv"}
