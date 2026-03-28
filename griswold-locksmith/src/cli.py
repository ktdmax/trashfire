"""Main CLI interface for Griswold Locksmith using Typer."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .auth import (
    authenticate,
    change_master_password,
    get_cached_password,
    lock_vault as auth_lock,
    store_biometric_key,
    verify_session,
)
from .config import DEBUG_MODE, get_config
from .db import VaultDatabase
from .export import (
    export_csv,
    export_encrypted,
    export_json,
    export_to_tmpfile,
    import_csv,
    import_encrypted,
    import_from_browser,
    import_json,
)
from .models import EntryType, VaultEntry
from .sharing import SharingManager
from .sync import SyncClient
from .utils import (
    check_password_strength,
    copy_to_clipboard,
    format_timestamp,
    generate_passphrase,
    get_system_info,
    mask_password,
    run_system_command,
)
from .vault import Vault

app = typer.Typer(
    name="griswold",
    help="Griswold Locksmith - CLI Password Manager & Secrets Vault",
    no_args_is_help=True,
)
console = Console()


def _open_vault() -> tuple[VaultDatabase, Vault, bytes]:
    """Open and authenticate the vault. Returns (db, vault, key)."""
    config = get_config()
    config.load()
    config.ensure_dirs()

    db = VaultDatabase()
    db.connect()

    key = authenticate(db)
    if key is None:
        console.print("[red]Authentication failed.[/red]")
        raise typer.Exit(1)

    vault = Vault(db, key)
    return db, vault, key


@app.command()
def init():
    """Initialize a new vault."""
    config = get_config()
    config.load()
    config.ensure_dirs()

    db_path = config.get_db_path()
    if db_path.exists():
        overwrite = typer.confirm("Vault already exists. Overwrite?")
        if not overwrite:
            raise typer.Exit(0)
        db_path.unlink()

    db = VaultDatabase()
    db.connect()

    from .auth import setup_master_password
    if setup_master_password(db):
        console.print("[green]Vault initialized successfully![/green]")
    else:
        console.print("[red]Failed to initialize vault.[/red]")
        raise typer.Exit(1)

    db.close()


@app.command()
def add(
    title: str = typer.Option(..., prompt=True, help="Entry title"),
    username: str = typer.Option("", prompt=True, help="Username/email"),
    password: str = typer.Option("", prompt=True, hide_input=True, help="Password (leave empty to generate)"),
    url: str = typer.Option("", help="Associated URL"),
    notes: str = typer.Option("", help="Notes"),
    folder: str = typer.Option("", help="Folder name"),
    entry_type: str = typer.Option("password", help="Entry type: password, note, card, api_key"),
    generate: bool = typer.Option(False, "--generate", "-g", help="Auto-generate password"),
    length: int = typer.Option(16, "--length", "-l", help="Generated password length"),
):
    """Add a new entry to the vault."""
    db, vault, key = _open_vault()

    if generate or not password:
        from .crypto import generate_password
        password = generate_password(length=length)
        console.print(f"[green]Generated password: {password}[/green]")  # BUG-0098: Generated password printed to terminal in plaintext, visible in scrollback (CWE-532, CVSS 4.0, LOW, Tier 1)

    try:
        etype = EntryType(entry_type)
    except ValueError:
        console.print(f"[red]Invalid entry type: {entry_type}[/red]")
        raise typer.Exit(1)

    entry = VaultEntry(
        title=title,
        entry_type=etype,
        username=username,
        password=password,
        url=url,
        notes=notes,
        folder=folder,
    )

    entry_id = vault.add_entry(entry)
    console.print(f"[green]Entry added: {entry_id}[/green]")
    db.close()


@app.command()
def get(
    entry_id: str = typer.Argument(..., help="Entry ID to retrieve"),
    show_password: bool = typer.Option(False, "--show", "-s", help="Show password in plaintext"),
    clipboard: bool = typer.Option(False, "--copy", "-c", help="Copy password to clipboard"),
):
    """Retrieve a vault entry."""
    db, vault, key = _open_vault()

    entry = vault.get_entry(entry_id)
    if not entry:
        console.print(f"[red]Entry not found: {entry_id}[/red]")
        raise typer.Exit(1)

    vault.display_entry(entry, show_password=show_password)

    if clipboard:
        pw = vault.get_clipboard_text(entry_id)
        if pw and copy_to_clipboard(pw):
            console.print("[green]Password copied to clipboard.[/green]")

    db.close()


@app.command(name="list")
def list_entries(
    folder: Optional[str] = typer.Option(None, "--folder", "-f", help="Filter by folder"),
    entry_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by type"),
):
    """List all vault entries."""
    db, vault, key = _open_vault()

    entries = vault.list_entries(folder=folder, entry_type=entry_type)
    if not entries:
        console.print("[yellow]No entries found.[/yellow]")
        raise typer.Exit(0)

    table = Table(title="Vault Entries")
    table.add_column("ID", style="dim")
    table.add_column("Title", style="bold")
    table.add_column("Username")
    table.add_column("Type")
    table.add_column("Folder")
    table.add_column("Updated")

    for e in entries:
        table.add_row(
            e["entry_id"][:12] + "...",
            e["title"],
            e["username"] or "-",
            e["entry_type"],
            e["folder"] or "-",
            format_timestamp(e["updated_at"]) if e["updated_at"] else "-",
        )

    console.print(table)
    db.close()


@app.command()
def search(
    query: str = typer.Argument(..., help="Search term"),
):
    """Search vault entries by title or username."""
    db, vault, key = _open_vault()

    results = vault.search(query)
    if not results:
        console.print("[yellow]No matching entries found.[/yellow]")
        raise typer.Exit(0)

    for entry in results:
        vault.display_entry(entry, show_password=False)

    db.close()


@app.command()
def delete(
    entry_id: str = typer.Argument(..., help="Entry ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a vault entry."""
    db, vault, key = _open_vault()

    entry = vault.get_entry(entry_id)
    if not entry:
        console.print(f"[red]Entry not found: {entry_id}[/red]")
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Delete entry '{entry.title}'?")
        if not confirm:
            raise typer.Exit(0)

    vault.delete_entry(entry_id)
    console.print(f"[green]Entry deleted: {entry_id}[/green]")
    db.close()


@app.command()
def generate(
    length: int = typer.Option(16, "--length", "-l", help="Password length"),
    passphrase: bool = typer.Option(False, "--passphrase", "-p", help="Generate passphrase instead"),
    words: int = typer.Option(4, "--words", "-w", help="Number of words for passphrase"),
    clipboard: bool = typer.Option(False, "--copy", "-c", help="Copy to clipboard"),
):
    """Generate a random password or passphrase."""
    if passphrase:
        result = generate_passphrase(word_count=words)
    else:
        from .crypto import generate_password
        result = generate_password(length=length)

    strength = check_password_strength(result)

    console.print(f"[bold green]{result}[/bold green]")
    console.print(f"Strength: {strength['strength']} ({strength['entropy_bits']} bits)")

    if strength["issues"]:
        for issue in strength["issues"]:
            console.print(f"  [yellow]- {issue}[/yellow]")

    if clipboard and copy_to_clipboard(result):
        console.print("[green]Copied to clipboard.[/green]")


@app.command()
def lock():
    """Lock the vault."""
    auth_lock()
    console.print("[green]Vault locked.[/green]")


@app.command(name="change-password")
def change_password():
    """Change the master password."""
    db, vault, key = _open_vault()

    new_key = change_master_password(db, key)
    if new_key:
        count = vault.re_encrypt_all(key, new_key)
        console.print(f"[green]Re-encrypted {count} entries with new key.[/green]")
    else:
        console.print("[red]Password change failed.[/red]")

    db.close()


@app.command(name="export")
def export_cmd(
    output: str = typer.Option(..., "--output", "-o", help="Output file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Export format: json, csv, encrypted"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Encryption passphrase"),
):
    """Export vault entries."""
    db, vault, key = _open_vault()

    if fmt == "json":
        export_json(vault, output)
    elif fmt == "csv":
        export_csv(vault, output)
    elif fmt == "encrypted":
        if not passphrase:
            passphrase = typer.prompt("Enter export passphrase", hide_input=True)
        export_encrypted(vault, output, passphrase)
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")

    db.close()


@app.command(name="import")
def import_cmd(
    input_file: str = typer.Option(..., "--input", "-i", help="Input file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Import format: json, csv, encrypted, browser"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Decryption passphrase"),
    browser: Optional[str] = typer.Option(None, "--browser", "-b", help="Browser name for browser import"),
):
    """Import vault entries."""
    db, vault, key = _open_vault()

    if fmt == "json":
        import_json(vault, input_file)
    elif fmt == "csv":
        import_csv(vault, input_file)
    elif fmt == "encrypted":
        if not passphrase:
            passphrase = typer.prompt("Enter import passphrase", hide_input=True)
        import_encrypted(vault, input_file, passphrase)
    elif fmt == "browser":
        if not browser:
            console.print("[red]Specify --browser for browser import[/red]")
            raise typer.Exit(1)
        import_from_browser(vault, browser, input_file)
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")

    db.close()


@app.command()
def sync(
    direction: str = typer.Argument("both", help="Sync direction: push, pull, or both"),
):
    """Sync vault with remote server."""
    db, vault, key = _open_vault()
    client = SyncClient(db, key)

    if direction in ("push", "both"):
        client.push()
    if direction in ("pull", "both"):
        client.pull()
    if direction not in ("push", "pull", "both"):
        console.print(f"[red]Invalid direction: {direction}[/red]")

    db.close()


@app.command(name="sync-status")
def sync_status():
    """Show sync status."""
    db, vault, key = _open_vault()
    client = SyncClient(db, key)

    status = client.get_sync_status()
    table = Table(title="Sync Status")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    for k, v in status.items():
        table.add_row(k.replace("_", " ").title(), str(v))

    console.print(table)
    db.close()


@app.command(name="share")
def share_secret(
    entry_id: str = typer.Argument(..., help="Entry ID to share"),
    recipient: str = typer.Option(..., "--to", "-t", help="Recipient name"),
    expires: Optional[int] = typer.Option(None, "--expires", "-e", help="Hours until expiry"),
):
    """Share a secret with another user."""
    db, vault, key = _open_vault()

    entry = vault.get_entry(entry_id)
    if not entry:
        console.print(f"[red]Entry not found: {entry_id}[/red]")
        raise typer.Exit(1)

    sharing = SharingManager()
    package = sharing.share_secret(entry.password, recipient, expires_hours=expires)
    if package:
        serialized = sharing.serialize_package(package)
        console.print(f"[green]Share package created![/green]")
        console.print(f"Package: {serialized[:80]}...")

    db.close()


@app.command(name="keygen")
def keygen(
    name: str = typer.Argument(..., help="Identity name for the keypair"),
):
    """Generate a new RSA keypair for secret sharing."""
    sharing = SharingManager()
    fingerprint = sharing.generate_identity(name)
    console.print(f"[green]Keypair generated. Fingerprint: {fingerprint}[/green]")


@app.command(name="keylist")
def keylist():
    """List all keys in the keyring."""
    sharing = SharingManager()
    keys = sharing.list_keys()

    if not keys:
        console.print("[yellow]No keys in keyring.[/yellow]")
        return

    table = Table(title="Keyring")
    table.add_column("Name", style="bold")
    table.add_column("Fingerprint")
    table.add_column("Has Private Key")

    for k in keys:
        table.add_row(
            k["name"],
            k["fingerprint"],
            "[green]Yes[/green]" if k["has_private"] else "[dim]No[/dim]",
        )

    console.print(table)


@app.command()
def backup():
    """Create a vault backup."""
    db, vault, key = _open_vault()
    backup_path = vault.create_backup()
    console.print(f"[green]Backup created: {backup_path}[/green]")
    db.close()


@app.command()
def audit(
    limit: int = typer.Option(50, "--limit", "-n", help="Number of entries to show"),
):
    """View the audit log."""
    db, vault, key = _open_vault()

    logs = db.get_audit_log(limit=limit)
    if not logs:
        console.print("[yellow]No audit log entries.[/yellow]")
        raise typer.Exit(0)

    table = Table(title="Audit Log")
    table.add_column("Time", style="dim")
    table.add_column("Action", style="bold")
    table.add_column("Entry ID")
    table.add_column("Details")

    for log in logs:
        table.add_row(
            format_timestamp(log["timestamp"]),
            log["action"],
            (log["entry_id"] or "-")[:12],
            log["details"][:60] if log["details"] else "-",
        )

    console.print(table)
    db.close()


@app.command()
def info():
    """Show vault and system information."""
    config = get_config()
    config.load()

    sys_info = get_system_info()
    table = Table(title="System Information")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    for k, v in sys_info.items():
        table.add_row(k.title(), v)

    table.add_row("Vault Path", str(config.get_db_path()))
    table.add_row("Config Path", str(config._config_path))
    table.add_row("Debug Mode", str(DEBUG_MODE))
    # BUG-0099: Displays debug mode status and paths, useful for reconnaissance (CWE-200, CVSS 2.5, BEST_PRACTICE, Tier 1)

    console.print(table)


@app.command()
def run(
    command: str = typer.Argument(..., help="System command to execute"),
):
    """Run a system command (admin utility)."""
    # BUG-0100: Direct command execution from CLI argument, arbitrary code execution (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    returncode, stdout, stderr = run_system_command(command)
    if stdout:
        console.print(stdout)
    if stderr:
        console.print(f"[red]{stderr}[/red]")
    raise typer.Exit(returncode)


if __name__ == "__main__":
    app()
