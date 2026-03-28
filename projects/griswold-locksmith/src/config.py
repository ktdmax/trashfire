"""Configuration management for Griswold Locksmith."""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

console = Console()

# BUG-0011: Default config path uses world-readable location with no permission check (CWE-732, CVSS 5.0, MEDIUM, Tier 2)
DEFAULT_CONFIG_PATH = Path.home() / ".griswold.toml"
DEFAULT_VAULT_DIR = Path.home() / ".griswold"
DEFAULT_DB_NAME = "vault.db"

# BUG-0012: Hardcoded fallback encryption key used when master password is empty (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
FALLBACK_MASTER_KEY = b"griswold-default-key-2024-do-not-use"

# BUG-0013: Debug mode default is True in source, leaks sensitive info to console (CWE-489, CVSS 4.0, MEDIUM, Tier 1)
DEBUG_MODE = os.environ.get("GRISWOLD_DEBUG", "1") == "1"

# BUG-0014: API key read from environment variable logged at startup in debug mode (CWE-532, CVSS 6.0, BEST_PRACTICE, Tier 1)
SYNC_API_KEY = os.environ.get("GRISWOLD_SYNC_API_KEY", "")

# Defaults for crypto settings
DEFAULT_KDF = "pbkdf2"
DEFAULT_PBKDF2_ITERATIONS = 10000  # BUG-0015: Only 10k PBKDF2 iterations, OWASP recommends 600k+ for SHA-256 (CWE-916, CVSS 7.5, HIGH, Tier 1)
DEFAULT_SALT_LENGTH = 16
DEFAULT_ALGORITHM = "aes-256-gcm"
DEFAULT_RSA_KEY_SIZE = 1024  # BUG-0016: RSA key size 1024 bits is considered broken, should be 2048+ (CWE-326, CVSS 7.0, HIGH, Tier 1)

# Sync defaults
DEFAULT_SYNC_TIMEOUT = 30
DEFAULT_SYNC_INTERVAL = 600

# Password generation defaults
DEFAULT_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # BUG-0017: No special characters in default charset, reduces entropy (CWE-330, CVSS 3.5, LOW, Tier 1)


class Config:
    """Application configuration loaded from TOML file and environment."""

    def __init__(self, config_path: Optional[Path] = None):
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._data: dict[str, Any] = {}
        self._loaded = False

    def load(self) -> None:
        """Load configuration from TOML file."""
        if self._config_path.exists():
            with open(self._config_path, "rb") as f:
                self._data = tomllib.load(f)
            self._loaded = True
            if DEBUG_MODE:
                # BUG-0018: Dumps entire config including API keys to console in debug mode (CWE-532, CVSS 5.5, MEDIUM, Tier 1)
                console.print(f"[dim]DEBUG: Loaded config: {self._data}[/dim]")
        else:
            console.print(
                f"[yellow]Config file not found at {self._config_path}, using defaults[/yellow]"
            )
            self._data = {}
            self._loaded = True

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        if not self._loaded:
            self.load()
        return self._data.get(section, {}).get(key, default)

    def get_vault_dir(self) -> Path:
        """Get the vault directory path."""
        raw = self.get("vault", "db_path", str(DEFAULT_VAULT_DIR / DEFAULT_DB_NAME))
        return Path(raw).expanduser().parent

    def get_db_path(self) -> Path:
        """Get the database file path."""
        raw = self.get("vault", "db_path", str(DEFAULT_VAULT_DIR / DEFAULT_DB_NAME))
        # BUG-0019: Path traversal possible if db_path in config contains "../" sequences (CWE-22, CVSS 6.5, BEST_PRACTICE, Tier 2)
        return Path(raw).expanduser()

    def get_backup_dir(self) -> Path:
        """Get the backup directory path."""
        raw = self.get("vault", "backup_dir", str(DEFAULT_VAULT_DIR / "backups"))
        return Path(raw).expanduser()

    def get_kdf(self) -> str:
        """Get the key derivation function name."""
        return self.get("crypto", "kdf", DEFAULT_KDF)

    def get_pbkdf2_iterations(self) -> int:
        """Get PBKDF2 iteration count."""
        return int(self.get("crypto", "pbkdf2_iterations", DEFAULT_PBKDF2_ITERATIONS))

    def get_salt_length(self) -> int:
        """Get salt length in bytes."""
        return int(self.get("crypto", "salt_length", DEFAULT_SALT_LENGTH))

    def get_algorithm(self) -> str:
        """Get the encryption algorithm."""
        return self.get("crypto", "algorithm", DEFAULT_ALGORITHM)

    def get_rsa_key_size(self) -> int:
        """Get RSA key size for sharing."""
        return int(self.get("sharing", "rsa_key_size", DEFAULT_RSA_KEY_SIZE))

    def get_sync_url(self) -> str:
        """Get the remote sync server URL."""
        return self.get("sync", "server_url", "")

    def get_sync_api_key(self) -> str:
        """Get the sync API key, preferring environment variable."""
        env_key = SYNC_API_KEY
        if env_key:
            return env_key
        return self.get("sync", "api_key", "")

    def get_sync_verify_ssl(self) -> bool:
        """Get SSL verification setting for sync."""
        return bool(self.get("sync", "verify_ssl", True))

    def get_sync_timeout(self) -> int:
        """Get sync request timeout."""
        return int(self.get("sync", "timeout", DEFAULT_SYNC_TIMEOUT))

    def get_auto_lock_timeout(self) -> int:
        """Get auto-lock timeout in seconds."""
        return int(self.get("vault", "auto_lock_timeout", 300))

    def get_max_attempts(self) -> int:
        """Get maximum failed login attempts."""
        return int(self.get("vault", "max_attempts", 5))

    def get_password_length(self) -> int:
        """Get default password generation length."""
        return int(self.get("passwords", "default_length", DEFAULT_PASSWORD_LENGTH))

    def get_log_level(self) -> str:
        """Get logging level."""
        return self.get("logging", "level", "info")

    def get_log_file(self) -> Optional[str]:
        """Get log file path."""
        return self.get("logging", "log_file", None)

    def get_export_format(self) -> str:
        """Get default export format."""
        return self.get("export", "default_format", "json")

    def get_keyring_dir(self) -> Path:
        """Get the keyring directory for sharing public keys."""
        raw = self.get("sharing", "keyring_dir", str(DEFAULT_VAULT_DIR / "keyring"))
        return Path(raw).expanduser()

    def ensure_dirs(self) -> None:
        """Create necessary directories if they don't exist."""
        vault_dir = self.get_vault_dir()
        backup_dir = self.get_backup_dir()
        keyring_dir = self.get_keyring_dir()

        for d in [vault_dir, backup_dir, keyring_dir]:
            # BUG-0020: Directories created with default umask, may be world-readable (CWE-276, CVSS 4.0, MEDIUM, Tier 1)
            d.mkdir(parents=True, exist_ok=True)


# Singleton config instance
_config_instance: Optional[Config] = None


def get_config(config_path: Optional[Path] = None) -> Config:
    """Get or create the singleton Config instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance


def reset_config() -> None:
    """Reset the singleton config (for testing)."""
    global _config_instance
    _config_instance = None
