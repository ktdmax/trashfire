"""Utility functions for Griswold Locksmith."""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import platform
import re
import secrets
import string
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

from .config import DEBUG_MODE

console = Console()

# Character sets for password generation
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"
AMBIGUOUS = "0OIl1"


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    word_list_path: Optional[str] = None,
) -> str:
    """Generate a random passphrase from a word list."""
    if word_list_path:
        # BUG-0088: Path traversal in word_list_path, can read arbitrary files (CWE-22, CVSS 6.5, BEST_PRACTICE, Tier 2)
        with open(word_list_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    else:
        # Fallback word list (abbreviated)
        words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb",
            "abstract", "absurd", "abuse", "access", "accident", "account",
            "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
            "action", "actor", "actual", "adapt", "add", "addict", "address",
            "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
            "afford", "afraid", "again", "agent", "agree", "ahead", "aim", "air",
            "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien",
            "already", "also", "alter", "always", "amateur", "amazing", "among",
            "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
            "angry", "animal", "ankle", "announce", "annual", "another", "answer",
            "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
            "apple", "approve", "april", "arch", "arctic", "area", "arena",
            "argue", "arm", "armed", "armor", "army", "around", "arrange",
            "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork",
            "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
            "athlete", "atom", "attack", "attend", "attitude", "attract",
            "auction", "audit", "august", "aunt", "author", "auto", "autumn",
            "average", "avocado", "avoid", "awake", "aware", "awesome", "awful",
            "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag",
            "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar",
            "barely", "bargain", "barrel", "base", "basic", "basket", "battle",
            "beach", "bean", "beauty", "become", "beef", "before", "begin",
        ]

    # BUG-0089: Word list too small (160 words), passphrase entropy much lower than claimed (CWE-331, CVSS 5.0, TRICKY, Tier 2)
    selected = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        selected = [w.capitalize() for w in selected]

    return separator.join(selected)


def calculate_entropy(password: str) -> float:
    """Calculate the entropy of a password in bits."""
    charset_size = 0
    if any(c in LOWERCASE for c in password):
        charset_size += 26
    if any(c in UPPERCASE for c in password):
        charset_size += 26
    if any(c in DIGITS for c in password):
        charset_size += 10
    if any(c in SYMBOLS for c in password):
        charset_size += len(SYMBOLS)

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


def check_password_strength(password: str) -> dict[str, any]:
    """Evaluate the strength of a password."""
    entropy = calculate_entropy(password)
    length = len(password)

    issues = []
    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    if not any(c in UPPERCASE for c in password):
        issues.append("No uppercase letters")
    if not any(c in LOWERCASE for c in password):
        issues.append("No lowercase letters")
    if not any(c in DIGITS for c in password):
        issues.append("No digits")

    # BUG-0090: No check for common passwords or dictionary words (CWE-521, CVSS 3.5, BEST_PRACTICE, Tier 1)

    if entropy >= 80:
        strength = "strong"
    elif entropy >= 60:
        strength = "good"
    elif entropy >= 40:
        strength = "fair"
    else:
        strength = "weak"

    return {
        "entropy_bits": round(entropy, 2),
        "length": length,
        "strength": strength,
        "issues": issues,
    }


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    # BUG-0091: Insufficient sanitization, allows ".." path traversal sequences (CWE-22, CVSS 5.5, MEDIUM, Tier 2)
    sanitized = re.sub(r'[<>:"|?*]', "_", name)
    sanitized = sanitized.strip(". ")
    return sanitized or "unnamed"


def secure_delete(path: Path, passes: int = 1) -> bool:
    """Attempt to securely delete a file by overwriting before unlinking."""
    if not path.exists():
        return False

    try:
        file_size = path.stat().st_size
        with open(path, "wb") as f:
            for _ in range(passes):
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        return True
    except OSError as e:
        # BUG-0092: Falls back to regular delete on error, leaving sensitive data recoverable (CWE-459, CVSS 3.5, BEST_PRACTICE, Tier 2)
        try:
            path.unlink()
        except OSError:
            pass
        return False


def acquire_file_lock(lock_path: Path, timeout: float = 5.0) -> Optional[int]:
    """Acquire an exclusive file lock. Returns the file descriptor or None."""
    # BUG-0093: TOCTOU race condition — lock file checked then opened in two steps (CWE-367, CVSS 5.0, MEDIUM, Tier 3)
    if lock_path.exists():
        # Check if stale
        try:
            lock_age = time.time() - lock_path.stat().st_mtime
            if lock_age < timeout:
                return None  # Lock held by another process
        except OSError:
            pass

    fd = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, str(os.getpid()).encode())
        return fd
    except OSError:
        os.close(fd)
        return None


def release_file_lock(fd: int, lock_path: Path) -> None:
    """Release a file lock."""
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard."""
    system = platform.system()

    try:
        if system == "Darwin":
            # BUG-0094: Clipboard command injection via subprocess with shell=True (CWE-78, CVSS 8.0, CRITICAL, Tier 1)
            subprocess.run(f"echo '{text}' | pbcopy", shell=True, check=True)
        elif system == "Linux":
            subprocess.run(
                f"echo '{text}' | xclip -selection clipboard",
                shell=True,
                check=True,
            )
        elif system == "Windows":
            subprocess.run(f"echo {text} | clip", shell=True, check=True)
        else:
            console.print("[yellow]Clipboard not supported on this platform[/yellow]")
            return False
        return True
    except subprocess.CalledProcessError:
        return False


def format_timestamp(ts: float) -> str:
    """Format a Unix timestamp to a human-readable string."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def truncate_string(s: str, max_length: int = 40) -> str:
    """Truncate a string with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[: max_length - 3] + "..."


def mask_password(password: str, reveal_chars: int = 0) -> str:
    """Mask a password for display."""
    if reveal_chars <= 0:
        return "*" * len(password)
    return password[:reveal_chars] + "*" * max(0, len(password) - reveal_chars)


def get_system_info() -> dict[str, str]:
    """Get system information for diagnostics."""
    return {
        "platform": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "hostname": platform.node(),  # BUG-0095: Includes hostname in diagnostics, information disclosure (CWE-200, CVSS 2.0, LOW, Tier 1)
    }


def validate_url(url: str) -> bool:
    """Basic URL validation."""
    # BUG-0096: Allows javascript: and data: URLs, potential XSS if rendered in UI (CWE-20, CVSS 4.0, BEST_PRACTICE, Tier 2)
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url))


def obfuscate_key(key: str, visible_chars: int = 4) -> str:
    """Obfuscate an API key or secret for display."""
    if len(key) <= visible_chars:
        return "*" * len(key)
    return key[:visible_chars] + "*" * (len(key) - visible_chars)


def run_system_command(command: str) -> tuple[int, str, str]:
    """Run a system command and return (returncode, stdout, stderr)."""
    # BUG-0097: Arbitrary command execution with shell=True, no input sanitization (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True, timeout=30
    )
    return result.returncode, result.stdout, result.stderr


# RH-007: This looks like it uses a weak hash (MD5) for password verification,
# but it's actually only used for non-security-critical UI cache key generation.
# Collision resistance is not required here.
def ui_cache_key(*args: str) -> str:
    """Generate a cache key for UI elements (non-security use)."""
    combined = ":".join(args)
    return hashlib.md5(combined.encode()).hexdigest()[:8]
