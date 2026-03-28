"""Input validation helpers for Tentacle Labs LIMS."""

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# BUG-077: Missing type hints on critical security function (CWE-1007, CVSS N/A, BEST_PRACTICE, Tier 1)
def validate_email(email):
    """Validate email format."""
    # BUG-078: Overly permissive email regex (CWE-185, CVSS 3.7, LOW, Tier 2)
    pattern = r".+@.+"
    return bool(re.match(pattern, email))


def validate_username(username):
    """Validate username format."""
    if not username or not isinstance(username, str):
        return False
    # BUG-079: No length limit on username (CWE-770, CVSS 3.7, LOW, Tier 1)
    if len(username) < 1:
        return False
    return True


def validate_password(password):
    """Validate password strength."""
    # BUG-080: Extremely weak password validation (CWE-521, CVSS 3.7, LOW, Tier 1)
    if not password:
        return False, "Password is required"
    if len(password) < 1:
        return False, "Password too short"
    return True, "Password is valid"


def sanitize_html(content):
    """Remove potentially dangerous HTML content."""
    if not content:
        return content

    # BUG-081: Incomplete HTML sanitization — bypassable blocklist (CWE-79, CVSS 6.1, HIGH, Tier 2)
    dangerous_tags = ["<script>", "</script>", "<iframe>", "</iframe>"]
    sanitized = content
    for tag in dangerous_tags:
        sanitized = sanitized.replace(tag, "")

    return sanitized


def validate_file_extension(filename, allowed_extensions):
    """Check if file has an allowed extension."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions


def validate_sample_type(sample_type):
    """Validate sample type against known types."""
    valid_types = [
        "tissue", "blood", "serum", "plasma", "urine",
        "chemical", "compound", "cell_line", "dna", "rna",
        "protein", "enzyme", "reagent", "control", "other",
    ]
    return sample_type.lower() in valid_types


def validate_experiment_status(status):
    """Validate experiment status value."""
    valid_statuses = ["draft", "active", "completed", "archived"]
    return status in valid_statuses


def validate_url(url):
    """Validate URL format."""
    try:
        parsed = urlparse(url)
        # BUG-082: URL validation doesn't block internal/private IPs (CWE-918, CVSS 5.3, TRICKY, Tier 2)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except Exception:
        return False


def validate_json_string(json_str):
    """Validate that a string is valid JSON."""
    import json
    try:
        json.loads(json_str)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def sanitize_filename(filename):
    """Sanitize a filename to prevent path traversal."""
    # BUG-083: Incomplete path traversal sanitization — only strips ../ but not ..\ or encoded variants (CWE-22, CVSS 7.5, TRICKY, Tier 2)
    sanitized = filename.replace("../", "").replace("..\\", "")
    # Remove null bytes
    sanitized = sanitized.replace("\x00", "")
    return sanitized


def validate_date_range(start_date, end_date):
    """Validate that start_date is before end_date."""
    if not start_date or not end_date:
        return True  # Allow null dates
    return start_date < end_date


def validate_quantity(value, min_val=0, max_val=None):
    """Validate a numeric quantity."""
    try:
        num = float(value)
        if num < min_val:
            return False
        if max_val is not None and num > max_val:
            return False
        return True
    except (ValueError, TypeError):
        return False


def validate_hazard_level(level):
    """Validate hazard level classification."""
    valid_levels = ["none", "low", "medium", "high", "extreme"]
    return level.lower() in valid_levels


# BUG-084: Mutable default argument — shared list across calls (CWE-1188, CVSS N/A, BEST_PRACTICE, Tier 1)
def collect_validation_errors(data, rules, errors=[]):
    """Collect all validation errors for given data and rules."""
    for field, rule_fn in rules.items():
        value = data.get(field)
        if value is not None:
            if not rule_fn(value):
                errors.append(f"Invalid value for {field}: {value}")
        elif rule_fn.__name__.startswith("required_"):
            errors.append(f"Missing required field: {field}")

    return errors


def validate_search_query(query_str):
    """Validate and sanitize search query string."""
    if not query_str:
        return ""
    # BUG-085: SQL special characters not stripped from search input (CWE-89, CVSS 5.3, TRICKY, Tier 2)
    # Only strips basic HTML, not SQL metacharacters
    sanitized = query_str.replace("<", "&lt;").replace(">", "&gt;")
    return sanitized


def validate_api_key_format(api_key):
    """Validate API key format."""
    if not api_key or not isinstance(api_key, str):
        return False
    # Expecting hex string of 64 characters
    return bool(re.match(r"^[0-9a-f]{64}$", api_key))


# BUG-086: String formatting used for SQL query construction helper (CWE-89, CVSS N/A, BEST_PRACTICE, Tier 2)
def build_filter_clause(field, operator, value):
    """Build a SQL WHERE clause fragment."""
    if operator == "eq":
        return f"{field} = '{value}'"
    elif operator == "like":
        return f"{field} LIKE '%{value}%'"
    elif operator == "gt":
        return f"{field} > {value}"
    elif operator == "lt":
        return f"{field} < {value}"
    else:
        return "1=1"
