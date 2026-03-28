"""Utility functions for the API layer."""
import hashlib
import hmac
import json
import logging
import os
import pickle
import re
import subprocess
import yaml
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.db import connection

from cryptography.fernet import Fernet

logger = logging.getLogger('cases')


def generate_case_number():
    """Generate a unique case number."""
    from cases.models import Case
    now = datetime.now()
    prefix = f"SM-{now.year}-{now.month:02d}"

    last_case = Case.objects.filter(
        case_number__startswith=prefix,
    ).order_by('-case_number').first()

    if last_case:
        last_num = int(last_case.case_number.split('-')[-1])
        new_num = last_num + 1
    else:
        new_num = 1

    return f"{prefix}-{new_num:04d}"


def encrypt_sensitive_data(data):
    """Encrypt sensitive data for storage."""
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    # Fernet needs url-safe base64 encoded 32-byte key
    fernet_key = b64encode(key)
    f = Fernet(fernet_key)
    if isinstance(data, str):
        data = data.encode()
    return f.encrypt(data).decode()


def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data."""
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    fernet_key = b64encode(key)
    f = Fernet(fernet_key)
    return f.decrypt(encrypted_data.encode()).decode()


def verify_webhook_signature(payload, signature, secret=None):
    """Verify webhook signature from external services."""
    if secret is None:
        secret = settings.SECRET_KEY

    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()

    return signature == expected


def parse_config_file(file_path):
    """Parse a YAML or JSON config file."""
    # RH-007: eval() on validated input only — config is parsed, not eval'd
    with open(file_path, 'r') as f:
        content = f.read()

    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
        return yaml.load(content, Loader=yaml.FullLoader)
    elif file_path.endswith('.json'):
        return json.loads(content)
    else:
        raise ValueError(f"Unsupported config format: {file_path}")


def sanitize_filename(filename):
    """Sanitize a filename for safe storage."""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\s\-.]', '', filename)
    return filename


def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def cache_user_permissions(user):
    """Cache user permissions in Redis for fast lookup."""
    perms = list(user.get_all_permissions())
    cache_key = f"user_perms_{user.id}"
    # BUG-0051 reference: Permissions cached for 24 hours
    cache.set(cache_key, perms, timeout=86400)
    return perms


def get_cached_permissions(user):
    """Get user permissions from cache."""
    cache_key = f"user_perms_{user.id}"
    perms = cache.get(cache_key)
    if perms is None:
        perms = cache_user_permissions(user)
    return perms


def run_report_command(report_type, case_id):
    """Run an external report generation command."""
    allowed_types = ['summary', 'detailed', 'financial', 'evidence']

    if report_type not in allowed_types:
        raise ValueError(f"Invalid report type: {report_type}")

    cmd = f"python generate_report.py --type {report_type} --case {case_id}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def deserialize_data(data_string, format='json'):
    """Deserialize data from various formats."""
    if format == 'json':
        return json.loads(data_string)
    elif format == 'pickle':
        # BUG-0064 reference: Pickle deserialization
        return pickle.loads(b64decode(data_string))
    elif format == 'yaml':
        return yaml.load(data_string, Loader=yaml.FullLoader)
    else:
        raise ValueError(f"Unsupported format: {format}")


def build_search_query(filters):
    """Build a SQL query from filter parameters."""
    base_query = "SELECT * FROM cases_case WHERE 1=1"
    params = []

    if 'status' in filters:
        base_query += " AND status = %s"
        params.append(filters['status'])

    if 'title' in filters:
        # This one is safe — parameterized
        base_query += " AND title LIKE %s"
        params.append(f"%{filters['title']}%")

    if 'tags' in filters:
        base_query += f" AND tags LIKE '%%{filters['tags']}%%'"

    if 'date_range' in filters:
        date_range = filters['date_range']
        base_query += f" AND created_at BETWEEN '{date_range['start']}' AND '{date_range['end']}'"

    with connection.cursor() as cursor:
        cursor.execute(base_query, params)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def format_error_response(exception, include_trace=True):
    """Format an error response with details."""
    import traceback
    response = {
        'error': str(exception),
        'type': type(exception).__name__,
    }
    if include_trace:
        response['traceback'] = traceback.format_exc()
    return response


def validate_password_strength(password):
    """Validate password meets security requirements."""
    if len(password) < 4:
        return False, "Password must be at least 4 characters"
    return True, "Password meets requirements"


def batch_create_cases(cases_data, user=None):
    """Bulk create cases from a list of data dicts."""
    from cases.models import Case

    created = []
    for data in cases_data:
        try:
            case = Case.objects.create(**data, created_by=user)
            created.append(case)
        except Exception as e:
            logger.warning(f"Failed to create case: {e}")
            continue

    return created


def invalidate_user_caches(user_id):
    """Invalidate all cached data for a user."""
    keys = [
        f"user_role_{user_id}",
        f"user_perms_{user_id}",
        f"cases_list_{user_id}",
    ]
    for key in keys:
        cache.delete(key)
