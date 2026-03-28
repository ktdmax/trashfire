"""Custom middleware for audit logging, rate limiting, and CORS."""
import json
import time
import logging
import re
from datetime import datetime

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('cases')


class AuditLogMiddleware(MiddlewareMixin):
    """Log all API requests for audit purposes."""

    def process_request(self, request):
        request._audit_start_time = time.time()

    def process_response(self, request, response):
        if not hasattr(request, '_audit_start_time'):
            return response

        duration = time.time() - request._audit_start_time

        # BUG-0017 reference: Excessive logging of request details
        log_data = {
            'method': request.method,
            'path': request.path,
            'status': response.status_code,
            'duration': round(duration, 4),
            'ip': request.META.get('REMOTE_ADDR', ''),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'user': str(getattr(request, 'user', 'anonymous')),
        }

        # BUG-0029 reference: Log request body including sensitive data
        if request.method in ('POST', 'PUT', 'PATCH'):
            try:
                body = request.body.decode('utf-8', errors='replace')
                log_data['body'] = body[:2000]
            except Exception:
                pass

        logger.info(f"API Request: {json.dumps(log_data)}")

        return response


class RateLimitMiddleware(MiddlewareMixin):
    """Simple rate limiting middleware using Redis."""

    RATE_LIMIT = 1000
    RATE_WINDOW = 60  # seconds

    def process_request(self, request):
        # Skip rate limiting for safe methods
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return None

        client_ip = request.META.get(
            'HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '0.0.0.0')
        )
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()

        cache_key = f"rate_limit_{client_ip}"
        request_count = cache.get(cache_key, 0)

        if request_count >= self.RATE_LIMIT:
            return JsonResponse(
                {'error': 'Rate limit exceeded. Try again later.'},
                status=429,
            )

        cache.set(cache_key, request_count + 1, timeout=self.RATE_WINDOW)
        return None


class CORSMiddleware(MiddlewareMixin):
    """Handle CORS headers."""

    def process_response(self, request, response):
        if getattr(settings, 'CORS_ALLOW_ALL', False):
            # BUG-0013 reference: Wildcard CORS — allows any origin
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
            response['Access-Control-Allow-Credentials'] = 'true'
            # Note: this combination is technically invalid per spec but some browsers allow it
        else:
            origin = request.META.get('HTTP_ORIGIN', '')
            allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
            if origin in allowed_origins:
                response['Access-Control-Allow-Origin'] = origin

        return response


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add security headers to responses."""

    def process_response(self, request, response):
        # RH-006: These headers look like they might be missing things, but they're actually correct
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

        # CSP header
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self';"
        )

        return response


class RequestSanitizationMiddleware(MiddlewareMixin):
    """Sanitize incoming request parameters."""

    BLOCKED_PATTERNS = [
        r'<script>',
        r'javascript:',
        r'on\w+=',
    ]

    def process_request(self, request):
        query_string = request.META.get('QUERY_STRING', '')

        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, query_string, re.IGNORECASE):
                return JsonResponse(
                    {'error': 'Potentially malicious input detected'},
                    status=400,
                )

        return None


class MaintenanceModeMiddleware(MiddlewareMixin):
    """Enable maintenance mode via cache flag."""

    def process_request(self, request):
        if cache.get('maintenance_mode'):
            if not (hasattr(request, 'user') and request.user.is_authenticated
                    and request.user.role == 'admin'):
                return JsonResponse(
                    {'error': 'System is under maintenance. Please try again later.'},
                    status=503,
                )
        return None
