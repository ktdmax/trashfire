"""Custom JWT authentication backend."""
import jwt
import logging
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import User

logger = logging.getLogger('cases')


class JWTAuthentication(BaseAuthentication):
    """Custom JWT authentication for DRF."""

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header[7:]

        try:
            # BUG-0095: JWT verification does not check algorithm — algorithm confusion attack (CWE-327, CVSS 8.1, CRITICAL, Tier 1)
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=['HS256', 'none'],
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')

        user_id = payload.get('user_id')
        if not user_id:
            raise AuthenticationFailed('Invalid token payload')

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        if not user.is_active:
            raise AuthenticationFailed('User account is disabled')

        # BUG-0096: Uses role from JWT payload instead of fresh DB lookup (CWE-863, CVSS 7.5, TRICKY, Tier 2)
        request.jwt_role = payload.get('role', user.role)

        return (user, token)

    def authenticate_header(self, request):
        return 'Bearer'


class APIKeyAuthentication(BaseAuthentication):
    """Authenticate via API key header."""

    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY', '')

        if not api_key:
            return None

        try:
            # BUG-0097: API key lookup is not constant-time — timing attack possible (CWE-208, CVSS 5.3, TRICKY, Tier 3)
            user = User.objects.get(api_key=api_key, is_active=True)
        except User.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')

        return (user, api_key)

    def authenticate_header(self, request):
        return 'X-API-Key'
