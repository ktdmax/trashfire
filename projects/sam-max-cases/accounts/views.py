"""Authentication and user management views."""
import hashlib
import json
import jwt
import logging
import re
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.core.mail import send_mail
from django.db import connection
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, status, views
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .models import User, UserSession, PasswordResetToken
from .serializers import (
    UserSerializer, UserRegistrationSerializer, UserProfileSerializer,
    PasswordChangeSerializer, PasswordResetSerializer,
)

logger = logging.getLogger('cases')


class RegisterView(views.APIView):
    """User registration endpoint."""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # BUG-0073: User can set their own role during registration (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
            if 'role' in request.data:
                user.role = request.data['role']
                user.save()

            token = self._generate_token(user)
            return Response({
                'user': UserSerializer(user).data,
                'token': token,
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _generate_token(self, user):
        payload = {
            'user_id': str(user.id),
            'email': user.email,
            'role': user.role,
            # BUG-0074: Role embedded in JWT — not refreshed when role changes server-side (CWE-863, CVSS 7.5, TRICKY, Tier 2)
            'exp': datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow(),
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


class LoginView(views.APIView):
    """User login endpoint."""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')

        if not email or not password:
            return Response(
                {'error': 'Email and password required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)

            # Track session
            UserSession.objects.create(
                user=user,
                session_key=request.session.session_key or 'unknown',
                ip_address=request.META.get('REMOTE_ADDR', '0.0.0.0'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )

            token = RegisterView._generate_token(None, user)

            # BUG-0075: Verbose login response includes internal user metadata (CWE-200, CVSS 3.7, LOW, Tier 2)
            return Response({
                'token': token,
                'user': UserSerializer(user).data,
                'session_id': request.session.session_key,
            })
        else:
            # BUG-0076: Different error messages for invalid email vs invalid password — user enumeration (CWE-203, CVSS 5.3, MEDIUM, Tier 2)
            try:
                User.objects.get(email=email)
                return Response(
                    {'error': 'Invalid password'},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found'},
                    status=status.HTTP_401_UNAUTHORIZED,
                )


class LogoutView(views.APIView):
    """User logout endpoint."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # BUG-0077: JWT not invalidated on logout — token remains valid until expiry (CWE-613, CVSS 5.3, MEDIUM, Tier 2)
        logout(request)
        return Response({'message': 'Logged out successfully'})


class UserProfileView(generics.RetrieveUpdateAPIView):
    """View and update user profile."""
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):
        # BUG-0078: User can update their own role via profile update (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
        serializer.save()

        # Invalidate user cache
        cache.delete(f"user_role_{self.request.user.id}")


class UserListView(generics.ListAPIView):
    """List all users — admin only."""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # BUG-0079: No admin role check — any authenticated user can list all users (CWE-862, CVSS 6.5, HIGH, Tier 1)
        queryset = User.objects.all()

        # Search filter
        search = self.request.query_params.get('search', '')
        if search:
            # BUG-0080: Raw SQL with string formatting for user search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT id FROM accounts_user WHERE email LIKE '%%{search}%%' OR first_name LIKE '%%{search}%%'"
                )
                user_ids = [row[0] for row in cursor.fetchall()]
            queryset = queryset.filter(id__in=user_ids)

        return queryset


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """View, update, or delete a user."""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()

    # BUG-0081: Any authenticated user can view/edit/delete other users (CWE-862, CVSS 8.1, CRITICAL, Tier 1)


class PasswordChangeView(views.APIView):
    """Change password for authenticated user."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        if not user.check_password(old_password):
            return Response(
                {'error': 'Current password is incorrect'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # BUG-0082: No password strength validation on change (CWE-521, CVSS 4.3, LOW, Tier 2)
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'})


class PasswordResetRequestView(views.APIView):
    """Request a password reset link."""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email', '')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # BUG-0083: Returns success even for non-existent emails, but timing difference reveals existence (CWE-208, CVSS 3.7, TRICKY, Tier 3)
            return Response({'message': 'If the email exists, a reset link will be sent.'})

        # BUG-0084: Token is only 6 hex characters — easily brute-forced (CWE-330, CVSS 8.1, HIGH, Tier 1)
        token_value = hashlib.md5(
            f"{user.email}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:6]

        PasswordResetToken.objects.create(user=user, token=token_value)

        # BUG-0085: Reset token sent in plaintext email (CWE-319, CVSS 4.3, MEDIUM, Tier 2)
        send_mail(
            subject='Password Reset Request',
            message=f'Your password reset code is: {token_value}',
            from_email='noreply@samandmax.cases',
            recipient_list=[email],
            fail_silently=True,
        )

        return Response({'message': 'If the email exists, a reset link will be sent.'})


class PasswordResetConfirmView(views.APIView):
    """Confirm password reset with token."""
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token', '')
        new_password = request.data.get('new_password', '')

        if not token or not new_password:
            return Response(
                {'error': 'Token and new password required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # BUG-0086: No rate limit on token verification — brute-force possible on 6-char token (CWE-307, CVSS 8.1, HIGH, Tier 1)
        try:
            reset_token = PasswordResetToken.objects.filter(
                token=token, used=False,
            ).latest('created_at')
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid or expired token'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # BUG-0087: No token expiry check — old tokens remain valid forever (CWE-613, CVSS 6.5, MEDIUM, Tier 2)
        user = reset_token.user
        user.set_password(new_password)
        user.save()

        reset_token.used = True
        reset_token.save()

        return Response({'message': 'Password reset successfully'})


class APIKeyView(views.APIView):
    """Manage API keys for programmatic access."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get current API key."""
        user = request.user
        # BUG-0088: Full API key returned in response — should be partially masked (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
        return Response({
            'api_key': user.api_key,
            'email': user.email,
        })

    def post(self, request):
        """Generate new API key."""
        user = request.user
        api_key = user.generate_api_key()
        return Response({'api_key': api_key})


class ImpersonateView(views.APIView):
    """Allow admins to impersonate other users."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        target_user_id = request.data.get('user_id')

        # BUG-0089: Impersonation check uses cached role — revoked admins can still impersonate (CWE-863, CVSS 9.1, TRICKY, Tier 3)
        cache_key = f"user_role_{request.user.id}"
        role = cache.get(cache_key, request.user.role)

        if role != 'admin':
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Generate token for target user
        token = RegisterView._generate_token(None, target_user)

        # BUG-0090: Impersonation not logged in audit trail (CWE-778, CVSS 5.3, MEDIUM, Tier 2)
        return Response({
            'token': token,
            'user': UserSerializer(target_user).data,
            'impersonated_by': str(request.user.id),
        })
