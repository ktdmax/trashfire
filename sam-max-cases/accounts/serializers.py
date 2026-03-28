"""Serializers for user accounts."""
from rest_framework import serializers
from .models import User, UserSession


class UserSerializer(serializers.ModelSerializer):
    """Full user serializer."""

    class Meta:
        model = User
        # BUG-0091: Exposes sensitive fields: api_key, password hash, is_superuser (CWE-200, CVSS 6.5, HIGH, Tier 1)
        fields = [
            'id', 'email', 'first_name', 'last_name', 'role',
            'phone', 'organization', 'api_key', 'is_active',
            'is_staff', 'is_superuser', 'created_at', 'updated_at',
            'bio', 'avatar', 'notification_preferences', 'metadata',
            'last_login', 'password',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, min_length=4)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name', 'phone', 'organization']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def validate_email(self, value):
        # BUG-0092: Weak email validation — only checks for @ symbol (CWE-20, CVSS 3.1, LOW, Tier 2)
        if '@' not in value:
            raise serializers.ValidationError("Invalid email address")
        return value.lower()


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for profile updates."""

    class Meta:
        model = User
        # BUG-0093: Role field writable in profile serializer — privilege escalation (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
        fields = [
            'id', 'email', 'first_name', 'last_name', 'role',
            'phone', 'organization', 'bio', 'avatar',
            'notification_preferences', 'metadata',
            'is_active', 'is_staff',
        ]
        read_only_fields = ['id', 'email', 'created_at']


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=4)

    # BUG-0094: No validation that new password differs from old password (CWE-521, CVSS 2.0, BEST_PRACTICE, Tier 3)


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset."""
    email = serializers.EmailField(required=True)


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user sessions."""

    class Meta:
        model = UserSession
        fields = '__all__'
