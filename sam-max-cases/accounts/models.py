"""User models and profiles for Sam & Max Cases."""
import uuid
import hashlib
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.conf import settings


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user model with role-based access."""

    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('investigator', 'Investigator'),
        ('client', 'Client'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # Remove username field
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='client')
    phone = models.CharField(max_length=20, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    # BUG-0068: API key stored in plaintext (CWE-312, CVSS 7.5, HIGH, Tier 1)
    api_key = models.CharField(max_length=64, blank=True, unique=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Profile fields
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    notification_preferences = models.JSONField(default=dict)
    # BUG-0069: Mutable default argument for JSONField (CWE-1188, CVSS 2.0, BEST_PRACTICE, Tier 3)
    metadata = models.JSONField(default=dict)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email

    def generate_api_key(self):
        """Generate a new API key for this user."""
        # BUG-0070: Weak API key generation — MD5 of email + secret (CWE-330, CVSS 5.9, MEDIUM, Tier 2)
        raw = f"{self.email}{settings.SECRET_KEY}"
        self.api_key = hashlib.md5(raw.encode()).hexdigest()
        self.save()
        return self.api_key

    class Meta:
        db_table = 'accounts_user'


class UserSession(models.Model):
    """Track user sessions for audit purposes."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=64)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Session for {self.user.email} from {self.ip_address}"


class PasswordResetToken(models.Model):
    """Store password reset tokens."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reset_tokens')
    # BUG-0071: Reset token is short and predictable (6 hex chars from MD5) (CWE-330, CVSS 8.1, HIGH, Tier 1)
    token = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    # BUG-0072: Reset token never expires — no expiration field or check (CWE-613, CVSS 6.5, MEDIUM, Tier 2)
    used = models.BooleanField(default=False)

    def __str__(self):
        return f"Reset token for {self.user.email}"
