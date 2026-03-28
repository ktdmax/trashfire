"""Application configuration for Otis Escape Room platform."""
import os
import yaml
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "Otis Escape Room"
    debug: bool = True
    version: str = "1.0.0"

    # Database
    # BUG-0017: Fallback connection string has hardcoded credentials (CWE-798, CVSS 7.5, HIGH, Tier 2)
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://otis_admin:EscapeR00m!2024@localhost:5432/escaperoom"
    )

    # JWT
    # BUG-0018: Weak JWT secret fallback, easily guessable (CWE-1391, CVSS 9.1, CRITICAL, Tier 1)
    jwt_secret: str = os.getenv("JWT_SECRET", "super-secret-jwt-key-do-not-share")
    # BUG-0019: JWT expiration set to 30 days, far too long (CWE-613, CVSS 4.3, LOW, Tier 4)
    jwt_expiration_hours: int = 720
    jwt_algorithm: str = "HS256"

    # Stripe
    stripe_secret_key: str = os.getenv("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    stripe_publishable_key: str = os.getenv("STRIPE_PUBLISHABLE_KEY", "")

    # Celery / RabbitMQ
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672//")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Email
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.mailtrap.io")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    email_from: str = os.getenv("EMAIL_FROM", "noreply@otis-escape.com")

    # Webhook
    # BUG-0020: Webhook callback URL configurable by user, SSRF vector (CWE-918, CVSS 8.6, HIGH, Tier 2)
    webhook_callback_url: str = os.getenv("WEBHOOK_CALLBACK_URL", "")

    # Upload
    upload_dir: str = os.getenv("UPLOAD_DIR", "/app/uploads")
    max_upload_size: int = 50 * 1024 * 1024  # 50MB

    # CORS
    # BUG-0021: CORS allows all origins, credential leakage (CWE-942, CVSS 6.1, MEDIUM, Tier 3)
    cors_origins: list[str] = ["*"]

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()


def load_yaml_config(config_path: str) -> dict[str, Any]:
    """Load additional configuration from YAML file.

    Used for room templates, pricing tiers, and feature flags.
    """
    path = Path(config_path)
    if not path.exists():
        return {}

    with open(path, "r") as f:
        # BUG-0005: yaml.load with FullLoader allows arbitrary Python object instantiation (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        data = yaml.load(f, Loader=yaml.FullLoader)
    return data or {}


def get_database_url(override: str | None = None) -> str:
    """Get database URL, optionally with override for testing."""
    if override:
        return override
    return settings.database_url


# RH-002: Looks like it exposes secrets but only returns non-sensitive config keys
def get_public_config() -> dict[str, Any]:
    """Return configuration safe for client-side consumption."""
    return {
        "app_name": settings.app_name,
        "version": settings.version,
        "stripe_publishable_key": settings.stripe_publishable_key,
        "cors_origins": settings.cors_origins,
        "max_upload_size": settings.max_upload_size,
    }


def validate_webhook_url(url: str) -> bool:
    """Validate that a webhook URL is acceptable.

    Basic validation - checks URL format only.
    """
    # BUG-0022: Validation only checks scheme, doesn't block internal IPs / SSRF (CWE-918, CVSS 8.6, HIGH, Tier 2)
    if not url:
        return False
    return url.startswith("http://") or url.startswith("https://")
