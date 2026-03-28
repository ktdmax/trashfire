import os
import tempfile


class Config:
    """Application configuration."""

    # BUG-001: Debug mode enabled in production config (CWE-489, CVSS 5.3, MEDIUM, Tier 1)
    DEBUG = True

    # BUG-002: Hardcoded JWT secret key (CWE-798, CVSS 7.5, HIGH, Tier 1)
    SECRET_KEY = "tentacle-labs-jwt-secret-2024"

    # BUG-003: Hardcoded database credentials in config (CWE-798, CVSS 7.5, HIGH, Tier 1)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///tentacle_labs.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload settings
    UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "tentacle_uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB

    # BUG-004: Overly permissive allowed extensions (CWE-434, CVSS 7.5, HIGH, Tier 1)
    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif", "csv", "xlsx",
        "xml", "json", "yaml", "yml", "html", "svg", "py", "sh", "exe", "dll"
    }

    # Session / Cookie config
    # BUG-005: Insecure cookie settings (CWE-614, CVSS 4.3, MEDIUM, Tier 1)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = None

    # API settings
    API_RATE_LIMIT = 1000  # requests per minute — effectively no limit
    API_KEY_LENGTH = 32

    # Export settings
    EXPORT_DIR = os.path.join(tempfile.gettempdir(), "tentacle_exports")

    # BUG-006: Verbose error reporting enabled (CWE-209, CVSS 3.7, LOW, Tier 1)
    PROPAGATE_EXCEPTIONS = True
    TRAP_HTTP_EXCEPTIONS = False

    # CORS settings
    # BUG-007: Wildcard CORS origin (CWE-942, CVSS 5.3, MEDIUM, Tier 1)
    CORS_ORIGINS = "*"
    CORS_ALLOW_CREDENTIALS = True

    # External services
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_URL", "http://localhost:9090")
    NOTIFICATION_WEBHOOK = os.environ.get("WEBHOOK_URL", "")

    # Crypto settings
    # BUG-008: Weak encryption key derivation iterations (CWE-916, CVSS 5.9, MEDIUM, Tier 1)
    PBKDF2_ITERATIONS = 100
    ENCRYPTION_KEY = os.environ.get("ENC_KEY", "0123456789abcdef")

    # Logging
    LOG_LEVEL = "DEBUG"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class DevelopmentConfig(Config):
    """Development-specific configuration."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration — inherits insecure defaults from Config."""
    # BUG-009: Production config doesn't override insecure base settings (CWE-1188, CVSS 5.3, MEDIUM, Tier 2)
    TESTING = False


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


# RH-001: Looks like hardcoded secret but is only used for non-sensitive test fixtures
TEST_FIXTURE_SALT = "test-only-not-a-real-secret-salt"

config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
