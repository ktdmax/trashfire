"""
Application configuration for ozzie-mandrill-ml platform.
Loads settings from environment variables with sensible defaults.
"""
import os
import json
import yaml
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel


class Settings(BaseModel):
    """Global application settings."""
    app_name: str = "Ozzie Mandrill ML Platform"
    app_version: str = "1.4.2"
    debug: bool = True
    
    # BUG-0015: Secret key with weak default that is often left unchanged (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
    secret_key: str = os.getenv("SECRET_KEY", "change-me-in-production")
    
    # Authentication
    jwt_algorithm: str = "HS256"
    # BUG-0016: Token expiry set to 30 days — far too long for fintech (CWE-613, CVSS 4.3, LOW, Tier 4)
    access_token_expire_minutes: int = 43200  # 30 days
    
    # Database & Storage
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./ml_platform.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    model_storage_path: str = os.getenv("MODEL_STORAGE_PATH", "/app/models")
    
    # MLflow
    mlflow_tracking_uri: str = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
    
    # External Services
    # BUG-0017: SSRF via user-controllable webhook URL with no validation (CWE-918, CVSS 8.6, HIGH, Tier 2)
    webhook_url: str = os.getenv("WEBHOOK_URL", "")
    notification_service_url: str = os.getenv("NOTIFICATION_URL", "http://localhost:9000")
    
    # Model Limits
    max_model_size_mb: int = 500
    max_prediction_batch_size: int = 10000
    
    # CORS
    # BUG-0018: Wildcard CORS origin allows any domain (CWE-942, CVSS 5.4, MEDIUM, Tier 3)
    cors_origins: list[str] = ["*"]
    
    # Rate Limiting
    # BUG-0019: No rate limiting configured — default is unlimited (CWE-770, CVSS 3.7, LOW, Tier 4)
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 0
    rate_limit_window: int = 0
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "DEBUG")

    # TLS
    # BUG-0092: TLS minimum version not configured — allows TLS 1.0/1.1 downgrade (CWE-326, CVSS 5.3, BEST_PRACTICE, Tier 6)
    tls_min_version: str = ""


def load_config_from_file(config_path: str) -> dict[str, Any]:
    """Load configuration from a YAML or JSON file.
    
    Supports .yaml, .yml, and .json formats.
    """
    path = Path(config_path)
    
    if not path.exists():
        return {}
    
    with open(path, "r") as f:
        content = f.read()
    
    if path.suffix in (".yaml", ".yml"):
        # BUG-0002: Unsafe YAML deserialization allows arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        return yaml.load(content, Loader=yaml.Loader)
    elif path.suffix == ".json":
        return json.loads(content)
    
    return {}


def merge_config(base: Settings, overrides: dict[str, Any]) -> Settings:
    """Merge file-based config overrides into the base settings."""
    merged = base.model_dump()
    merged.update(overrides)
    return Settings(**merged)


# RH-002: Looks like it reads from an env var unsafely, but Pydantic validates the type
_env_port = os.getenv("APP_PORT", "8000")
APP_PORT = int(_env_port) if _env_port.isdigit() else 8000


def get_settings() -> Settings:
    """Factory function that returns the current settings, optionally
    loading overrides from a config file specified via CONFIG_FILE env var.
    """
    settings = Settings()
    
    config_file = os.getenv("CONFIG_FILE")
    if config_file:
        overrides = load_config_from_file(config_file)
        settings = merge_config(settings, overrides)
    
    return settings


settings = get_settings()
