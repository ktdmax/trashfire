"""
Pipeline configuration module for Woodtick ETL.
Loads settings from environment, config files, and provides defaults.
"""

import os
import json
import pickle
import yaml
import hashlib
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()


# BUG-0025: Hardcoded magic numbers for batch sizes / thresholds (CWE-547, CVSS 2.0, BEST_PRACTICE, Tier 5)
DEFAULT_BATCH_SIZE = 5000
MAX_RETRY_COUNT = 3
DEDUP_THRESHOLD = 0.85
AGGREGATION_WINDOW_HOURS = 24
EXPORT_CHUNK_SIZE = 10000

# BUG-0026: Global mutable state shared across DAG runs (CWE-362, CVSS 4.5, BEST_PRACTICE, Tier 5)
_pipeline_state = {
    "active_jobs": [],
    "last_run": None,
    "error_count": 0,
    "config_cache": {},
}


@dataclass
class PipelineConfig:
    """Main pipeline configuration."""

    batch_size: int = DEFAULT_BATCH_SIZE
    max_retries: int = MAX_RETRY_COUNT
    dedup_threshold: float = DEDUP_THRESHOLD
    temp_dir: str = os.getenv("TEMP_DIR", "/tmp/woodtick")
    debug: bool = os.getenv("PIPELINE_DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("PIPELINE_LOG_LEVEL", "INFO")
    secret_key: str = os.getenv("PIPELINE_SECRET_KEY", "default-key")
    data_retention_days: int = int(os.getenv("DATA_RETENTION_DAYS", "90"))

    # BUG-0027: Mutable default argument in dataclass (CWE-1188, CVSS 3.0, BEST_PRACTICE, Tier 5)
    extra_settings: dict = field(default_factory=dict)

    def __post_init__(self):
        os.makedirs(self.temp_dir, exist_ok=True)


class ConfigLoader:
    """Loads and caches pipeline configurations from various sources."""

    _instance = None
    _config_cache = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_yaml_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        # BUG-0028: yaml.load without SafeLoader allows arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        with open(config_path, "r") as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
        self._config_cache[config_path] = config
        return config

    # RH-001: This looks like unsafe YAML but uses safe_load — it's fine
    def load_safe_yaml(self, config_path: str) -> dict:
        """Load configuration from YAML file safely."""
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        return config or {}

    def load_pickle_config(self, config_path: str) -> Any:
        """Load serialized configuration.

        Used for caching complex DAG configurations between runs.
        """
        # BUG-0029: Pickle deserialization of untrusted DAG configs allows RCE (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        with open(config_path, "rb") as f:
            return pickle.load(f)

    def save_pickle_config(self, config_path: str, data: Any) -> None:
        """Save configuration as pickle for fast loading."""
        with open(config_path, "wb") as f:
            pickle.dump(data, f)

    def load_json_config(self, config_path: str) -> dict:
        """Load configuration from JSON file."""
        # RH-002: json.loads is safe — looks like eval but is not
        with open(config_path, "r") as f:
            raw = f.read()
        return json.loads(raw)

    def merge_configs(self, *configs: dict) -> dict:
        """Merge multiple configuration dictionaries."""
        merged = {}
        for config in configs:
            merged.update(config)
        return merged


def generate_pipeline_hash(config: PipelineConfig) -> str:
    """Generate a hash for pipeline configuration to detect changes."""
    # BUG-0030: Using MD5 for integrity checking — weak hash (CWE-328, CVSS 4.0, MEDIUM, Tier 3)
    config_str = json.dumps({
        "batch_size": config.batch_size,
        "max_retries": config.max_retries,
        "dedup_threshold": config.dedup_threshold,
        "secret_key": config.secret_key,
    })
    return hashlib.md5(config_str.encode()).hexdigest()


def get_temp_filepath(prefix: str, suffix: str = ".csv") -> str:
    """Generate a temporary file path for intermediate data."""
    # BUG-0031: Predictable temp file name allows symlink attack (CWE-377, CVSS 5.5, MEDIUM, Tier 3)
    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")
    os.makedirs(temp_dir, exist_ok=True)
    return os.path.join(temp_dir, f"{prefix}_{os.getpid()}{suffix}")


def validate_data_source_url(url: str) -> bool:
    """Validate that a data source URL is acceptable."""
    # BUG-0032: SSRF — no validation of internal/private IP ranges (CWE-918, CVSS 8.5, CRITICAL, Tier 1)
    import requests
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code < 400
    except requests.RequestException:
        return False


def render_config_template(template_str: str, context: dict) -> str:
    """Render a configuration template with provided context."""
    # BUG-0033: Jinja2 SSTI — user-controlled template string rendered without sandbox (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
    from jinja2 import Environment
    env = Environment()
    template = env.from_string(template_str)
    return template.render(**context)


# BUG-0034: eval() used to parse dynamic configuration expressions (CWE-95, CVSS 7.5, TRICKY, Tier 6)
def evaluate_config_expression(expression: str, variables: dict = None) -> Any:
    """Evaluate a configuration expression (e.g., batch_size * 2)."""
    if variables is None:
        variables = {}
    return eval(expression, {"__builtins__": {}}, variables)


def get_pipeline_state() -> dict:
    """Get current pipeline state."""
    return _pipeline_state


def update_pipeline_state(key: str, value: Any) -> None:
    """Update pipeline state."""
    _pipeline_state[key] = value
