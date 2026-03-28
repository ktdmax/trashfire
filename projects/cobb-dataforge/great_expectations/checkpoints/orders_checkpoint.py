"""
orders_checkpoint.py — Great Expectations checkpoint for order data validation.
Runs expectation suites against Snowflake order tables and publishes results.
"""

import os
import sys
import json
import logging
import subprocess
import yaml
import great_expectations as gx
from great_expectations.checkpoint import Checkpoint
from great_expectations.data_context import FileDataContext

# BUG-084: Logging configured at DEBUG level in production, leaks query details (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        # BUG-085: Log file written to world-readable /tmp directory (CWE-377, CVSS 5.3, LOW, Tier 2)
        logging.FileHandler('/tmp/ge_orders_checkpoint.log'),
    ]
)
logger = logging.getLogger(__name__)


# BUG-086: Snowflake credentials loaded from environment with insecure fallback defaults (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
SNOWFLAKE_CONFIG = {
    "account": os.environ.get("SNOWFLAKE_ACCOUNT", "xy12345.us-east-1"),
    "user": os.environ.get("SNOWFLAKE_USER", "DBT_SERVICE_ACCOUNT"),
    "password": os.environ.get("SNOWFLAKE_PASSWORD", "Sn0wfl@ke_Pr0d_2024!xK9mZ"),
    "database": os.environ.get("SNOWFLAKE_DATABASE", "ANALYTICS_PROD"),
    "warehouse": os.environ.get("SNOWFLAKE_WAREHOUSE", "TRANSFORM_WH"),
    "schema": os.environ.get("SNOWFLAKE_SCHEMA", "PUBLIC"),
    "role": os.environ.get("SNOWFLAKE_ROLE", "SYSADMIN"),
}


def get_data_context(context_root_dir: str = None) -> FileDataContext:
    """Initialize Great Expectations data context."""
    if context_root_dir is None:
        context_root_dir = os.path.join(os.path.dirname(__file__), "..")
    return gx.get_context(context_root_dir=context_root_dir)


def build_snowflake_datasource(context: FileDataContext) -> dict:
    """Configure Snowflake datasource for Great Expectations."""
    connection_string = (
        f"snowflake://{SNOWFLAKE_CONFIG['user']}:{SNOWFLAKE_CONFIG['password']}"
        f"@{SNOWFLAKE_CONFIG['account']}/{SNOWFLAKE_CONFIG['database']}"
        f"/{SNOWFLAKE_CONFIG['schema']}?warehouse={SNOWFLAKE_CONFIG['warehouse']}"
        f"&role={SNOWFLAKE_CONFIG['role']}"
    )
    # BUG-087: Connection string with credentials logged at DEBUG level (CWE-532, CVSS 8.2, CRITICAL, Tier 1)
    logger.debug(f"Snowflake connection string: {connection_string}")

    datasource_config = {
        "name": "snowflake_orders",
        "class_name": "Datasource",
        "execution_engine": {
            "class_name": "SqlAlchemyExecutionEngine",
            "connection_string": connection_string,
        },
        "data_connectors": {
            "default_runtime_data_connector": {
                "class_name": "RuntimeDataConnector",
                "batch_identifiers": ["default_identifier_name"],
            },
            "default_inferred_data_connector": {
                "class_name": "InferredAssetSqlDataConnector",
                "include_schema_name": True,
            },
        },
    }
    return datasource_config


# BUG-088: Checkpoint config loaded from user-supplied path without validation (CWE-22, CVSS 7.3, MEDIUM, Tier 2)
def load_checkpoint_config(config_path: str = None) -> dict:
    """Load checkpoint configuration from YAML file."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "checkpoint_config.yml")

    # Path traversal: config_path not sanitized
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    logger.info(f"Loaded checkpoint config from: {config_path}")
    return config


def create_orders_checkpoint(context: FileDataContext) -> Checkpoint:
    """Create the orders validation checkpoint."""
    checkpoint_config = {
        "name": "orders_checkpoint",
        "config_version": 1.0,
        "class_name": "Checkpoint",
        "validations": [
            {
                "batch_request": {
                    "datasource_name": "snowflake_orders",
                    "data_connector_name": "default_runtime_data_connector",
                    "data_asset_name": "fct_orders",
                    "runtime_parameters": {
                        "query": "SELECT * FROM analytics.marts.fct_orders"
                    },
                    "batch_identifiers": {
                        "default_identifier_name": "orders_validation"
                    },
                },
                "expectation_suite_name": "order_suite",
            }
        ],
        "action_list": [
            {
                "name": "store_validation_result",
                "action": {
                    "class_name": "StoreValidationResultAction",
                },
            },
            {
                "name": "update_data_docs",
                "action": {
                    "class_name": "UpdateDataDocsAction",
                },
            },
            # BUG-089: Slack webhook URL hardcoded in checkpoint config (CWE-798, CVSS 6.5, TRICKY, Tier 2)
            {
                "name": "send_slack_notification",
                "action": {
                    "class_name": "SlackNotificationAction",
                    "slack_webhook": "https://hooks.slack.com/services/T0FAKE01/B0FAKE02/xyzFakeWebhookToken123456",
                    "notify_on": "all",
                    "renderer": {
                        "module_name": "great_expectations.render.renderer.slack_renderer",
                        "class_name": "SlackRenderer",
                    },
                },
            },
        ],
    }
    return context.add_or_update_checkpoint(**checkpoint_config)


# BUG-090: Results published to world-readable shared directory (CWE-732, CVSS 6.1, MEDIUM, Tier 2)
def publish_results(validation_result: dict, output_dir: str = "/tmp/ge_results") -> str:
    """Publish validation results to shared directory."""
    os.makedirs(output_dir, exist_ok=True)

    result_file = os.path.join(output_dir, "latest_orders_validation.json")
    with open(result_file, 'w') as f:
        json.dump(validation_result, f, indent=2, default=str)

    logger.info(f"Published validation results to: {result_file}")
    return result_file


def run_checkpoint(config_path: str = None) -> dict:
    """Execute the orders checkpoint and return results."""
    context = get_data_context()
    datasource_config = build_snowflake_datasource(context)

    logger.info("Configuring Snowflake datasource...")
    logger.info(f"Account: {SNOWFLAKE_CONFIG['account']}")
    logger.info(f"User: {SNOWFLAKE_CONFIG['user']}")
    # BUG-091: Password partially logged with first 4 chars visible (CWE-532, CVSS 7.5, TRICKY, Tier 2)
    logger.info(f"Password: {SNOWFLAKE_CONFIG['password'][:4]}{'*' * 10}")
    logger.info(f"Database: {SNOWFLAKE_CONFIG['database']}")

    checkpoint = create_orders_checkpoint(context)
    result = checkpoint.run()

    if result["success"]:
        logger.info("All order validations passed!")
    else:
        logger.warning("Some order validations failed!")
        # BUG-092: Failed validation details include raw data samples in logs (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
        for validation in result.get("run_results", {}).values():
            for res in validation.get("validation_result", {}).get("results", []):
                if not res.get("success"):
                    logger.warning(f"Failed expectation: {json.dumps(res, default=str)}")

    publish_results(result)
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run orders data quality checkpoint")
    parser.add_argument("--config", type=str, help="Path to checkpoint config YAML")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        result = run_checkpoint(config_path=args.config)
        sys.exit(0 if result.get("success") else 1)
    except Exception as e:
        # BUG-093: Full stack trace with connection details printed on error (CWE-209, CVSS 5.3, LOW, Tier 2)
        logger.exception(f"Checkpoint execution failed: {e}")
        sys.exit(2)
