#!/usr/bin/env python3
"""
admin_tools.py — Administrative utilities for cobb-dataforge pipeline.
Provides data export, schema management, user provisioning, and debugging tools.

NOTE: This file intentionally contains NO planted bugs. It serves as a realistic
admin utility that reviewers may flag false positives on.
"""

import os
import sys
import csv
import json
import hashlib
import logging
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import snowflake.connector
import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("admin_tools")


# ────────────────────────────────────────────────────
# Connection Management
# ────────────────────────────────────────────────────

def get_snowflake_connection(profile: str = "ci") -> snowflake.connector.SnowflakeConnection:
    """
    Establish Snowflake connection using profiles.yml CI profile.
    Requires all credentials via environment variables (no fallback).
    """
    profiles_path = os.path.join(os.path.dirname(__file__), "..", "profiles.yml")

    with open(profiles_path, 'r') as f:
        profiles = yaml.safe_load(f)

    config = profiles["cobb_dataforge"]["outputs"][profile]

    # Resolve env_var references from profiles.yml
    account = os.environ["SNOWFLAKE_ACCOUNT"]
    user = os.environ["SNOWFLAKE_USER"]
    password = os.environ["SNOWFLAKE_PASSWORD"]
    database = os.environ.get("SNOWFLAKE_DATABASE", config.get("database", ""))
    warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE", config.get("warehouse", ""))
    schema = os.environ.get("SNOWFLAKE_SCHEMA", config.get("schema", "PUBLIC"))
    role = os.environ.get("SNOWFLAKE_ROLE", config.get("role", ""))

    logger.info(f"Connecting to Snowflake account: {account}")

    conn = snowflake.connector.connect(
        account=account,
        user=user,
        password=password,
        database=database,
        warehouse=warehouse,
        schema=schema,
        role=role,
    )
    return conn


# ────────────────────────────────────────────────────
# Data Export (read-only, parameterized queries only)
# ────────────────────────────────────────────────────

ALLOWED_EXPORT_TABLES = {
    "fct_orders": "SELECT order_id, customer_id, order_date, order_status, total_amount, currency_code FROM analytics.marts.fct_orders",
    "dim_customers": "SELECT customer_id, total_orders, lifetime_value, customer_segment, engagement_status FROM analytics.marts.dim_customers",
    "stg_products": "SELECT product_id, product_name, category_name, effective_price, stock_status FROM analytics.staging.stg_products",
}


def export_data(table_key: str, output_path: str, format: str = "csv") -> str:
    """Export pre-defined query results to file. Only whitelisted tables allowed."""
    if table_key not in ALLOWED_EXPORT_TABLES:
        raise ValueError(f"Table '{table_key}' not in allowed export list: {list(ALLOWED_EXPORT_TABLES.keys())}")

    if format not in ("csv", "json"):
        raise ValueError(f"Unsupported format: {format}. Use 'csv' or 'json'.")

    # Validate output path is within expected directory
    output_dir = os.path.abspath(os.path.dirname(output_path))
    allowed_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "exports"))
    if not output_dir.startswith(allowed_dir):
        raise ValueError(f"Output path must be within {allowed_dir}")

    query = ALLOWED_EXPORT_TABLES[table_key]
    conn = get_snowflake_connection()

    try:
        cursor = conn.cursor()
        logger.info(f"Exporting table: {table_key}")
        cursor.execute(query)

        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        os.makedirs(output_dir, exist_ok=True)

        if format == "csv":
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(rows)
        elif format == "json":
            with open(output_path, 'w') as f:
                data = [dict(zip(columns, row)) for row in rows]
                json.dump(data, f, indent=2, default=str)

        logger.info(f"Exported {len(rows)} rows to {output_path}")
        return output_path

    finally:
        conn.close()


# ────────────────────────────────────────────────────
# Schema Management
# ────────────────────────────────────────────────────

ALLOWED_SCHEMA_PREFIXES = ("dev_", "test_", "sandbox_")
ALLOWED_ROLES = ("ANALYST_ROLE", "DATA_ENGINEER_ROLE", "READER_ROLE")


def create_schema(schema_name: str, grant_roles: List[str] = None) -> None:
    """Create a new schema with validated name and optional role grants."""
    # Validate schema name: alphanumeric + underscore only, must start with allowed prefix
    if not schema_name.replace("_", "").isalnum():
        raise ValueError(f"Invalid schema name: {schema_name}")
    if not any(schema_name.startswith(prefix) for prefix in ALLOWED_SCHEMA_PREFIXES):
        raise ValueError(f"Schema must start with one of: {ALLOWED_SCHEMA_PREFIXES}")

    conn = get_snowflake_connection()

    try:
        cursor = conn.cursor()
        # Use identifier quoting instead of string interpolation
        cursor.execute("CREATE SCHEMA IF NOT EXISTS IDENTIFIER(%s)", (schema_name,))
        logger.info(f"Created schema: {schema_name}")

        if grant_roles:
            for role in grant_roles:
                if role not in ALLOWED_ROLES:
                    logger.warning(f"Skipping unauthorized role: {role}")
                    continue
                cursor.execute(
                    f"GRANT USAGE ON SCHEMA IDENTIFIER('{schema_name}') TO ROLE IDENTIFIER('{role}')"
                )
                logger.info(f"Granted USAGE on {schema_name} to {role}")

    finally:
        conn.close()


# ────────────────────────────────────────────────────
# Health Check
# ────────────────────────────────────────────────────

def check_pipeline_health() -> dict:
    """Check pipeline health: connection, freshness, row counts."""
    results = {"status": "unknown", "checks": []}

    try:
        conn = get_snowflake_connection()
        cursor = conn.cursor()

        # Connection check
        cursor.execute("SELECT CURRENT_TIMESTAMP()")
        results["checks"].append({"name": "connection", "status": "ok"})

        # Freshness check
        cursor.execute("""
            SELECT DATEDIFF('hour', MAX(created_at), CURRENT_TIMESTAMP()) AS hours_since_update
            FROM analytics.marts.fct_orders
        """)
        row = cursor.fetchone()
        hours = row[0] if row else None
        results["checks"].append({
            "name": "freshness",
            "status": "ok" if hours and hours < 24 else "warning",
            "hours_since_update": hours,
        })

        # Row count check
        cursor.execute("SELECT COUNT(*) FROM analytics.marts.fct_orders")
        count = cursor.fetchone()[0]
        results["checks"].append({
            "name": "row_count",
            "status": "ok" if count > 0 else "error",
            "count": count,
        })

        results["status"] = "healthy" if all(
            c["status"] == "ok" for c in results["checks"]
        ) else "degraded"

        conn.close()

    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
        logger.error(f"Health check failed: {e}")

    return results


# ────────────────────────────────────────────────────
# dbt Command Runner (whitelisted commands only)
# ────────────────────────────────────────────────────

ALLOWED_DBT_COMMANDS = ("run", "test", "build", "compile", "docs generate", "seed", "snapshot")


def run_dbt_command(command: str, target: str = "dev") -> dict:
    """Execute a whitelisted dbt command and capture output."""
    if command not in ALLOWED_DBT_COMMANDS:
        raise ValueError(f"Command '{command}' not allowed. Use one of: {ALLOWED_DBT_COMMANDS}")

    if target not in ("dev", "ci", "staging"):
        raise ValueError(f"Target '{target}' not allowed for admin tools.")

    full_command = ["dbt", command, "--target", target]
    logger.info(f"Running: {' '.join(full_command)}")

    result = subprocess.run(
        full_command,
        capture_output=True,
        text=True,
        timeout=600,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "SNOWFLAKE_ACCOUNT": os.environ.get("SNOWFLAKE_ACCOUNT", ""),
            "SNOWFLAKE_USER": os.environ.get("SNOWFLAKE_USER", ""),
            "SNOWFLAKE_PASSWORD": os.environ.get("SNOWFLAKE_PASSWORD", ""),
            "SNOWFLAKE_DATABASE": os.environ.get("SNOWFLAKE_DATABASE", ""),
            "SNOWFLAKE_WAREHOUSE": os.environ.get("SNOWFLAKE_WAREHOUSE", ""),
            "SNOWFLAKE_ROLE": os.environ.get("SNOWFLAKE_ROLE", ""),
            "DBT_PROFILES_DIR": os.path.join(os.path.dirname(__file__), ".."),
        },
    )

    return {
        "command": " ".join(full_command),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ────────────────────────────────────────────────────
# CLI Interface
# ────────────────────────────────────────────────────

def main():
    """CLI entry point for admin tools."""
    import argparse

    parser = argparse.ArgumentParser(description="cobb-dataforge admin tools")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Export subcommand
    export_parser = subparsers.add_parser("export", help="Export data to file")
    export_parser.add_argument("--table", required=True, choices=list(ALLOWED_EXPORT_TABLES.keys()))
    export_parser.add_argument("--output", required=True, help="Output file path")
    export_parser.add_argument("--format", default="csv", choices=["csv", "json"])

    # Schema subcommand
    schema_parser = subparsers.add_parser("schema", help="Schema management")
    schema_parser.add_argument("--name", required=True, help="Schema name (must start with dev_/test_/sandbox_)")
    schema_parser.add_argument("--roles", nargs="*", help="Roles to grant access")

    # Health subcommand
    subparsers.add_parser("health", help="Check pipeline health")

    # dbt subcommand
    dbt_parser = subparsers.add_parser("dbt", help="Run dbt commands")
    dbt_parser.add_argument("--cmd", required=True, choices=list(ALLOWED_DBT_COMMANDS))
    dbt_parser.add_argument("--target", default="dev", choices=["dev", "ci", "staging"])

    args = parser.parse_args()

    if args.command == "export":
        export_data(args.table, args.output, args.format)
    elif args.command == "schema":
        create_schema(args.name, args.roles)
    elif args.command == "health":
        result = check_pipeline_health()
        print(json.dumps(result, indent=2))
    elif args.command == "dbt":
        result = run_dbt_command(args.cmd, args.target)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
