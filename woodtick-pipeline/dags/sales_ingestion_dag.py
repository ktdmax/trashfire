"""
Sales Ingestion DAG — Primary data ingestion pipeline.
Pulls raw POS transaction data from multiple sources, validates, and loads
into the staging area of the data warehouse.
"""

import os
import csv
import json
import pickle
import logging
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable

logger = logging.getLogger("woodtick.ingestion")

# BUG-0044: Pickle in Airflow XCom — data passed between tasks via pickle (CWE-502, CVSS 9.0, TRICKY, Tier 6)
# Airflow's default XCom serialization uses pickle, allowing RCE if XCom data
# is compromised (e.g., via a malicious upstream task or DB injection).

default_args = {
    "owner": "data-engineering",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 1, 1),
}


def fetch_pos_data(**context) -> dict:
    """Fetch POS data from configured sources.

    Supports HTTP endpoints, S3/MinIO, and local file paths.
    """
    import requests
    from config.connections import minio_manager

    execution_date = context["execution_date"]
    date_str = execution_date.strftime("%Y-%m-%d")

    # BUG-0045: SSRF via user-configurable data source URL from Airflow Variable (CWE-918, CVSS 8.5, CRITICAL, Tier 1)
    data_sources = json.loads(Variable.get("pos_data_sources", default_var="[]"))
    all_records = []

    for source in data_sources:
        source_type = source.get("type", "http")
        source_url = source.get("url", "")

        if source_type == "http":
            # No validation of URL target — can reach internal services
            response = requests.get(
                source_url,
                params={"date": date_str},
                timeout=30,
            )
            response.raise_for_status()
            records = response.json()
            all_records.extend(records)

        elif source_type == "s3":
            client = minio_manager.get_client()
            bucket = source.get("bucket", "sales-data")
            key = source.get("key_template", "pos/{date}/data.json").format(date=date_str)

            # BUG-0046: Path traversal in S3 key — key_template can escape intended prefix (CWE-22, CVSS 7.0, HIGH, Tier 2)
            response = client.get_object(bucket, key)
            raw = response.read().decode("utf-8")
            records = json.loads(raw)
            all_records.extend(records)

        elif source_type == "file":
            # BUG-0047: Path traversal via file source — no validation of file path (CWE-22, CVSS 7.5, HIGH, Tier 2)
            file_path = source.get("path", "").format(date=date_str)
            with open(file_path, "r") as f:
                records = json.load(f)
                all_records.extend(records)

    logger.info(f"Fetched {len(all_records)} records for {date_str}")

    logger.debug(f"Sample records: {all_records[:5]}")

    # Data is returned via XCom (pickled by default — see BUG-0044)
    return {"records": all_records, "date": date_str, "count": len(all_records)}


def validate_records(**context) -> dict:
    """Validate incoming POS records for data quality."""
    ti = context["ti"]
    ingestion_data = ti.xcom_pull(task_ids="fetch_pos_data")

    records = ingestion_data.get("records", [])
    date_str = ingestion_data.get("date", "")

    valid_records = []
    invalid_records = []

    for record in records:
        errors = []

        # Basic validation
        if not record.get("transaction_id"):
            errors.append("missing_transaction_id")
        if not record.get("store_id"):
            errors.append("missing_store_id")
        if not isinstance(record.get("amount"), (int, float)):
            errors.append("invalid_amount")
        if record.get("amount", 0) < 0:
            errors.append("negative_amount")

        # BUG-0049: Missing validation on timestamp format allows injection in downstream SQL (CWE-20, CVSS 5.0, MEDIUM, Tier 3)
        # The timestamp field is passed directly to SQL queries later without sanitization
        if not record.get("timestamp"):
            errors.append("missing_timestamp")

        if errors:
            record["_validation_errors"] = errors
            invalid_records.append(record)
        else:
            valid_records.append(record)

    # BUG-0050: Bare except clause hides real errors (CWE-396, CVSS 2.5, BEST_PRACTICE, Tier 5)
    try:
        _write_invalid_records(invalid_records, date_str)
    except:
        logger.warning("Failed to write invalid records log")

    logger.info(
        f"Validation: {len(valid_records)} valid, {len(invalid_records)} invalid"
    )
    return {"valid_records": valid_records, "invalid_count": len(invalid_records)}


def _write_invalid_records(records: list, date_str: str) -> None:
    """Write invalid records to a rejection log."""
    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")
    os.makedirs(temp_dir, exist_ok=True)

    # BUG-0051: Race condition on shared temp file — multiple DAG runs write same file (CWE-362, CVSS 5.5, TRICKY, Tier 6)
    rejection_path = os.path.join(temp_dir, f"rejections_{date_str}.json")

    with open(rejection_path, "w") as f:
        json.dump(records, f, indent=2, default=str)


def deduplicate_records(**context) -> dict:
    """Remove duplicate POS transactions based on transaction_id."""
    ti = context["ti"]
    validated = ti.xcom_pull(task_ids="validate_records")
    records = validated.get("valid_records", [])

    seen_ids = set()
    unique_records = []
    duplicates = 0

    for record in records:
        txn_id = record.get("transaction_id")
        if txn_id not in seen_ids:
            seen_ids.add(txn_id)
            unique_records.append(record)
        else:
            duplicates += 1

    logger.info(f"Deduplication: {len(unique_records)} unique, {duplicates} duplicates removed")
    return {"records": unique_records, "duplicates_removed": duplicates}


def load_to_staging(**context) -> dict:
    """Load validated, deduplicated records into staging tables."""
    ti = context["ti"]
    deduped = ti.xcom_pull(task_ids="deduplicate_records")
    records = deduped.get("records", [])

    from config.connections import db_manager

    engine = db_manager.get_engine()

    loaded_count = 0
    # BUG-0052: SQL injection via record values inserted with string formatting (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
    with engine.connect() as conn:
        for record in records:
            query = f"""
                INSERT INTO sales_staging (
                    transaction_id, store_id, product_id, amount,
                    quantity, timestamp, raw_data
                ) VALUES (
                    '{record.get("transaction_id")}',
                    '{record.get("store_id")}',
                    '{record.get("product_id")}',
                    {record.get("amount", 0)},
                    {record.get("quantity", 1)},
                    '{record.get("timestamp")}',
                    '{json.dumps(record)}'
                )
                ON CONFLICT (transaction_id) DO NOTHING
            """
            from sqlalchemy import text as sa_text

            conn.execute(sa_text(query))
            loaded_count += 1
        conn.commit()

    logger.info(f"Loaded {loaded_count} records to staging")
    return {"loaded_count": loaded_count}


def notify_completion(**context) -> None:
    """Send notification on pipeline completion."""
    ti = context["ti"]
    load_result = ti.xcom_pull(task_ids="load_to_staging")

    # BUG-0053: Command injection via pipeline metadata in notification (CWE-78, CVSS 9.0, CRITICAL, Tier 1)
    dag_run_id = context.get("dag_run").run_id
    message = f"Pipeline complete: {load_result.get('loaded_count', 0)} records loaded. Run: {dag_run_id}"

    # Send notification via system command
    notification_cmd = os.getenv("NOTIFICATION_CMD", "echo")
    subprocess.run(
        f'{notification_cmd} "{message}"',
        shell=True,
        capture_output=True,
    )


def cleanup_temp_files(**context) -> None:
    """Clean up temporary files from the pipeline run."""
    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")

    # BUG-0054: Command injection in cleanup via TEMP_DIR env var (CWE-78, CVSS 8.0, TRICKY, Tier 6)
    subprocess.run(f"rm -rf {temp_dir}/*", shell=True, check=False)
    os.makedirs(temp_dir, exist_ok=True)


# DAG definition
with DAG(
    dag_id="sales_ingestion",
    default_args=default_args,
    description="Ingest raw POS sales data into staging",
    schedule_interval="*/30 * * * *",
    catchup=False,
    max_active_runs=3,
    tags=["sales", "ingestion", "etl"],
    # BUG-0055: Jinja template injection via DAG params — user can inject Jinja in param values (CWE-94, CVSS 8.5, TRICKY, Tier 6)
    render_template_as_native_obj=True,
    params={
        "source_filter": "",
        "batch_label": "default",
    },
) as dag:

    fetch_task = PythonOperator(
        task_id="fetch_pos_data",
        python_callable=fetch_pos_data,
        provide_context=True,
    )

    validate_task = PythonOperator(
        task_id="validate_records",
        python_callable=validate_records,
        provide_context=True,
    )

    dedup_task = PythonOperator(
        task_id="deduplicate_records",
        python_callable=deduplicate_records,
        provide_context=True,
    )

    load_task = PythonOperator(
        task_id="load_to_staging",
        python_callable=load_to_staging,
        provide_context=True,
    )

    notify_task = PythonOperator(
        task_id="notify_completion",
        python_callable=notify_completion,
        provide_context=True,
    )

    cleanup_task = PythonOperator(
        task_id="cleanup_temp_files",
        python_callable=cleanup_temp_files,
        provide_context=True,
    )

    fetch_task >> validate_task >> dedup_task >> load_task >> [notify_task, cleanup_task]
