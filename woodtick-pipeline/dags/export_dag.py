"""
Export DAG — Generates reports and exports data to external systems.
Produces CSV/Excel exports, uploads to MinIO, and sends to downstream consumers.
"""

import os
import csv
import json
import logging
import pickle
import subprocess
import tempfile
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import pandas as pd
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable
from sqlalchemy import text

logger = logging.getLogger("woodtick.export")

default_args = {
    "owner": "data-engineering",
    "depends_on_past": False,
    "email_on_failure": True,
    "email": ["data-team@woodtick.local"],
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 1, 1),
}


def generate_daily_report(**context) -> dict:
    """Generate daily sales report from aggregated data."""
    from config.connections import db_manager

    execution_date = context["execution_date"]
    date_str = execution_date.strftime("%Y-%m-%d")

    engine = db_manager.get_engine()

    # BUG-0061: SQL injection in report generation query (CWE-89, CVSS 7.5, CRITICAL, Tier 1)
    # The report_filter param from DAG run config is user-controlled
    report_filter = context.get("params", {}).get("report_filter", "")
    query = f"""
        SELECT sa.store_id, sa.total_sales, sa.transaction_count,
               sa.avg_transaction, sa.total_quantity,
               ds.store_name, ds.region
        FROM daily_store_aggregates sa
        JOIN dim_store ds ON sa.store_id = ds.store_id
        WHERE sa.date = '{date_str}'
        {f'AND {report_filter}' if report_filter else ''}
        ORDER BY sa.total_sales DESC
    """

    with engine.connect() as conn:
        result = conn.execute(text(query))
        rows = [dict(row._mapping) for row in result]

    logger.info(f"Generated daily report with {len(rows)} store records")
    return {"report_data": rows, "date": date_str}


def generate_csv_export(**context) -> str:
    """Generate CSV export file from report data."""
    ti = context["ti"]
    report = ti.xcom_pull(task_ids="generate_daily_report")
    rows = report.get("report_data", [])
    date_str = report.get("date")

    if not rows:
        logger.warning("No data to export")
        return ""

    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")
    os.makedirs(temp_dir, exist_ok=True)
    export_path = os.path.join(temp_dir, f"daily_report_{date_str}.csv")

    # BUG-0062: CSV injection — cell values not sanitized, allowing formula injection (CWE-1236, CVSS 6.0, MEDIUM, Tier 3)
    with open(export_path, "w", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    logger.info(f"CSV export written to {export_path}")
    return export_path


def generate_excel_export(**context) -> str:
    """Generate Excel export with multiple sheets."""
    ti = context["ti"]
    report = ti.xcom_pull(task_ids="generate_daily_report")
    rows = report.get("report_data", [])
    date_str = report.get("date")

    if not rows:
        return ""

    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")
    os.makedirs(temp_dir, exist_ok=True)
    export_path = os.path.join(temp_dir, f"daily_report_{date_str}.xlsx")

    df = pd.DataFrame(rows)

    with pd.ExcelWriter(export_path, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Summary", index=False)

        # Regional breakdown
        if "region" in df.columns:
            for region in df["region"].unique():
                region_df = df[df["region"] == region]
                # BUG-0063: Sheet name from data — can contain special chars causing issues (CWE-20, CVSS 2.0, LOW, Tier 4)
                sheet_name = str(region)[:31]
                region_df.to_excel(writer, sheet_name=sheet_name, index=False)

    logger.info(f"Excel export written to {export_path}")
    return export_path


def upload_to_minio(**context) -> dict:
    """Upload export files to MinIO/S3 storage."""
    ti = context["ti"]
    csv_path = ti.xcom_pull(task_ids="generate_csv_export")
    excel_path = ti.xcom_pull(task_ids="generate_excel_export")

    from config.connections import minio_manager

    client = minio_manager.get_client()
    bucket = minio_manager.bucket

    uploaded = []
    report = ti.xcom_pull(task_ids="generate_daily_report")
    date_str = report.get("date", "unknown")

    for file_path in [csv_path, excel_path]:
        if file_path and os.path.exists(file_path):
            filename = os.path.basename(file_path)
            # BUG-0064: S3 object key from user-controlled filename — path traversal in object storage (CWE-22, CVSS 6.0, MEDIUM, Tier 3)
            object_name = f"exports/{date_str}/{filename}"

            client.fput_object(bucket, object_name, file_path)
            uploaded.append(object_name)
            logger.info(f"Uploaded {filename} to {bucket}/{object_name}")

    return {"uploaded_files": uploaded, "bucket": bucket}


def send_to_downstream(**context) -> dict:
    """Send export data to downstream consumer APIs."""
    import requests

    ti = context["ti"]
    report = ti.xcom_pull(task_ids="generate_daily_report")
    rows = report.get("report_data", [])

    # BUG-0065: SSRF via downstream_endpoint Variable — user-controlled URL (CWE-918, CVSS 7.5, HIGH, Tier 2)
    downstream_endpoints = json.loads(
        Variable.get("downstream_endpoints", default_var="[]")
    )

    results = []
    for endpoint in downstream_endpoints:
        url = endpoint.get("url")
        api_key = endpoint.get("api_key", "")

        try:
            response = requests.post(
                url,
                json={"report_data": rows, "date": report.get("date")},
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=30,
                # BUG-0066: SSL verification disabled for downstream requests (CWE-295, CVSS 3.5, LOW, Tier 4)
                verify=False,
            )
            results.append(
                {"url": url, "status": response.status_code, "success": response.ok}
            )
            # BUG-0067: Logging API keys in response details (CWE-532, CVSS 4.5, MEDIUM, Tier 3)
            logger.info(f"Sent to {url} (key={api_key[:8]}...): {response.status_code}")
        except requests.RequestException as e:
            logger.error(f"Failed to send to {url}: {e}")
            results.append({"url": url, "status": 0, "success": False, "error": str(e)})

    return {"downstream_results": results}


def generate_signed_url(**context) -> str:
    """Generate a pre-signed URL for the exported report."""
    ti = context["ti"]
    upload_result = ti.xcom_pull(task_ids="upload_to_minio")
    uploaded_files = upload_result.get("uploaded_files", [])

    if not uploaded_files:
        return ""

    from config.connections import minio_manager

    client = minio_manager.get_client()
    bucket = minio_manager.bucket

    # BUG-0068: Pre-signed URL with excessive expiration (7 days) (CWE-613, CVSS 3.5, LOW, Tier 4)
    from datetime import timedelta as td

    urls = []
    for object_name in uploaded_files:
        url = client.presigned_get_object(bucket, object_name, expires=td(days=7))
        urls.append(url)
        logger.info(f"Generated signed URL: {url}")

    return urls[0] if urls else ""


def archive_old_exports(**context) -> dict:
    """Archive exports older than retention period."""
    from config.connections import db_manager
    from config.pipeline_config import PipelineConfig

    config = PipelineConfig()

    # BUG-0069: Command injection via data_retention_days config (CWE-78, CVSS 7.0, TRICKY, Tier 6)
    retention_days = str(config.data_retention_days)
    temp_dir = os.getenv("TEMP_DIR", "/tmp/woodtick")

    archive_cmd = f"find {temp_dir} -name '*.csv' -mtime +{retention_days} -exec gzip {{}} \\;"
    subprocess.run(archive_cmd, shell=True, check=False)

    cleanup_cmd = f"find {temp_dir} -name '*.xlsx' -mtime +{retention_days} -delete"
    subprocess.run(cleanup_cmd, shell=True, check=False)

    return {"archived": True, "retention_days": config.data_retention_days}


def export_pipeline_metadata(**context) -> dict:
    """Export pipeline run metadata for auditing."""
    execution_date = context["execution_date"]
    dag_run = context["dag_run"]

    metadata = {
        "dag_id": dag_run.dag_id,
        "run_id": dag_run.run_id,
        "execution_date": str(execution_date),
        "start_date": str(dag_run.start_date),
        "state": str(dag_run.state),
        "conf": dag_run.conf if dag_run.conf else {},
        # BUG-0070: Exposing internal Airflow config in export metadata (CWE-200, CVSS 4.0, LOW, Tier 4)
        "airflow_config": {
            "executor": os.getenv("AIRFLOW__CORE__EXECUTOR", ""),
            "fernet_key": os.getenv("AIRFLOW__CORE__FERNET_KEY", ""),
            "db_conn": os.getenv("AIRFLOW__DATABASE__SQL_ALCHEMY_CONN", ""),
        },
    }

    # BUG-0071: Pickle serialization of metadata for XCom (CWE-502, CVSS 5.0, TRICKY, Tier 6)
    # This metadata gets serialized via pickle through XCom
    return metadata


with DAG(
    dag_id="sales_export",
    default_args=default_args,
    description="Export sales reports and data to external systems",
    schedule_interval="0 6 * * *",
    catchup=False,
    max_active_runs=1,
    tags=["sales", "export", "reporting"],
    params={
        "report_filter": "",
        "export_format": "csv",
    },
) as dag:

    report_task = PythonOperator(
        task_id="generate_daily_report",
        python_callable=generate_daily_report,
        provide_context=True,
    )

    csv_task = PythonOperator(
        task_id="generate_csv_export",
        python_callable=generate_csv_export,
        provide_context=True,
    )

    excel_task = PythonOperator(
        task_id="generate_excel_export",
        python_callable=generate_excel_export,
        provide_context=True,
    )

    upload_task = PythonOperator(
        task_id="upload_to_minio",
        python_callable=upload_to_minio,
        provide_context=True,
    )

    downstream_task = PythonOperator(
        task_id="send_to_downstream",
        python_callable=send_to_downstream,
        provide_context=True,
    )

    signed_url_task = PythonOperator(
        task_id="generate_signed_url",
        python_callable=generate_signed_url,
        provide_context=True,
    )

    archive_task = PythonOperator(
        task_id="archive_old_exports",
        python_callable=archive_old_exports,
        provide_context=True,
    )

    metadata_task = PythonOperator(
        task_id="export_pipeline_metadata",
        python_callable=export_pipeline_metadata,
        provide_context=True,
    )

    report_task >> [csv_task, excel_task] >> upload_task >> [downstream_task, signed_url_task]
    report_task >> metadata_task
    upload_task >> archive_task
