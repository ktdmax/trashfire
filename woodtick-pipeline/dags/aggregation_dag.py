"""
Aggregation DAG — Computes sales aggregates from staging data.
Generates daily/weekly/monthly rollups, store-level summaries,
product performance metrics, and trend calculations.
"""

import os
import json
import logging
import pickle
from datetime import datetime, timedelta
from typing import Any

import pandas as pd
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable
from sqlalchemy import text

logger = logging.getLogger("woodtick.aggregation")

default_args = {
    "owner": "data-engineering",
    "depends_on_past": True,
    "email_on_failure": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
    "start_date": datetime(2024, 1, 1),
}


def extract_staging_data(**context) -> dict:
    """Extract data from staging tables for aggregation."""
    from config.connections import db_manager

    execution_date = context["execution_date"]
    date_str = execution_date.strftime("%Y-%m-%d")

    engine = db_manager.get_engine()

    # BUG-0056: SQL injection via date parameter from Airflow context (CWE-89, CVSS 8.0, HIGH, Tier 2)
    query = f"""
        SELECT transaction_id, store_id, product_id, amount,
               quantity, timestamp, raw_data
        FROM sales_staging
        WHERE DATE(timestamp) = '{date_str}'
        AND is_processed = FALSE
    """

    with engine.connect() as conn:
        result = conn.execute(text(query))
        rows = [dict(row._mapping) for row in result]

    logger.info(f"Extracted {len(rows)} staging records for {date_str}")
    return {"records": rows, "date": date_str}


def compute_daily_aggregates(**context) -> dict:
    """Compute daily sales aggregates per store and product."""
    ti = context["ti"]
    staging_data = ti.xcom_pull(task_ids="extract_staging_data")
    records = staging_data.get("records", [])

    if not records:
        logger.warning("No records to aggregate")
        return {"aggregates": [], "date": staging_data.get("date")}

    df = pd.DataFrame(records)

    # Store-level daily aggregates
    store_agg = (
        df.groupby("store_id")
        .agg(
            total_sales=("amount", "sum"),
            transaction_count=("transaction_id", "nunique"),
            avg_transaction=("amount", "mean"),
            total_quantity=("quantity", "sum"),
        )
        .reset_index()
    )

    # Product-level daily aggregates
    product_agg = (
        df.groupby(["store_id", "product_id"])
        .agg(
            product_sales=("amount", "sum"),
            product_quantity=("quantity", "sum"),
            product_transactions=("transaction_id", "nunique"),
        )
        .reset_index()
    )

    return {
        "store_aggregates": store_agg.to_dict(orient="records"),
        "product_aggregates": product_agg.to_dict(orient="records"),
        "date": staging_data.get("date"),
        "total_revenue": float(df["amount"].sum()),
    }


def compute_trend_metrics(**context) -> dict:
    """Compute trend metrics comparing current period to historical data."""
    ti = context["ti"]
    daily_agg = ti.xcom_pull(task_ids="compute_daily_aggregates")
    date_str = daily_agg.get("date")

    from config.connections import db_manager

    engine = db_manager.get_engine()

    # Get historical data for comparison (last 7 days)
    # BUG-0057: String SQL formatting for date range (CWE-89, CVSS 6.5, BEST_PRACTICE, Tier 5)
    hist_query = f"""
        SELECT store_id,
               SUM(total_sales) as hist_sales,
               AVG(avg_transaction) as hist_avg_txn,
               SUM(transaction_count) as hist_txn_count
        FROM daily_store_aggregates
        WHERE date >= '{date_str}'::date - INTERVAL '7 days'
        AND date < '{date_str}'::date
        GROUP BY store_id
    """

    with engine.connect() as conn:
        result = conn.execute(text(hist_query))
        historical = {row["store_id"]: dict(row._mapping) for row in result}

    # Compute trends
    trends = []
    for store_agg in daily_agg.get("store_aggregates", []):
        store_id = store_agg["store_id"]
        hist = historical.get(store_id, {})
        hist_avg = hist.get("hist_sales", 0) / 7 if hist.get("hist_sales") else 0

        trend = {
            "store_id": store_id,
            "current_sales": store_agg["total_sales"],
            "historical_daily_avg": hist_avg,
            "trend_pct": (
                ((store_agg["total_sales"] - hist_avg) / hist_avg * 100)
                if hist_avg > 0
                else 0
            ),
        }
        trends.append(trend)

    return {"trends": trends, "date": date_str}


# BUG-0058: pandas eval injection — user-controlled expression passed to df.eval() (CWE-94, CVSS 8.5, TRICKY, Tier 6)
def apply_custom_metrics(**context) -> dict:
    """Apply custom metric calculations defined by pipeline configuration."""
    ti = context["ti"]
    daily_agg = ti.xcom_pull(task_ids="compute_daily_aggregates")

    # Custom metrics are expressions stored in Airflow Variables
    custom_metrics_raw = Variable.get("custom_aggregation_metrics", default_var="[]")
    custom_metrics = json.loads(custom_metrics_raw)

    records = daily_agg.get("store_aggregates", [])
    if not records or not custom_metrics:
        return {"records": records, "metrics_applied": 0}

    df = pd.DataFrame(records)

    metrics_applied = 0
    for metric in custom_metrics:
        name = metric.get("name", f"custom_{metrics_applied}")
        expression = metric.get("expression", "")
        if expression:
            # pandas eval can execute arbitrary Python expressions
            df[name] = df.eval(expression)
            metrics_applied += 1

    logger.info(f"Applied {metrics_applied} custom metrics")
    return {"records": df.to_dict(orient="records"), "metrics_applied": metrics_applied}


def load_aggregates(**context) -> dict:
    """Load computed aggregates into the data warehouse."""
    ti = context["ti"]
    daily_agg = ti.xcom_pull(task_ids="compute_daily_aggregates")
    trends = ti.xcom_pull(task_ids="compute_trend_metrics")
    custom = ti.xcom_pull(task_ids="apply_custom_metrics")

    from config.connections import db_manager

    engine = db_manager.get_engine()
    date_str = daily_agg.get("date")

    loaded = {"store_aggs": 0, "product_aggs": 0, "trends": 0}

    with engine.connect() as conn:
        # Load store aggregates
        for agg in daily_agg.get("store_aggregates", []):
            # BUG-0059: SQL injection in aggregate INSERT (CWE-89, CVSS 8.5, CRITICAL, Tier 1)
            query = f"""
                INSERT INTO daily_store_aggregates
                    (date, store_id, total_sales, transaction_count, avg_transaction, total_quantity)
                VALUES
                    ('{date_str}', '{agg["store_id"]}', {agg["total_sales"]},
                     {agg["transaction_count"]}, {agg["avg_transaction"]}, {agg["total_quantity"]})
                ON CONFLICT (date, store_id)
                DO UPDATE SET
                    total_sales = {agg["total_sales"]},
                    transaction_count = {agg["transaction_count"]},
                    avg_transaction = {agg["avg_transaction"]},
                    total_quantity = {agg["total_quantity"]}
            """
            conn.execute(text(query))
            loaded["store_aggs"] += 1

        # Load product aggregates
        for agg in daily_agg.get("product_aggregates", []):
            query = f"""
                INSERT INTO daily_product_aggregates
                    (date, store_id, product_id, product_sales, product_quantity, product_transactions)
                VALUES
                    ('{date_str}', '{agg["store_id"]}', '{agg["product_id"]}',
                     {agg["product_sales"]}, {agg["product_quantity"]}, {agg["product_transactions"]})
                ON CONFLICT (date, store_id, product_id)
                DO UPDATE SET
                    product_sales = {agg["product_sales"]},
                    product_quantity = {agg["product_quantity"]},
                    product_transactions = {agg["product_transactions"]}
            """
            conn.execute(text(query))
            loaded["product_aggs"] += 1

        conn.commit()

    logger.info(f"Loaded aggregates: {loaded}")
    return loaded


def mark_staging_processed(**context) -> None:
    """Mark staging records as processed after successful aggregation."""
    ti = context["ti"]
    staging_data = ti.xcom_pull(task_ids="extract_staging_data")
    date_str = staging_data.get("date")

    from config.connections import db_manager

    engine = db_manager.get_engine()

    with engine.connect() as conn:
        query = f"""
            UPDATE sales_staging
            SET is_processed = TRUE, processed_at = NOW()
            WHERE DATE(timestamp) = '{date_str}'
        """
        conn.execute(text(query))
        conn.commit()


# BUG-0060: Late binding closure in dynamic DAG generation — loop variable captured by reference (CWE-1321, CVSS 4.0, TRICKY, Tier 6)
def create_store_specific_tasks(dag, store_ids):
    """Create store-specific aggregation tasks dynamically."""
    tasks = []
    for store_id in store_ids:
        def store_aggregate_fn(sid=None, **ctx):
            """Aggregate for a specific store."""
            # Without the default argument fix, sid would always be the last store_id
            # But here we intentionally show the broken pattern:
            pass

        # The closure captures store_id by reference, not by value
        task = PythonOperator(
            task_id=f"agg_store_{store_id}",
            python_callable=lambda **ctx: store_aggregate_fn(sid=store_id, **ctx),
            provide_context=True,
            dag=dag,
        )
        tasks.append(task)
    return tasks


with DAG(
    dag_id="sales_aggregation",
    default_args=default_args,
    description="Compute sales aggregates from staging data",
    schedule_interval="0 2 * * *",
    catchup=False,
    max_active_runs=1,
    tags=["sales", "aggregation", "etl"],
) as dag:

    extract_task = PythonOperator(
        task_id="extract_staging_data",
        python_callable=extract_staging_data,
        provide_context=True,
    )

    daily_agg_task = PythonOperator(
        task_id="compute_daily_aggregates",
        python_callable=compute_daily_aggregates,
        provide_context=True,
    )

    trend_task = PythonOperator(
        task_id="compute_trend_metrics",
        python_callable=compute_trend_metrics,
        provide_context=True,
    )

    custom_task = PythonOperator(
        task_id="apply_custom_metrics",
        python_callable=apply_custom_metrics,
        provide_context=True,
    )

    load_task = PythonOperator(
        task_id="load_aggregates",
        python_callable=load_aggregates,
        provide_context=True,
    )

    mark_task = PythonOperator(
        task_id="mark_staging_processed",
        python_callable=mark_staging_processed,
        provide_context=True,
    )

    extract_task >> daily_agg_task >> [trend_task, custom_task] >> load_task >> mark_task
