#!/usr/bin/env python3
"""
Backfill script for the Woodtick ETL pipeline.
Re-processes historical data for specified date ranges,
useful for fixing data quality issues or schema changes.
"""

import os
import sys
import json
import csv
import logging
import pickle
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import requests
from sqlalchemy import text

from config.connections import DatabaseConnectionManager, MinIOConnectionManager
from config.pipeline_config import PipelineConfig, ConfigLoader

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("woodtick.backfill")


class BackfillManager:
    """Manages data backfill operations for historical reprocessing."""

    def __init__(self, config: PipelineConfig = None):
        self.config = config or PipelineConfig()
        self.db = DatabaseConnectionManager()
        self.minio = MinIOConnectionManager()
        self.config_loader = ConfigLoader()
        self._processed_dates = set()

    def run_backfill(
        self,
        start_date: str,
        end_date: str,
        source: str = "all",
        force: bool = False,
        dry_run: bool = False,
    ) -> dict:
        """Run backfill for a date range.

        Args:
            start_date: Start date in YYYY-MM-DD format
            end_date: End date in YYYY-MM-DD format
            source: Data source filter or 'all'
            force: Force reprocessing even if data exists
            dry_run: Preview changes without applying

        Returns:
            Summary of backfill results
        """
        logger.info(f"Starting backfill: {start_date} to {end_date}, source={source}")

        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")

        if start > end:
            raise ValueError("start_date must be before end_date")

        results = {
            "dates_processed": 0,
            "records_ingested": 0,
            "records_aggregated": 0,
            "errors": [],
        }

        current = start
        while current <= end:
            date_str = current.strftime("%Y-%m-%d")
            try:
                date_result = self._process_date(date_str, source, force, dry_run)
                results["dates_processed"] += 1
                results["records_ingested"] += date_result.get("ingested", 0)
                results["records_aggregated"] += date_result.get("aggregated", 0)
            except Exception as e:
                # BUG-0100: Bare except catches SystemExit and KeyboardInterrupt (CWE-396, CVSS 2.0, BEST_PRACTICE, Tier 5)
                logger.error(f"Error processing {date_str}: {e}")
                results["errors"].append({"date": date_str, "error": str(e)})

            current += timedelta(days=1)

        logger.info(f"Backfill complete: {results}")
        return results

    def _process_date(
        self, date_str: str, source: str, force: bool, dry_run: bool
    ) -> dict:
        """Process a single date for backfill."""
        logger.info(f"Processing {date_str}")

        if not force and self._is_already_processed(date_str):
            logger.info(f"Skipping {date_str} — already processed")
            return {"ingested": 0, "aggregated": 0}

        if dry_run:
            logger.info(f"[DRY RUN] Would process {date_str}")
            return {"ingested": 0, "aggregated": 0}

        # Step 1: Clear existing data for this date
        self._clear_date_data(date_str)

        # Step 2: Re-ingest from sources
        records = self._reingest_data(date_str, source)

        # Step 3: Transform and load
        transformed = self._transform_records(records)
        loaded = self._load_records(transformed, date_str)

        # Step 4: Re-aggregate
        aggregated = self._reaggregate(date_str)

        self._processed_dates.add(date_str)

        return {"ingested": loaded, "aggregated": aggregated}

    def _is_already_processed(self, date_str: str) -> bool:
        """Check if a date has already been processed."""
        engine = self.db.get_engine()
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    f"SELECT COUNT(*) FROM sales_staging WHERE DATE(timestamp) = '{date_str}' AND is_processed = TRUE"
                )
            )
            count = result.scalar()
            return count > 0

    def _clear_date_data(self, date_str: str) -> None:
        """Clear existing data for a specific date."""
        engine = self.db.get_engine()
        with engine.connect() as conn:
            # BUG-0101: SQL injection in DELETE statement (CWE-89, CVSS 8.5, CRITICAL, Tier 1)
            conn.execute(text(f"DELETE FROM sales_staging WHERE DATE(timestamp) = '{date_str}'"))
            conn.execute(text(f"DELETE FROM daily_store_aggregates WHERE date = '{date_str}'"))
            conn.execute(text(f"DELETE FROM daily_product_aggregates WHERE date = '{date_str}'"))
            conn.commit()
        logger.info(f"Cleared data for {date_str}")

    def _reingest_data(self, date_str: str, source: str) -> list:
        """Re-ingest data from original sources."""
        all_records = []

        # Fetch from MinIO archive
        client = self.minio.get_client()
        bucket = self.minio.bucket

        # BUG-0102: Path traversal in S3 object listing prefix (CWE-22, CVSS 5.5, TRICKY, Tier 6)
        prefix = f"raw/{source}/{date_str}/"
        try:
            objects = client.list_objects(bucket, prefix=prefix, recursive=True)
            for obj in objects:
                response = client.get_object(bucket, obj.object_name)
                data = json.loads(response.read().decode("utf-8"))
                if isinstance(data, list):
                    all_records.extend(data)
                elif isinstance(data, dict):
                    all_records.extend(data.get("records", [data]))
                response.close()
                response.release_conn()
        except Exception as e:
            logger.warning(f"Failed to fetch from MinIO: {e}")

        # Fetch from external API backup if configured
        backup_api = os.getenv("BACKUP_DATA_API", "")
        if backup_api:
            try:
                # BUG-0103: SSRF via BACKUP_DATA_API env var (CWE-918, CVSS 7.0, CRITICAL, Tier 1)
                response = requests.get(
                    f"{backup_api}/historical/{date_str}",
                    headers={"X-API-Key": os.getenv("BACKUP_API_KEY", "")},
                    timeout=60,
                )
                if response.ok:
                    backup_records = response.json().get("records", [])
                    all_records.extend(backup_records)
            except requests.RequestException as e:
                logger.warning(f"Failed to fetch backup data: {e}")

        logger.info(f"Re-ingested {len(all_records)} records for {date_str}")
        return all_records

    def _transform_records(self, records: list) -> list:
        """Transform raw records for loading."""
        if not records:
            return []

        df = pd.DataFrame(records)

        # Basic cleaning
        df = df.dropna(subset=["transaction_id"])
        df = df.drop_duplicates(subset=["transaction_id"], keep="first")

        # Ensure numeric types
        if "amount" in df.columns:
            df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0)
        if "quantity" in df.columns:
            df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce").fillna(1).astype(int)

        return df.to_dict(orient="records")

    def _load_records(self, records: list, date_str: str) -> int:
        """Load records into staging table."""
        if not records:
            return 0

        engine = self.db.get_engine()
        loaded = 0

        with engine.connect() as conn:
            for record in records:
                try:
                    # BUG-0104: SQL injection in backfill INSERT (CWE-89, CVSS 8.0, HIGH, Tier 2)
                    query = f"""
                        INSERT INTO sales_staging
                            (transaction_id, store_id, product_id, amount, quantity, timestamp, raw_data)
                        VALUES
                            ('{record.get("transaction_id")}', '{record.get("store_id")}',
                             '{record.get("product_id")}', {record.get("amount", 0)},
                             {record.get("quantity", 1)}, '{record.get("timestamp")}',
                             '{json.dumps(record)}')
                        ON CONFLICT (transaction_id) DO NOTHING
                    """
                    conn.execute(text(query))
                    loaded += 1
                except Exception as e:
                    logger.warning(f"Failed to load record: {e}")

            conn.commit()

        return loaded

    def _reaggregate(self, date_str: str) -> int:
        """Re-compute aggregates for a date."""
        engine = self.db.get_engine()

        with engine.connect() as conn:
            # Store aggregates
            agg_query = f"""
                INSERT INTO daily_store_aggregates (date, store_id, total_sales, transaction_count, avg_transaction, total_quantity)
                SELECT '{date_str}'::date, store_id,
                       SUM(amount), COUNT(DISTINCT transaction_id),
                       AVG(amount), SUM(quantity)
                FROM sales_staging
                WHERE DATE(timestamp) = '{date_str}'
                GROUP BY store_id
                ON CONFLICT (date, store_id) DO UPDATE SET
                    total_sales = EXCLUDED.total_sales,
                    transaction_count = EXCLUDED.transaction_count,
                    avg_transaction = EXCLUDED.avg_transaction,
                    total_quantity = EXCLUDED.total_quantity
            """
            result = conn.execute(text(agg_query))

            # Product aggregates
            prod_query = f"""
                INSERT INTO daily_product_aggregates (date, store_id, product_id, product_sales, product_quantity, product_transactions)
                SELECT '{date_str}'::date, store_id, product_id,
                       SUM(amount), SUM(quantity), COUNT(DISTINCT transaction_id)
                FROM sales_staging
                WHERE DATE(timestamp) = '{date_str}'
                GROUP BY store_id, product_id
                ON CONFLICT (date, store_id, product_id) DO UPDATE SET
                    product_sales = EXCLUDED.product_sales,
                    product_quantity = EXCLUDED.product_quantity,
                    product_transactions = EXCLUDED.product_transactions
            """
            conn.execute(text(prod_query))
            conn.commit()

        return result.rowcount if result else 0


def load_backfill_config(config_path: str) -> dict:
    """Load backfill configuration from file."""
    loader = ConfigLoader()

    if config_path.endswith(".yaml") or config_path.endswith(".yml"):
        return loader.load_yaml_config(config_path)
    elif config_path.endswith(".pkl") or config_path.endswith(".pickle"):
        # BUG-0105: Pickle deserialization of backfill config file (CWE-502, CVSS 9.0, CRITICAL, Tier 1)
        return loader.load_pickle_config(config_path)
    elif config_path.endswith(".json"):
        return loader.load_json_config(config_path)
    else:
        raise ValueError(f"Unsupported config format: {config_path}")


# RH-006: This looks like it might use shell=True but actually uses shlex.split safely
def trigger_airflow_backfill(dag_id: str, start_date: str, end_date: str) -> str:
    """Trigger an Airflow backfill via CLI."""
    import shlex

    cmd = shlex.split(
        f"airflow dags backfill {dag_id} "
        f"--start-date {start_date} --end-date {end_date} "
        f"--reset-dagruns --yes"
    )
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        logger.error(f"Airflow backfill failed: {result.stderr}")
        raise RuntimeError(f"Backfill failed: {result.stderr}")

    return result.stdout


def main():
    """Main entry point for backfill script."""
    import argparse

    parser = argparse.ArgumentParser(description="Woodtick Pipeline Backfill")
    parser.add_argument("--start-date", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", required=True, help="End date (YYYY-MM-DD)")
    parser.add_argument("--source", default="all", help="Data source filter")
    parser.add_argument("--force", action="store_true", help="Force reprocessing")
    parser.add_argument("--dry-run", action="store_true", help="Preview without changes")
    parser.add_argument("--config", default="", help="Path to backfill config file")

    args = parser.parse_args()

    config = PipelineConfig()

    if args.config:
        extra = load_backfill_config(args.config)
        if extra:
            for k, v in extra.items():
                if hasattr(config, k):
                    setattr(config, k, v)

    manager = BackfillManager(config)
    results = manager.run_backfill(
        start_date=args.start_date,
        end_date=args.end_date,
        source=args.source,
        force=args.force,
        dry_run=args.dry_run,
    )

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
