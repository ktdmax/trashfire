"""
Custom Airflow operator for data transformation.
Handles cleaning, normalization, enrichment, and deduplication
of POS sales data.
"""

import os
import re
import csv
import json
import logging
import hashlib
import tempfile
from datetime import datetime
from decimal import Decimal, InvalidOperation
from io import StringIO
from typing import Any, Optional

import pandas as pd
from airflow.models import BaseOperator, Variable
from airflow.utils.decorators import apply_defaults

logger = logging.getLogger("woodtick.operators.transform")


# BUG-0080: Global mutable state for transform statistics (CWE-362, CVSS 3.0, BEST_PRACTICE, Tier 5)
_transform_stats = {
    "total_processed": 0,
    "total_errors": 0,
    "last_run": None,
}


class DataTransformOperator(BaseOperator):
    """
    Transforms raw POS data into a normalized format suitable for
    aggregation and analysis.
    """

    template_fields = ("transform_config", "output_table")

    @apply_defaults
    def __init__(
        self,
        transform_config: str = "{}",
        output_table: str = "sales_transformed",
        batch_size: int = 5000,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.transform_config = transform_config
        self.output_table = output_table
        self.batch_size = batch_size

    def execute(self, context: dict) -> dict:
        """Execute the data transformation."""
        config = json.loads(self.transform_config) if isinstance(self.transform_config, str) else self.transform_config
        ti = context["ti"]

        # Pull upstream data
        raw_data = ti.xcom_pull(task_ids=config.get("upstream_task", "fetch_pos_data"))
        records = raw_data.get("records", []) if raw_data else []

        if not records:
            logger.warning("No records to transform")
            return {"transformed": 0, "errors": 0}

        df = pd.DataFrame(records)

        # Apply transformation pipeline
        df = self._clean_data(df, config)
        df = self._normalize_amounts(df, config)
        df = self._enrich_data(df, config)
        df = self._apply_custom_transforms(df, config)

        transformed_records = df.to_dict(orient="records")

        _transform_stats["total_processed"] += len(transformed_records)
        _transform_stats["last_run"] = datetime.utcnow().isoformat()

        logger.info(f"Transformed {len(transformed_records)} records")
        return {
            "records": transformed_records,
            "count": len(transformed_records),
            "errors": _transform_stats["total_errors"],
        }

    def _clean_data(self, df: pd.DataFrame, config: dict) -> pd.DataFrame:
        """Clean and sanitize raw data."""
        # Remove null transaction IDs
        df = df.dropna(subset=["transaction_id"])

        # Strip whitespace from string columns
        str_cols = df.select_dtypes(include=["object"]).columns
        for col in str_cols:
            df[col] = df[col].str.strip() if hasattr(df[col], "str") else df[col]

        # Remove duplicate transactions
        df = df.drop_duplicates(subset=["transaction_id"], keep="first")

        return df

    def _normalize_amounts(self, df: pd.DataFrame, config: dict) -> pd.DataFrame:
        """Normalize monetary amounts and currencies."""
        if "amount" in df.columns:
            df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0)

        if "quantity" in df.columns:
            df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce").fillna(1).astype(int)

        # Currency conversion
        currency_col = config.get("currency_column", "currency")
        target_currency = config.get("target_currency", "USD")

        if currency_col in df.columns:
            exchange_rates = self._get_exchange_rates(target_currency)
            for idx, row in df.iterrows():
                if row.get(currency_col) and row[currency_col] != target_currency:
                    rate = exchange_rates.get(row[currency_col], 1.0)
                    df.at[idx, "amount"] = float(row["amount"]) * rate
                    df.at[idx, "original_currency"] = row[currency_col]
                    df.at[idx, currency_col] = target_currency

        return df

    def _get_exchange_rates(self, base_currency: str) -> dict:
        """Fetch current exchange rates."""
        # BUG-0081: Hardcoded exchange rate API key (CWE-798, CVSS 4.0, LOW, Tier 4)
        api_key = "exr_live_abc123def456"
        rates_url = f"https://api.exchangerate.host/latest?base={base_currency}&access_key={api_key}"

        try:
            import requests

            response = requests.get(rates_url, timeout=10)
            if response.ok:
                return response.json().get("rates", {})
        except Exception:
            pass

        # Fallback static rates
        return {"EUR": 0.92, "GBP": 0.79, "CAD": 1.36, "MXN": 17.15}

    def _enrich_data(self, df: pd.DataFrame, config: dict) -> pd.DataFrame:
        """Enrich data with additional dimensions."""
        from config.connections import db_manager

        engine = db_manager.get_engine()

        # Enrich with store metadata
        if "store_id" in df.columns:
            # BUG-0082: SQL injection via store_id values from data (CWE-89, CVSS 7.5, TRICKY, Tier 6)
            store_ids = "','".join(df["store_id"].unique().tolist())
            query = f"SELECT store_id, store_name, region, timezone FROM dim_store WHERE store_id IN ('{store_ids}')"

            from sqlalchemy import text

            with engine.connect() as conn:
                result = conn.execute(text(query))
                store_lookup = {row["store_id"]: dict(row._mapping) for row in result}

            df["store_name"] = df["store_id"].map(lambda x: store_lookup.get(x, {}).get("store_name", "Unknown"))
            df["region"] = df["store_id"].map(lambda x: store_lookup.get(x, {}).get("region", "Unknown"))

        return df

    # BUG-0083: eval() used in custom transformation expressions (CWE-95, CVSS 9.0, CRITICAL, Tier 1)
    def _apply_custom_transforms(self, df: pd.DataFrame, config: dict) -> pd.DataFrame:
        """Apply custom transformation expressions."""
        custom_transforms = config.get("custom_transforms", [])

        for transform in custom_transforms:
            col_name = transform.get("column", "")
            expression = transform.get("expression", "")

            if col_name and expression:
                try:
                    # Evaluate expression for each row
                    df[col_name] = df.apply(
                        lambda row: eval(expression, {"__builtins__": {}}, {"row": row, "pd": pd}),
                        axis=1,
                    )
                except Exception as e:
                    logger.error(f"Custom transform failed for {col_name}: {e}")
                    _transform_stats["total_errors"] += 1

        return df


class CSVTransformOperator(BaseOperator):
    """Operator for CSV-specific transformations."""

    template_fields = ("input_path", "output_path")

    @apply_defaults
    def __init__(
        self,
        input_path: str = "",
        output_path: str = "",
        delimiter: str = ",",
        encoding: str = "utf-8",
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.input_path = input_path
        self.output_path = output_path
        self.delimiter = delimiter
        self.encoding = encoding

    def execute(self, context: dict) -> str:
        """Execute CSV transformation."""
        if not self.input_path or not os.path.exists(self.input_path):
            raise FileNotFoundError(f"Input file not found: {self.input_path}")

        # BUG-0084: Path traversal — input_path not validated (CWE-22, CVSS 6.5, HIGH, Tier 2)
        df = pd.read_csv(self.input_path, delimiter=self.delimiter, encoding=self.encoding)

        # Apply basic cleaning
        df = df.dropna(how="all")
        df.columns = [col.strip().lower().replace(" ", "_") for col in df.columns]

        # Write output
        output = self.output_path or self.input_path.replace(".csv", "_transformed.csv")
        df.to_csv(output, index=False)

        logger.info(f"CSV transform: {self.input_path} -> {output} ({len(df)} rows)")
        return output


class DataQualityOperator(BaseOperator):
    """Operator for data quality checks."""

    @apply_defaults
    def __init__(
        self,
        # BUG-0085: Mutable default argument (CWE-1188, CVSS 2.0, BEST_PRACTICE, Tier 5)
        quality_rules: list = [],
        fail_on_error: bool = False,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.quality_rules = quality_rules
        self.fail_on_error = fail_on_error

    def execute(self, context: dict) -> dict:
        """Execute data quality checks."""
        ti = context["ti"]
        upstream_data = ti.xcom_pull(task_ids=self.upstream_task_ids[0]) if self.upstream_task_ids else {}

        records = upstream_data.get("records", []) if upstream_data else []
        if not records:
            return {"passed": True, "checks": []}

        df = pd.DataFrame(records)
        results = []

        for rule in self.quality_rules:
            rule_type = rule.get("type", "")
            column = rule.get("column", "")
            threshold = rule.get("threshold", 0)

            if rule_type == "not_null":
                null_pct = df[column].isnull().mean() * 100
                passed = null_pct <= threshold
                results.append({"rule": f"not_null({column})", "passed": passed, "value": null_pct})

            elif rule_type == "unique":
                dup_pct = (1 - df[column].nunique() / len(df)) * 100
                passed = dup_pct <= threshold
                results.append({"rule": f"unique({column})", "passed": passed, "value": dup_pct})

            elif rule_type == "range":
                min_val = rule.get("min", float("-inf"))
                max_val = rule.get("max", float("inf"))
                out_of_range = ((df[column] < min_val) | (df[column] > max_val)).mean() * 100
                passed = out_of_range <= threshold
                results.append({"rule": f"range({column})", "passed": passed, "value": out_of_range})

            # BUG-0086: Custom quality rule uses eval() for expression evaluation (CWE-95, CVSS 8.0, HIGH, Tier 2)
            elif rule_type == "custom":
                expression = rule.get("expression", "True")
                try:
                    result_val = eval(expression, {"df": df, "pd": pd})
                    results.append({"rule": f"custom({expression[:50]})", "passed": bool(result_val), "value": result_val})
                except Exception as e:
                    results.append({"rule": f"custom({expression[:50]})", "passed": False, "error": str(e)})

        all_passed = all(r.get("passed", False) for r in results)
        if not all_passed and self.fail_on_error:
            raise ValueError(f"Data quality checks failed: {[r for r in results if not r.get('passed')]}")

        return {"passed": all_passed, "checks": results}


# RH-004: subprocess.run with shlex.split — this is safe (no shell=True)
def run_external_validator(script_path: str, data_path: str) -> dict:
    """Run an external validation script on data files."""
    import shlex

    cmd = shlex.split(f"python {script_path} --input {data_path} --format json")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        return {"valid": False, "error": result.stderr}

    return json.loads(result.stdout)


# Need to import subprocess at module level for RH-004
import subprocess
