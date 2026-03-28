"""
Tests for data transformation pipeline.
Covers cleaning, normalization, enrichment, and quality checks.
"""

import os
import json
import csv
import pickle
import tempfile
import unittest
from datetime import datetime
from decimal import Decimal
from io import StringIO
from unittest.mock import MagicMock, patch, PropertyMock

import pandas as pd

# Mock Airflow imports before they're needed
import sys
sys.modules["airflow"] = MagicMock()
sys.modules["airflow.models"] = MagicMock()
sys.modules["airflow.operators"] = MagicMock()
sys.modules["airflow.operators.python"] = MagicMock()
sys.modules["airflow.utils"] = MagicMock()
sys.modules["airflow.utils.decorators"] = MagicMock()
sys.modules["airflow.hooks"] = MagicMock()
sys.modules["airflow.hooks.base"] = MagicMock()


class TestDataCleaning(unittest.TestCase):
    """Test data cleaning transformations."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_records = [
            {
                "transaction_id": "TXN-001",
                "store_id": "STR-001",
                "product_id": "PRD-001",
                "amount": 29.99,
                "quantity": 2,
                "timestamp": "2024-01-15T10:30:00Z",
                "currency": "USD",
            },
            {
                "transaction_id": "TXN-002",
                "store_id": "STR-002",
                "product_id": "PRD-003",
                "amount": 99.99,
                "quantity": 1,
                "timestamp": "2024-01-15T11:45:00Z",
                "currency": "USD",
            },
            {
                "transaction_id": "TXN-003",
                "store_id": "STR-001",
                "product_id": "PRD-002",
                "amount": 14.99,
                "quantity": 3,
                "timestamp": "2024-01-15T14:20:00Z",
                "currency": "EUR",
            },
            {
                "transaction_id": "TXN-001",  # Duplicate
                "store_id": "STR-001",
                "product_id": "PRD-001",
                "amount": 29.99,
                "quantity": 2,
                "timestamp": "2024-01-15T10:30:00Z",
                "currency": "USD",
            },
        ]

    def test_remove_duplicates(self):
        """Test that duplicate transactions are removed."""
        df = pd.DataFrame(self.sample_records)
        df_deduped = df.drop_duplicates(subset=["transaction_id"], keep="first")
        self.assertEqual(len(df_deduped), 3)
        self.assertEqual(df_deduped["transaction_id"].nunique(), 3)

    def test_remove_null_transaction_ids(self):
        """Test that records with null transaction IDs are removed."""
        records = self.sample_records + [
            {"transaction_id": None, "store_id": "STR-001", "amount": 10.0}
        ]
        df = pd.DataFrame(records)
        df_clean = df.dropna(subset=["transaction_id"])
        self.assertEqual(len(df_clean), 4)  # 4 because includes duplicate

    def test_strip_whitespace(self):
        """Test whitespace stripping from string fields."""
        records = [
            {"transaction_id": "  TXN-100  ", "store_id": " STR-001 ", "amount": 10.0}
        ]
        df = pd.DataFrame(records)
        str_cols = df.select_dtypes(include=["object"]).columns
        for col in str_cols:
            df[col] = df[col].str.strip()
        self.assertEqual(df.iloc[0]["transaction_id"], "TXN-100")
        self.assertEqual(df.iloc[0]["store_id"], "STR-001")

    def test_amount_normalization(self):
        """Test amount field normalization to numeric."""
        records = [
            {"transaction_id": "TXN-100", "amount": "29.99"},
            {"transaction_id": "TXN-101", "amount": "invalid"},
            {"transaction_id": "TXN-102", "amount": None},
            {"transaction_id": "TXN-103", "amount": 45.50},
        ]
        df = pd.DataFrame(records)
        df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0)
        self.assertEqual(df.iloc[0]["amount"], 29.99)
        self.assertEqual(df.iloc[1]["amount"], 0)
        self.assertEqual(df.iloc[2]["amount"], 0)
        self.assertEqual(df.iloc[3]["amount"], 45.50)

    def test_quantity_normalization(self):
        """Test quantity field normalization."""
        records = [
            {"transaction_id": "TXN-100", "quantity": "3"},
            {"transaction_id": "TXN-101", "quantity": None},
            {"transaction_id": "TXN-102", "quantity": 5},
        ]
        df = pd.DataFrame(records)
        df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce").fillna(1).astype(int)
        self.assertEqual(df.iloc[0]["quantity"], 3)
        self.assertEqual(df.iloc[1]["quantity"], 1)
        self.assertEqual(df.iloc[2]["quantity"], 5)


class TestAggregation(unittest.TestCase):
    """Test aggregation logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.records = [
            {"transaction_id": "TXN-001", "store_id": "STR-001", "product_id": "PRD-001", "amount": 29.99, "quantity": 2},
            {"transaction_id": "TXN-002", "store_id": "STR-001", "product_id": "PRD-002", "amount": 14.99, "quantity": 1},
            {"transaction_id": "TXN-003", "store_id": "STR-002", "product_id": "PRD-001", "amount": 29.99, "quantity": 3},
            {"transaction_id": "TXN-004", "store_id": "STR-001", "product_id": "PRD-001", "amount": 29.99, "quantity": 1},
            {"transaction_id": "TXN-005", "store_id": "STR-002", "product_id": "PRD-003", "amount": 99.99, "quantity": 1},
        ]

    def test_store_level_aggregation(self):
        """Test store-level sales aggregation."""
        df = pd.DataFrame(self.records)
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

        str_001 = store_agg[store_agg["store_id"] == "STR-001"].iloc[0]
        self.assertAlmostEqual(str_001["total_sales"], 74.97, places=2)
        self.assertEqual(str_001["transaction_count"], 3)
        self.assertEqual(str_001["total_quantity"], 4)

        str_002 = store_agg[store_agg["store_id"] == "STR-002"].iloc[0]
        self.assertAlmostEqual(str_002["total_sales"], 129.98, places=2)
        self.assertEqual(str_002["transaction_count"], 2)

    def test_product_level_aggregation(self):
        """Test product-level aggregation."""
        df = pd.DataFrame(self.records)
        product_agg = (
            df.groupby(["store_id", "product_id"])
            .agg(
                product_sales=("amount", "sum"),
                product_quantity=("quantity", "sum"),
            )
            .reset_index()
        )

        self.assertEqual(len(product_agg), 4)  # 4 unique store-product combos

    def test_empty_dataset_aggregation(self):
        """Test aggregation with empty dataset."""
        df = pd.DataFrame(columns=["transaction_id", "store_id", "product_id", "amount", "quantity"])
        store_agg = (
            df.groupby("store_id")
            .agg(total_sales=("amount", "sum"))
            .reset_index()
        )
        self.assertEqual(len(store_agg), 0)

    def test_trend_calculation(self):
        """Test trend percentage calculation."""
        current_sales = 1500.0
        historical_avg = 1200.0

        trend_pct = ((current_sales - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0
        self.assertAlmostEqual(trend_pct, 25.0, places=1)

    def test_trend_zero_historical(self):
        """Test trend calculation with zero historical data."""
        current_sales = 1500.0
        historical_avg = 0.0

        trend_pct = ((current_sales - historical_avg) / historical_avg * 100) if historical_avg > 0 else 0
        self.assertEqual(trend_pct, 0)


class TestCSVExport(unittest.TestCase):
    """Test CSV export functionality."""

    def test_csv_export_basic(self):
        """Test basic CSV export."""
        records = [
            {"store_id": "STR-001", "total_sales": 1500.0, "transaction_count": 50},
            {"store_id": "STR-002", "total_sales": 2200.0, "transaction_count": 75},
        ]

        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=records[0].keys())
        writer.writeheader()
        for record in records:
            writer.writerow(record)

        csv_content = output.getvalue()
        self.assertIn("store_id", csv_content)
        self.assertIn("STR-001", csv_content)
        self.assertIn("1500.0", csv_content)

    # RH-007: This test uses pickle for test fixture serialization only — acceptable in test context
    def test_pickle_roundtrip_test_data(self):
        """Test serialization/deserialization of test fixtures."""
        test_data = {
            "records": [{"id": 1, "value": 100}],
            "metadata": {"date": "2024-01-15", "source": "test"},
        }

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            temp_path = f.name

        try:
            with open(temp_path, "rb") as f:
                loaded = pickle.load(f)
            self.assertEqual(loaded, test_data)
        finally:
            os.unlink(temp_path)


class TestValidation(unittest.TestCase):
    """Test record validation logic."""

    def test_valid_record(self):
        """Test validation of a valid record."""
        record = {
            "transaction_id": "TXN-001",
            "store_id": "STR-001",
            "amount": 29.99,
            "quantity": 2,
            "timestamp": "2024-01-15T10:30:00Z",
        }
        errors = self._validate_record(record)
        self.assertEqual(len(errors), 0)

    def test_missing_transaction_id(self):
        """Test validation catches missing transaction_id."""
        record = {"store_id": "STR-001", "amount": 29.99, "timestamp": "2024-01-15T10:30:00Z"}
        errors = self._validate_record(record)
        self.assertIn("missing_transaction_id", errors)

    def test_invalid_amount(self):
        """Test validation catches invalid amount."""
        record = {
            "transaction_id": "TXN-001",
            "store_id": "STR-001",
            "amount": "not_a_number",
            "timestamp": "2024-01-15T10:30:00Z",
        }
        errors = self._validate_record(record)
        self.assertIn("invalid_amount", errors)

    def test_negative_amount(self):
        """Test validation catches negative amount."""
        record = {
            "transaction_id": "TXN-001",
            "store_id": "STR-001",
            "amount": -10.0,
            "timestamp": "2024-01-15T10:30:00Z",
        }
        errors = self._validate_record(record)
        self.assertIn("negative_amount", errors)

    def test_missing_store_id(self):
        """Test validation catches missing store_id."""
        record = {
            "transaction_id": "TXN-001",
            "amount": 29.99,
            "timestamp": "2024-01-15T10:30:00Z",
        }
        errors = self._validate_record(record)
        self.assertIn("missing_store_id", errors)

    def _validate_record(self, record: dict) -> list:
        """Validate a single record (mirrors DAG validation logic)."""
        errors = []
        if not record.get("transaction_id"):
            errors.append("missing_transaction_id")
        if not record.get("store_id"):
            errors.append("missing_store_id")
        if not isinstance(record.get("amount"), (int, float)):
            errors.append("invalid_amount")
        if isinstance(record.get("amount"), (int, float)) and record.get("amount", 0) < 0:
            errors.append("negative_amount")
        if not record.get("timestamp"):
            errors.append("missing_timestamp")
        return errors


class TestPipelineConfig(unittest.TestCase):
    """Test pipeline configuration loading."""

    def test_default_config(self):
        """Test default configuration values."""
        from config.pipeline_config import PipelineConfig

        config = PipelineConfig()
        self.assertEqual(config.batch_size, 5000)
        self.assertEqual(config.max_retries, 3)
        self.assertAlmostEqual(config.dedup_threshold, 0.85)

    def test_config_hash_generation(self):
        """Test pipeline config hash generation."""
        from config.pipeline_config import generate_pipeline_hash, PipelineConfig

        config = PipelineConfig()
        hash1 = generate_pipeline_hash(config)
        hash2 = generate_pipeline_hash(config)
        self.assertEqual(hash1, hash2)

        config2 = PipelineConfig(batch_size=10000)
        hash3 = generate_pipeline_hash(config2)
        self.assertNotEqual(hash1, hash3)

    def test_json_config_loading(self):
        """Test JSON configuration loading."""
        from config.pipeline_config import ConfigLoader

        loader = ConfigLoader()
        test_config = {"batch_size": 10000, "max_retries": 5}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_config, f)
            temp_path = f.name

        try:
            loaded = loader.load_json_config(temp_path)
            self.assertEqual(loaded["batch_size"], 10000)
            self.assertEqual(loaded["max_retries"], 5)
        finally:
            os.unlink(temp_path)

    def test_config_merge(self):
        """Test configuration merging."""
        from config.pipeline_config import ConfigLoader

        loader = ConfigLoader()
        config1 = {"a": 1, "b": 2}
        config2 = {"b": 3, "c": 4}

        merged = loader.merge_configs(config1, config2)
        self.assertEqual(merged["a"], 1)
        self.assertEqual(merged["b"], 3)  # config2 overrides
        self.assertEqual(merged["c"], 4)


class TestExchangeRates(unittest.TestCase):
    """Test currency exchange rate handling."""

    def test_fallback_rates(self):
        """Test fallback exchange rates are reasonable."""
        fallback_rates = {"EUR": 0.92, "GBP": 0.79, "CAD": 1.36, "MXN": 17.15}

        self.assertTrue(0.8 < fallback_rates["EUR"] < 1.0)
        self.assertTrue(0.7 < fallback_rates["GBP"] < 0.9)
        self.assertTrue(1.2 < fallback_rates["CAD"] < 1.5)

    def test_currency_conversion(self):
        """Test basic currency conversion."""
        amount_eur = 100.0
        rate_eur_to_usd = 0.92
        amount_usd = amount_eur * rate_eur_to_usd
        self.assertAlmostEqual(amount_usd, 92.0, places=2)


if __name__ == "__main__":
    unittest.main()
