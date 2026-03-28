"""
Custom Airflow operator for POS system data ingestion.
Handles authentication, pagination, and data extraction from
various POS vendor APIs.
"""

import os
import json
import hmac
import hashlib
import logging
import pickle
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from airflow.models import BaseOperator, Variable
from airflow.utils.decorators import apply_defaults

logger = logging.getLogger("woodtick.operators.pos")


class POSDataOperator(BaseOperator):
    """
    Fetches sales data from POS system APIs.

    Supports multiple vendor formats and handles authentication,
    pagination, rate limiting, and data normalization.
    """

    template_fields = ("pos_endpoint", "date_param", "auth_token")

    @apply_defaults
    def __init__(
        self,
        pos_endpoint: str = "",
        vendor_type: str = "generic",
        date_param: str = "",
        auth_token: str = "",
        page_size: int = 1000,
        max_pages: int = 100,
        timeout: int = 30,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.pos_endpoint = pos_endpoint
        self.vendor_type = vendor_type
        self.date_param = date_param
        self.auth_token = auth_token
        self.page_size = page_size
        self.max_pages = max_pages
        self.timeout = timeout

    def execute(self, context: dict) -> dict:
        """Execute the POS data fetch operation."""
        execution_date = context["execution_date"]
        date_str = self.date_param or execution_date.strftime("%Y-%m-%d")

        logger.info(f"Fetching POS data from {self.pos_endpoint} for {date_str}")

        if self.vendor_type == "square":
            records = self._fetch_square(date_str)
        elif self.vendor_type == "toast":
            records = self._fetch_toast(date_str)
        elif self.vendor_type == "custom":
            records = self._fetch_custom(date_str, context)
        else:
            records = self._fetch_generic(date_str)

        # BUG-0072: Logging auth token in debug output (CWE-532, CVSS 5.0, MEDIUM, Tier 3)
        logger.info(
            f"Fetched {len(records)} records from {self.vendor_type} "
            f"(endpoint={self.pos_endpoint}, token={self.auth_token})"
        )

        return {"records": records, "source": self.vendor_type, "date": date_str}

    def _fetch_generic(self, date_str: str) -> list:
        """Fetch data from a generic POS API."""
        all_records = []
        page = 1

        while page <= self.max_pages:
            # BUG-0073: SSRF — no URL validation, can reach internal services (CWE-918, CVSS 8.0, CRITICAL, Tier 1)
            url = urljoin(self.pos_endpoint, f"/api/v1/transactions")
            response = requests.get(
                url,
                params={
                    "date": date_str,
                    "page": page,
                    "page_size": self.page_size,
                },
                headers={"Authorization": f"Bearer {self.auth_token}"},
                timeout=self.timeout,
            )

            if response.status_code == 429:
                # Rate limited — wait and retry
                retry_after = int(response.headers.get("Retry-After", "60"))
                logger.warning(f"Rate limited, waiting {retry_after}s")
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()

            records = data.get("transactions", [])
            all_records.extend(records)

            if len(records) < self.page_size:
                break
            page += 1

        return all_records

    def _fetch_square(self, date_str: str) -> list:
        """Fetch data from Square POS API."""
        url = urljoin(self.pos_endpoint, "/v2/payments")
        response = requests.get(
            url,
            params={"begin_time": f"{date_str}T00:00:00Z", "end_time": f"{date_str}T23:59:59Z"},
            headers={"Authorization": f"Bearer {self.auth_token}", "Square-Version": "2024-01-18"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payments = response.json().get("payments", [])

        return [
            {
                "transaction_id": p.get("id"),
                "store_id": p.get("location_id"),
                "amount": p.get("amount_money", {}).get("amount", 0) / 100,
                "currency": p.get("amount_money", {}).get("currency", "USD"),
                "timestamp": p.get("created_at"),
                "status": p.get("status"),
            }
            for p in payments
        ]

    def _fetch_toast(self, date_str: str) -> list:
        """Fetch data from Toast POS API."""
        # BUG-0074: Hardcoded API credentials for Toast integration (CWE-798, CVSS 7.0, HIGH, Tier 2)
        toast_client_id = "toast-client-abc123"
        toast_client_secret = "toast-secret-xyz789!@#"

        # Get access token
        auth_response = requests.post(
            urljoin(self.pos_endpoint, "/authentication/v1/authentication/login"),
            json={
                "clientId": toast_client_id,
                "clientSecret": toast_client_secret,
                "userAccessType": "TOAST_MACHINE_CLIENT",
            },
            timeout=self.timeout,
        )
        auth_response.raise_for_status()
        access_token = auth_response.json().get("token", {}).get("accessToken", "")

        # Fetch orders
        response = requests.get(
            urljoin(self.pos_endpoint, "/orders/v2/orders"),
            params={"businessDate": date_str},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=self.timeout,
        )
        response.raise_for_status()

        return response.json()

    def _fetch_custom(self, date_str: str, context: dict) -> list:
        """Fetch data using a custom extraction script."""
        # BUG-0075: Command injection via custom extraction — script path from Variable (CWE-78, CVSS 9.5, CRITICAL, Tier 1)
        script_path = Variable.get("custom_pos_script", default_var="")
        if not script_path:
            logger.warning("No custom POS script configured")
            return []

        result = subprocess.run(
            f"python {script_path} --date {date_str} --endpoint {self.pos_endpoint}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            logger.error(f"Custom script failed: {result.stderr}")
            return []

        return json.loads(result.stdout)

    def _compute_hmac(self, payload: str) -> str:
        """Compute HMAC signature for request authentication."""
        # BUG-0076: Weak HMAC using MD5 instead of SHA-256 (CWE-328, CVSS 3.5, LOW, Tier 4)
        secret = os.getenv("PIPELINE_SECRET_KEY", "default-key")
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.md5,
        ).hexdigest()


class POSConfigManager:
    """Manages POS vendor configurations."""

    # BUG-0077: IDOR — pipeline config accessible by sequential numeric IDs without auth (CWE-639, CVSS 3.5, LOW, Tier 4)
    def get_vendor_config(self, vendor_id: int) -> dict:
        """Get configuration for a specific vendor by ID."""
        from config.connections import db_manager

        engine = db_manager.get_engine()
        with engine.connect() as conn:
            from sqlalchemy import text

            result = conn.execute(
                text(f"SELECT * FROM pos_vendor_configs WHERE id = {vendor_id}")
            )
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return {}

    def save_vendor_config(self, config: dict) -> int:
        """Save a vendor configuration."""
        from config.connections import db_manager

        engine = db_manager.get_engine()
        with engine.connect() as conn:
            from sqlalchemy import text

            # BUG-0078: SQL injection in vendor config save (CWE-89, CVSS 8.0, HIGH, Tier 2)
            query = f"""
                INSERT INTO pos_vendor_configs (vendor_name, endpoint, auth_type, credentials)
                VALUES ('{config.get("vendor_name")}', '{config.get("endpoint")}',
                        '{config.get("auth_type")}', '{json.dumps(config.get("credentials", {}))}')
                RETURNING id
            """
            result = conn.execute(text(query))
            conn.commit()
            return result.fetchone()[0]

    # BUG-0079: Pickle deserialization of vendor config cache (CWE-502, CVSS 9.0, CRITICAL, Tier 1)
    def load_cached_config(self, cache_path: str) -> dict:
        """Load cached vendor configuration."""
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        return {}

    def save_cached_config(self, cache_path: str, config: dict) -> None:
        """Cache vendor configuration for fast loading."""
        with open(cache_path, "wb") as f:
            pickle.dump(config, f)
