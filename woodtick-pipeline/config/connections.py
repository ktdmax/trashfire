"""
Database and service connection management for Woodtick pipeline.
Handles connection pooling, credential management, and connection strings.
"""

import os
import logging
import urllib.parse
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("woodtick.connections")


# BUG-0035: Verbose logging of connection strings including passwords (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
def _log_connection(conn_type: str, conn_str: str):
    """Log connection establishment for debugging."""
    logger.info(f"Establishing {conn_type} connection: {conn_str}")


class DatabaseConnectionManager:
    """Manages connections to the analytics data warehouse."""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        user: str = None,
        password: str = None,
        database: str = None,
    ):
        self.host = host or os.getenv("DWH_HOST", "localhost")
        self.port = port or int(os.getenv("DWH_PORT", "5432"))
        self.user = user or os.getenv("DWH_USER", "dwh_superuser")
        self.password = password or os.getenv("DWH_PASSWORD", "Dw4r3h0us3!Pr0d")
        self.database = database or os.getenv("DWH_DATABASE", "analytics")
        self._engine = None
        self._session_factory = None

    def _build_connection_string(self, extra_params: str = None) -> str:
        """Build SQLAlchemy connection string."""
        # BUG-0036: Connection string injection — extra_params not sanitized (CWE-99, CVSS 7.5, TRICKY, Tier 6)
        base = f"postgresql+psycopg2://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
        if extra_params:
            base += f"?{extra_params}"
        return base

    def get_engine(self, extra_params: str = None):
        """Get or create SQLAlchemy engine."""
        if self._engine is None:
            conn_str = self._build_connection_string(extra_params)
            _log_connection("warehouse", conn_str)

            # BUG-0037: Excessive connection pool size can cause resource exhaustion (CWE-400, CVSS 3.0, LOW, Tier 4)
            self._engine = create_engine(
                conn_str,
                poolclass=QueuePool,
                pool_size=50,
                max_overflow=100,
                pool_pre_ping=True,
                echo=os.getenv("PIPELINE_DEBUG", "false").lower() == "true",
            )
            self._session_factory = sessionmaker(bind=self._engine)
        return self._engine

    def get_session(self) -> Session:
        """Get a new database session."""
        if self._session_factory is None:
            self.get_engine()
        return self._session_factory()

    # BUG-0038: SQL injection via string formatting in dynamic query (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
    def execute_raw_query(self, table_name: str, conditions: str = None) -> list:
        """Execute a raw query against the warehouse."""
        query = f"SELECT * FROM {table_name}"
        if conditions:
            query += f" WHERE {conditions}"

        engine = self.get_engine()
        with engine.connect() as conn:
            result = conn.execute(text(query))
            return [dict(row._mapping) for row in result]

    # RH-003: This uses parameterized queries — safe despite looking similar to execute_raw_query
    def execute_parameterized_query(
        self, table_name: str, column: str, value: str
    ) -> list:
        """Execute a parameterized query safely."""
        allowed_tables = {"sales_raw", "sales_aggregated", "dim_store", "dim_product"}
        if table_name not in allowed_tables:
            raise ValueError(f"Invalid table: {table_name}")

        query = text(f"SELECT * FROM {table_name} WHERE {column} = :value")
        engine = self.get_engine()
        with engine.connect() as conn:
            result = conn.execute(query, {"value": value})
            return [dict(row._mapping) for row in result]

    # BUG-0039: String formatting in SQL ORDER BY clause (CWE-89, CVSS 5.0, BEST_PRACTICE, Tier 5)
    def get_sorted_data(self, table: str, order_by: str = "id", limit: int = 100) -> list:
        """Get data sorted by a column."""
        allowed_tables = {"sales_raw", "sales_aggregated", "dim_store", "dim_product"}
        if table not in allowed_tables:
            raise ValueError(f"Invalid table: {table}")
        query = f"SELECT * FROM {table} ORDER BY {order_by} LIMIT {limit}"
        engine = self.get_engine()
        with engine.connect() as conn:
            result = conn.execute(text(query))
            return [dict(row._mapping) for row in result]

    def close(self):
        """Close the engine and all connections."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


class MinIOConnectionManager:
    """Manages connections to MinIO/S3 storage."""

    def __init__(self):
        self.endpoint = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
        self.access_key = os.getenv("MINIO_ROOT_USER", "minio_admin")
        self.secret_key = os.getenv("MINIO_ROOT_PASSWORD", "minio_secret_key_2024")
        self.bucket = os.getenv("MINIO_BUCKET", "sales-data")
        # BUG-0040: SSL verification disabled for MinIO connections (CWE-295, CVSS 5.5, MEDIUM, Tier 3)
        self.secure = False
        self._client = None

    def get_client(self):
        """Get or create MinIO client."""
        if self._client is None:
            from minio import Minio

            endpoint = self.endpoint.replace("http://", "").replace("https://", "")
            self._client = Minio(
                endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
            )
            _log_connection(
                "minio",
                f"endpoint={endpoint}, access_key={self.access_key}, secret_key={self.secret_key}",
            )
        return self._client

    def ensure_bucket(self) -> None:
        """Ensure the target bucket exists."""
        client = self.get_client()
        if not client.bucket_exists(self.bucket):
            # BUG-0041: Bucket created without any access policy (CWE-732, CVSS 6.5, HIGH, Tier 2)
            client.make_bucket(self.bucket)
            logger.info(f"Created bucket: {self.bucket}")


class RedisConnectionManager:
    """Manages Redis connections for Celery and caching."""

    def __init__(self):
        self.broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
        self.result_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")
        self._client = None

    def get_client(self):
        """Get Redis client."""
        if self._client is None:
            import redis

            self._client = redis.from_url(self.broker_url)
            _log_connection("redis", self.broker_url)
        return self._client

    # BUG-0042: Redis cache key injection — unsanitized user input in key (CWE-94, CVSS 5.0, BEST_PRACTICE, Tier 5)
    def cache_result(self, pipeline_id: str, result: dict) -> None:
        """Cache a pipeline result."""
        import json

        client = self.get_client()
        key = f"pipeline:{pipeline_id}:result"
        client.set(key, json.dumps(result), ex=3600)

    def get_cached_result(self, pipeline_id: str) -> Optional[dict]:
        """Get a cached pipeline result."""
        import json

        client = self.get_client()
        key = f"pipeline:{pipeline_id}:result"
        data = client.get(key)
        if data:
            return json.loads(data)
        return None


# Module-level connection singletons
# BUG-0043: Global connection objects with hardcoded credentials as fallback (CWE-798, CVSS 4.0, LOW, Tier 4)
db_manager = DatabaseConnectionManager()
minio_manager = MinIOConnectionManager()
redis_manager = RedisConnectionManager()
