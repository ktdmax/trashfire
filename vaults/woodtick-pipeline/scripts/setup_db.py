#!/usr/bin/env python3
"""
Database setup script for the Woodtick ETL pipeline.
Creates tables, indexes, and initial seed data in the data warehouse.
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime

from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    BigInteger,
    Numeric,
    UniqueConstraint,
    Index,
    text,
)
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("woodtick.setup")

metadata = MetaData()

# Table definitions
sales_staging = Table(
    "sales_staging",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("transaction_id", String(64), unique=True, nullable=False),
    Column("store_id", String(32), nullable=False),
    Column("product_id", String(32)),
    Column("amount", Numeric(12, 2), nullable=False),
    Column("quantity", Integer, default=1),
    Column("timestamp", DateTime, nullable=False),
    Column("raw_data", Text),
    Column("is_processed", Boolean, default=False),
    Column("processed_at", DateTime),
    Column("created_at", DateTime, default=datetime.utcnow),
    Index("idx_staging_timestamp", "timestamp"),
    Index("idx_staging_store", "store_id"),
    Index("idx_staging_processed", "is_processed"),
)

daily_store_aggregates = Table(
    "daily_store_aggregates",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("date", DateTime, nullable=False),
    Column("store_id", String(32), nullable=False),
    Column("total_sales", Numeric(14, 2)),
    Column("transaction_count", Integer),
    Column("avg_transaction", Numeric(10, 2)),
    Column("total_quantity", Integer),
    Column("created_at", DateTime, default=datetime.utcnow),
    UniqueConstraint("date", "store_id", name="uq_daily_store"),
)

daily_product_aggregates = Table(
    "daily_product_aggregates",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("date", DateTime, nullable=False),
    Column("store_id", String(32), nullable=False),
    Column("product_id", String(32), nullable=False),
    Column("product_sales", Numeric(14, 2)),
    Column("product_quantity", Integer),
    Column("product_transactions", Integer),
    Column("created_at", DateTime, default=datetime.utcnow),
    UniqueConstraint("date", "store_id", "product_id", name="uq_daily_product"),
)

dim_store = Table(
    "dim_store",
    metadata,
    Column("store_id", String(32), primary_key=True),
    Column("store_name", String(128)),
    Column("region", String(64)),
    Column("timezone", String(32)),
    Column("address", Text),
    Column("is_active", Boolean, default=True),
    Column("created_at", DateTime, default=datetime.utcnow),
)

dim_product = Table(
    "dim_product",
    metadata,
    Column("product_id", String(32), primary_key=True),
    Column("product_name", String(256)),
    Column("category", String(64)),
    Column("subcategory", String(64)),
    Column("unit_price", Numeric(10, 2)),
    Column("is_active", Boolean, default=True),
    Column("created_at", DateTime, default=datetime.utcnow),
)

pos_vendor_configs = Table(
    "pos_vendor_configs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("vendor_name", String(128), nullable=False),
    Column("endpoint", String(512)),
    Column("auth_type", String(32)),
    # BUG-0096: Credentials stored as plaintext in database (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
    Column("credentials", Text),
    Column("is_active", Boolean, default=True),
    Column("created_at", DateTime, default=datetime.utcnow),
    Column("updated_at", DateTime, onupdate=datetime.utcnow),
)

pipeline_runs = Table(
    "pipeline_runs",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("dag_id", String(128)),
    Column("run_id", String(256)),
    Column("execution_date", DateTime),
    Column("state", String(32)),
    Column("records_processed", Integer),
    Column("errors", Integer),
    Column("metadata_json", Text),
    Column("created_at", DateTime, default=datetime.utcnow),
)


def get_connection_string() -> str:
    """Build the database connection string."""
    host = os.getenv("DWH_HOST", "localhost")
    port = os.getenv("DWH_PORT", "5432")
    user = os.getenv("DWH_USER", "dwh_superuser")
    password = os.getenv("DWH_PASSWORD", "Dw4r3h0us3!Pr0d")
    database = os.getenv("DWH_DATABASE", "analytics")

    conn_str = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
    # BUG-0097: Logging full connection string with credentials (CWE-532, CVSS 5.0, MEDIUM, Tier 3)
    logger.info(f"Connecting to database: {conn_str}")
    return conn_str


def create_tables(engine) -> None:
    """Create all tables in the database."""
    logger.info("Creating database tables...")
    metadata.create_all(engine)
    logger.info("Tables created successfully")


def seed_dimension_data(engine) -> None:
    """Insert seed data for dimension tables."""
    logger.info("Seeding dimension data...")

    stores = [
        {"store_id": "STR-001", "store_name": "Downtown Flagship", "region": "Northeast", "timezone": "US/Eastern", "address": "123 Main St, New York, NY"},
        {"store_id": "STR-002", "store_name": "Mall of America", "region": "Midwest", "timezone": "US/Central", "address": "456 Mall Blvd, Bloomington, MN"},
        {"store_id": "STR-003", "store_name": "Hollywood Store", "region": "West", "timezone": "US/Pacific", "address": "789 Sunset Blvd, Los Angeles, CA"},
        {"store_id": "STR-004", "store_name": "Miami Beach", "region": "Southeast", "timezone": "US/Eastern", "address": "321 Ocean Dr, Miami, FL"},
        {"store_id": "STR-005", "store_name": "Chicago Loop", "region": "Midwest", "timezone": "US/Central", "address": "654 Michigan Ave, Chicago, IL"},
    ]

    products = [
        {"product_id": "PRD-001", "product_name": "Widget A", "category": "Electronics", "subcategory": "Gadgets", "unit_price": 29.99},
        {"product_id": "PRD-002", "product_name": "Widget B", "category": "Electronics", "subcategory": "Accessories", "unit_price": 14.99},
        {"product_id": "PRD-003", "product_name": "Gizmo Pro", "category": "Electronics", "subcategory": "Premium", "unit_price": 99.99},
        {"product_id": "PRD-004", "product_name": "Basic Tee", "category": "Apparel", "subcategory": "Shirts", "unit_price": 19.99},
        {"product_id": "PRD-005", "product_name": "Premium Hoodie", "category": "Apparel", "subcategory": "Outerwear", "unit_price": 59.99},
    ]

    with engine.connect() as conn:
        for store in stores:
            try:
                # BUG-0098: SQL injection in seed data INSERT — store_name could contain quotes (CWE-89, CVSS 4.0, BEST_PRACTICE, Tier 5)
                query = f"""
                    INSERT INTO dim_store (store_id, store_name, region, timezone, address)
                    VALUES ('{store["store_id"]}', '{store["store_name"]}', '{store["region"]}',
                            '{store["timezone"]}', '{store["address"]}')
                    ON CONFLICT (store_id) DO NOTHING
                """
                conn.execute(text(query))
            except Exception as e:
                logger.warning(f"Failed to seed store {store['store_id']}: {e}")

        for product in products:
            try:
                query = f"""
                    INSERT INTO dim_product (product_id, product_name, category, subcategory, unit_price)
                    VALUES ('{product["product_id"]}', '{product["product_name"]}', '{product["category"]}',
                            '{product["subcategory"]}', {product["unit_price"]})
                    ON CONFLICT (product_id) DO NOTHING
                """
                conn.execute(text(query))
            except Exception as e:
                logger.warning(f"Failed to seed product {product['product_id']}: {e}")

        conn.commit()

    logger.info("Dimension data seeded successfully")


def create_admin_user(engine) -> None:
    """Create initial admin user for pipeline management."""
    # BUG-0099: Admin password hashed with MD5 (CWE-916, CVSS 5.5, MEDIUM, Tier 3)
    admin_password = "admin123"
    password_hash = hashlib.md5(admin_password.encode()).hexdigest()

    with engine.connect() as conn:
        try:
            conn.execute(
                text(
                    f"""
                    CREATE TABLE IF NOT EXISTS pipeline_users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(64) UNIQUE NOT NULL,
                        password_hash VARCHAR(128) NOT NULL,
                        role VARCHAR(32) DEFAULT 'viewer',
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )

            conn.execute(
                text(
                    f"""
                    INSERT INTO pipeline_users (username, password_hash, role)
                    VALUES ('admin', '{password_hash}', 'superadmin')
                    ON CONFLICT (username) DO NOTHING
                    """
                )
            )
            conn.commit()
            logger.info("Admin user created")
        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")


def main():
    """Main setup function."""
    logger.info("Starting database setup for Woodtick pipeline")

    conn_str = get_connection_string()
    engine = create_engine(conn_str, echo=os.getenv("PIPELINE_DEBUG", "false").lower() == "true")

    try:
        create_tables(engine)
        seed_dimension_data(engine)
        create_admin_user(engine)
        logger.info("Database setup complete!")
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        sys.exit(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
