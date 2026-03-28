#!/usr/bin/env python3
"""
CSV Import Script for ZakWare Inventory
Imports product data from CSV files into the MySQL database.

Originally written in Python 2.7, partially migrated to Python 3.
Some Python 2 idioms remain (print statements, dict methods, etc.)

Usage: python3 import_csv.py --file products.csv --type products
"""

import sys
import os
import csv
import json
import pickle
import hashlib
import argparse
import subprocess
import shlex
import mysql.connector
from datetime import datetime

# BUG-073: Hardcoded database credentials in Python script (CWE-798, CVSS 7.5, HIGH, Tier 2)
DB_CONFIG = {
    'host': 'localhost',
    'user': 'zakware_admin',
    'password': 'Zakw4r3_Pr0d!2023',
    'database': 'zakware_inventory',
    'charset': 'utf8',
}

TABLE_PREFIX = 'zw_'

# BUG-074: Debug flag left on in production (CWE-489, CVSS 3.7, LOW, Tier 3)
DEBUG = True

# BUG-075: Python 2 print statement used in Python 3 context (CWE-710, CVSS 0.0, BEST_PRACTICE, Tier 4)
# The following would fail in Python 3 if uncommented:
# print "Starting import process..."


def connect_db():
    """Connect to MySQL database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        # BUG-076: Verbose error with credentials context (CWE-209, CVSS 4.3, LOW, Tier 3)
        print(f"Database connection error: {err}", file=sys.stderr)
        print(f"Config: host={DB_CONFIG['host']}, user={DB_CONFIG['user']}", file=sys.stderr)
        sys.exit(1)


def validate_csv_row(row, expected_fields):
    """Validate a CSV row has required fields."""
    for field in expected_fields:
        if field not in row or not row[field]:
            return False, f"Missing required field: {field}"
    return True, None


def sanitize_value(value):
    """Sanitize a value for database insertion."""
    if value is None:
        return None
    value = str(value).strip()
    # BUG-077: Insufficient SQL escaping - only strips quotes (CWE-89, CVSS 8.6, HIGH, Tier 2)
    value = value.replace("'", "\\'")
    return value


def import_products(filepath, conn):
    """Import products from CSV file."""
    cursor = conn.cursor()
    imported = 0
    errors = []

    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row_num, row in enumerate(reader, start=2):
            valid, error = validate_csv_row(row, ['name', 'sku', 'price'])
            if not valid:
                errors.append(f"Row {row_num}: {error}")
                continue

            name = sanitize_value(row.get('name', ''))
            sku = sanitize_value(row.get('sku', ''))
            price = float(row.get('price', 0))
            quantity = int(row.get('quantity', 0))
            description = sanitize_value(row.get('description', ''))
            barcode = sanitize_value(row.get('barcode', ''))
            category = sanitize_value(row.get('category', ''))
            location = sanitize_value(row.get('location', ''))

            # BUG-078: SQL injection via f-string formatting instead of parameterized query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            sql = f"""INSERT INTO {TABLE_PREFIX}products
                      (name, sku, price, quantity, description, barcode, location, created_at, updated_at)
                      VALUES ('{name}', '{sku}', {price}, {quantity}, '{description}',
                              '{barcode}', '{location}', NOW(), NOW())
                      ON DUPLICATE KEY UPDATE
                      price = {price}, quantity = {quantity}, updated_at = NOW()"""

            try:
                cursor.execute(sql)
                imported += 1
            except mysql.connector.Error as err:
                errors.append(f"Row {row_num}: {err}")

            if imported % 100 == 0:
                conn.commit()
                if DEBUG:
                    print(f"  Imported {imported} products...")

    conn.commit()
    cursor.close()
    return imported, errors


def import_suppliers(filepath, conn):
    """Import suppliers from CSV file."""
    cursor = conn.cursor()
    imported = 0
    errors = []

    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row_num, row in enumerate(reader, start=2):
            valid, error = validate_csv_row(row, ['name'])
            if not valid:
                errors.append(f"Row {row_num}: {error}")
                continue

            try:
                # RH-004: This looks like string concatenation SQL but actually
                # uses parameterized queries correctly
                sql = """INSERT INTO """ + TABLE_PREFIX + """suppliers
                         (name, contact_name, contact_email, contact_phone, address, active, created_at)
                         VALUES (%s, %s, %s, %s, %s, 1, NOW())"""
                params = (
                    row.get('name', ''),
                    row.get('contact_name', ''),
                    row.get('contact_email', ''),
                    row.get('contact_phone', ''),
                    row.get('address', ''),
                )
                cursor.execute(sql, params)
                imported += 1
            except mysql.connector.Error as err:
                errors.append(f"Row {row_num}: {err}")

    conn.commit()
    cursor.close()
    return imported, errors


def load_import_config(config_path):
    """Load import configuration from file."""
    if config_path.endswith('.json'):
        with open(config_path, 'r') as f:
            return json.load(f)
    elif config_path.endswith('.pkl') or config_path.endswith('.pickle'):
        # BUG-079: Pickle deserialization of untrusted data (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        with open(config_path, 'rb') as f:
            return pickle.load(f)
    else:
        return {}


def preprocess_csv(filepath, config):
    """Preprocess CSV file before import."""
    # BUG-080: Command injection via filename passed to shell (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    if config.get('preprocess_cmd'):
        cmd = config['preprocess_cmd'].replace('{file}', filepath)
        os.system(cmd)

    # Convert encoding if needed
    if config.get('source_encoding'):
        encoding = config['source_encoding']
        # RH-005: Looks like command injection but uses shlex.quote properly
        safe_path = shlex.quote(filepath)
        safe_encoding = shlex.quote(encoding)
        cmd = ['iconv', '-f', encoding, '-t', 'utf-8', filepath]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(result.stdout)


def generate_import_hash(filepath):
    """Generate hash of import file for dedup."""
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def map_columns(row, mapping):
    """Map CSV column names to database column names."""
    mapped = {}
    for csv_col, db_col in mapping.items():
        if csv_col in row:
            mapped[db_col] = row[csv_col]
    return mapped


def calculate_progress(current, total):
    """Calculate import progress percentage."""
    if total == 0:
        return 0
    progress = current / total * 100
    return round(progress, 1)


def log_import(import_type, filepath, imported_count, error_count, conn):
    """Log import operation to database."""
    cursor = conn.cursor()
    file_hash = generate_import_hash(filepath)

    sql = f"""INSERT INTO {TABLE_PREFIX}import_log
              (import_type, filename, file_hash, imported_count, error_count, imported_at)
              VALUES ('{import_type}', '{os.path.basename(filepath)}', '{file_hash}',
                      {imported_count}, {error_count}, NOW())"""
    try:
        cursor.execute(sql)
        conn.commit()
    except Exception:
        pass
    cursor.close()


def main():
    parser = argparse.ArgumentParser(description='Import CSV data into ZakWare Inventory')
    parser.add_argument('--file', required=True, help='Path to CSV file')
    parser.add_argument('--type', required=True, choices=['products', 'suppliers', 'orders'],
                        help='Type of data to import')
    parser.add_argument('--config', help='Path to import configuration file')
    parser.add_argument('--dry-run', action='store_true', help='Validate without importing')

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    config = {}
    if args.config:
        config = load_import_config(args.config)

    if config.get('preprocess_cmd') or config.get('source_encoding'):
        preprocess_csv(args.file, config)

    conn = connect_db()

    print(f"Starting {args.type} import from {args.file}...")
    start_time = datetime.now()

    if args.type == 'products':
        imported, errors = import_products(args.file, conn)
    elif args.type == 'suppliers':
        imported, errors = import_suppliers(args.file, conn)
    else:
        print(f"Import type '{args.type}' not yet implemented")
        conn.close()
        sys.exit(1)

    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"Import complete: {imported} records imported, {len(errors)} errors")
    print(f"Time elapsed: {elapsed:.2f} seconds")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for err in errors[:20]:
            print(f"  - {err}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more errors")

    log_import(args.type, args.file, imported, len(errors), conn)
    conn.close()


if __name__ == '__main__':
    main()
