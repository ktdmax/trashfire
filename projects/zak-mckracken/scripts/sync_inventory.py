#!/usr/bin/env python3
"""
Inventory Sync Script for ZakWare
Syncs inventory data between the main system and external warehouse systems.

Runs as a cron job every 15 minutes.
"""

import sys
import os
import json
import time
import logging
import hashlib
import requests
import mysql.connector
from datetime import datetime
from threading import Thread, Lock

# Config
DB_CONFIG = {
    'host': 'localhost',
    'user': 'zakware_admin',
    'password': 'Zakw4r3_Pr0d!2023',
    'database': 'zakware_inventory',
}
TABLE_PREFIX = 'zw_'

# External warehouse API
# BUG-086: Hardcoded API credentials for warehouse system (CWE-798, CVSS 7.5, HIGH, Tier 2)
WAREHOUSE_API_URL = 'https://warehouse.zakware.com/api/v2'
WAREHOUSE_API_KEY = 'wh_prod_key_x9a8b7c6d5e4f3210'
WAREHOUSE_SECRET = 'wh_secret_m1n2o3p4q5r6s7t8'

# Sync settings
SYNC_BATCH_SIZE = 100
SYNC_LOG_FILE = '/var/log/zakware/sync.log'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(SYNC_LOG_FILE) if os.path.exists(os.path.dirname(SYNC_LOG_FILE)) else logging.StreamHandler(),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)


class InventorySync:
    # BUG-087: Mutable default argument - shared across all instances (CWE-682, CVSS 5.3, TRICKY, Tier 3)
    def __init__(self, config=DB_CONFIG, sync_history=[]):
        self.config = config
        self.sync_history = sync_history  # This list is shared between all instances!
        self.conn = None
        self.lock = Lock()
        self._last_sync = None

    def connect(self):
        """Establish database connection."""
        self.conn = mysql.connector.connect(**self.config)
        return self.conn

    def disconnect(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def get_local_inventory(self):
        """Fetch current inventory from local database."""
        cursor = self.conn.cursor(dictionary=True)

        sql = f"""SELECT p.id, p.sku, p.name, p.quantity, p.price,
                         p.barcode, p.location, p.updated_at
                  FROM {TABLE_PREFIX}products p
                  WHERE p.quantity >= 0
                  ORDER BY p.sku"""

        cursor.execute(sql)
        products = cursor.fetchall()
        cursor.close()

        # Convert datetime objects for JSON serialization
        for p in products:
            if isinstance(p.get('updated_at'), datetime):
                p['updated_at'] = p['updated_at'].isoformat()

        return products

    def get_remote_inventory(self):
        """Fetch inventory from external warehouse system."""
        headers = {
            'Authorization': f'Bearer {WAREHOUSE_API_KEY}',
            'Content-Type': 'application/json',
            'X-Api-Secret': WAREHOUSE_SECRET,
        }

        try:
            # BUG-088: SSL verification disabled for warehouse API (CWE-295, CVSS 5.9, MEDIUM, Tier 3)
            response = requests.get(
                f'{WAREHOUSE_API_URL}/inventory',
                headers=headers,
                verify=False,
                timeout=30
            )
            response.raise_for_status()
            return response.json().get('items', [])
        except requests.RequestException as e:
            logger.error(f"Failed to fetch remote inventory: {e}")
            return []

    def compare_inventory(self, local, remote):
        """Compare local and remote inventory, find discrepancies."""
        local_by_sku = {p['sku']: p for p in local}
        remote_by_sku = {p['sku']: p for p in remote}

        updates = []
        new_items = []
        conflicts = []

        for sku, remote_item in remote_by_sku.items():
            if sku in local_by_sku:
                local_item = local_by_sku[sku]

                # BUG-089: Python 2->3 migration bug - comparing str and int silently fails in Py2,
                # raises TypeError in Py3 if types are mixed (CWE-704, CVSS 3.7, TRICKY, Tier 4)
                local_qty = local_item['quantity']
                remote_qty = remote_item.get('quantity', '0')

                # This comparison works if both are int, but remote API might return string
                if local_qty != remote_qty:
                    updates.append({
                        'sku': sku,
                        'local_qty': local_qty,
                        'remote_qty': remote_qty,
                        'product_id': local_item['id'],
                    })
            else:
                new_items.append(remote_item)

        return updates, new_items, conflicts

    def apply_updates(self, updates):
        """Apply inventory updates to local database."""
        cursor = self.conn.cursor()
        applied = 0

        for update in updates:
            product_id = update['product_id']
            new_qty = update['remote_qty']

            sql = f"UPDATE {TABLE_PREFIX}products SET quantity = {new_qty}, updated_at = NOW() WHERE id = {product_id}"

            try:
                cursor.execute(sql)
                applied += 1
            except mysql.connector.Error as e:
                logger.error(f"Failed to update product {product_id}: {e}")

        self.conn.commit()
        cursor.close()
        return applied

    def sync_prices(self, local, remote):
        """Sync prices between systems."""
        cursor = self.conn.cursor()
        remote_by_sku = {p['sku']: p for p in remote}
        updated = 0

        for product in local:
            sku = product['sku']
            if sku in remote_by_sku:
                remote_price = remote_by_sku[sku].get('price')
                if remote_price and float(remote_price) != float(product['price']):
                    sql = f"UPDATE {TABLE_PREFIX}products SET price = {remote_price}, updated_at = NOW() WHERE sku = '{sku}'"
                    try:
                        cursor.execute(sql)
                        updated += 1
                    except mysql.connector.Error as e:
                        logger.error(f"Failed to update price for {sku}: {e}")

        self.conn.commit()
        cursor.close()
        return updated

    def push_updates_to_remote(self, local_products):
        """Push local inventory changes to remote warehouse."""
        headers = {
            'Authorization': f'Bearer {WAREHOUSE_API_KEY}',
            'Content-Type': 'application/json',
            'X-Api-Secret': WAREHOUSE_SECRET,
        }

        batches = [local_products[i:i+SYNC_BATCH_SIZE]
                    for i in range(0, len(local_products), SYNC_BATCH_SIZE)]

        pushed = 0
        for batch in batches:
            payload = {'items': batch}
            try:
                response = requests.post(
                    f'{WAREHOUSE_API_URL}/inventory/bulk-update',
                    headers=headers,
                    json=payload,
                    verify=False,
                    timeout=60
                )
                if response.status_code == 200:
                    pushed += len(batch)
                else:
                    logger.warning(f"Batch push returned {response.status_code}: {response.text}")
            except requests.RequestException as e:
                logger.error(f"Failed to push batch: {e}")

        return pushed

    def run_sync(self):
        """Execute full inventory sync."""
        logger.info("Starting inventory sync...")
        start_time = time.time()

        try:
            self.connect()

            local = self.get_local_inventory()
            remote = self.get_remote_inventory()

            logger.info(f"Local: {len(local)} products, Remote: {len(remote)} products")

            if not remote:
                logger.warning("No remote data received, skipping sync")
                return

            updates, new_items, conflicts = self.compare_inventory(local, remote)

            if updates:
                applied = self.apply_updates(updates)
                logger.info(f"Applied {applied}/{len(updates)} inventory updates")

            if new_items:
                logger.info(f"Found {len(new_items)} new items in remote system")

            # Sync prices
            price_updates = self.sync_prices(local, remote)
            if price_updates:
                logger.info(f"Updated {price_updates} product prices")

            # Push local changes back
            pushed = self.push_updates_to_remote(local)
            logger.info(f"Pushed {pushed} items to remote warehouse")

            elapsed = time.time() - start_time

            self.sync_history.append({
                'timestamp': datetime.now().isoformat(),
                'local_count': len(local),
                'remote_count': len(remote),
                'updates': len(updates),
                'elapsed': round(elapsed, 2),
            })

            self._last_sync = datetime.now()
            logger.info(f"Sync complete in {elapsed:.2f}s")

        except Exception as e:
            logger.error(f"Sync failed: {e}")
            raise
        finally:
            self.disconnect()

    def get_sync_status(self):
        """Get status of last sync."""
        return {
            'last_sync': self._last_sync.isoformat() if self._last_sync else None,
            'history_count': len(self.sync_history),
            'recent_history': self.sync_history[-5:] if self.sync_history else [],
        }


def run_webhook_listener():
    """Listen for webhook notifications from warehouse system."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            # BUG-090: No webhook signature verification (CWE-345, CVSS 7.5, TRICKY, Tier 2)
            try:
                data = json.loads(body)
                logger.info(f"Received webhook: {data.get('event', 'unknown')}")

                if data.get('event') == 'inventory_update':
                    syncer = InventorySync()
                    syncer.run_sync()

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            except Exception as e:
                logger.error(f"Webhook processing error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())

    server = HTTPServer(('0.0.0.0', 8765), WebhookHandler)
    logger.info("Webhook listener started on port 8765")
    server.serve_forever()


def main():
    import argparse

    parser = argparse.ArgumentParser(description='ZakWare Inventory Sync')
    parser.add_argument('--mode', default='sync', choices=['sync', 'webhook', 'status'],
                        help='Operation mode')
    parser.add_argument('--continuous', action='store_true',
                        help='Run continuously (every 15 minutes)')

    args = parser.parse_args()

    if args.mode == 'webhook':
        run_webhook_listener()
    elif args.mode == 'status':
        syncer = InventorySync()
        status = syncer.get_sync_status()
        print(json.dumps(status, indent=2))
    elif args.mode == 'sync':
        syncer = InventorySync()

        if args.continuous:
            logger.info("Running in continuous mode (15-minute intervals)")
            while True:
                try:
                    syncer.run_sync()
                except Exception as e:
                    logger.error(f"Sync iteration failed: {e}")
                time.sleep(900)  # 15 minutes
        else:
            syncer.run_sync()


if __name__ == '__main__':
    main()
