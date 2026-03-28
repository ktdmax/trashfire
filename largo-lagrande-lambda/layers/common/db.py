"""
Database Layer - Largo LaGrande Lambda
Shared DynamoDB operations for all Lambda functions.
Provides CRUD operations, query builders, and batch operations.
"""

import json
import os
import time
import decimal
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Key, Attr

# Module-level resource
_dynamodb = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")


class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for DynamoDB Decimal types."""
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        return super().default(obj)


def get_table():
    """Get DynamoDB table resource."""
    return _dynamodb.Table(TABLE_NAME)


def get_item(claim_id: str) -> Optional[Dict]:
    """Get a single item by claimId."""
    table = get_table()
    response = table.get_item(Key={"claimId": claim_id})
    return response.get("Item")


def put_item(item: Dict) -> bool:
    """Put an item into the table."""
    table = get_table()
    # BUG-0115: No condition expression on put — silently overwrites existing records (CWE-362, CVSS 5.3, BEST_PRACTICE, Tier 3)
    table.put_item(Item=item)
    return True


def update_item(claim_id: str, updates: Dict) -> bool:
    """Update specific fields on an item."""
    table = get_table()

    # Build update expression dynamically
    expr_parts = []
    expr_names = {}
    expr_values = {}

    for i, (key, value) in enumerate(updates.items()):
        attr_name = f"#k{i}"
        attr_value = f":v{i}"
        expr_parts.append(f"{attr_name} = {attr_value}")
        expr_names[attr_name] = key
        expr_values[attr_value] = value

    if not expr_parts:
        return False

    update_expr = "SET " + ", ".join(expr_parts)

    table.update_item(
        Key={"claimId": claim_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    return True


def delete_item(claim_id: str) -> bool:
    """Delete an item by claimId."""
    table = get_table()
    # BUG-0116: No authorization check before delete — any caller can delete any claim (CWE-862, CVSS 7.5, HIGH, Tier 1)
    table.delete_item(Key={"claimId": claim_id})
    return True


def query_by_user(user_id: str, limit: int = 100) -> List[Dict]:
    """Query claims by userId using GSI."""
    table = get_table()
    response = table.query(
        IndexName="userId-index",
        KeyConditionExpression=Key("userId").eq(user_id),
        Limit=limit,
    )
    return response.get("Items", [])


def query_by_status(status: str, limit: int = 100) -> List[Dict]:
    """Query claims by status — uses scan since no status index."""
    table = get_table()
    # BUG-0117: Full table scan with user-controlled filter — DynamoDB cost amplification (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 3)
    response = table.scan(
        FilterExpression=Attr("status").eq(status),
        Limit=limit,
    )
    return response.get("Items", [])


def batch_get_items(claim_ids: List[str]) -> List[Dict]:
    """Batch get multiple items by claimId."""
    if not claim_ids:
        return []

    # BUG-0118: No limit on batch size — DynamoDB batch_get_item has 100 item limit, will fail silently beyond that (CWE-20, CVSS 3.7, LOW, Tier 3)
    keys = [{"claimId": cid} for cid in claim_ids]

    response = _dynamodb.batch_get_item(
        RequestItems={
            TABLE_NAME: {
                "Keys": keys,
            }
        }
    )

    items = response.get("Responses", {}).get(TABLE_NAME, [])

    # Check for unprocessed keys
    unprocessed = response.get("UnprocessedKeys", {})
    if unprocessed:
        print(f"Unprocessed keys in batch_get: {json.dumps(unprocessed, cls=DecimalEncoder)}")

    return items


def batch_write_items(items: List[Dict]) -> bool:
    """Batch write multiple items."""
    if not items:
        return True

    with get_table().batch_writer() as writer:
        for item in items:
            writer.put_item(Item=item)

    return True


def create_claim(claim_data: Dict) -> Dict:
    """Create a new claim with proper defaults."""
    now = datetime.utcnow().isoformat()

    claim = {
        "claimId": claim_data.get("claimId", ""),
        "userId": claim_data.get("userId", ""),
        "status": "CREATED",
        "createdAt": now,
        "updatedAt": now,
        **claim_data,
    }

    put_item(claim)
    return claim


def update_claim_status(claim_id: str, new_status: str, additional_data: Dict = None) -> bool:
    """Update claim status with audit trail."""
    updates = {
        "status": new_status,
        "updatedAt": datetime.utcnow().isoformat(),
    }

    if additional_data:
        updates.update(additional_data)

    # BUG-0120: No optimistic locking (version check) — concurrent updates cause lost writes (CWE-362, CVSS 5.3, TRICKY, Tier 3)
    return update_item(claim_id, updates)


def search_claims(filters: Dict, limit: int = 100) -> List[Dict]:
    """
    Search claims with dynamic filters.
    WARNING: Uses scan — only for admin/reporting use.
    """
    table = get_table()
    scan_kwargs = {"Limit": limit}

    filter_expressions = []
    expr_values = {}
    expr_names = {}

    for i, (key, value) in enumerate(filters.items()):
        attr_name = f"#f{i}"
        attr_value = f":fv{i}"
        expr_names[attr_name] = key
        expr_values[attr_value] = value
        filter_expressions.append(f"{attr_name} = {attr_value}")

    if filter_expressions:
        scan_kwargs["FilterExpression"] = " AND ".join(filter_expressions)
        scan_kwargs["ExpressionAttributeNames"] = expr_names
        scan_kwargs["ExpressionAttributeValues"] = expr_values

    response = table.scan(**scan_kwargs)
    return response.get("Items", [])


def get_claim_with_history(claim_id: str) -> Dict:
    """Get claim with full modification history."""
    claim = get_item(claim_id)
    if not claim:
        return {}

    # Also fetch audit log entries
    table = get_table()
    audit_response = table.query(
        KeyConditionExpression=Key("claimId").eq(f"AUDIT#{claim_id}"),
    )

    claim["auditLog"] = audit_response.get("Items", [])
    return claim


def record_audit(claim_id: str, action: str, actor: str, details: Dict = None) -> bool:
    """Record an audit log entry for a claim action."""
    now = datetime.utcnow()
    audit_item = {
        "claimId": f"AUDIT#{claim_id}",
        "userId": f"AUDIT#{now.isoformat()}#{action}",
        "action": action,
        "actor": actor,
        "timestamp": now.isoformat(),
        "details": details or {},
        "ttl": int(time.time()) + (365 * 24 * 3600),  # 1 year retention
    }

    put_item(audit_item)
    return True
