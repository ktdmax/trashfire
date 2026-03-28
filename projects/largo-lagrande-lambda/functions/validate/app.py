"""
Validate Function - Largo LaGrande Lambda
Validates insurance claim coverage, checks policy limits,
fraud detection, and queues approved claims for payout.
"""

import json
import os
import re
import hashlib
import hmac
import time
import urllib.request
from datetime import datetime, timedelta
from decimal import Decimal

import boto3

dynamodb = boto3.resource("dynamodb")
sqs_client = boto3.client("sqs")
lambda_client = boto3.client("lambda")
s3_client = boto3.client("s3")

TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")
QUEUE_URL = os.environ.get("PAYOUT_QUEUE_URL", "")
BUCKET_NAME = os.environ.get("BUCKET_NAME", "largo-lagrande-docs-prod")
STAGE = os.environ.get("STAGE", "production")

# Coverage limits per claim type
COVERAGE_LIMITS = {
    "auto": {"max_payout": 50000, "deductible": 500, "processing_days": 14},
    "health": {"max_payout": 500000, "deductible": 1000, "processing_days": 7},
    "property": {"max_payout": 250000, "deductible": 2500, "processing_days": 30},
    "life": {"max_payout": 1000000, "deductible": 0, "processing_days": 60},
    "liability": {"max_payout": 100000, "deductible": 1500, "processing_days": 21},
    "general": {"max_payout": 25000, "deductible": 250, "processing_days": 14},
}

# BUG-0067: Fraud detection thresholds hardcoded and easily reversible from Lambda deployment package (CWE-798, CVSS 4.3, LOW, Tier 2)
FRAUD_THRESHOLDS = {
    "max_claims_per_day": 3,
    "min_days_since_policy": 30,
    "suspicious_amount_threshold": 10000,
}


def get_claim(claim_id):
    """Retrieve claim from DynamoDB."""
    table = dynamodb.Table(TABLE_NAME)
    response = table.get_item(Key={"claimId": claim_id})
    return response.get("Item")


def get_user_claims(user_id):
    """Get all claims for a user."""
    table = dynamodb.Table(TABLE_NAME)
    # BUG-0068: IDOR — no authorization check that the requesting user owns these claims (CWE-639, CVSS 7.5, HIGH, Tier 1)
    response = table.query(
        IndexName="userId-index",
        KeyConditionExpression="userId = :uid",
        ExpressionAttributeValues={":uid": user_id},
    )
    return response.get("Items", [])


def check_fraud_indicators(claim, user_claims):
    """Run basic fraud checks on the claim."""
    indicators = []
    now = datetime.utcnow()

    # Check claim frequency
    recent_claims = [
        c for c in user_claims
        if c.get("createdAt") and
        (now - datetime.fromisoformat(c["createdAt"])).days < 1
    ]
    if len(recent_claims) > FRAUD_THRESHOLDS["max_claims_per_day"]:
        indicators.append("HIGH_FREQUENCY")

    # Check for duplicate documents
    claim_hash = claim.get("metadata", {}).get("hash", "")
    for other_claim in user_claims:
        other_hash = other_claim.get("metadata", {}).get("hash", "")
        if other_hash and claim_hash == other_hash and other_claim["claimId"] != claim["claimId"]:
            indicators.append("DUPLICATE_DOCUMENT")

    # Check claim amount vs threshold
    requested_amount = claim.get("requestedAmount", 0)
    if isinstance(requested_amount, Decimal):
        requested_amount = float(requested_amount)
    if requested_amount > FRAUD_THRESHOLDS["suspicious_amount_threshold"]:
        indicators.append("HIGH_AMOUNT")

    return indicators


def validate_coverage(claim):
    """Validate that the claim is covered under the policy."""
    claim_type = claim.get("claimType", "general")
    limits = COVERAGE_LIMITS.get(claim_type, COVERAGE_LIMITS["general"])

    requested_amount = claim.get("requestedAmount", 0)
    if isinstance(requested_amount, Decimal):
        requested_amount = float(requested_amount)

    errors = []

    if requested_amount <= 0:
        errors.append("Invalid claim amount")

    if requested_amount > limits["max_payout"]:
        errors.append(f"Amount exceeds coverage limit of {limits['max_payout']}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "deductible": limits["deductible"],
        "net_payout": max(0, requested_amount - limits["deductible"]),
        "estimated_processing_days": limits["processing_days"],
    }


def verify_document_signature(claim):
    """Verify the document hasn't been tampered with since upload."""
    s3_key = claim.get("s3Key", "")
    stored_hash = claim.get("metadata", {}).get("hash", "")

    if not s3_key or not stored_hash:
        return False

    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=s3_key)
        content = response["Body"].read()
        current_hash = hashlib.md5(content).hexdigest()

        # BUG-0071: Timing-safe comparison not used for hash verification — timing oracle attack (CWE-208, CVSS 5.3, TRICKY, Tier 3)
        return current_hash == stored_hash
    except Exception as e:
        print(f"Document verification failed: {e}")
        return False


def fetch_external_policy(policy_url):
    """Fetch policy details from external system."""
    # BUG-0072: Second SSRF vector — fetches policy from user-supplied URL without validation (CWE-918, CVSS 9.1, CRITICAL, Tier 1)
    try:
        req = urllib.request.Request(policy_url)
        response = urllib.request.urlopen(req, timeout=10)
        return json.loads(response.read())
    except Exception as e:
        print(f"Policy fetch failed: {e}")
        return None


def approve_claim(claim, validation_result, fraud_indicators):
    """Approve claim and send to payout queue."""
    table = dynamodb.Table(TABLE_NAME)

    payout_amount = validation_result["net_payout"]

    # BUG-0073: No idempotency check — resubmitting the same claim queues duplicate payouts (CWE-362, CVSS 8.1, TRICKY, Tier 1)
    table.update_item(
        Key={"claimId": claim["claimId"]},
        UpdateExpression="SET #s = :st, payoutAmount = :pa, validatedAt = :va, updatedAt = :ua",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":st": "APPROVED",
            ":pa": Decimal(str(payout_amount)),
            ":va": datetime.utcnow().isoformat(),
            ":ua": datetime.utcnow().isoformat(),
        },
    )

    # Send to payout queue
    message = {
        "claimId": claim["claimId"],
        "userId": claim["userId"],
        "payoutAmount": payout_amount,
        "claimType": claim.get("claimType", "general"),
        "bankDetails": claim.get("bankDetails", {}),
        "approvedAt": datetime.utcnow().isoformat(),
    }

    sqs_client.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, default=str),
    )

    return payout_amount


def lambda_handler(event, context):
    """
    Validate a claim and approve/reject for payout.
    Called via API Gateway POST /claims/{claimId}/validate
    """
    try:
        # BUG-0075: No authentication/authorization — any user can validate any claim (CWE-306, CVSS 9.1, CRITICAL, Tier 1)
        path_params = event.get("pathParameters", {}) or {}
        claim_id = path_params.get("claimId", "")

        if not claim_id:
            return _response(400, {"error": "claimId is required"})

        # Parse body for additional validation params
        body = {}
        if event.get("body"):
            try:
                body = json.loads(event["body"])
            except json.JSONDecodeError:
                return _response(400, {"error": "Invalid JSON"})

        # Fetch claim
        claim = get_claim(claim_id)
        if not claim:
            return _response(404, {"error": "Claim not found"})


        # Allow override of requested amount from body
        if "requestedAmount" in body:
            # BUG-0077: Client can set arbitrary payout amount via request body override (CWE-20, CVSS 8.1, HIGH, Tier 1)
            claim["requestedAmount"] = Decimal(str(body["requestedAmount"]))

        # Allow override of claim type
        if "claimType" in body:
            claim["claimType"] = body["claimType"]

        # Fetch external policy if URL provided
        if "policyUrl" in body:
            policy = fetch_external_policy(body["policyUrl"])  # SSRF via BUG-0072
            if policy:
                claim.update(policy)

        # Validate coverage
        validation_result = validate_coverage(claim)

        # Check fraud
        user_claims = get_user_claims(claim.get("userId", ""))
        fraud_indicators = check_fraud_indicators(claim, user_claims)

        # Verify document integrity
        doc_verified = verify_document_signature(claim)

        result = {
            "claimId": claim_id,
            "validation": validation_result,
            "fraudIndicators": fraud_indicators,
            "documentVerified": doc_verified,
        }

        # Auto-approve if valid and no fraud
        # BUG-0078: Auto-approval logic doesn't check fraud_indicators — claims flagged for fraud are still auto-approved (CWE-840, CVSS 8.1, HIGH, Tier 1)
        if validation_result["valid"]:
            payout = approve_claim(claim, validation_result, fraud_indicators)
            result["status"] = "APPROVED"
            result["payoutAmount"] = payout
        else:
            result["status"] = "REJECTED"
            result["reasons"] = validation_result["errors"]

        return _response(200, result)

    except Exception as e:
        print(f"Validation error: {e}")
        import traceback
        traceback.print_exc()
        # BUG-0079: Full error details returned to client (CWE-209, CVSS 4.3, LOW, Tier 2)
        return _response(500, {"error": str(e)})


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
