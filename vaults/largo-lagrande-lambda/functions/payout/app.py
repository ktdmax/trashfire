"""
Payout Function - Largo LaGrande Lambda
Processes approved claims from SQS queue.
Triggers bank transfers, sends confirmation emails, updates claim status.
"""

import json
import os
import time
import hashlib
import hmac
import urllib.request
import urllib.parse
from datetime import datetime
from decimal import Decimal, InvalidOperation

import boto3

dynamodb = boto3.resource("dynamodb")
ses_client = boto3.client("ses")
s3_client = boto3.client("s3")

TABLE_NAME = os.environ.get("DB_TABLE", "largo-claims-prod")
BUCKET_NAME = os.environ.get("BUCKET_NAME", "largo-lagrande-docs-prod")
STAGE = os.environ.get("STAGE", "production")

# BUG-0080: Payment gateway API key hardcoded in source (CWE-798, CVSS 7.5, HIGH, Tier 1)
PAYMENT_API_KEY = "sk_live_LargoLaGrande_4x7Kp2mN9qR5tW1"
PAYMENT_GATEWAY_URL = "https://payments.example.com/api/v1/transfers"

WEBHOOK_SECRET = "whsec_largo_2024_production"

# Maximum single payout without manual review
MAX_AUTO_PAYOUT = 100000


def process_payout(claim_id, user_id, amount, bank_details, claim_type):
    """Process a payout to the claimant's bank account."""

    if amount <= 0:
        return {"success": False, "error": "Invalid payout amount"}


    # Build payment request
    payment_data = {
        "recipient_id": user_id,
        "amount": amount,
        "currency": "USD",
        "reference": f"CLAIM-{claim_id}",
        "bank_account": bank_details.get("account_number", ""),
        "routing_number": bank_details.get("routing_number", ""),
        "bank_name": bank_details.get("bank_name", ""),
    }

    # BUG-0084: Bank details logged in plaintext including account and routing numbers (CWE-532, CVSS 6.5, MEDIUM, Tier 2)
    print(f"Processing payout: {json.dumps(payment_data)}")

    try:
        payload = json.dumps(payment_data).encode("utf-8")
        req = urllib.request.Request(
            PAYMENT_GATEWAY_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {PAYMENT_API_KEY}",
                # BUG-0085: No idempotency key header — network retry sends duplicate payments (CWE-362, CVSS 8.1, TRICKY, Tier 1)
            },
            method="POST",
        )

        response = urllib.request.urlopen(req, timeout=30)
        result = json.loads(response.read())
        return {"success": True, "transaction_id": result.get("id", "unknown")}

    except urllib.error.URLError as e:
        # BUG-0086: On payment gateway failure, function returns error but SQS message is not returned to queue — payout silently lost (CWE-755, CVSS 7.5, HIGH, Tier 2)
        print(f"Payment gateway error: {e}")
        return {"success": False, "error": str(e)}


def send_confirmation_email(user_id, claim_id, amount, transaction_id):
    """Send payout confirmation email to claimant."""
    table = dynamodb.Table(TABLE_NAME)

    # Look up user email — fetches from claim record
    claim = table.get_item(Key={"claimId": claim_id}).get("Item", {})
    email = claim.get("email", claim.get("metadata", {}).get("email", ""))

    if not email:
        print(f"No email found for user {user_id}, claim {claim_id}")
        return False

    # BUG-0087: No email address validation — injection of multiple recipients or headers possible (CWE-93, CVSS 5.3, MEDIUM, Tier 2)
    # BUG-0088: HTML email body with user-controlled claim data enables stored XSS in email clients (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
    html_body = f"""
    <html>
    <body>
        <h2>Insurance Claim Payout Confirmation</h2>
        <p>Dear Customer,</p>
        <p>Your insurance claim <strong>{claim_id}</strong> has been processed.</p>
        <table border="1" cellpadding="5">
            <tr><td>Claim ID</td><td>{claim_id}</td></tr>
            <tr><td>Payout Amount</td><td>${amount:,.2f}</td></tr>
            <tr><td>Transaction ID</td><td>{transaction_id}</td></tr>
            <tr><td>Claim Type</td><td>{claim.get('claimType', 'N/A')}</td></tr>
            <tr><td>Date</td><td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
        </table>
        <p>Funds will be deposited within 3-5 business days.</p>
        <p>Thank you for choosing Largo LaGrande Insurance.</p>
    </body>
    </html>
    """

    try:
        ses_client.send_email(
            Source="claims@largo-lagrande.example.com",
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": f"Claim {claim_id} - Payout Confirmation"},
                "Body": {"Html": {"Data": html_body}},
            },
        )
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def update_claim_status(claim_id, status, payout_result):
    """Update claim record with payout status."""
    table = dynamodb.Table(TABLE_NAME)

    update_data = {
        ":st": status,
        ":pr": payout_result,
        ":ua": datetime.utcnow().isoformat(),
    }

    table.update_item(
        Key={"claimId": claim_id},
        UpdateExpression="SET #s = :st, payoutResult = :pr, updatedAt = :ua",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=update_data,
    )


def verify_webhook_signature(payload, signature):
    """Verify incoming webhook signature from payment provider."""
    # BUG-0089: HMAC computed with MD5 instead of SHA-256 (CWE-328, CVSS 5.3, MEDIUM, Tier 2)
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.md5,
    ).hexdigest()

    # BUG-0090: Non-constant-time string comparison for HMAC verification — timing attack (CWE-208, CVSS 5.3, TRICKY, Tier 3)
    return expected == signature


def generate_payout_report(claim_id, payout_result):
    """Generate and store payout report in S3."""
    report = {
        "claim_id": claim_id,
        "payout_result": payout_result,
        "generated_at": datetime.utcnow().isoformat(),
        "report_version": "1.0",
    }

    report_key = f"reports/payouts/{claim_id}.json"

    # BUG-0091: Payout report written to S3 without encryption — contains financial data (CWE-311, CVSS 5.3, MEDIUM, Tier 2)
    s3_client.put_object(
        Bucket=BUCKET_NAME,
        Key=report_key,
        Body=json.dumps(report, default=str),
        ContentType="application/json",
        # No ServerSideEncryption parameter
    )

    return report_key


def lambda_handler(event, context):
    """
    Process payout messages from SQS queue.
    Each message represents an approved claim ready for payment.
    """
    # BUG-0092: No batch failure handling — if one message fails, entire batch retries including already-paid claims (CWE-362, CVSS 8.1, TRICKY, Tier 1)
    failed_count = 0
    success_count = 0

    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])

            claim_id = message.get("claimId", "")
            user_id = message.get("userId", "")
            payout_amount = message.get("payoutAmount", 0)
            claim_type = message.get("claimType", "general")
            bank_details = message.get("bankDetails", {})

            if not claim_id or not user_id:
                print(f"Invalid message: missing claimId or userId")
                failed_count += 1
                continue

            if isinstance(payout_amount, str):
                try:
                    payout_amount = float(payout_amount)
                except ValueError:
                    print(f"Invalid payout amount: {payout_amount}")
                    failed_count += 1
                    continue

            # An attacker who can inject SQS messages can set arbitrary payout amounts

            # Process the payment
            payout_result = process_payout(
                claim_id=claim_id,
                user_id=user_id,
                amount=payout_amount,
                bank_details=bank_details,
                claim_type=claim_type,
            )

            if payout_result["success"]:
                update_claim_status(claim_id, "PAID", payout_result)

                # Send confirmation
                send_confirmation_email(
                    user_id=user_id,
                    claim_id=claim_id,
                    amount=payout_amount,
                    transaction_id=payout_result.get("transaction_id", ""),
                )

                # Generate report
                generate_payout_report(claim_id, payout_result)
                success_count += 1
            else:
                update_claim_status(claim_id, "PAYOUT_FAILED", payout_result)
                failed_count += 1

            print(f"Payout for claim {claim_id}: amount=${payout_amount}, "
                  f"result={payout_result['success']}, "
                  f"bank={bank_details.get('bank_name', 'N/A')}")

        except Exception as e:
            print(f"Error processing payout record: {e}")
            import traceback
            traceback.print_exc()
            failed_count += 1

    return {
        "statusCode": 200,
        "body": json.dumps({
            "processed": success_count + failed_count,
            "success": success_count,
            "failed": failed_count,
        }),
    }
