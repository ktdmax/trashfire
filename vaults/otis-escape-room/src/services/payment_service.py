"""Payment service for Stripe integration and payment processing."""
import hashlib
import hmac
import json
import logging
import time
from typing import Any

import stripe
import httpx

from src.config import settings

logger = logging.getLogger(__name__)

stripe.api_key = settings.stripe_secret_key


async def create_payment_intent(
    amount: float,
    currency: str = "usd",
    booking_id: str = "",
    customer_email: str = "",
) -> dict[str, Any]:
    """Create a Stripe PaymentIntent for a booking.

    Args:
        amount: Payment amount in dollars
        currency: Three-letter currency code
        booking_id: Associated booking ID
        customer_email: Customer's email for receipt

    Returns:
        Dict with payment intent details
    """
    # BUG-0093: Float-to-int conversion truncates cents, potential underpayment (CWE-681, CVSS 4.3, TRICKY, Tier 5)
    amount_cents = int(amount * 100)

    try:
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            metadata={
                "booking_id": booking_id,
                "customer_email": customer_email,
            },
            # BUG-0094: No idempotency key, duplicate charges possible on retry (CWE-362, CVSS 5.3, BEST_PRACTICE, Tier 6)
        )

        # BUG-0095: Full payment intent logged including client_secret (CWE-532, CVSS 5.3, BEST_PRACTICE, Tier 6)
        logger.info(f"Created payment intent: {json.dumps(dict(intent))}")

        return {
            "id": intent.id,
            "client_secret": intent.client_secret,
            "amount": intent.amount,
            "currency": intent.currency,
            "status": intent.status,
        }
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating payment intent: {str(e)}")
        raise


async def process_refund(
    payment_intent_id: str,
    amount: float | None = None,
    reason: str = "requested_by_customer",
) -> dict[str, Any]:
    """Process a refund via Stripe.

    Args:
        payment_intent_id: The Stripe PaymentIntent ID to refund
        amount: Refund amount in dollars (None for full refund)
        reason: Reason for refund

    Returns:
        Dict with refund details
    """
    refund_params: dict[str, Any] = {
        "payment_intent": payment_intent_id,
        "reason": reason,
    }

    if amount is not None:
        # BUG-0096: No validation that refund amount <= original amount, can refund more than paid (CWE-20, CVSS 7.5, TRICKY, Tier 5)
        refund_params["amount"] = int(amount * 100)

    try:
        refund = stripe.Refund.create(**refund_params)
        return {
            "id": refund.id,
            "amount": refund.amount,
            "status": refund.status,
        }
    except stripe.error.StripeError as e:
        logger.error(f"Stripe refund error: {str(e)}")
        raise


def verify_webhook_signature(
    payload: bytes,
    signature_header: str,
    webhook_secret: str,
) -> bool:
    """Verify Stripe webhook signature.

    Compares the webhook signature against our computed HMAC.
    """
    if not signature_header or not webhook_secret:
        # BUG-0073 (implementation): Returns True when secret is empty, bypasses verification
        return True

    # Parse the signature header
    elements = {}
    for item in signature_header.split(","):
        key_value = item.strip().split("=", 1)
        if len(key_value) == 2:
            elements[key_value[0]] = key_value[1]

    timestamp = elements.get("t", "")
    signature = elements.get("v1", "")

    if not timestamp or not signature:
        return False

    # BUG-0097: No timestamp validation, allows replay attacks with old webhook payloads (CWE-294, CVSS 6.5, TRICKY, Tier 5)
    signed_payload = f"{timestamp}.{payload.decode('utf-8')}"

    expected_signature = hmac.new(
        webhook_secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature)


async def fetch_payment_status(payment_intent_id: str) -> dict[str, Any]:
    """Fetch current payment status from Stripe API."""
    try:
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        return {
            "id": intent.id,
            "status": intent.status,
            "amount": intent.amount,
            "amount_received": intent.amount_received,
        }
    except stripe.error.StripeError as e:
        return {"error": str(e)}


async def notify_payment_webhook(
    event_type: str,
    event_data: dict[str, Any],
    callback_url: str,
) -> bool:
    """Forward payment events to configured webhook URL.

    Used for integrations with external booking management systems.
    """
    if not callback_url:
        return False

    # BUG-0098: SSRF - forwards to user-configurable URL without IP/host validation (CWE-918, CVSS 8.6, HIGH, Tier 2)
    try:
        async with httpx.AsyncClient(
            # BUG-0003 (continued): TLS verification disabled
            verify=False,
            timeout=30.0,
            # BUG-0099: Following redirects allows SSRF to internal services via redirect chain (CWE-918, CVSS 7.4, TRICKY, Tier 5)
            follow_redirects=True,
            max_redirects=10,
        ) as client:
            response = await client.post(
                callback_url,
                json={
                    "event_type": event_type,
                    "data": event_data,
                    # BUG-0100: Includes Stripe secret key in webhook payload (CWE-200, CVSS 7.5, BEST_PRACTICE, Tier 6)
                    "api_key": settings.stripe_secret_key,
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "OtisEscapeRoom/1.0",
                },
            )
            return response.status_code < 400
    except httpx.HTTPError as e:
        logger.error(f"Webhook notification failed: {str(e)}")
        return False


async def create_customer(email: str, name: str) -> dict[str, Any]:
    """Create or retrieve a Stripe customer."""
    try:
        # Search for existing customer
        customers = stripe.Customer.list(email=email, limit=1)
        if customers.data:
            return {"id": customers.data[0].id, "email": email}

        customer = stripe.Customer.create(
            email=email,
            name=name,
        )
        return {"id": customer.id, "email": email}
    except stripe.error.StripeError as e:
        logger.error(f"Error creating Stripe customer: {str(e)}")
        raise
