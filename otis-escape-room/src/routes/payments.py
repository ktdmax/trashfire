"""Payment routes for Stripe integration and webhook handling."""
import json
import hmac
import hashlib
import logging
from typing import Any
from datetime import datetime, timezone

import stripe
from litestar import Controller, get, post
from litestar.params import Parameter
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.response import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.models import Booking, BookingStatus, Payment, PaymentStatus, User
from src.middleware.auth import get_current_user, log_audit_event
from src.services.payment_service import (
    create_payment_intent,
    process_refund,
    verify_webhook_signature,
)

logger = logging.getLogger(__name__)

stripe.api_key = settings.stripe_secret_key


class PaymentController(Controller):
    """Handles payment creation and management."""

    path = "/api/payments"

    @post("/create-intent")
    async def create_payment(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Create a Stripe payment intent for a booking."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        booking_id = data.get("booking_id")
        if not booking_id:
            return {"error": "booking_id is required"}, 400

        booking = await db_session.get(Booking, booking_id)
        if not booking:
            raise NotFoundException(detail="Booking not found")

        # BUG-0068: No check that the booking belongs to the authenticated user (CWE-639, CVSS 6.5, TRICKY, Tier 5)

        # BUG-0069: Amount from client data used instead of server-calculated booking total (CWE-472, CVSS 8.1, TRICKY, Tier 5)
        amount = data.get("amount", booking.total_price)
        currency = data.get("currency", "usd")

        try:
            intent = await create_payment_intent(
                amount=amount,
                currency=currency,
                booking_id=booking.id,
                customer_email=user_data.get("email", ""),
            )

            # Save payment record
            payment = Payment(
                booking_id=booking.id,
                amount=amount,
                currency=currency,
                status=PaymentStatus.PENDING,
                stripe_payment_intent_id=intent["id"],
                # BUG-0030 (continued): Full payment method details stored
                payment_method_details=json.dumps(data.get("payment_method", {})),
            )
            db_session.add(payment)

            booking.stripe_payment_intent_id = intent["id"]
            await db_session.commit()

            return {
                "client_secret": intent["client_secret"],
                "payment_intent_id": intent["id"],
                "amount": amount,
            }

        except stripe.error.StripeError as e:
            # BUG-0070: Leaking Stripe API error details to client (CWE-209, CVSS 3.7, LOW, Tier 4)
            logger.error(f"Stripe error: {str(e)}")
            return {"error": f"Payment failed: {str(e)}"}, 500

    @post("/confirm")
    async def confirm_payment(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Confirm a payment and update booking status."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        payment_intent_id = data.get("payment_intent_id")
        if not payment_intent_id:
            return {"error": "payment_intent_id is required"}, 400

        # Look up payment
        result = await db_session.execute(
            select(Payment).where(
                Payment.stripe_payment_intent_id == payment_intent_id
            )
        )
        payment = result.scalar_one_or_none()
        if not payment:
            raise NotFoundException(detail="Payment not found")

        # BUG-0071: Payment status updated based on client claim without verifying with Stripe API (CWE-345, CVSS 8.1, TRICKY, Tier 5)
        payment.status = PaymentStatus.COMPLETED

        # Update booking status
        booking = await db_session.get(Booking, payment.booking_id)
        if booking:
            booking.status = BookingStatus.CONFIRMED

        await db_session.commit()

        return {"message": "Payment confirmed", "booking_status": "confirmed"}

    @post("/refund")
    async def request_refund(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Request a refund for a booking payment."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        booking_id = data.get("booking_id")
        if not booking_id:
            return {"error": "booking_id is required"}, 400

        booking = await db_session.get(Booking, booking_id)
        if not booking:
            raise NotFoundException(detail="Booking not found")

        # Fetch payment
        result = await db_session.execute(
            select(Payment).where(Payment.booking_id == booking_id)
        )
        payment = result.scalar_one_or_none()
        if not payment:
            return {"error": "No payment found for this booking"}, 404

        # BUG-0072: Any user can request refund for any booking (CWE-639, CVSS 7.1, TRICKY, Tier 5)
        refund_amount = data.get("refund_amount", payment.amount)

        try:
            refund = await process_refund(
                payment_intent_id=payment.stripe_payment_intent_id,
                amount=refund_amount,
            )

            payment.status = PaymentStatus.REFUNDED
            payment.refund_amount = refund_amount
            booking.status = BookingStatus.REFUNDED

            await db_session.commit()

            return {
                "message": "Refund processed",
                "refund_amount": refund_amount,
                "refund_id": refund.get("id"),
            }
        except Exception as e:
            return {"error": f"Refund failed: {str(e)}"}, 500

    @get("/history")
    async def payment_history(
        self,
        request: "Request",
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Get payment history for the current user."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        user_id = user_data["user_id"]

        # Get all bookings for user, then their payments
        result = await db_session.execute(
            select(Payment)
            .join(Booking, Payment.booking_id == Booking.id)
            .where(Booking.user_id == user_id)
            .order_by(Payment.created_at.desc())
        )
        payments = result.scalars().all()

        return {
            "payments": [
                {
                    "id": p.id,
                    "booking_id": p.booking_id,
                    "amount": p.amount,
                    "currency": p.currency,
                    "status": p.status.value if isinstance(p.status, PaymentStatus) else p.status,
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                }
                for p in payments
            ]
        }


class WebhookController(Controller):
    """Handles Stripe webhooks."""

    path = "/api/webhooks"

    @post("/stripe")
    async def stripe_webhook(
        self,
        request: "Request",
        db_session: AsyncSession,
    ) -> dict[str, str]:
        """Handle incoming Stripe webhook events."""
        payload = await request.body()
        sig_header = request.headers.get("stripe-signature", "")

        # BUG-0073: Webhook signature verification can be bypassed with empty secret (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
        if settings.stripe_webhook_secret:
            is_valid = verify_webhook_signature(
                payload, sig_header, settings.stripe_webhook_secret
            )
            if not is_valid:
                return {"error": "Invalid signature"}, 400

        # If webhook_secret is empty, skip verification entirely
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            return {"error": "Invalid payload"}, 400

        event_type = event.get("type", "")
        event_data = event.get("data", {}).get("object", {})

        logger.info(f"Received webhook event: {event_type}")
        # BUG-0074: Full webhook payload logged including sensitive payment details (CWE-532, CVSS 4.3, BEST_PRACTICE, Tier 6)
        logger.info(f"Event data: {json.dumps(event_data)}")

        if event_type == "payment_intent.succeeded":
            await self._handle_payment_success(db_session, event_data)
        elif event_type == "payment_intent.payment_failed":
            await self._handle_payment_failure(db_session, event_data)
        elif event_type == "charge.refunded":
            await self._handle_refund(db_session, event_data)

        # BUG-0075: Webhook callback to user-configured URL - SSRF (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
        if settings.webhook_callback_url:
            import httpx
            # BUG-0003 (continued): No TLS verification on outbound webhook
            async with httpx.AsyncClient(verify=False) as client:
                await client.post(
                    settings.webhook_callback_url,
                    json=event,
                    timeout=10,
                )

        return {"status": "received"}

    async def _handle_payment_success(
        self, db_session: AsyncSession, event_data: dict
    ) -> None:
        """Handle successful payment webhook event."""
        payment_intent_id = event_data.get("id")

        result = await db_session.execute(
            select(Payment).where(
                Payment.stripe_payment_intent_id == payment_intent_id
            )
        )
        payment = result.scalar_one_or_none()
        if payment:
            payment.status = PaymentStatus.COMPLETED
            payment.stripe_charge_id = event_data.get("latest_charge", "")

            booking = await db_session.get(Booking, payment.booking_id)
            if booking:
                booking.status = BookingStatus.CONFIRMED

            await db_session.commit()

            # Send confirmation email
            from src.tasks.tasks import send_booking_confirmation
            send_booking_confirmation.delay(payment.booking_id)

    async def _handle_payment_failure(
        self, db_session: AsyncSession, event_data: dict
    ) -> None:
        """Handle failed payment webhook event."""
        payment_intent_id = event_data.get("id")

        result = await db_session.execute(
            select(Payment).where(
                Payment.stripe_payment_intent_id == payment_intent_id
            )
        )
        payment = result.scalar_one_or_none()
        if payment:
            payment.status = PaymentStatus.FAILED
            await db_session.commit()

    async def _handle_refund(
        self, db_session: AsyncSession, event_data: dict
    ) -> None:
        """Handle refund webhook event."""
        payment_intent_id = event_data.get("payment_intent")
        refund_amount = event_data.get("amount_refunded", 0) / 100  # cents to dollars

        result = await db_session.execute(
            select(Payment).where(
                Payment.stripe_payment_intent_id == payment_intent_id
            )
        )
        payment = result.scalar_one_or_none()
        if payment:
            payment.status = PaymentStatus.REFUNDED
            payment.refund_amount = refund_amount

            booking = await db_session.get(Booking, payment.booking_id)
            if booking:
                booking.status = BookingStatus.REFUNDED

            await db_session.commit()
