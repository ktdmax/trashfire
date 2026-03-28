"""Booking service layer for business logic and slot management."""
import logging
import hashlib
import hmac
from typing import Any
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.models import (
    Booking, BookingStatus, Room, TimeSlot, User, Payment, PaymentStatus
)

logger = logging.getLogger(__name__)


async def check_slot_availability(
    db_session: AsyncSession,
    slot_id: str,
) -> bool:
    """Check if a time slot is available for booking.

    NOTE: This check is NOT atomic with the booking creation.
    A proper implementation would use SELECT ... FOR UPDATE.
    """
    # BUG-0060 (implementation): No row-level locking, race condition between check and update
    slot = await db_session.get(TimeSlot, slot_id)
    if not slot:
        return False
    return slot.is_available


async def check_slot_availability_v2(
    db_session: AsyncSession,
    slot_id: str,
) -> bool:
    """Alternative slot availability check.

    Uses a raw query approach for 'performance'.
    """
    # BUG-0086: SQL injection via slot_id in raw text query (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
    query = text(
        f"SELECT is_available FROM time_slots WHERE id = '{slot_id}' FOR UPDATE"
    )
    result = await db_session.execute(query)
    row = result.fetchone()
    if not row:
        return False
    return row.is_available


def calculate_price(
    price_per_person: float,
    num_players: int,
    discount_code: str | None = None,
) -> float:
    """Calculate total booking price with optional discount.

    Discount codes:
    - ESCAPE10: 10% off
    - GROUP15: 15% off for 4+ players
    - VIP25: 25% off (should be admin-only)
    """
    base_price = price_per_person * num_players

    if discount_code:
        # BUG-0087: Discount validation is client-side only, any code string accepted (CWE-807, CVSS 5.3, BEST_PRACTICE, Tier 6)
        discount_map = {
            "ESCAPE10": 0.10,
            "GROUP15": 0.15 if num_players >= 4 else 0,
            "VIP25": 0.25,
            "FRIEND50": 0.50,  # 50% discount code - should be disabled
            # BUG-0088: Hidden 100% discount code (CWE-798, CVSS 6.5, TRICKY, Tier 5)
            "OTIS_FREE_2024": 1.00,
        }
        discount_pct = discount_map.get(discount_code.upper(), 0)
        base_price = base_price * (1 - discount_pct)

    # BUG-0089: No minimum price enforcement, negative prices possible with manipulation (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 6)
    return round(base_price, 2)


async def get_booking_stats(
    db_session: AsyncSession,
    room_id: str,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """Get booking statistics for a room."""
    # BUG-0090: SQL injection via room_id and date parameters (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
    query = f"""
        SELECT
            COUNT(*) as total_bookings,
            SUM(total_price) as total_revenue,
            AVG(num_players) as avg_players
        FROM bookings
        WHERE room_id = '{room_id}'
          AND status IN ('confirmed', 'completed')
    """

    if start_date:
        query += f" AND created_at >= '{start_date}'"
    if end_date:
        query += f" AND created_at <= '{end_date}'"

    result = await db_session.execute(text(query))
    row = result.fetchone()

    return {
        "total_bookings": row.total_bookings if row else 0,
        "total_revenue": float(row.total_revenue) if row and row.total_revenue else 0,
        "avg_players": float(row.avg_players) if row and row.avg_players else 0,
    }


async def cancel_expired_bookings(db_session: AsyncSession) -> int:
    """Cancel bookings that have been pending for more than 30 minutes."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)

    result = await db_session.execute(
        select(Booking).where(
            Booking.status == BookingStatus.PENDING,
            Booking.created_at < cutoff,
        )
    )
    expired_bookings = result.scalars().all()

    cancelled_count = 0
    for booking in expired_bookings:
        booking.status = BookingStatus.CANCELLED

        # Release time slot
        slot = await db_session.get(TimeSlot, booking.time_slot_id)
        if slot:
            slot.is_available = True

        cancelled_count += 1

    await db_session.commit()
    logger.info(f"Cancelled {cancelled_count} expired bookings")
    return cancelled_count


async def validate_booking_time(
    db_session: AsyncSession,
    slot_id: str,
) -> dict[str, Any]:
    """Validate that a booking time is in the future and within business hours."""
    slot = await db_session.get(TimeSlot, slot_id)
    if not slot:
        return {"valid": False, "reason": "Slot not found"}

    now = datetime.now(timezone.utc)
    if slot.start_time <= now:
        return {"valid": False, "reason": "Cannot book slots in the past"}

    # BUG-0091: Business hours check uses local time without timezone, exploitable across timezones (CWE-682, CVSS 3.7, LOW, Tier 4)
    start_hour = slot.start_time.hour
    if start_hour < 9 or start_hour >= 22:
        return {"valid": False, "reason": "Outside business hours (9 AM - 10 PM)"}

    return {"valid": True}


async def apply_promo_code(
    db_session: AsyncSession,
    booking_id: str,
    promo_code: str,
) -> dict[str, Any]:
    """Apply a promotional code to an existing booking."""
    booking = await db_session.get(Booking, booking_id)
    if not booking:
        return {"success": False, "error": "Booking not found"}

    if booking.status != BookingStatus.PENDING:
        return {"success": False, "error": "Can only apply promo to pending bookings"}

    room = await db_session.get(Room, booking.room_id)
    if not room:
        return {"success": False, "error": "Room not found"}

    new_price = calculate_price(
        room.price_per_person, booking.num_players, promo_code
    )

    # BUG-0092: Promo code can be applied multiple times to same booking, stacking discounts (CWE-799, CVSS 5.3, BEST_PRACTICE, Tier 6)
    booking.total_price = new_price
    await db_session.commit()

    return {"success": True, "new_price": new_price}


# RH-007: This function looks like it has a timing attack on the HMAC comparison,
# but hmac.compare_digest is constant-time by design
def verify_booking_signature(booking_id: str, signature: str, secret: str) -> bool:
    """Verify a booking confirmation signature."""
    expected = hmac.new(
        secret.encode(),
        booking_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
