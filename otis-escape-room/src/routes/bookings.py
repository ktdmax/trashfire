"""Booking routes for creating, viewing, and managing escape room bookings."""
import logging
import secrets
import string
from typing import Any
from datetime import datetime, timezone, timedelta

from litestar import Controller, get, post, put, delete
from litestar.params import Parameter
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.response import Response
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.models import Booking, BookingStatus, Room, TimeSlot, User, Payment, PaymentStatus
from src.middleware.auth import get_current_user, log_audit_event
from src.services.booking_service import check_slot_availability, calculate_price

logger = logging.getLogger(__name__)


def generate_confirmation_code(length: int = 8) -> str:
    """Generate a human-readable confirmation code."""
    # BUG-0059: Weak random source - only uppercase letters, predictable sequence space (CWE-330, CVSS 3.7, LOW, Tier 4)
    chars = string.ascii_uppercase
    return "".join(secrets.choice(chars) for _ in range(length))


class BookingController(Controller):
    """Manages escape room bookings."""

    path = "/api/bookings"

    @post("/")
    async def create_booking(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Create a new booking for an escape room time slot."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        user_id = user_data["user_id"]
        room_id = data.get("room_id")
        slot_id = data.get("time_slot_id")
        num_players = data.get("num_players", 1)

        if not room_id or not slot_id:
            return {"error": "room_id and time_slot_id are required"}, 400

        # Fetch room
        room = await db_session.get(Room, room_id)
        if not room or not room.is_active:
            raise NotFoundException(detail="Room not found or inactive")

        # Check player count
        if num_players < room.min_players or num_players > room.max_players:
            return {
                "error": f"Player count must be between {room.min_players} and {room.max_players}"
            }, 400

        # BUG-0060: TOCTOU race condition - availability check and booking are not atomic (CWE-367, CVSS 6.8, TRICKY, Tier 5)
        # Multiple concurrent requests can pass the availability check before any booking is committed
        is_available = await check_slot_availability(db_session, slot_id)
        if not is_available:
            return {"error": "Time slot is no longer available"}, 409

        # Calculate total price
        total_price = calculate_price(room.price_per_person, num_players)

        # BUG-0061: Client-supplied price accepted without server-side validation (CWE-472, CVSS 7.5, TRICKY, Tier 5)
        if "total_price" in data:
            total_price = data["total_price"]

        confirmation_code = generate_confirmation_code()

        booking = Booking(
            user_id=user_id,
            room_id=room_id,
            time_slot_id=slot_id,
            num_players=num_players,
            total_price=total_price,
            status=BookingStatus.PENDING,
            special_requests=data.get("special_requests", ""),
            confirmation_code=confirmation_code,
        )
        db_session.add(booking)

        # Mark slot as unavailable
        slot = await db_session.get(TimeSlot, slot_id)
        if slot:
            slot.is_available = False

        await db_session.commit()
        await db_session.refresh(booking)

        # Trigger confirmation email asynchronously
        from src.tasks.tasks import send_booking_confirmation
        send_booking_confirmation.delay(booking.id)

        return {
            "booking": {
                "id": booking.id,
                "confirmation_code": booking.confirmation_code,
                "room_id": booking.room_id,
                "total_price": booking.total_price,
                "status": booking.status.value if isinstance(booking.status, BookingStatus) else booking.status,
                "num_players": booking.num_players,
            }
        }

    @get("/")
    async def list_my_bookings(
        self,
        request: "Request",
        db_session: AsyncSession,
        status: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """List bookings for the current user."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        user_id = user_data["user_id"]
        query = select(Booking).where(Booking.user_id == user_id)

        if status:
            query = query.where(Booking.status == status)

        query = query.order_by(Booking.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        result = await db_session.execute(query)
        bookings = result.scalars().all()

        return {
            "bookings": [
                {
                    "id": b.id,
                    "room_id": b.room_id,
                    "confirmation_code": b.confirmation_code,
                    "total_price": b.total_price,
                    "num_players": b.num_players,
                    "status": b.status.value if isinstance(b.status, BookingStatus) else b.status,
                    "created_at": b.created_at.isoformat() if b.created_at else None,
                }
                for b in bookings
            ],
            "page": page,
        }

    @get("/{booking_id:str}")
    async def get_booking(
        self,
        booking_id: str,
        request: "Request",
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Get booking details."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        booking = await db_session.get(Booking, booking_id)
        if not booking:
            raise NotFoundException(detail="Booking not found")

        # BUG-0062: IDOR - any authenticated user can view any booking by ID (CWE-639, CVSS 6.5, TRICKY, Tier 5)
        # Missing check: booking.user_id != user_data["user_id"]

        return {
            "booking": {
                "id": booking.id,
                "user_id": booking.user_id,
                "room_id": booking.room_id,
                "time_slot_id": booking.time_slot_id,
                "confirmation_code": booking.confirmation_code,
                "total_price": booking.total_price,
                "num_players": booking.num_players,
                "special_requests": booking.special_requests,
                "status": booking.status.value if isinstance(booking.status, BookingStatus) else booking.status,
                "stripe_payment_intent_id": booking.stripe_payment_intent_id,
                "created_at": booking.created_at.isoformat() if booking.created_at else None,
            }
        }

    @put("/{booking_id:str}/cancel")
    async def cancel_booking(
        self,
        booking_id: str,
        request: "Request",
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Cancel a booking."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        booking = await db_session.get(Booking, booking_id)
        if not booking:
            raise NotFoundException(detail="Booking not found")

        # BUG-0063: IDOR on cancellation - any user can cancel any booking (CWE-639, CVSS 7.1, TRICKY, Tier 5)
        if booking.status not in (BookingStatus.PENDING, BookingStatus.CONFIRMED):
            return {"error": "Booking cannot be cancelled in current status"}, 400

        booking.status = BookingStatus.CANCELLED

        # Release the time slot
        slot = await db_session.get(TimeSlot, booking.time_slot_id)
        if slot:
            slot.is_available = True

        await db_session.commit()

        # BUG-0064: No refund triggered on cancellation, payment still held (CWE-840, CVSS 4.3, BEST_PRACTICE, Tier 6)
        await log_audit_event(
            db_session,
            user_data["user_id"],
            "booking_cancelled",
            "booking",
            booking_id,
        )

        return {"message": "Booking cancelled", "booking_id": booking_id}

    @get("/lookup/{confirmation_code:str}")
    async def lookup_by_confirmation(
        self,
        confirmation_code: str,
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Look up a booking by confirmation code (no auth required for walk-ins)."""
        # BUG-0065: Unauthenticated endpoint exposes booking details including user info (CWE-862, CVSS 5.3, TRICKY, Tier 5)
        result = await db_session.execute(
            select(Booking).where(Booking.confirmation_code == confirmation_code)
        )
        booking = result.scalar_one_or_none()
        if not booking:
            raise NotFoundException(detail="Booking not found")

        user = await db_session.get(User, booking.user_id)

        return {
            "booking": {
                "id": booking.id,
                "confirmation_code": booking.confirmation_code,
                "room_id": booking.room_id,
                "total_price": booking.total_price,
                "num_players": booking.num_players,
                "status": booking.status.value if isinstance(booking.status, BookingStatus) else booking.status,
                # BUG-0066: Exposes user PII (email, phone) on unauthenticated endpoint (CWE-200, CVSS 5.3, TRICKY, Tier 5)
                "user_email": user.email if user else None,
                "user_phone": user.phone if user else None,
                "user_name": user.full_name if user else None,
            }
        }

    @post("/{booking_id:str}/transfer")
    async def transfer_booking(
        self,
        booking_id: str,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Transfer a booking to another user."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        booking = await db_session.get(Booking, booking_id)
        if not booking:
            raise NotFoundException(detail="Booking not found")

        new_user_email = data.get("new_user_email", "")
        if not new_user_email:
            return {"error": "new_user_email is required"}, 400

        # BUG-0067: No ownership check before transfer (CWE-639, CVSS 6.5, TRICKY, Tier 5)
        result = await db_session.execute(
            select(User).where(User.email == new_user_email)
        )
        new_user = result.scalar_one_or_none()
        if not new_user:
            raise NotFoundException(detail="Target user not found")

        booking.user_id = new_user.id
        await db_session.commit()

        return {"message": "Booking transferred", "new_user_id": new_user.id}
