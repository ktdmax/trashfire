"""Celery tasks for asynchronous background operations."""
import logging
import json
import pickle
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Any

from celery import Celery
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from src.config import settings
from src.models.models import (
    Booking, BookingStatus, Room, TimeSlot, User, Payment, PaymentStatus
)

logger = logging.getLogger(__name__)

app = Celery(
    "otis_tasks",
    broker=settings.rabbitmq_url,
    backend=settings.redis_url,
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    result_expires=timedelta(hours=24),
)

# Synchronous engine for Celery tasks
engine = create_engine(settings.database_url)


@app.task(name="send_booking_confirmation")
def send_booking_confirmation(booking_id: str) -> dict[str, Any]:
    """Send booking confirmation email asynchronously.

    Fetches booking details and sends a formatted confirmation email
    to the customer.
    """
    with Session(engine) as session:
        booking = session.get(Booking, booking_id)
        if not booking:
            logger.error(f"Booking {booking_id} not found for confirmation")
            return {"status": "error", "reason": "booking_not_found"}

        user = session.get(User, booking.user_id)
        room = session.get(Room, booking.room_id)
        slot = session.get(TimeSlot, booking.time_slot_id)

        if not user or not room:
            return {"status": "error", "reason": "related_data_missing"}

        # Import here to avoid circular dependency
        import asyncio
        from src.services.email_service import send_booking_confirmation_email

        success = asyncio.run(
            send_booking_confirmation_email(
                to_email=user.email,
                user_name=user.full_name or user.username,
                room_name=room.name,
                slot_time=slot.start_time.isoformat() if slot else "TBD",
                num_players=booking.num_players,
                total_price=booking.total_price,
                confirmation_code=booking.confirmation_code or "",
            )
        )

        return {"status": "sent" if success else "failed", "booking_id": booking_id}


@app.task(name="cancel_expired_bookings")
def cancel_expired_bookings_task() -> dict[str, Any]:
    """Periodic task to cancel bookings that have been pending too long.

    Runs every 15 minutes via Celery Beat.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)

    with Session(engine) as session:
        bookings = session.execute(
            select(Booking).where(
                Booking.status == BookingStatus.PENDING,
                Booking.created_at < cutoff,
            )
        ).scalars().all()

        cancelled = 0
        for booking in bookings:
            booking.status = BookingStatus.CANCELLED

            slot = session.get(TimeSlot, booking.time_slot_id)
            if slot:
                slot.is_available = True

            cancelled += 1

        session.commit()
        logger.info(f"Expired bookings task: cancelled {cancelled} bookings")

    return {"cancelled": cancelled}


@app.task(name="generate_daily_report")
def generate_daily_report(date_str: str | None = None) -> dict[str, Any]:
    """Generate a daily revenue and booking report.

    Args:
        date_str: Optional date string (YYYY-MM-DD). Defaults to yesterday.
    """
    if not date_str:
        date_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

    with Session(engine) as session:
        result = session.execute(
            text("""
                SELECT
                    COUNT(*) as total_bookings,
                    SUM(b.total_price) as total_revenue,
                    COUNT(DISTINCT b.user_id) as unique_customers,
                    COUNT(DISTINCT b.room_id) as rooms_booked
                FROM bookings b
                WHERE DATE(b.created_at) = :report_date
                  AND b.status IN ('confirmed', 'completed')
            """),
            {"report_date": date_str},
        )
        row = result.fetchone()

        report = {
            "date": date_str,
            "total_bookings": row.total_bookings if row else 0,
            "total_revenue": float(row.total_revenue) if row and row.total_revenue else 0.0,
            "unique_customers": row.unique_customers if row else 0,
            "rooms_booked": row.rooms_booked if row else 0,
        }

        logger.info(f"Daily report for {date_str}: {json.dumps(report)}")
        return report


@app.task(name="process_webhook_event")
def process_webhook_event(event_payload: str) -> dict[str, Any]:
    """Process a queued webhook event.

    Events are queued for reliability and processed asynchronously.
    """
    try:
        event = json.loads(event_payload)
    except json.JSONDecodeError:
        return {"status": "error", "reason": "invalid_json_payload"}

    event_type = event.get("type", "unknown")
    logger.info(f"Processing queued webhook event: {event_type}")

    return {"status": "processed", "event_type": event_type}


@app.task(name="cleanup_old_data")
def cleanup_old_data(days_to_keep: int = 90) -> dict[str, Any]:
    """Clean up old audit logs and cancelled bookings.

    Runs weekly to keep database size manageable.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

    with Session(engine) as session:
        # Clean old audit logs
        deleted_logs = session.execute(
            text(f"DELETE FROM audit_logs WHERE created_at < '{cutoff.isoformat()}'")
        ).rowcount

        # Clean old cancelled bookings
        deleted_bookings = session.execute(
            text(
                f"DELETE FROM bookings WHERE status = 'cancelled' "
                f"AND created_at < '{cutoff.isoformat()}'"
            )
        ).rowcount

        session.commit()

    return {
        "deleted_audit_logs": deleted_logs,
        "deleted_cancelled_bookings": deleted_bookings,
    }


@app.task(name="sync_with_external_calendar")
def sync_with_external_calendar(
    room_id: str,
    calendar_url: str,
) -> dict[str, Any]:
    """Sync room availability with an external calendar service.

    Used to import/export time slots from Google Calendar, Outlook, etc.
    """
    import httpx
    from urllib.parse import urlparse
    parsed = urlparse(calendar_url)
    if parsed.scheme not in ("https",) or not parsed.hostname:
        return {"status": "error", "reason": "invalid_calendar_url"}
    try:
        response = httpx.get(calendar_url, verify=True, follow_redirects=False, timeout=10)
        calendar_data = response.text

        # Parse iCal data (simplified)
        events = []
        if "BEGIN:VEVENT" in calendar_data:
            for block in calendar_data.split("BEGIN:VEVENT")[1:]:
                event = {}
                for line in block.split("\n"):
                    if line.startswith("DTSTART:"):
                        event["start"] = line.split(":", 1)[1].strip()
                    elif line.startswith("DTEND:"):
                        event["end"] = line.split(":", 1)[1].strip()
                    elif line.startswith("SUMMARY:"):
                        event["title"] = line.split(":", 1)[1].strip()
                if event:
                    events.append(event)

        return {
            "status": "synced",
            "room_id": room_id,
            "events_found": len(events),
        }
    except Exception as e:
        return {"status": "error", "reason": str(e)}


@app.task(name="generate_room_thumbnail")
def generate_room_thumbnail(
    image_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generate a thumbnail for a room image.

    Uses ImageMagick convert command for resizing.
    """
    if not output_path:
        output_path = image_path.replace(".", "_thumb.")

    result = subprocess.run(
        ["convert", image_path, "-resize", "300x200", output_path],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        logger.error(f"Thumbnail generation failed: {result.stderr}")
        return {"status": "error", "reason": result.stderr}

    return {"status": "created", "path": output_path}


# Celery Beat schedule for periodic tasks
app.conf.beat_schedule = {
    "cancel-expired-bookings": {
        "task": "cancel_expired_bookings",
        "schedule": timedelta(minutes=15),
    },
    "generate-daily-report": {
        "task": "generate_daily_report",
        "schedule": timedelta(days=1),
    },
    "cleanup-old-data": {
        "task": "cleanup_old_data",
        "schedule": timedelta(days=7),
    },
}
