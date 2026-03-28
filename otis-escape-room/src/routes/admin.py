"""Admin routes for managing rooms, bookings, users, and revenue reports."""
import csv
import io
import logging
import os
from typing import Any
from datetime import datetime, timezone, timedelta

from litestar import Controller, get, post, put, delete
from litestar.params import Parameter
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.response import Response
from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import AsyncSession
from jinja2 import Environment, BaseLoader

from src.config import settings
from src.models.models import (
    User, UserRole, Room, Booking, BookingStatus,
    Payment, PaymentStatus, AuditLog, Review
)
from src.middleware.auth import get_current_user, require_role, log_audit_event

logger = logging.getLogger(__name__)

# BUG-0076: Jinja2 Environment with no sandboxing for admin templates (CWE-1336, CVSS 7.5, HIGH, Tier 2)
template_env = Environment(loader=BaseLoader())


class AdminController(Controller):
    """Admin panel routes for platform management."""

    # BUG-0077: No authentication middleware on admin controller (CWE-862, CVSS 9.1, CRITICAL, Tier 1)
    path = "/api/admin"

    @get("/dashboard")
    async def dashboard(
        self,
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Get admin dashboard statistics."""
        # No auth check - accessible to anyone who knows the URL

        total_users = await db_session.scalar(
            select(func.count()).select_from(User)
        )
        total_rooms = await db_session.scalar(
            select(func.count()).select_from(Room)
        )
        total_bookings = await db_session.scalar(
            select(func.count()).select_from(Booking)
        )
        total_revenue = await db_session.scalar(
            select(func.sum(Payment.amount)).where(
                Payment.status == PaymentStatus.COMPLETED
            )
        ) or 0

        recent_bookings = await db_session.execute(
            select(Booking)
            .order_by(Booking.created_at.desc())
            .limit(10)
        )

        return {
            "total_users": total_users,
            "total_rooms": total_rooms,
            "total_bookings": total_bookings,
            "total_revenue": float(total_revenue),
            "recent_bookings": [
                {
                    "id": b.id,
                    "user_id": b.user_id,
                    "room_id": b.room_id,
                    "total_price": b.total_price,
                    "status": b.status.value if isinstance(b.status, BookingStatus) else b.status,
                    "created_at": b.created_at.isoformat() if b.created_at else None,
                }
                for b in recent_bookings.scalars().all()
            ],
        }

    @get("/users")
    async def list_users(
        self,
        db_session: AsyncSession,
        search: str | None = None,
        role: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> dict[str, Any]:
        """List all users with search and filtering."""
        # BUG-0078: SQL injection via search parameter in admin user listing (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
        query = "SELECT id, email, username, role, full_name, phone, is_active, created_at FROM users WHERE 1=1"

        if search:
            query += f" AND (email ILIKE '%{search}%' OR username ILIKE '%{search}%' OR full_name ILIKE '%{search}%')"

        if role:
            query += f" AND role = '{role}'"

        query += f" ORDER BY created_at DESC LIMIT {per_page} OFFSET {(page - 1) * per_page}"

        result = await db_session.execute(text(query))
        users = result.fetchall()

        return {
            "users": [
                {
                    "id": u.id,
                    "email": u.email,
                    "username": u.username,
                    "role": u.role,
                    "full_name": u.full_name,
                    "phone": u.phone,
                    "is_active": u.is_active,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                }
                for u in users
            ],
            "page": page,
        }

    @put("/users/{user_id:str}")
    async def update_user(
        self,
        user_id: str,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Update user details (admin only - but no auth check)."""
        user = await db_session.get(User, user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        # BUG-0079: Mass assignment on admin user update, can set password_hash directly (CWE-915, CVSS 8.1, HIGH, Tier 2)
        for key, value in data.items():
            if hasattr(user, key):
                setattr(user, key, value)

        await db_session.commit()
        await db_session.refresh(user)

        return {"message": "User updated", "user_id": user.id}

    @delete("/users/{user_id:str}")
    async def delete_user(
        self,
        user_id: str,
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Delete a user account."""
        # BUG-0080: No soft-delete, hard deletes user and orphans their bookings/payments (CWE-404, CVSS 4.3, BEST_PRACTICE, Tier 6)
        user = await db_session.get(User, user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        await db_session.delete(user)
        await db_session.commit()

        return {"message": "User deleted", "user_id": user_id}

    @get("/revenue")
    async def revenue_report(
        self,
        db_session: AsyncSession,
        start_date: str | None = None,
        end_date: str | None = None,
        group_by: str = "day",
    ) -> dict[str, Any]:
        """Generate revenue report with date range and grouping."""
        # BUG-0081: SQL injection via group_by parameter (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
        query = f"""
            SELECT
                date_trunc('{group_by}', p.created_at) as period,
                SUM(p.amount) as total_revenue,
                COUNT(*) as payment_count
            FROM payments p
            WHERE p.status = 'COMPLETED'
        """

        if start_date:
            query += f" AND p.created_at >= '{start_date}'"
        if end_date:
            query += f" AND p.created_at <= '{end_date}'"

        query += f" GROUP BY date_trunc('{group_by}', p.created_at)"
        query += " ORDER BY period DESC"

        result = await db_session.execute(text(query))
        rows = result.fetchall()

        return {
            "report": [
                {
                    "period": str(row.period),
                    "total_revenue": float(row.total_revenue) if row.total_revenue else 0,
                    "payment_count": row.payment_count,
                }
                for row in rows
            ],
        }

    @get("/revenue/export")
    async def export_revenue_csv(
        self,
        db_session: AsyncSession,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> Response:
        """Export revenue data as CSV."""
        query = select(Payment).where(Payment.status == PaymentStatus.COMPLETED)

        if start_date:
            query = query.where(Payment.created_at >= start_date)
        if end_date:
            query = query.where(Payment.created_at <= end_date)

        result = await db_session.execute(query)
        payments = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Payment ID", "Booking ID", "Amount", "Currency", "Status", "Created At"])

        for p in payments:
            writer.writerow([
                p.id, p.booking_id, p.amount, p.currency,
                p.status.value if isinstance(p.status, PaymentStatus) else p.status,
                p.created_at.isoformat() if p.created_at else "",
            ])

        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=revenue_export.csv"},
        )

    @get("/audit-logs")
    async def get_audit_logs(
        self,
        db_session: AsyncSession,
        user_id: str | None = None,
        action: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> dict[str, Any]:
        """View audit logs."""
        query = select(AuditLog).order_by(AuditLog.created_at.desc())

        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if action:
            query = query.where(AuditLog.action == action)

        query = query.offset((page - 1) * per_page).limit(per_page)

        result = await db_session.execute(query)
        logs = result.scalars().all()

        return {
            "logs": [
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    # BUG-0082: Audit log details exposed in API without redaction (CWE-200, CVSS 4.3, BEST_PRACTICE, Tier 6)
                    "details": log.details,
                    "ip_address": log.ip_address,
                    "created_at": log.created_at.isoformat() if log.created_at else None,
                }
                for log in logs
            ],
            "page": page,
        }

    @post("/notifications/send")
    async def send_notification(
        self,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Send a notification to users (admin tool)."""
        recipient_email = data.get("email", "")
        subject = data.get("subject", "")
        # BUG-0083: Template rendered from user input - SSTI in admin notification (CWE-1336, CVSS 8.6, CRITICAL, Tier 1)
        body_template = data.get("body", "")

        template = template_env.from_string(body_template)
        rendered_body = template.render(
            app_name=settings.app_name,
            config=settings,  # Exposes all settings including secrets
        )

        from src.services.email_service import send_email
        await send_email(recipient_email, subject, rendered_body)

        return {"message": "Notification sent"}

    @post("/rooms/{room_id:str}/bulk-slots")
    async def create_bulk_slots(
        self,
        room_id: str,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Create time slots in bulk for a room."""
        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        slots_data = data.get("slots", [])
        created = 0

        for slot_data in slots_data:
            start_str = slot_data.get("start_time", "")
            end_str = slot_data.get("end_time", "")

            if not start_str or not end_str:
                continue

            # BUG-0084: No overlap check when creating bulk slots, allows double-booking at DB level (CWE-367, CVSS 5.3, BEST_PRACTICE, Tier 6)
            from datetime import datetime as dt
            slot = __import__("src.models.models", fromlist=["TimeSlot"]).TimeSlot(
                room_id=room_id,
                start_time=dt.fromisoformat(start_str),
                end_time=dt.fromisoformat(end_str),
                is_available=True,
            )
            db_session.add(slot)
            created += 1

        await db_session.commit()
        return {"message": f"Created {created} time slots"}

    @post("/backup/export")
    async def export_database(
        self,
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Export database backup."""
        export_format = data.get("format", "sql")
        # BUG-0085: OS command injection via export format parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        output_file = f"/tmp/backup_{datetime.now().strftime('%Y%m%d')}.{export_format}"

        os.system(
            f"pg_dump {settings.database_url} --format={export_format} > {output_file}"
        )

        return {"message": "Backup created", "file": output_file}
