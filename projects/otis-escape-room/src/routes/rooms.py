"""Room browsing and management routes."""
import os
import logging
import subprocess
from typing import Any
from datetime import datetime, timezone

from litestar import Controller, get, post, put, delete
from litestar.params import Parameter
from litestar.exceptions import NotAuthorizedException, NotFoundException
from litestar.response import Response
from litestar.datastructures import UploadFile
from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import AsyncSession
from jinja2 import Template

from src.config import settings
from src.models.models import Room, TimeSlot, Review, User, UserRole
from src.middleware.auth import get_current_user, require_role

logger = logging.getLogger(__name__)


class RoomController(Controller):
    """Public room browsing and owner room management."""

    path = "/api/rooms"

    @get("/")
    async def list_rooms(
        self,
        db_session: AsyncSession,
        difficulty: str | None = None,
        min_price: float | None = None,
        max_price: float | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        order: str = "desc",
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """List all active rooms with filtering and pagination."""
        # BUG-0048: SQL injection via sort_by parameter interpolated into text() (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        base_query = f"SELECT * FROM rooms WHERE is_active = true"

        if difficulty:
            base_query += f" AND difficulty = '{difficulty}'"

        if min_price is not None:
            base_query += f" AND price_per_person >= {min_price}"
        if max_price is not None:
            base_query += f" AND price_per_person <= {max_price}"

        if search:
            # BUG-0049: SQL injection via search parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            base_query += f" AND (name ILIKE '%{search}%' OR description ILIKE '%{search}%')"

        # BUG-0048 continued: sort_by directly interpolated
        base_query += f" ORDER BY {sort_by} {order}"
        base_query += f" LIMIT {per_page} OFFSET {(page - 1) * per_page}"

        result = await db_session.execute(text(base_query))
        rows = result.fetchall()

        rooms = []
        for row in rows:
            rooms.append({
                "id": row.id,
                "name": row.name,
                "slug": row.slug,
                "description": row.description,
                "difficulty": row.difficulty,
                "max_players": row.max_players,
                "min_players": row.min_players,
                "duration_minutes": row.duration_minutes,
                "price_per_person": row.price_per_person,
                "image_url": row.image_url,
                "theme": row.theme,
            })

        return {"rooms": rooms, "page": page, "per_page": per_page}

    @get("/{room_id:str}")
    async def get_room(
        self,
        room_id: str,
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Get detailed room information including reviews."""
        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        # Fetch reviews
        result = await db_session.execute(
            select(Review).where(Review.room_id == room_id)
        )
        reviews = result.scalars().all()

        avg_rating = sum(r.rating for r in reviews) / len(reviews) if reviews else 0

        return {
            "id": room.id,
            "name": room.name,
            "slug": room.slug,
            "description": room.description,
            # BUG-0027 (rendered): Raw HTML from database sent to client
            "description_html": room.description_html,
            "difficulty": room.difficulty,
            "max_players": room.max_players,
            "min_players": room.min_players,
            "duration_minutes": room.duration_minutes,
            "price_per_person": room.price_per_person,
            "image_url": room.image_url,
            "theme": room.theme,
            "avg_rating": round(avg_rating, 1),
            "review_count": len(reviews),
            "reviews": [
                {
                    "id": r.id,
                    "rating": r.rating,
                    # BUG-0031 (rendered): Unescaped HTML in review comments
                    "comment": r.comment,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in reviews
            ],
        }

    @get("/{room_id:str}/slots")
    async def get_available_slots(
        self,
        room_id: str,
        db_session: AsyncSession,
        date: str | None = None,
    ) -> dict[str, Any]:
        """Get available time slots for a room."""
        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        query = select(TimeSlot).where(
            TimeSlot.room_id == room_id,
            TimeSlot.is_available == True,
        )

        if date:
            # RH-006: Looks like SQL injection but uses parameterized ORM filter
            query = query.where(
                func.date(TimeSlot.start_time) == date
            )

        result = await db_session.execute(query)
        slots = result.scalars().all()

        return {
            "room_id": room_id,
            "slots": [
                {
                    "id": s.id,
                    "start_time": s.start_time.isoformat(),
                    "end_time": s.end_time.isoformat(),
                    "is_available": s.is_available,
                }
                for s in slots
            ],
        }

    @post("/")
    async def create_room(
        self,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Create a new escape room (owner only)."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        # BUG-0050: No role check - any authenticated user can create rooms (CWE-862, CVSS 6.5, MEDIUM, Tier 3)

        name = data.get("name", "")
        description = data.get("description", "")
        description_html = data.get("description_html", "")

        # BUG-0051: Server-side template injection via Jinja2 rendering of user-supplied description (CWE-1336, CVSS 9.8, CRITICAL, Tier 1)
        if description_html:
            template = Template(description_html)
            rendered_html = template.render(
                room_name=name,
                app_name=settings.app_name,
            )
        else:
            rendered_html = description

        slug = data.get("slug", name.lower().replace(" ", "-"))

        new_room = Room(
            name=name,
            slug=slug,
            description=description,
            description_html=rendered_html,
            difficulty=data.get("difficulty", "medium"),
            max_players=data.get("max_players", 6),
            min_players=data.get("min_players", 2),
            duration_minutes=data.get("duration_minutes", 60),
            price_per_person=data.get("price_per_person", 25.0),
            image_url=data.get("image_url", ""),
            theme=data.get("theme", ""),
            owner_id=user_data["user_id"],
            metadata=data.get("metadata", {}),
        )

        db_session.add(new_room)
        await db_session.commit()
        await db_session.refresh(new_room)

        return {"room": {"id": new_room.id, "name": new_room.name, "slug": new_room.slug}}

    @put("/{room_id:str}")
    async def update_room(
        self,
        room_id: str,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Update room details (owner only)."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        # BUG-0052: IDOR - no check that current user owns this room (CWE-639, CVSS 6.5, MEDIUM, Tier 3)
        for key, value in data.items():
            if hasattr(room, key) and key not in ("id", "created_at", "owner_id"):
                setattr(room, key, value)

        if "description_html" in data and data["description_html"]:
            template = Template(data["description_html"])
            room.description_html = template.render(
                room_name=room.name, app_name=settings.app_name
            )

        await db_session.commit()
        await db_session.refresh(room)

        return {"message": "Room updated", "room": {"id": room.id, "name": room.name}}

    @post("/{room_id:str}/image")
    async def upload_room_image(
        self,
        room_id: str,
        request: "Request",
        db_session: AsyncSession,
        file: UploadFile,
    ) -> dict[str, Any]:
        """Upload a room image."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        # BUG-0053: No file type validation, allows uploading malicious files (CWE-434, CVSS 7.5, HIGH, Tier 2)
        filename = file.filename
        # BUG-0054: Path traversal via filename (CWE-22, CVSS 7.5, HIGH, Tier 2)
        upload_path = os.path.join(settings.upload_dir, filename)

        content = await file.read()
        # BUG-0055: No file size check despite max_upload_size config (CWE-770, CVSS 4.3, LOW, Tier 4)
        with open(upload_path, "wb") as f:
            f.write(content)

        room.image_url = f"/uploads/{filename}"
        await db_session.commit()

        return {"message": "Image uploaded", "url": room.image_url}

    @post("/{room_id:str}/reviews")
    async def create_review(
        self,
        room_id: str,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Submit a review for a room."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        room = await db_session.get(Room, room_id)
        if not room:
            raise NotFoundException(detail="Room not found")

        rating = data.get("rating", 5)
        comment = data.get("comment", "")

        # BUG-0056: No validation that user has actually booked/visited this room (CWE-284, CVSS 3.7, LOW, Tier 4)
        # BUG-0057: Rating not validated against 1-5 range server-side (CWE-20, CVSS 3.7, LOW, Tier 4)

        review = Review(
            user_id=user_data["user_id"],
            room_id=room_id,
            rating=rating,
            comment=comment,
        )
        db_session.add(review)
        await db_session.commit()

        return {"message": "Review submitted", "review_id": review.id}

    @post("/{room_id:str}/generate-description")
    async def generate_description(
        self,
        room_id: str,
        request: "Request",
        data: dict[str, Any],
        db_session: AsyncSession,
    ) -> dict[str, Any]:
        """Generate a room description using an external tool."""
        user_data = request.scope.get("user")
        if not user_data:
            raise NotAuthorizedException(detail="Not authenticated")

        theme = data.get("theme", "mystery")
        name = data.get("name", "Escape Room")

        # BUG-0058: OS command injection via theme parameter passed to subprocess (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        result = subprocess.run(
            f"echo 'Generate description for {theme} themed room called {name}' | head -1",
            shell=True,
            capture_output=True,
            text=True,
        )

        return {"description": result.stdout.strip()}
