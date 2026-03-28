"""SQLAlchemy models for the Otis Escape Room platform."""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, Enum, Index, UniqueConstraint, CheckConstraint,
    JSON, LargeBinary
)
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class UserRole(PyEnum):
    CUSTOMER = "customer"
    OWNER = "owner"
    ADMIN = "admin"


class BookingStatus(PyEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    REFUNDED = "refunded"


class PaymentStatus(PyEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"


class RoomDifficulty(PyEnum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    # BUG-0023: Password stored as plain string column, no enforced hashing at model level (CWE-257, CVSS 7.5, HIGH, Tier 2)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole), default=UserRole.CUSTOMER, nullable=False
    )
    full_name: Mapped[str] = mapped_column(String(200), nullable=True)
    phone: Mapped[str] = mapped_column(String(20), nullable=True)
    # BUG-0024: Storing full credit card number in DB (CWE-311, CVSS 8.6, HIGH, Tier 2)
    saved_card_number: Mapped[str] = mapped_column(String(19), nullable=True)
    saved_card_expiry: Mapped[str] = mapped_column(String(5), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # BUG-0025: Password reset token stored without expiry, reusable indefinitely (CWE-640, CVSS 7.5, HIGH, Tier 2)
    reset_token: Mapped[str] = mapped_column(String(255), nullable=True)
    profile_image_url: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    # BUG-0026: Storing user preferences as pickled blob, deserialization risk (CWE-502, CVSS 8.1, HIGH, Tier 2)
    preferences: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    bookings = relationship("Booking", back_populates="user", lazy="selectin")
    reviews = relationship("Review", back_populates="user", lazy="selectin")

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


class Room(Base):
    __tablename__ = "rooms"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    # BUG-0027: Room description rendered as raw HTML, stored XSS (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
    description_html: Mapped[str] = mapped_column(Text, nullable=True)
    difficulty: Mapped[str] = mapped_column(
        Enum(RoomDifficulty), default=RoomDifficulty.MEDIUM
    )
    max_players: Mapped[int] = mapped_column(Integer, default=6)
    min_players: Mapped[int] = mapped_column(Integer, default=2)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    price_per_person: Mapped[float] = mapped_column(Float, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    image_url: Mapped[str] = mapped_column(Text, nullable=True)
    theme: Mapped[str] = mapped_column(String(100), nullable=True)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    # BUG-0028: Metadata stored as JSON without sanitization, injection in admin queries (CWE-94, CVSS 5.4, MEDIUM, Tier 3)
    metadata: Mapped[dict] = mapped_column(JSON, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    owner = relationship("User", foreign_keys=[owner_id])
    bookings = relationship("Booking", back_populates="room", lazy="selectin")
    time_slots = relationship("TimeSlot", back_populates="room", lazy="selectin")
    reviews = relationship("Review", back_populates="room", lazy="selectin")

    __table_args__ = (
        Index("idx_room_slug", "slug"),
        Index("idx_room_active", "is_active"),
    )


class TimeSlot(Base):
    __tablename__ = "time_slots"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    room_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rooms.id"), nullable=False
    )
    start_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_available: Mapped[bool] = mapped_column(Boolean, default=True)
    # RH-003: Looks like a race condition but the availability check + update
    # is handled atomically via SELECT FOR UPDATE in the booking service
    locked_until: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    locked_by: Mapped[str] = mapped_column(String(36), nullable=True)

    room = relationship("Room", back_populates="time_slots")
    booking = relationship("Booking", back_populates="time_slot", uselist=False)

    __table_args__ = (
        Index("idx_slot_room_time", "room_id", "start_time"),
        UniqueConstraint("room_id", "start_time", name="uq_room_start"),
    )


class Booking(Base):
    __tablename__ = "bookings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    room_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rooms.id"), nullable=False
    )
    time_slot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("time_slots.id"), nullable=False
    )
    num_players: Mapped[int] = mapped_column(Integer, nullable=False)
    total_price: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(BookingStatus), default=BookingStatus.PENDING
    )
    # BUG-0029: Booking notes rendered without escaping in admin panel (CWE-79, CVSS 5.4, MEDIUM, Tier 3)
    special_requests: Mapped[str] = mapped_column(Text, nullable=True)
    confirmation_code: Mapped[str] = mapped_column(String(20), unique=True, nullable=True)
    stripe_payment_intent_id: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="bookings")
    room = relationship("Room", back_populates="bookings")
    time_slot = relationship("TimeSlot", back_populates="booking")
    payment = relationship("Payment", back_populates="booking", uselist=False)

    __table_args__ = (
        Index("idx_booking_user", "user_id"),
        Index("idx_booking_status", "status"),
    )


class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    booking_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("bookings.id"), nullable=False
    )
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[str] = mapped_column(
        Enum(PaymentStatus), default=PaymentStatus.PENDING
    )
    stripe_payment_intent_id: Mapped[str] = mapped_column(String(255), nullable=True)
    stripe_charge_id: Mapped[str] = mapped_column(String(255), nullable=True)
    # BUG-0030: Payment method details logged including full card info (CWE-532, CVSS 4.3, LOW, Tier 4)
    payment_method_details: Mapped[str] = mapped_column(Text, nullable=True)
    refund_amount: Mapped[float] = mapped_column(Float, nullable=True, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    booking = relationship("Booking", back_populates="payment")


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    room_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rooms.id"), nullable=False
    )
    rating: Mapped[int] = mapped_column(Integer, nullable=False)
    # BUG-0031: Review comment allows HTML, rendered unescaped on room page (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
    comment: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="reviews")
    room = relationship("Room", back_populates="reviews")

    __table_args__ = (
        CheckConstraint("rating >= 1 AND rating <= 5", name="ck_rating_range"),
        UniqueConstraint("user_id", "room_id", name="uq_user_room_review"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=True)
    # BUG-0032: Audit log stores raw request body including passwords and tokens (CWE-532, CVSS 5.3, MEDIUM, Tier 3)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_action", "action"),
    )
