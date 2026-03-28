"""Main Litestar application for the Otis Escape Room booking platform."""
import logging
import os
import sys
from typing import Any
from pathlib import Path

from litestar import Litestar, get, post, Request
from litestar.config.cors import CORSConfig
from litestar.di import Provide
from litestar.logging import LoggingConfig
from litestar.static_files import StaticFilesConfig
from litestar.openapi import OpenAPIConfig
from litestar.response import Response
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from src.config import settings, get_public_config
from src.middleware.auth import AuthMiddleware
from src.routes.auth import AuthController
from src.routes.rooms import RoomController
from src.routes.bookings import BookingController
from src.routes.payments import PaymentController, WebhookController
from src.routes.admin import AdminController

logger = logging.getLogger(__name__)

# Database setup
# BUG-0017 (used): Hardcoded credentials in connection string fallback
async_engine = create_async_engine(
    settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.debug,  # BUG-0008 (effect): SQL queries logged in production when debug=true
    pool_size=20,
    max_overflow=10,
)

async_session_factory = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncSession:
    """Dependency provider for database sessions."""
    async with async_session_factory() as session:
        yield session


@get("/api/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.version,
    }


@get("/api/config")
async def public_config() -> dict[str, Any]:
    """Return public configuration for frontend."""
    return get_public_config()


@post("/api/feedback")
async def submit_feedback(
    request: Request,
    data: dict[str, Any],
) -> dict[str, str]:
    """Submit user feedback.

    Feedback is logged for review by the team.
    """
    name = data.get("name", "Anonymous")
    email = data.get("email", "")
    message = data.get("message", "")
    safe_name = name.replace("\n", "").replace("\r", "")
    safe_email = email.replace("\n", "").replace("\r", "")
    logger.info(f"Feedback from {safe_name} ({safe_email})")

    return {"message": "Thank you for your feedback!"}


@get("/api/debug/env")
async def debug_env() -> dict[str, Any]:
    """Debug endpoint to inspect environment.

    Should be disabled in production.
    """
    return {"error": "Debug endpoint disabled in all environments"}


# Logging configuration
logging_config = LoggingConfig(
    root={"level": "DEBUG" if settings.debug else "INFO", "handlers": ["console"]},
    formatters={
        "standard": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"}
    },
    handlers={
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        }
    },
)

# CORS configuration
cors_config = CORSConfig(
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
    max_age=86400,
)

# OpenAPI configuration
openapi_config = OpenAPIConfig(
    title="Otis Escape Room API",
    version=settings.version,
    description="Escape room booking and management platform",
)

# Static files for uploads
static_files_config = [
    StaticFilesConfig(
        directories=[settings.upload_dir],
        path="/uploads",
        # RH-007 (duplicate label, but unique red herring): Looks like directory listing is enabled
        # but Litestar's StaticFilesConfig does not serve directory listings by default
    ),
]

# Create the application
app = Litestar(
    route_handlers=[
        health_check,
        public_config,
        submit_feedback,
        debug_env,
        AuthController,
        RoomController,
        BookingController,
        PaymentController,
        WebhookController,
        AdminController,
    ],
    dependencies={"db_session": Provide(get_db_session)},
    middleware=[AuthMiddleware],
    cors_config=cors_config,
    openapi_config=openapi_config,
    logging_config=logging_config,
    debug=settings.debug,
)
