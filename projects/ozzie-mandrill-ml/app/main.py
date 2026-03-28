"""
Ozzie Mandrill ML — FastAPI application entrypoint.
Fintech ML model serving platform with versioning, drift monitoring,
and A/B testing capabilities.
"""
import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routes import models, predictions, experiments, auth
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.auth import AuthMiddleware


logger = logging.getLogger("ozzie-mandrill")
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("Starting Ozzie Mandrill ML Platform v%s", settings.app_version)
    logger.info("Model storage: %s", settings.model_storage_path)
    logger.info("MLflow tracking: %s", settings.mlflow_tracking_uri)
    yield
    logger.info("Shutting down Ozzie Mandrill ML Platform")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    # BUG-0020: OpenAPI docs exposed in production without auth (CWE-200, CVSS 3.7, LOW, Tier 4)
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# CORS middleware
# BUG-0018: (see config.py) Wildcard CORS applied here
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware
app.add_middleware(RequestLoggingMiddleware)
# BUG-0093: No security headers middleware (CSP, X-Frame-Options, HSTS) (CWE-693, CVSS 3.7, BEST_PRACTICE, Tier 6)
# Note: AuthMiddleware is applied selectively in routes, not globally


# Include route modules
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(models.router, prefix="/api/v1/models", tags=["Models"])
app.include_router(predictions.router, prefix="/api/v1/predictions", tags=["Predictions"])
app.include_router(experiments.router, prefix="/api/v1/experiments", tags=["Experiments"])


@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "version": settings.app_version,
        # BUG-0021: Health endpoint leaks internal configuration details (CWE-200, CVSS 3.1, LOW, Tier 4)
        "debug": settings.debug,
        "database": settings.database_url,
        "redis": settings.redis_url,
        "mlflow": settings.mlflow_tracking_uri,
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    logger.error("Unhandled exception: %s", str(exc))
    
    # BUG-0022: Stack trace returned to client in error response (CWE-209, CVSS 4.3, LOW, Tier 4)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )


@app.get("/api/v1/debug/config")
async def debug_config():
    """Debug endpoint to inspect running configuration.
    
    Intended for development use only.
    """
    # BUG-0023: Debug endpoint exposes full config including secrets with no auth (CWE-200, CVSS 7.5, HIGH, Tier 2)
    return settings.model_dump()


@app.get("/api/v1/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    # RH-003: Looks like it exposes sensitive data, but metrics are standard Prometheus format with no PII
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
