"""Tentacle Labs LIMS — Flask application factory."""

import os
import logging

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

from config import config_map

db = SQLAlchemy()
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map["development"]))

    # Ensure upload and export directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["EXPORT_DIR"], exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from app.routes.experiments import experiments_bp
    from app.routes.samples import samples_bp
    from app.routes.files import files_bp
    from app.routes.users import users_bp
    from app.routes.export import export_bp
    from app.auth import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(experiments_bp, url_prefix="/api/experiments")
    app.register_blueprint(samples_bp, url_prefix="/api/samples")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(export_bp, url_prefix="/api/export")

    # Register middleware
    from app.middleware import register_middleware
    register_middleware(app)

    # Create tables
    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    # BUG-013: Verbose error handler leaks internal details (CWE-209, CVSS 3.7, LOW, Tier 1)
    @app.errorhandler(Exception)
    def handle_exception(e):
        import traceback
        logger.error(f"Unhandled exception: {e}")
        return jsonify({
            "error": str(e),
            "type": type(e).__name__,
            "traceback": traceback.format_exc(),
            "request_url": request.url,
            "request_method": request.method,
        }), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found", "path": request.path}), 404

    # BUG-014: CORS headers set globally with wildcard and credentials (CWE-942, CVSS 5.3, MEDIUM, Tier 1)
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin", "*")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        return response

    # Health check
    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "healthy",
            "service": "tentacle-labs-lims",
            "version": "1.2.0",
            # BUG-015: Info disclosure — internal config leaked via health endpoint (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
            "debug": app.config["DEBUG"],
            "database": app.config["SQLALCHEMY_DATABASE_URI"],
            "environment": os.environ.get("FLASK_ENV", "development"),
        })

    return app
