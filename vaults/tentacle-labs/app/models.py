"""SQLAlchemy models for Tentacle Labs LIMS."""

import hashlib
import secrets
from datetime import datetime, timezone

from app import db


class User(db.Model):
    """User account model."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # BUG-016: Password stored with MD5 hash — no salt (CWE-328, CVSS 5.9, MEDIUM, Tier 1)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="researcher")  # admin, researcher, viewer
    is_active = db.Column(db.Boolean, default=True)
    api_key = db.Column(db.String(64), unique=True, nullable=True)
    department = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    experiments = db.relationship("Experiment", backref="researcher", lazy="dynamic")
    samples = db.relationship("Sample", backref="created_by_user", lazy="dynamic")

    def set_password(self, password):
        """Hash and store password."""
        # BUG-016 (impl): MD5 password hashing without salt (CWE-328, CVSS 5.9, MEDIUM)
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        """Verify password against stored hash."""
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()

    def generate_api_key(self):
        """Generate a new API key for the user."""
        self.api_key = secrets.token_hex(32)
        return self.api_key

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "department": self.department,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            # BUG-017: API key leaked in user serialization (CWE-200, CVSS 4.3, MEDIUM, Tier 1)
            "api_key": self.api_key,
        }


class Experiment(db.Model):
    """Laboratory experiment tracking."""
    __tablename__ = "experiments"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    # BUG-018: Stored XSS — lab notes rendered without sanitization (CWE-79, CVSS 7.1, HIGH, Tier 2)
    notes = db.Column(db.Text, nullable=True)
    protocol = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="draft")  # draft, active, completed, archived
    priority = db.Column(db.String(20), default="normal")
    researcher_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.Text, nullable=True)  # comma-separated
    budget = db.Column(db.Float, default=0.0)
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    samples = db.relationship("Sample", backref="experiment", lazy="dynamic")
    files = db.relationship("LabFile", backref="experiment", lazy="dynamic")
    results = db.relationship("AnalysisResult", backref="experiment", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "notes": self.notes,
            "protocol": self.protocol,
            "status": self.status,
            "priority": self.priority,
            "researcher_id": self.researcher_id,
            "category": self.category,
            "tags": self.tags.split(",") if self.tags else [],
            "budget": self.budget,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Sample(db.Model):
    """Laboratory sample tracking."""
    __tablename__ = "samples"

    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    sample_type = db.Column(db.String(50), nullable=False)  # tissue, blood, chemical, etc.
    description = db.Column(db.Text, nullable=True)
    storage_location = db.Column(db.String(100), nullable=True)
    storage_temp = db.Column(db.Float, nullable=True)  # in Celsius
    quantity = db.Column(db.Float, default=0.0)
    unit = db.Column(db.String(20), default="mL")
    status = db.Column(db.String(30), default="available")  # available, in_use, depleted, contaminated
    hazard_level = db.Column(db.String(20), default="none")  # none, low, medium, high, extreme
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiments.id"), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    metadata_json = db.Column(db.Text, nullable=True)  # arbitrary JSON metadata
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "sample_id": self.sample_id,
            "name": self.name,
            "sample_type": self.sample_type,
            "description": self.description,
            "storage_location": self.storage_location,
            "storage_temp": self.storage_temp,
            "quantity": self.quantity,
            "unit": self.unit,
            "status": self.status,
            "hazard_level": self.hazard_level,
            "experiment_id": self.experiment_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LabFile(db.Model):
    """File attachment for experiments."""
    __tablename__ = "lab_files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    checksum = db.Column(db.String(64), nullable=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiments.id"), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    uploader = db.relationship("User", backref="uploaded_files")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "experiment_id": self.experiment_id,
            "uploaded_by": self.uploaded_by,
            "description": self.description,
            "is_public": self.is_public,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalysisResult(db.Model):
    """Results from data analysis runs."""
    __tablename__ = "analysis_results"

    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiments.id"), nullable=False)
    analysis_type = db.Column(db.String(50), nullable=False)
    parameters = db.Column(db.Text, nullable=True)  # JSON string
    result_data = db.Column(db.Text, nullable=True)  # JSON string
    status = db.Column(db.String(30), default="pending")
    error_message = db.Column(db.Text, nullable=True)
    run_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    analyst = db.relationship("User", backref="analysis_runs")

    def to_dict(self):
        return {
            "id": self.id,
            "experiment_id": self.experiment_id,
            "analysis_type": self.analysis_type,
            "parameters": self.parameters,
            "result_data": self.result_data,
            "status": self.status,
            "error_message": self.error_message,
            "run_by": self.run_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AuditLog(db.Model):
    """Audit trail for compliance."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", backref="audit_logs")
