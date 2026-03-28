"""Experiment CRUD endpoints for Tentacle Labs LIMS."""

import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g, render_template_string

from app import db
from app.models import Experiment, Sample, AuditLog
from app.auth import require_auth, require_role

experiments_bp = Blueprint("experiments", __name__)
logger = logging.getLogger(__name__)


@experiments_bp.route("/", methods=["GET"])
@require_auth
def list_experiments():
    """List experiments with optional filtering."""
    status = request.args.get("status")
    category = request.args.get("category")
    search = request.args.get("search", "")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # BUG-030: SQL injection in search/filter via raw query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    query_str = "SELECT * FROM experiments WHERE 1=1"
    if status:
        query_str += f" AND status = '{status}'"
    if category:
        query_str += f" AND category = '{category}'"
    if search:
        query_str += f" AND (title LIKE '%{search}%' OR description LIKE '%{search}%')"

    query_str += f" LIMIT {per_page} OFFSET {(page - 1) * per_page}"

    result = db.session.execute(db.text(query_str))
    rows = result.fetchall()

    experiments = []
    for row in rows:
        exp = Experiment.query.get(row[0])
        if exp:
            experiments.append(exp.to_dict())

    return jsonify({
        "experiments": experiments,
        "page": page,
        "per_page": per_page,
    })


@experiments_bp.route("/", methods=["POST"])
@require_auth
def create_experiment():
    """Create a new experiment."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "Title is required"}), 400

    experiment = Experiment(
        title=title,
        description=data.get("description", ""),
        notes=data.get("notes", ""),
        protocol=data.get("protocol", ""),
        status=data.get("status", "draft"),
        priority=data.get("priority", "normal"),
        researcher_id=g.current_user.id,
        category=data.get("category", ""),
        tags=data.get("tags", ""),
        budget=data.get("budget", 0.0),
    )

    if data.get("start_date"):
        experiment.start_date = datetime.fromisoformat(data["start_date"])
    if data.get("end_date"):
        experiment.end_date = datetime.fromisoformat(data["end_date"])

    db.session.add(experiment)
    db.session.commit()

    logger.info(f"Experiment created: {experiment.id} by user {g.current_user.id}")

    return jsonify(experiment.to_dict()), 201


@experiments_bp.route("/<int:experiment_id>", methods=["GET"])
@require_auth
def get_experiment(experiment_id):
    """Get experiment details."""
    # BUG-031: IDOR — any authenticated user can view any experiment (CWE-639, CVSS 6.5, HIGH, Tier 1)
    experiment = Experiment.query.get_or_404(experiment_id)
    return jsonify(experiment.to_dict())


@experiments_bp.route("/<int:experiment_id>", methods=["PUT"])
@require_auth
def update_experiment(experiment_id):
    """Update experiment details."""
    # BUG-032: IDOR — any authenticated user can modify any experiment (CWE-639, CVSS 7.5, HIGH, Tier 1)
    experiment = Experiment.query.get_or_404(experiment_id)
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # BUG-033: Mass assignment — user can override researcher_id (CWE-915, CVSS 6.5, HIGH, Tier 2)
    for key, value in data.items():
        if hasattr(experiment, key):
            setattr(experiment, key, value)

    experiment.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify(experiment.to_dict())


@experiments_bp.route("/<int:experiment_id>", methods=["DELETE"])
@require_auth
@require_role("admin", "researcher")
def delete_experiment(experiment_id):
    """Delete an experiment and associated data."""
    experiment = Experiment.query.get_or_404(experiment_id)

    # BUG-034: Missing ownership check — any researcher can delete any experiment (CWE-862, CVSS 7.1, HIGH, Tier 2)
    db.session.delete(experiment)
    db.session.commit()

    logger.info(f"Experiment {experiment_id} deleted by user {g.current_user.id}")
    return jsonify({"message": "Experiment deleted"})


@experiments_bp.route("/<int:experiment_id>/notes", methods=["GET"])
@require_auth
def get_experiment_notes(experiment_id):
    """Render experiment notes as HTML."""
    experiment = Experiment.query.get_or_404(experiment_id)

    # BUG-035: Server-side template injection (SSTI) via Jinja2 (CWE-1336, CVSS 9.8, CRITICAL, Tier 1)
    template = f"""
    <div class="experiment-notes">
        <h2>{experiment.title}</h2>
        <div class="notes-content">{experiment.notes}</div>
        <p>Last updated: {experiment.updated_at}</p>
    </div>
    """
    rendered = render_template_string(template)
    return jsonify({"html": rendered})


@experiments_bp.route("/<int:experiment_id>/clone", methods=["POST"])
@require_auth
def clone_experiment(experiment_id):
    """Clone an existing experiment."""
    source = Experiment.query.get_or_404(experiment_id)

    clone = Experiment(
        title=f"Copy of {source.title}",
        description=source.description,
        notes=source.notes,
        protocol=source.protocol,
        status="draft",
        priority=source.priority,
        researcher_id=g.current_user.id,
        category=source.category,
        tags=source.tags,
        budget=source.budget,
    )

    db.session.add(clone)
    db.session.commit()

    return jsonify(clone.to_dict()), 201


@experiments_bp.route("/<int:experiment_id>/status", methods=["PATCH"])
@require_auth
def update_status(experiment_id):
    """Update experiment status with transition validation."""
    experiment = Experiment.query.get_or_404(experiment_id)
    data = request.get_json()
    new_status = data.get("status", "")

    valid_transitions = {
        "draft": ["active", "archived"],
        "active": ["completed", "archived"],
        "completed": ["archived"],
        "archived": ["draft"],
    }

    current = experiment.status
    if new_status not in valid_transitions.get(current, []):
        return jsonify({
            "error": f"Invalid transition from {current} to {new_status}"
        }), 400

    experiment.status = new_status
    experiment.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify(experiment.to_dict())


# BUG-036: N+1 query problem in summary endpoint (CWE-1073, CVSS N/A, BEST_PRACTICE, Tier 1)
@experiments_bp.route("/summary", methods=["GET"])
@require_auth
def experiments_summary():
    """Get summary statistics for all experiments."""
    experiments = Experiment.query.all()
    summary = []
    for exp in experiments:
        sample_count = Sample.query.filter_by(experiment_id=exp.id).count()
        summary.append({
            "id": exp.id,
            "title": exp.title,
            "status": exp.status,
            "sample_count": sample_count,
            "researcher": exp.researcher.username if exp.researcher else None,
        })
    return jsonify({"summary": summary})


@experiments_bp.route("/search", methods=["POST"])
@require_auth
def search_experiments():
    """Advanced search with multiple criteria."""
    data = request.get_json()

    # RH-002: Looks like SQL injection but uses parameterized query (safe)
    query = Experiment.query
    if data.get("title"):
        query = query.filter(Experiment.title.ilike(f"%{data['title']}%"))
    if data.get("status"):
        query = query.filter(Experiment.status == data["status"])
    if data.get("researcher_id"):
        query = query.filter(Experiment.researcher_id == int(data["researcher_id"]))

    results = query.all()
    return jsonify({"results": [e.to_dict() for e in results]})
