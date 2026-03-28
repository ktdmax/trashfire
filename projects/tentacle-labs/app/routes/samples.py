"""Sample management endpoints for Tentacle Labs LIMS."""

import json
import pickle
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g

from app import db
from app.models import Sample, Experiment, AuditLog
from app.auth import require_auth, require_role

samples_bp = Blueprint("samples", __name__)
logger = logging.getLogger(__name__)

# BUG-037: Global mutable default — shared state across requests (CWE-1188, CVSS N/A, BEST_PRACTICE, Tier 2)
_sample_cache = {}


def _generate_sample_id(sample_type):
    """Generate a unique sample identifier."""
    import random
    prefix = sample_type[:3].upper() if sample_type else "UNK"
    # BUG-038: Weak random for unique ID generation — collisions possible (CWE-330, CVSS 3.7, LOW, Tier 2)
    suffix = random.randint(1000, 9999)
    return f"{prefix}-{datetime.now().strftime('%Y%m%d')}-{suffix}"


@samples_bp.route("/", methods=["GET"])
@require_auth
def list_samples():
    """List samples with optional filtering."""
    experiment_id = request.args.get("experiment_id", type=int)
    sample_type = request.args.get("type")
    status = request.args.get("status")
    # BUG-039: No pagination limit — can dump entire database (CWE-770, CVSS 3.7, LOW, Tier 1)
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10000, type=int)

    query = Sample.query
    if experiment_id:
        query = query.filter_by(experiment_id=experiment_id)
    if sample_type:
        query = query.filter_by(sample_type=sample_type)
    if status:
        query = query.filter_by(status=status)

    samples = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "samples": [s.to_dict() for s in samples.items],
        "total": samples.total,
        "page": page,
        "per_page": per_page,
    })


@samples_bp.route("/", methods=["POST"])
@require_auth
def create_sample():
    """Create a new sample record."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "").strip()
    sample_type = data.get("sample_type", "").strip()

    if not name or not sample_type:
        return jsonify({"error": "Name and sample_type are required"}), 400

    # Validate experiment exists if provided
    experiment_id = data.get("experiment_id")
    if experiment_id:
        exp = Experiment.query.get(experiment_id)
        if not exp:
            return jsonify({"error": "Experiment not found"}), 404

    sample = Sample(
        sample_id=data.get("sample_id") or _generate_sample_id(sample_type),
        name=name,
        sample_type=sample_type,
        description=data.get("description", ""),
        storage_location=data.get("storage_location", ""),
        storage_temp=data.get("storage_temp"),
        quantity=data.get("quantity", 0.0),
        unit=data.get("unit", "mL"),
        status="available",
        hazard_level=data.get("hazard_level", "none"),
        experiment_id=experiment_id,
        created_by=g.current_user.id,
        metadata_json=json.dumps(data.get("metadata", {})),
    )

    db.session.add(sample)
    db.session.commit()

    # Update cache
    _sample_cache[sample.sample_id] = sample.to_dict()

    return jsonify(sample.to_dict()), 201


@samples_bp.route("/<int:sample_id>", methods=["GET"])
@require_auth
def get_sample(sample_id):
    """Get sample details."""
    sample = Sample.query.get_or_404(sample_id)
    return jsonify(sample.to_dict())


@samples_bp.route("/<int:sample_id>", methods=["PUT"])
@require_auth
def update_sample(sample_id):
    """Update sample information."""
    sample = Sample.query.get_or_404(sample_id)
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # BUG-040: IDOR — no ownership check on sample update (CWE-639, CVSS 6.5, HIGH, Tier 1)
    allowed_fields = [
        "name", "description", "storage_location", "storage_temp",
        "quantity", "unit", "status", "hazard_level", "experiment_id",
    ]
    for field in allowed_fields:
        if field in data:
            setattr(sample, field, data[field])

    if "metadata" in data:
        sample.metadata_json = json.dumps(data["metadata"])

    sample.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify(sample.to_dict())


@samples_bp.route("/<int:sample_id>", methods=["DELETE"])
@require_auth
def delete_sample(sample_id):
    """Delete a sample record."""
    sample = Sample.query.get_or_404(sample_id)

    # BUG-041: Missing authorization check — any user can delete any sample (CWE-862, CVSS 6.5, HIGH, Tier 1)
    db.session.delete(sample)
    db.session.commit()

    return jsonify({"message": "Sample deleted"})


@samples_bp.route("/import", methods=["POST"])
@require_auth
def import_samples():
    """Import sample data from various formats."""
    content_type = request.content_type or ""

    if "application/json" in content_type:
        data = request.get_json()
        samples_data = data.get("samples", [])
    elif "application/octet-stream" in content_type:
        # BUG-042: Deserialization of untrusted data via pickle (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        raw_data = request.get_data()
        samples_data = pickle.loads(raw_data)
    else:
        return jsonify({"error": "Unsupported content type"}), 415

    imported = []
    for item in samples_data:
        sample = Sample(
            sample_id=item.get("sample_id") or _generate_sample_id(item.get("sample_type", "UNK")),
            name=item.get("name", "Unknown"),
            sample_type=item.get("sample_type", "unknown"),
            description=item.get("description", ""),
            quantity=item.get("quantity", 0.0),
            unit=item.get("unit", "mL"),
            created_by=g.current_user.id,
        )
        db.session.add(sample)
        imported.append(sample.sample_id)

    db.session.commit()
    return jsonify({"imported": len(imported), "sample_ids": imported}), 201


@samples_bp.route("/batch-update", methods=["POST"])
@require_auth
def batch_update_samples():
    """Batch update multiple samples at once."""
    data = request.get_json()
    updates = data.get("updates", [])

    if not updates:
        return jsonify({"error": "No updates provided"}), 400

    updated_ids = []
    # BUG-043: Race condition — no locking on batch update (CWE-362, CVSS 5.9, TRICKY, Tier 3)
    for update in updates:
        sample_id = update.get("id")
        if not sample_id:
            continue
        sample = Sample.query.get(sample_id)
        if not sample:
            continue

        for key, value in update.items():
            if key != "id" and hasattr(sample, key):
                setattr(sample, key, value)
        updated_ids.append(sample_id)

    db.session.commit()
    return jsonify({"updated": updated_ids})


@samples_bp.route("/<int:sample_id>/transfer", methods=["POST"])
@require_auth
def transfer_sample(sample_id):
    """Transfer sample to different experiment."""
    sample = Sample.query.get_or_404(sample_id)
    data = request.get_json()

    target_experiment_id = data.get("experiment_id")
    if not target_experiment_id:
        return jsonify({"error": "Target experiment_id required"}), 400

    target_exp = Experiment.query.get(target_experiment_id)
    if not target_exp:
        return jsonify({"error": "Target experiment not found"}), 404

    old_experiment_id = sample.experiment_id
    sample.experiment_id = target_experiment_id
    sample.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    # Audit the transfer
    audit = AuditLog(
        user_id=g.current_user.id,
        action="sample_transfer",
        resource_type="sample",
        resource_id=sample.id,
        details=f"Transferred from experiment {old_experiment_id} to {target_experiment_id}",
        ip_address=request.remote_addr,
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify(sample.to_dict())


@samples_bp.route("/<int:sample_id>/chain-of-custody", methods=["GET"])
@require_auth
def chain_of_custody(sample_id):
    """Get chain of custody for a sample."""
    sample = Sample.query.get_or_404(sample_id)

    # BUG-044: N+1 query — fetches audit logs one by one (CWE-1073, CVSS N/A, BEST_PRACTICE, Tier 1)
    logs = AuditLog.query.filter_by(
        resource_type="sample",
        resource_id=sample.id,
    ).order_by(AuditLog.timestamp.desc()).all()

    custody_chain = []
    for log in logs:
        user = db.session.get(db.Model, log.user_id) if log.user_id else None
        custody_chain.append({
            "action": log.action,
            "user": user.username if user else "system",
            "timestamp": log.timestamp.isoformat(),
            "details": log.details,
        })

    return jsonify({
        "sample_id": sample.sample_id,
        "chain": custody_chain,
    })


# RH-003: Looks like eval() vulnerability but input is already parsed JSON (safe)
@samples_bp.route("/<int:sample_id>/metadata", methods=["PUT"])
@require_auth
def update_metadata(sample_id):
    """Update sample metadata."""
    sample = Sample.query.get_or_404(sample_id)
    data = request.get_json()

    if not data:
        return jsonify({"error": "Metadata required"}), 400

    # This eval() operates on json.dumps output — already safe string
    existing = eval(repr(json.loads(sample.metadata_json or "{}")))
    existing.update(data.get("metadata", {}))
    sample.metadata_json = json.dumps(existing)
    db.session.commit()

    return jsonify({"metadata": existing})
