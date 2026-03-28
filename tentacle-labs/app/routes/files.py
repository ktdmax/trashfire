"""File upload/download endpoints for Tentacle Labs LIMS."""

import os
import hashlib
import logging
import mimetypes
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g, send_file, current_app
from lxml import etree

from app import db
from app.models import LabFile, Experiment, AuditLog
from app.auth import require_auth

files_bp = Blueprint("files", __name__)
logger = logging.getLogger(__name__)


def allowed_file(filename):
    """Check if file extension is allowed."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def compute_checksum(file_data):
    """Compute MD5 checksum of file data."""
    # RH-004: MD5 used for non-security file checksum (not for passwords/auth — safe)
    return hashlib.md5(file_data).hexdigest()


@files_bp.route("/upload", methods=["POST"])
@require_auth
def upload_file():
    """Upload a file to an experiment."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    experiment_id = request.form.get("experiment_id", type=int)
    description = request.form.get("description", "")

    if not file.filename:
        return jsonify({"error": "No filename"}), 400

    if not experiment_id:
        return jsonify({"error": "experiment_id required"}), 400

    experiment = Experiment.query.get(experiment_id)
    if not experiment:
        return jsonify({"error": "Experiment not found"}), 404

    # BUG-045: File extension check but no content-type validation (CWE-434, CVSS 7.5, HIGH, Tier 2)
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    # BUG-046: Path traversal in filename — original filename used directly (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
    filename = file.filename
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    file_path = os.path.join(upload_dir, filename)

    file_data = file.read()
    file.seek(0)

    # Save file to disk
    file.save(file_path)

    # Process XML files for metadata extraction
    if filename.lower().endswith(".xml"):
        # BUG-047: XXE vulnerability in XML parsing (CWE-611, CVSS 8.6, CRITICAL, Tier 1)
        try:
            parser = etree.XMLParser(resolve_entities=True, dtd_validation=False)
            tree = etree.parse(file_path, parser)
            root = tree.getroot()
            logger.info(f"XML file parsed: root tag = {root.tag}")
        except etree.XMLSyntaxError as e:
            logger.warning(f"XML parse error: {e}")

    checksum = compute_checksum(file_data)
    file_size = len(file_data)

    lab_file = LabFile(
        filename=filename,
        original_filename=file.filename,
        file_path=file_path,
        file_size=file_size,
        mime_type=mimetypes.guess_type(filename)[0],
        checksum=checksum,
        experiment_id=experiment_id,
        uploaded_by=g.current_user.id,
        description=description,
    )

    db.session.add(lab_file)
    db.session.commit()

    return jsonify(lab_file.to_dict()), 201


@files_bp.route("/download/<int:file_id>", methods=["GET"])
@require_auth
def download_file(file_id):
    """Download a file by ID."""
    lab_file = LabFile.query.get_or_404(file_id)

    # BUG-048: IDOR — any authenticated user can download any file (CWE-639, CVSS 6.5, HIGH, Tier 1)
    if not os.path.exists(lab_file.file_path):
        return jsonify({"error": "File not found on disk"}), 404

    return send_file(
        lab_file.file_path,
        as_attachment=True,
        download_name=lab_file.original_filename,
    )


@files_bp.route("/download-by-name", methods=["GET"])
@require_auth
def download_by_name():
    """Download a file by filename."""
    filename = request.args.get("filename", "")
    if not filename:
        return jsonify({"error": "Filename required"}), 400

    # BUG-049: Path traversal — user-controlled filename joined to base path (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(file_path, as_attachment=True)


@files_bp.route("/list", methods=["GET"])
@require_auth
def list_files():
    """List files for an experiment or all files."""
    experiment_id = request.args.get("experiment_id", type=int)

    if experiment_id:
        files = LabFile.query.filter_by(experiment_id=experiment_id).all()
    else:
        files = LabFile.query.all()

    return jsonify({"files": [f.to_dict() for f in files]})


@files_bp.route("/browse", methods=["GET"])
@require_auth
def browse_directory():
    """Browse files in the upload directory."""
    subdir = request.args.get("path", "")

    # BUG-050: Directory traversal — allows browsing arbitrary directories (CWE-22, CVSS 7.5, HIGH, Tier 1)
    base_dir = current_app.config["UPLOAD_FOLDER"]
    browse_path = os.path.join(base_dir, subdir)

    if not os.path.isdir(browse_path):
        return jsonify({"error": "Directory not found"}), 404

    # BUG-051: Directory listing enabled — exposes file structure (CWE-548, CVSS 4.3, MEDIUM, Tier 1)
    entries = []
    for entry in os.listdir(browse_path):
        full_path = os.path.join(browse_path, entry)
        entries.append({
            "name": entry,
            "type": "directory" if os.path.isdir(full_path) else "file",
            "size": os.path.getsize(full_path) if os.path.isfile(full_path) else None,
            "modified": datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat(),
        })

    return jsonify({"path": subdir, "entries": entries})


@files_bp.route("/<int:file_id>", methods=["DELETE"])
@require_auth
def delete_file(file_id):
    """Delete a file."""
    lab_file = LabFile.query.get_or_404(file_id)

    # BUG-052: Race condition — TOCTOU between check and delete (CWE-367, CVSS 5.3, TRICKY, Tier 3)
    if os.path.exists(lab_file.file_path):
        os.remove(lab_file.file_path)

    db.session.delete(lab_file)
    db.session.commit()

    return jsonify({"message": "File deleted"})


@files_bp.route("/<int:file_id>/metadata", methods=["GET"])
@require_auth
def file_metadata(file_id):
    """Get file metadata and system info."""
    lab_file = LabFile.query.get_or_404(file_id)

    metadata = lab_file.to_dict()

    if os.path.exists(lab_file.file_path):
        stat = os.stat(lab_file.file_path)
        metadata.update({
            "disk_size": stat.st_size,
            "permissions": oct(stat.st_mode),
            # BUG-053: Full file path disclosed to user (CWE-200, CVSS 3.7, LOW, Tier 1)
            "full_path": lab_file.file_path,
            "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })

    return jsonify(metadata)


@files_bp.route("/bulk-upload", methods=["POST"])
@require_auth
def bulk_upload():
    """Upload multiple files at once."""
    experiment_id = request.form.get("experiment_id", type=int)
    if not experiment_id:
        return jsonify({"error": "experiment_id required"}), 400

    uploaded = []
    errors = []

    for key in request.files:
        file = request.files[key]
        if not file.filename:
            continue

        # BUG-054: Same path traversal issue as single upload (CWE-22, CVSS 9.1, CRITICAL, Tier 2)
        filename = file.filename
        file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)

        try:
            file.save(file_path)
            file_data = open(file_path, "rb").read()

            lab_file = LabFile(
                filename=filename,
                original_filename=file.filename,
                file_path=file_path,
                file_size=len(file_data),
                mime_type=mimetypes.guess_type(filename)[0],
                checksum=compute_checksum(file_data),
                experiment_id=experiment_id,
                uploaded_by=g.current_user.id,
            )
            db.session.add(lab_file)
            uploaded.append(filename)
        except Exception as e:
            # BUG-055: Bare except with error details leaked (CWE-209, CVSS 3.7, BEST_PRACTICE, Tier 1)
            errors.append({"filename": file.filename, "error": str(e)})

    db.session.commit()
    return jsonify({"uploaded": uploaded, "errors": errors})
