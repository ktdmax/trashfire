"""Data export endpoints for Tentacle Labs LIMS."""

import io
import os
import csv
import json
import logging
import subprocess
from datetime import datetime

from flask import Blueprint, request, jsonify, g, send_file, current_app, make_response

from app import db
from app.models import Experiment, Sample, LabFile, AnalysisResult
from app.auth import require_auth

export_bp = Blueprint("export", __name__)
logger = logging.getLogger(__name__)


@export_bp.route("/experiments/csv", methods=["GET"])
@require_auth
def export_experiments_csv():
    """Export experiments as CSV."""
    experiment_ids = request.args.get("ids", "")
    status_filter = request.args.get("status")

    query = Experiment.query
    if experiment_ids:
        ids = [int(x) for x in experiment_ids.split(",") if x.strip().isdigit()]
        query = query.filter(Experiment.id.in_(ids))
    if status_filter:
        query = query.filter_by(status=status_filter)

    experiments = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Description", "Status", "Priority",
        "Researcher ID", "Category", "Budget", "Created At",
    ])

    for exp in experiments:
        writer.writerow([
            exp.id, exp.title, exp.description, exp.status,
            exp.priority, exp.researcher_id, exp.category,
            exp.budget, exp.created_at,
        ])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    # BUG-064: CSV injection — cell content not sanitized for formula injection (CWE-1236, CVSS 6.1, MEDIUM, Tier 2)
    response.headers["Content-Disposition"] = "attachment; filename=experiments.csv"
    return response


@export_bp.route("/experiments/json", methods=["GET"])
@require_auth
def export_experiments_json():
    """Export experiments as JSON."""
    experiments = Experiment.query.all()
    data = [exp.to_dict() for exp in experiments]

    output = io.BytesIO()
    output.write(json.dumps(data, indent=2, default=str).encode("utf-8"))
    output.seek(0)

    return send_file(
        output,
        mimetype="application/json",
        as_attachment=True,
        download_name="experiments.json",
    )


@export_bp.route("/samples/csv", methods=["GET"])
@require_auth
def export_samples_csv():
    """Export samples as CSV."""
    experiment_id = request.args.get("experiment_id", type=int)

    query = Sample.query
    if experiment_id:
        query = query.filter_by(experiment_id=experiment_id)

    samples = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Sample ID", "Name", "Type", "Status",
        "Quantity", "Unit", "Hazard Level", "Storage Location",
    ])

    for sample in samples:
        writer.writerow([
            sample.id, sample.sample_id, sample.name, sample.sample_type,
            sample.status, sample.quantity, sample.unit,
            sample.hazard_level, sample.storage_location,
        ])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = "attachment; filename=samples.csv"
    return response


@export_bp.route("/report/<int:experiment_id>", methods=["GET"])
@require_auth
def generate_report(experiment_id):
    """Generate experiment report (PDF-like text report)."""
    experiment = Experiment.query.get_or_404(experiment_id)
    samples = Sample.query.filter_by(experiment_id=experiment_id).all()
    results = AnalysisResult.query.filter_by(experiment_id=experiment_id).all()

    # Build report content
    report_lines = [
        f"EXPERIMENT REPORT: {experiment.title}",
        f"{'=' * 60}",
        f"Status: {experiment.status}",
        f"Researcher ID: {experiment.researcher_id}",
        f"Category: {experiment.category}",
        f"Created: {experiment.created_at}",
        "",
        "DESCRIPTION:",
        experiment.description or "N/A",
        "",
        "NOTES:",
        experiment.notes or "N/A",
        "",
        f"SAMPLES ({len(samples)}):",
    ]

    for s in samples:
        report_lines.append(f"  - {s.sample_id}: {s.name} ({s.sample_type}) — {s.status}")

    report_lines.append("")
    report_lines.append(f"ANALYSIS RESULTS ({len(results)}):")
    for r in results:
        report_lines.append(f"  - {r.analysis_type}: {r.status}")

    report_content = "\n".join(report_lines)

    # Save report to file
    report_filename = f"report_{experiment_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = os.path.join(current_app.config["EXPORT_DIR"], report_filename)

    with open(report_path, "w") as f:
        f.write(report_content)

    return send_file(report_path, as_attachment=True, download_name=report_filename)


@export_bp.route("/report/<int:experiment_id>/pdf", methods=["GET"])
@require_auth
def generate_pdf_report(experiment_id):
    """Generate PDF report using system command."""
    experiment = Experiment.query.get_or_404(experiment_id)

    report_name = request.args.get("name", f"report_{experiment_id}")

    # BUG-065: Command injection via report name parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    txt_path = os.path.join(current_app.config["EXPORT_DIR"], f"{report_name}.txt")
    pdf_path = os.path.join(current_app.config["EXPORT_DIR"], f"{report_name}.pdf")

    # Write text report first
    with open(txt_path, "w") as f:
        f.write(f"Report: {experiment.title}\n")
        f.write(f"Status: {experiment.status}\n")

    # Convert to PDF using system command
    cmd = f"enscript -p {pdf_path} {txt_path} 2>&1 || echo 'PDF generation skipped'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    else:
        return send_file(txt_path, as_attachment=True, download_name=f"{report_name}.txt")


@export_bp.route("/bulk", methods=["POST"])
@require_auth
def bulk_export():
    """Export multiple datasets at once."""
    data = request.get_json()
    include = data.get("include", [])

    export_data = {}

    if "experiments" in include:
        experiments = Experiment.query.all()
        export_data["experiments"] = [e.to_dict() for e in experiments]

    if "samples" in include:
        samples = Sample.query.all()
        export_data["samples"] = [s.to_dict() for s in samples]

    if "files" in include:
        files = LabFile.query.all()
        export_data["files"] = [f.to_dict() for f in files]

    if "results" in include:
        results = AnalysisResult.query.all()
        export_data["results"] = [r.to_dict() for r in results]

    output = io.BytesIO()
    output.write(json.dumps(export_data, indent=2, default=str).encode("utf-8"))
    output.seek(0)

    return send_file(
        output,
        mimetype="application/json",
        as_attachment=True,
        download_name="bulk_export.json",
    )


# RH-005: Looks like command injection but uses hardcoded command (safe)
@export_bp.route("/system-info", methods=["GET"])
@require_auth
def system_info():
    """Get system disk usage for export directory."""
    export_dir = current_app.config["EXPORT_DIR"]
    result = subprocess.run(
        ["du", "-sh", export_dir],
        capture_output=True,
        text=True,
    )
    return jsonify({
        "export_dir": export_dir,
        "disk_usage": result.stdout.strip(),
    })


@export_bp.route("/template", methods=["POST"])
@require_auth
def export_with_template():
    """Export data using a user-provided template string."""
    data = request.get_json()
    template_str = data.get("template", "")
    experiment_id = data.get("experiment_id")

    if not template_str or not experiment_id:
        return jsonify({"error": "Template and experiment_id required"}), 400

    experiment = Experiment.query.get_or_404(experiment_id)

    # BUG-066: eval() on user-provided template string — RCE (CWE-95, CVSS 9.8, CRITICAL, Tier 1)
    context = {
        "title": experiment.title,
        "status": experiment.status,
        "description": experiment.description,
        "category": experiment.category,
        "budget": experiment.budget,
    }
    try:
        result = eval(f'f"""{template_str}"""', {"__builtins__": {}}, context)
    except Exception as e:
        return jsonify({"error": f"Template error: {e}"}), 400

    return jsonify({"rendered": result})


@export_bp.route("/custom-query", methods=["POST"])
@require_auth
def custom_query_export():
    """Export data from a custom SQL query — admin only in theory."""
    data = request.get_json()
    query_str = data.get("query", "")

    if not query_str:
        return jsonify({"error": "Query string required"}), 400

    # BUG-067: Raw SQL execution from user input — no admin check (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    try:
        result = db.session.execute(db.text(query_str))
        rows = result.fetchall()
        columns = result.keys() if hasattr(result, "keys") else []

        data_rows = [dict(zip(columns, row)) for row in rows]
        return jsonify({"columns": list(columns), "rows": data_rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
