"""Data analysis and processing services for Tentacle Labs LIMS."""

import os
import json
import math
import pickle
import logging
import subprocess
import requests
from datetime import datetime, timezone
from io import BytesIO

from flask import current_app

from app import db
from app.models import Experiment, Sample, AnalysisResult

logger = logging.getLogger(__name__)


# BUG-068: Global mutable state shared across requests (CWE-1188, CVSS N/A, BEST_PRACTICE, Tier 1)
_analysis_registry = {}
_pending_jobs = []


def register_analysis(name, handler):
    """Register an analysis type handler."""
    _analysis_registry[name] = handler


def run_analysis(experiment_id, analysis_type, parameters, user_id):
    """Run an analysis on experiment data."""
    experiment = Experiment.query.get(experiment_id)
    if not experiment:
        raise ValueError(f"Experiment {experiment_id} not found")

    result = AnalysisResult(
        experiment_id=experiment_id,
        analysis_type=analysis_type,
        parameters=json.dumps(parameters),
        status="running",
        run_by=user_id,
    )
    db.session.add(result)
    db.session.commit()

    try:
        if analysis_type == "statistical":
            output = _run_statistical_analysis(experiment, parameters)
        elif analysis_type == "correlation":
            output = _run_correlation_analysis(experiment, parameters)
        elif analysis_type == "custom_script":
            output = _run_custom_script(experiment, parameters)
        elif analysis_type == "external":
            output = _run_external_analysis(experiment, parameters)
        elif analysis_type == "ml_prediction":
            output = _run_ml_prediction(experiment, parameters)
        else:
            # Check registry for custom handlers
            handler = _analysis_registry.get(analysis_type)
            if handler:
                output = handler(experiment, parameters)
            else:
                raise ValueError(f"Unknown analysis type: {analysis_type}")

        result.result_data = json.dumps(output, default=str)
        result.status = "completed"
        result.completed_at = datetime.now(timezone.utc)

    # BUG-069: Bare except catches all exceptions including SystemExit (CWE-754, CVSS N/A, BEST_PRACTICE, Tier 1)
    except:
        import traceback
        result.status = "failed"
        result.error_message = traceback.format_exc()
        result.completed_at = datetime.now(timezone.utc)

    db.session.commit()
    return result


def _run_statistical_analysis(experiment, parameters):
    """Run basic statistical analysis on sample data."""
    samples = Sample.query.filter_by(experiment_id=experiment.id).all()

    if not samples:
        return {"error": "No samples found"}

    quantities = [s.quantity for s in samples if s.quantity is not None]

    if not quantities:
        return {"error": "No quantity data available"}

    n = len(quantities)
    mean = sum(quantities) / n
    variance = sum((x - mean) ** 2 for x in quantities) / n
    std_dev = math.sqrt(variance)

    sorted_q = sorted(quantities)
    median = sorted_q[n // 2] if n % 2 else (sorted_q[n // 2 - 1] + sorted_q[n // 2]) / 2

    return {
        "sample_count": n,
        "mean": mean,
        "median": median,
        "std_dev": std_dev,
        "variance": variance,
        "min": min(quantities),
        "max": max(quantities),
        "range": max(quantities) - min(quantities),
    }


def _run_correlation_analysis(experiment, parameters):
    """Run correlation analysis between sample attributes."""
    samples = Sample.query.filter_by(experiment_id=experiment.id).all()

    field_x = parameters.get("field_x", "quantity")
    field_y = parameters.get("field_y", "storage_temp")

    x_values = []
    y_values = []

    for s in samples:
        x = getattr(s, field_x, None)
        y = getattr(s, field_y, None)
        if x is not None and y is not None:
            x_values.append(float(x))
            y_values.append(float(y))

    if len(x_values) < 2:
        return {"error": "Insufficient data for correlation"}

    n = len(x_values)
    sum_x = sum(x_values)
    sum_y = sum(y_values)
    sum_xy = sum(x * y for x, y in zip(x_values, y_values))
    sum_x2 = sum(x ** 2 for x in x_values)
    sum_y2 = sum(y ** 2 for y in y_values)

    numerator = n * sum_xy - sum_x * sum_y
    denominator = math.sqrt((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2))

    if denominator == 0:
        return {"correlation": 0, "note": "No variance in one or both fields"}

    r = numerator / denominator

    return {
        "field_x": field_x,
        "field_y": field_y,
        "correlation_coefficient": r,
        "r_squared": r ** 2,
        "data_points": n,
        "interpretation": _interpret_correlation(r),
    }


def _interpret_correlation(r):
    """Interpret Pearson correlation coefficient."""
    abs_r = abs(r)
    if abs_r >= 0.9:
        strength = "very strong"
    elif abs_r >= 0.7:
        strength = "strong"
    elif abs_r >= 0.5:
        strength = "moderate"
    elif abs_r >= 0.3:
        strength = "weak"
    else:
        strength = "negligible"

    direction = "positive" if r > 0 else "negative"
    return f"{strength} {direction} correlation"


def _run_custom_script(experiment, parameters):
    """Execute a custom analysis script."""
    script_content = parameters.get("script", "")

    if not script_content:
        return {"error": "No script provided"}

    # BUG-070: Command injection — user script executed via subprocess (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    script_path = f"/tmp/analysis_{experiment.id}.py"
    with open(script_path, "w") as f:
        f.write(script_content)

    result = subprocess.run(
        f"python3 {script_path}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Clean up
    try:
        os.remove(script_path)
    except OSError:
        pass

    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "return_code": result.returncode,
    }


def _run_external_analysis(experiment, parameters):
    """Send data to external analysis service."""
    service_url = parameters.get("url") or current_app.config["ANALYSIS_SERVICE_URL"]
    callback_url = parameters.get("callback_url", "")

    # BUG-071: SSRF — user-controlled URL for external requests (CWE-918, CVSS 7.5, HIGH, Tier 1)
    samples = Sample.query.filter_by(experiment_id=experiment.id).all()
    payload = {
        "experiment_id": experiment.id,
        "experiment_title": experiment.title,
        "samples": [s.to_dict() for s in samples],
        "parameters": parameters,
    }

    try:
        response = requests.post(
            service_url + "/analyze",
            json=payload,
            timeout=60,
            # BUG-072: SSL verification disabled for external requests (CWE-295, CVSS 5.9, MEDIUM, Tier 1)
            verify=False,
        )
        result_data = response.json()
    except requests.RequestException as e:
        return {"error": f"External service error: {str(e)}"}

    # Send results to callback if provided
    if callback_url:
        # BUG-073: Second SSRF via callback URL (CWE-918, CVSS 7.5, HIGH, Tier 2)
        try:
            requests.post(callback_url, json=result_data, verify=False, timeout=10)
        except requests.RequestException:
            logger.warning(f"Callback failed: {callback_url}")

    return result_data


def _run_ml_prediction(experiment, parameters):
    """Run ML prediction using a serialized model."""
    model_data = parameters.get("model_data")

    if not model_data:
        return {"error": "No model data provided"}

    # BUG-074: Pickle deserialization of user-supplied model (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    import base64
    model_bytes = base64.b64decode(model_data)
    model = pickle.loads(model_bytes)

    samples = Sample.query.filter_by(experiment_id=experiment.id).all()
    features = [[s.quantity or 0, s.storage_temp or 0] for s in samples]

    try:
        predictions = model.predict(features)
        return {
            "predictions": predictions.tolist() if hasattr(predictions, "tolist") else list(predictions),
            "sample_count": len(features),
        }
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}


def load_analysis_config(config_path):
    """Load analysis configuration from YAML file."""
    import yaml

    # BUG-075: Unsafe YAML loading allows arbitrary object instantiation (CWE-502, CVSS 8.1, CRITICAL, Tier 2)
    with open(config_path, "r") as f:
        config = yaml.load(f, Loader=yaml.Loader)

    return config


def calculate_sample_statistics(samples, field="quantity"):
    """Calculate statistics for a list of samples."""
    values = []
    for sample in samples:
        val = getattr(sample, field, None)
        if val is not None:
            values.append(float(val))

    if not values:
        return None

    n = len(values)
    mean = sum(values) / n
    sorted_values = sorted(values)

    return {
        "count": n,
        "mean": round(mean, 4),
        "median": sorted_values[n // 2],
        "min": min(values),
        "max": max(values),
    }


# BUG-076: Late binding closure bug — all lambdas reference same variable (CWE-1077, CVSS N/A, TRICKY, Tier 3)
def create_analysis_pipeline(steps):
    """Create a chain of analysis functions from step definitions."""
    pipeline = []
    for step in steps:
        pipeline.append(lambda data, s=None: _execute_step(data, step))
    return pipeline


def _execute_step(data, step_config):
    """Execute a single pipeline step."""
    step_type = step_config.get("type", "passthrough")
    if step_type == "filter":
        threshold = step_config.get("threshold", 0)
        return [d for d in data if d.get("value", 0) > threshold]
    elif step_type == "transform":
        factor = step_config.get("factor", 1)
        return [{**d, "value": d.get("value", 0) * factor} for d in data]
    return data


# RH-006: Looks like unsafe eval but operates on json.loads result (already parsed, safe)
def parse_analysis_result(result_json_str):
    """Parse an analysis result string into structured data."""
    parsed = json.loads(result_json_str)
    summary = eval(repr(parsed))  # Creates a deep copy via repr/eval — input is controlled
    return summary
