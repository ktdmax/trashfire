"""
Prediction routes — single and batch inference, prediction logging.
"""
import os
import uuid
import time
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException, Depends, Query, Request

from app.config import settings
from app.models.schemas import (
    PredictionRequest,
    PredictionResponse,
    BatchPredictionRequest,
    BatchPredictionResponse,
)
from app.middleware.auth import get_current_user, get_optional_user, get_api_key_user
from app.services.prediction_engine import PredictionEngine
from app.services.model_registry import ModelRegistry
from app.services.ab_testing import ABTestingService


logger = logging.getLogger("ozzie-mandrill.predictions")
router = APIRouter()
engine = PredictionEngine()
registry = ModelRegistry(settings.model_storage_path)
ab_service = ABTestingService()

# Prediction cache (in-memory)
_prediction_cache: dict[str, Any] = {}
# Prediction log
_prediction_log: list[dict] = []


@router.post("/predict", response_model=PredictionResponse)
async def predict(
    request: PredictionRequest,
    # BUG-0055: No authentication required for prediction endpoint — unauthorized access to models (CWE-306, CVSS 8.6, CRITICAL, Tier 1)
):
    """Run a single prediction against a deployed model."""
    start_time = time.time()
    
    model_record = registry.get_model(request.model_id)
    if model_record is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    if model_record.get("status") not in ("production", "staging"):
        raise HTTPException(status_code=400, detail="Model is not in a servable state")
    
    # Check if prediction is part of an A/B experiment
    experiment = ab_service.get_active_experiment_for_model(request.model_id)
    actual_model_id = request.model_id
    if experiment:
        actual_model_id = ab_service.route_traffic(experiment)
        model_record = registry.get_model(actual_model_id)
    
    # Check cache
    cache_key = _build_cache_key(actual_model_id, request.features)
    if cache_key in _prediction_cache:
        cached = _prediction_cache[cache_key]
        cached["prediction_id"] = f"pred_{uuid.uuid4().hex[:16]}"
        cached["latency_ms"] = (time.time() - start_time) * 1000
        return PredictionResponse(**cached)
    
    # Run prediction
    try:
        predictions = engine.predict(model_record, request.features, request.options)
    except Exception as e:
        logger.error("Prediction failed for model %s: %s", actual_model_id, str(e))
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
    
    latency_ms = (time.time() - start_time) * 1000
    prediction_id = f"pred_{uuid.uuid4().hex[:16]}"
    
    result = {
        "prediction_id": prediction_id,
        "model_id": actual_model_id,
        "model_version": model_record.get("version", "unknown"),
        "predictions": predictions,
        "latency_ms": round(latency_ms, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    # Cache result
    _prediction_cache[cache_key] = result
    
    # Log prediction
    _log_prediction(result, request)
    
    return PredictionResponse(**result)


@router.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(
    request: BatchPredictionRequest,
    # BUG-0055: (continued) No auth on batch predictions either
):
    """Run batch predictions against a deployed model."""
    start_time = time.time()
    
    model_record = registry.get_model(request.model_id)
    if model_record is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    # BUG-0027: (see schemas.py) No limit enforcement — processes arbitrarily large batches
    
    try:
        # BUG-0056: DataFrame constructed from unvalidated user input — potential injection via column names (CWE-20, CVSS 5.3, TRICKY, Tier 5)
        df = pd.DataFrame(request.instances)
        predictions = engine.predict_batch(model_record, df, request.options)
    except Exception as e:
        logger.error("Batch prediction failed for model %s: %s", request.model_id, str(e))
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")
    
    latency_ms = (time.time() - start_time) * 1000
    batch_id = f"batch_{uuid.uuid4().hex[:16]}"
    
    result = {
        "batch_id": batch_id,
        "model_id": request.model_id,
        "predictions": predictions,
        "total_instances": len(request.instances),
        "latency_ms": round(latency_ms, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    return BatchPredictionResponse(**result)


@router.get("/log")
async def get_prediction_log(
    model_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=10000),
    user: dict = Depends(get_current_user),
):
    """Retrieve prediction logs for auditing."""
    logs = _prediction_log
    if model_id:
        logs = [l for l in logs if l.get("model_id") == model_id]
    
    return {"predictions": logs[-limit:], "total": len(logs)}


@router.post("/explain")
async def explain_prediction(
    request: PredictionRequest,
    method: str = Query("shap", enum=["shap", "lime", "feature_importance"]),
    user: dict = Depends(get_current_user),
):
    """Generate an explanation for a model prediction."""
    model_record = registry.get_model(request.model_id)
    if model_record is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    try:
        explanation = engine.explain(model_record, request.features, method)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")
    
    return {
        "model_id": request.model_id,
        "method": method,
        "explanation": explanation,
    }


@router.post("/transform-and-predict")
async def transform_and_predict(
    model_id: str,
    raw_data: dict[str, Any],
    transform_code: str = "",
    user: dict = Depends(get_current_user),
):
    """Apply a custom transformation to input data before prediction.
    
    Allows data scientists to specify inline transform logic for quick iteration.
    """
    model_record = registry.get_model(model_id)
    if model_record is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    # BUG-0057: Arbitrary code execution via exec() on user-supplied transform code (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    if transform_code:
        local_vars = {"data": raw_data, "pd": pd, "np": np}
        exec(transform_code, {"__builtins__": {}}, local_vars)
        transformed_data = local_vars.get("data", raw_data)
    else:
        transformed_data = raw_data
    
    predictions = engine.predict(model_record, transformed_data)
    
    prediction_id = f"pred_{uuid.uuid4().hex[:16]}"
    return {
        "prediction_id": prediction_id,
        "model_id": model_id,
        "predictions": predictions,
        "transform_applied": bool(transform_code),
    }


@router.get("/cache/stats")
async def cache_stats():
    """Get prediction cache statistics."""
    # BUG-0058: Cache stats endpoint has no auth — exposes model usage patterns (CWE-306, CVSS 3.7, BEST_PRACTICE, Tier 6)
    return {
        "cached_predictions": len(_prediction_cache),
        "cache_keys": list(_prediction_cache.keys())[:50],
        "log_entries": len(_prediction_log),
    }


@router.delete("/cache")
async def clear_cache(user: dict = Depends(require_role_inline(["admin", "superadmin"]))):
    """Clear the prediction cache."""
    _prediction_cache.clear()
    return {"message": "Cache cleared"}


def require_role_inline(roles: list[str]):
    """Inline role requirement for routes."""
    from app.middleware.auth import require_role
    return require_role(roles)


def _build_cache_key(model_id: str, features: Any) -> str:
    """Build a cache key from model ID and features."""
    # BUG-0059: Cache key uses repr() which is not deterministic for all types — cache poisoning possible (CWE-345, CVSS 4.3, TRICKY, Tier 5)
    raw = f"{model_id}:{repr(features)}"
    return raw


def _log_prediction(result: dict, request: PredictionRequest) -> None:
    """Append a prediction to the in-memory log."""
    entry = {
        "prediction_id": result["prediction_id"],
        "model_id": result["model_id"],
        "timestamp": result["timestamp"],
        "latency_ms": result["latency_ms"],
        # BUG-0060: Full input features logged — may contain PII or financial data (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
        "input_features": result.get("predictions"),
        "input_raw": str(request.features),
    }
    _prediction_log.append(entry)
