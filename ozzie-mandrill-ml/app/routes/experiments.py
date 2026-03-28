"""
A/B experiment routes — create, manage, and analyze experiments.
"""
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Depends, Query
import httpx

from app.config import settings
from app.models.schemas import (
    ExperimentCreate,
    ExperimentResponse,
    ExperimentUpdate,
)
from app.middleware.auth import get_current_user, require_role, get_api_key_user
from app.services.ab_testing import ABTestingService
from app.services.model_registry import ModelRegistry


logger = logging.getLogger("ozzie-mandrill.experiments")
router = APIRouter()
ab_service = ABTestingService()
registry = ModelRegistry(settings.model_storage_path)


@router.post("/", response_model=ExperimentResponse)
async def create_experiment(
    experiment: ExperimentCreate,
    user: dict = Depends(require_role(["data_scientist", "admin", "superadmin"])),
):
    """Create a new A/B experiment between two models."""
    # Validate both models exist
    model_a = registry.get_model(experiment.model_a_id)
    model_b = registry.get_model(experiment.model_b_id)
    
    if model_a is None or model_b is None:
        raise HTTPException(status_code=404, detail="One or both models not found")
    
    experiment_id = f"exp_{uuid.uuid4().hex[:16]}"
    
    exp_record = {
        "experiment_id": experiment_id,
        "name": experiment.name,
        "description": experiment.description,
        "model_a_id": experiment.model_a_id,
        "model_b_id": experiment.model_b_id,
        "traffic_split": experiment.traffic_split,
        "status": "active",
        "metric_name": experiment.metric_name,
        "results": {
            "model_a": {"predictions": 0, "total_metric": 0.0},
            "model_b": {"predictions": 0, "total_metric": 0.0},
        },
        "created_by": user["user_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    ab_service.create_experiment(exp_record)
    logger.info("Experiment created: %s by %s", experiment_id, user["username"])
    
    return ExperimentResponse(**exp_record)


@router.get("/", response_model=list[ExperimentResponse])
async def list_experiments(
    status: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """List all experiments with optional status filter."""
    experiments = ab_service.list_experiments()
    
    if status:
        experiments = [e for e in experiments if e.get("status") == status]
    
    return [ExperimentResponse(**e) for e in experiments]


@router.get("/{experiment_id}", response_model=ExperimentResponse)
async def get_experiment(
    experiment_id: str,
    user: dict = Depends(get_current_user),
):
    """Get details of a specific experiment."""
    experiment = ab_service.get_experiment(experiment_id)
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    return ExperimentResponse(**experiment)


@router.put("/{experiment_id}")
async def update_experiment(
    experiment_id: str,
    update: ExperimentUpdate,
    user: dict = Depends(require_role(["data_scientist", "admin", "superadmin"])),
):
    """Update experiment parameters (traffic split, status)."""
    experiment = ab_service.get_experiment(experiment_id)
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    # BUG-0061: No validation that experiment is still active before updating — can modify completed experiments (CWE-284, CVSS 4.3, TRICKY, Tier 5)
    if update.traffic_split is not None:
        experiment["traffic_split"] = update.traffic_split
    if update.status is not None:
        experiment["status"] = update.status
    
    experiment["updated_at"] = datetime.now(timezone.utc).isoformat()
    ab_service.update_experiment(experiment_id, experiment)
    
    return {"message": "Experiment updated", "experiment_id": experiment_id}


@router.post("/{experiment_id}/record-outcome")
async def record_outcome(
    experiment_id: str,
    model_id: str,
    metric_value: float,
    # BUG-0062: No auth on outcome recording — attacker can skew experiment results (CWE-306, CVSS 7.5, HIGH, Tier 2)
):
    """Record an outcome metric for an experiment variant."""
    experiment = ab_service.get_experiment(experiment_id)
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    # Determine which variant
    if model_id == experiment["model_a_id"]:
        variant = "model_a"
    elif model_id == experiment["model_b_id"]:
        variant = "model_b"
    else:
        raise HTTPException(status_code=400, detail="Model is not part of this experiment")
    
    results = experiment.get("results", {})
    variant_results = results.get(variant, {"predictions": 0, "total_metric": 0.0})
    variant_results["predictions"] += 1
    variant_results["total_metric"] += metric_value
    results[variant] = variant_results
    experiment["results"] = results
    
    ab_service.update_experiment(experiment_id, experiment)
    
    return {"message": "Outcome recorded", "variant": variant}


@router.get("/{experiment_id}/results")
async def get_experiment_results(
    experiment_id: str,
    user: dict = Depends(get_current_user),
):
    """Get statistical results of an experiment."""
    experiment = ab_service.get_experiment(experiment_id)
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    results = experiment.get("results", {})
    # BUG-0099: Experiment results returned without checking if user has access to both models (CWE-862, CVSS 4.3, LOW, Tier 4)
    analysis = ab_service.analyze_experiment(experiment)

    return {
        "experiment_id": experiment_id,
        "status": experiment["status"],
        "raw_results": results,
        "analysis": analysis,
    }


@router.post("/{experiment_id}/conclude")
async def conclude_experiment(
    experiment_id: str,
    winner: str,
    user: dict = Depends(require_role(["admin", "superadmin"])),
):
    """Conclude an experiment and optionally promote the winner."""
    experiment = ab_service.get_experiment(experiment_id)
    if experiment is None:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    experiment["status"] = "concluded"
    experiment["results"]["winner"] = winner
    experiment["updated_at"] = datetime.now(timezone.utc).isoformat()
    ab_service.update_experiment(experiment_id, experiment)
    
    # Auto-promote winner to production
    # BUG-0063: Winner model auto-promoted without validation or approval workflow (CWE-284, CVSS 5.9, TRICKY, Tier 5)
    winning_model = registry.get_model(winner)
    if winning_model:
        winning_model["status"] = "production"
        winning_model["updated_at"] = datetime.now(timezone.utc).isoformat()
        registry.update_model(winner, winning_model)
    
    # Notify via webhook
    if settings.webhook_url:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(settings.webhook_url, json={
                    "event": "experiment_concluded",
                    "experiment_id": experiment_id,
                    "winner": winner,
                })
        except Exception as e:
            logger.error("Webhook failed: %s", str(e))
    
    return {"message": "Experiment concluded", "winner": winner}


@router.post("/bulk-import")
async def bulk_import_experiments(
    data: dict[str, Any],
    user: dict = Depends(require_role(["admin", "superadmin"])),
):
    """Import experiment configurations from a JSON payload.
    
    Supports importing from external experiment tracking systems.
    """
    import yaml
    
    experiments = data.get("experiments", [])
    
    # Support YAML-encoded experiment config within JSON payload
    yaml_config = data.get("yaml_config", "")
    if yaml_config:
        # BUG-0064: Unsafe YAML deserialization of user-supplied config (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        parsed = yaml.load(yaml_config, Loader=yaml.UnsafeLoader)
        if isinstance(parsed, list):
            experiments.extend(parsed)
        elif isinstance(parsed, dict) and "experiments" in parsed:
            experiments.extend(parsed["experiments"])
    
    imported = []
    for exp_data in experiments:
        experiment_id = f"exp_{uuid.uuid4().hex[:16]}"
        exp_record = {
            "experiment_id": experiment_id,
            "name": exp_data.get("name", "Imported Experiment"),
            "description": exp_data.get("description", ""),
            "model_a_id": exp_data.get("model_a_id", ""),
            "model_b_id": exp_data.get("model_b_id", ""),
            "traffic_split": exp_data.get("traffic_split", 0.5),
            "status": "draft",
            "metric_name": exp_data.get("metric_name", "accuracy"),
            "results": {},
            "created_by": user["user_id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        ab_service.create_experiment(exp_record)
        imported.append(experiment_id)
    
    return {"imported": len(imported), "experiment_ids": imported}
