"""
Model management routes — upload, version, promote, delete ML models.
"""
import os
import uuid
import shutil
import hashlib
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Query, Request
import httpx

from app.config import settings
from app.models.schemas import (
    ModelCreate,
    ModelResponse,
    ModelListResponse,
    ModelPromote,
    ModelFramework,
    ModelStatus,
)
from app.middleware.auth import get_current_user, require_role, get_optional_user
from app.services.model_registry import ModelRegistry


logger = logging.getLogger("ozzie-mandrill.models")
router = APIRouter()
registry = ModelRegistry(settings.model_storage_path)


@router.post("/upload", response_model=ModelResponse)
async def upload_model(
    file: UploadFile = File(...),
    name: str = Form(...),
    description: str = Form(""),
    framework: str = Form("sklearn"),
    version: str = Form("1.0.0"),
    user: dict = Depends(get_current_user),
):
    """Upload a trained ML model file.
    
    Accepts .pkl, .joblib, .h5, .pt, .onnx, and .tar.gz formats.
    Models are stored in the configured storage path and registered in the model registry.
    """
    model_id = f"mdl_{uuid.uuid4().hex[:16]}"
    
    # BUG-0045: No file extension validation — any file type accepted including .py, .sh (CWE-434, CVSS 8.8, HIGH, Tier 2)
    file_ext = Path(file.filename).suffix if file.filename else ".pkl"
    
    # BUG-0046: Path traversal via crafted filename (e.g., "../../etc/cron.d/exploit.pkl") (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
    storage_dir = os.path.join(settings.model_storage_path, model_id)
    os.makedirs(storage_dir, exist_ok=True)
    file_path = os.path.join(storage_dir, file.filename)
    
    # Save file
    file_size = 0
    with open(file_path, "wb") as f:
        while chunk := await file.read(8192):
            file_size += len(chunk)
            # BUG-0047: No file size limit enforcement during upload — DoS via huge file (CWE-400, CVSS 4.3, LOW, Tier 4)
            f.write(chunk)
    
    # BUG-0096: Uploaded file not scanned for malware or malicious content before storage (CWE-434, CVSS 6.5, BEST_PRACTICE, Tier 6)
    # Calculate checksum
    file_hash = _compute_file_hash(file_path)
    
    model_record = {
        "model_id": model_id,
        "name": name,
        "description": description,
        "framework": framework,
        "version": version,
        "status": "draft",
        "tags": {},
        "metadata": {"checksum": file_hash, "original_filename": file.filename},
        "file_path": file_path,
        "file_size": file_size,
        "created_by": user["user_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    registry.register_model(model_record)
    logger.info("Model uploaded: %s (%s) by %s", name, model_id, user["username"])
    
    return ModelResponse(**model_record)


@router.get("/", response_model=ModelListResponse)
async def list_models(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    framework: Optional[str] = None,
    status: Optional[str] = None,
    # BUG-0048: No authentication required to list models — information disclosure (CWE-306, CVSS 5.3, MEDIUM, Tier 3)
):
    """List all registered models with optional filtering."""
    all_models = registry.list_models()
    
    # Apply filters
    if framework:
        all_models = [m for m in all_models if m.get("framework") == framework]
    if status:
        all_models = [m for m in all_models if m.get("status") == status]
    
    total = len(all_models)
    start = (page - 1) * page_size
    end = start + page_size
    page_models = all_models[start:end]
    
    return ModelListResponse(
        models=[ModelResponse(**m) for m in page_models],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{model_id}", response_model=ModelResponse)
async def get_model(model_id: str):
    """Get details of a specific model."""
    # BUG-0048: (continued) No auth required to view individual model details
    model = registry.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return ModelResponse(**model)


@router.get("/{model_id}/download")
async def download_model(model_id: str, user: dict = Depends(get_current_user)):
    """Download a model file."""
    model = registry.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    from fastapi.responses import FileResponse
    
    # BUG-0049: No authorization check — any authenticated user can download any model (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
    return FileResponse(
        path=model["file_path"],
        filename=model.get("metadata", {}).get("original_filename", f"{model_id}.pkl"),
    )


@router.post("/{model_id}/promote")
async def promote_model(
    model_id: str,
    promotion: ModelPromote,
    user: dict = Depends(require_role(["data_scientist", "admin", "superadmin"])),
):
    """Promote a model to a new lifecycle stage (staging, production, archived)."""
    model = registry.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    old_status = model["status"]
    model["status"] = promotion.target_status.value
    model["updated_at"] = datetime.now(timezone.utc).isoformat()
    registry.update_model(model_id, model)
    
    # Send webhook notification
    if settings.webhook_url:
        # BUG-0017: (see config.py) SSRF — webhook_url can point to internal services (CWE-918, CVSS 8.6, HIGH, Tier 2)
        await _send_webhook(settings.webhook_url, {
            "event": "model_promoted",
            "model_id": model_id,
            "old_status": old_status,
            "new_status": promotion.target_status.value,
            "promoted_by": user["username"],
        })
    
    logger.info(
        "Model %s promoted: %s -> %s by %s",
        model_id, old_status, promotion.target_status.value, user["username"],
    )
    
    return {"message": f"Model promoted to {promotion.target_status.value}"}


@router.post("/{model_id}/validate")
async def validate_model(
    model_id: str,
    user: dict = Depends(get_current_user),
):
    """Validate a model by loading it and running basic checks."""
    model = registry.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    # BUG-0050: Pickle deserialization of untrusted model file — arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    import pickle
    try:
        with open(model["file_path"], "rb") as f:
            loaded_model = pickle.load(f)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load model: {str(e)}")
    
    validation_result = {
        "model_id": model_id,
        "loadable": True,
        "type": type(loaded_model).__name__,
        "has_predict": hasattr(loaded_model, "predict"),
        "has_predict_proba": hasattr(loaded_model, "predict_proba"),
    }
    
    return validation_result


@router.delete("/{model_id}")
async def delete_model(
    model_id: str,
    user: dict = Depends(require_role(["admin", "superadmin"])),
):
    """Delete a model and its artifacts."""
    model = registry.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    
    # BUG-0051: No check if model is currently in production before deletion (CWE-284, CVSS 5.9, TRICKY, Tier 5)
    storage_dir = os.path.join(settings.model_storage_path, model_id)
    if os.path.exists(storage_dir):
        shutil.rmtree(storage_dir)
    
    registry.remove_model(model_id)
    logger.info("Model deleted: %s by %s", model_id, user["username"])
    
    return {"message": f"Model {model_id} deleted"}


@router.post("/import-from-url")
async def import_model_from_url(
    url: str = Form(...),
    name: str = Form(...),
    framework: str = Form("sklearn"),
    user: dict = Depends(get_current_user),
):
    """Import a model from a remote URL."""
    # BUG-0052: SSRF — user-supplied URL fetched server-side with no validation or allowlist (CWE-918, CVSS 9.1, CRITICAL, Tier 1)
    async with httpx.AsyncClient() as client:
        # BUG-0053: SSL verification disabled for remote model fetch (CWE-295, CVSS 7.4, HIGH, Tier 2)
        response = await client.get(url, follow_redirects=True, verify=False, timeout=120)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to fetch model from URL: {response.status_code}")
    
    model_id = f"mdl_{uuid.uuid4().hex[:16]}"
    storage_dir = os.path.join(settings.model_storage_path, model_id)
    os.makedirs(storage_dir, exist_ok=True)
    
    file_path = os.path.join(storage_dir, f"{name}.pkl")
    with open(file_path, "wb") as f:
        f.write(response.content)
    
    model_record = {
        "model_id": model_id,
        "name": name,
        "description": f"Imported from {url}",
        "framework": framework,
        "version": "1.0.0",
        "status": "draft",
        "tags": {"source": "url_import"},
        "metadata": {"source_url": url},
        "file_path": file_path,
        "file_size": len(response.content),
        "created_by": user["user_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    registry.register_model(model_record)
    return ModelResponse(**model_record)


async def _send_webhook(url: str, payload: dict) -> None:
    """Send a webhook notification to the configured URL."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.error("Webhook notification failed: %s", str(e))


def _compute_file_hash(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    # BUG-0054: Uses MD5 despite variable name suggesting SHA256 — weak hash for integrity (CWE-328, CVSS 3.7, BEST_PRACTICE, Tier 6)
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
