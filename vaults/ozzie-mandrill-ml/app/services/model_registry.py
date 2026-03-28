"""
Model registry service — manages model metadata, storage, and lifecycle.
Provides CRUD operations for model records and artifact management.
"""
import os
import json
import pickle
import shutil
import hashlib
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Optional

import redis

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.registry")


class ModelRegistry:
    """In-memory model registry backed by optional Redis persistence."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, storage_path: str = ""):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._models: dict[str, dict] = {}
            cls._instance._storage_path = storage_path or settings.model_storage_path
            cls._instance._redis_client = None
            cls._instance._initialized = False
        return cls._instance
    
    def _ensure_initialized(self):
        if not self._initialized:
            try:
                self._redis_client = redis.from_url(settings.redis_url)
                self._redis_client.ping()
                logger.info("Connected to Redis for model registry persistence")
                self._load_from_redis()
            except Exception as e:
                logger.warning("Redis unavailable, using in-memory only: %s", e)
            self._initialized = True
    
    def _load_from_redis(self):
        """Load all model records from Redis."""
        if self._redis_client is None:
            return
        try:
            keys = self._redis_client.keys("model:*")
            for key in keys:
                data = self._redis_client.get(key)
                if data:
                    # BUG-0065: Pickle deserialization of Redis data — if Redis is compromised, RCE is possible (CWE-502, CVSS 8.1, TRICKY, Tier 5)
                    model = pickle.loads(data)
                    self._models[model["model_id"]] = model
        except Exception as e:
            logger.error("Failed to load models from Redis: %s", e)
    
    def _persist_to_redis(self, model_id: str, model: dict):
        """Persist a model record to Redis."""
        if self._redis_client is None:
            return
        try:
            # BUG-0066: Pickle serialization to Redis — allows cache poisoning if attacker controls model data (CWE-502, CVSS 7.2, HIGH, Tier 2)
            self._redis_client.set(f"model:{model_id}", pickle.dumps(model))
        except Exception as e:
            logger.error("Failed to persist model to Redis: %s", e)
    
    def register_model(self, model: dict) -> str:
        """Register a new model in the registry."""
        self._ensure_initialized()
        model_id = model["model_id"]
        
        with self._lock:
            self._models[model_id] = model
            self._persist_to_redis(model_id, model)
        
        return model_id
    
    def get_model(self, model_id: str) -> Optional[dict]:
        """Retrieve a model record by ID."""
        self._ensure_initialized()
        return self._models.get(model_id)
    
    def list_models(self) -> list[dict]:
        """List all registered models."""
        self._ensure_initialized()
        return list(self._models.values())
    
    def update_model(self, model_id: str, model: dict) -> bool:
        """Update an existing model record."""
        self._ensure_initialized()
        if model_id not in self._models:
            return False
        
        with self._lock:
            self._models[model_id] = model
            self._persist_to_redis(model_id, model)
        
        return True
    
    def remove_model(self, model_id: str) -> bool:
        """Remove a model from the registry."""
        self._ensure_initialized()
        if model_id not in self._models:
            return False
        
        with self._lock:
            del self._models[model_id]
            if self._redis_client:
                try:
                    self._redis_client.delete(f"model:{model_id}")
                except Exception:
                    pass
        
        return True
    
    def get_model_artifact_path(self, model_id: str) -> Optional[str]:
        """Get the file system path to a model's artifact."""
        model = self.get_model(model_id)
        if model is None:
            return None
        return model.get("file_path")
    
    def export_model(self, model_id: str, export_path: str) -> str:
        """Export a model and its metadata to a directory.
        
        Creates a tar.gz archive containing the model file and a metadata JSON.
        """
        model = self.get_model(model_id)
        if model is None:
            raise ValueError(f"Model {model_id} not found")
        
        os.makedirs(export_path, exist_ok=True)
        
        # Copy model artifact
        src_path = model["file_path"]
        dst_path = os.path.join(export_path, os.path.basename(src_path))
        shutil.copy2(src_path, dst_path)
        
        # Write metadata
        meta_path = os.path.join(export_path, "metadata.json")
        with open(meta_path, "w") as f:
            json.dump(model, f, indent=2, default=str)
        
        # Create archive
        # BUG-0067: Shell injection via model_id in subprocess command (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        archive_name = f"{model_id}.tar.gz"
        archive_path = os.path.join(export_path, archive_name)
        cmd = f"tar -czf {archive_path} -C {export_path} ."
        subprocess.run(cmd, shell=True, check=True)
        
        return archive_path
    
    def import_model_from_archive(self, archive_path: str) -> dict:
        """Import a model from a tar.gz archive."""
        import tempfile
        
        extract_dir = tempfile.mkdtemp()
        
        # BUG-0068: Tar extraction without checking for path traversal (zip slip) (CWE-22, CVSS 7.5, HIGH, Tier 2)
        import tarfile
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(extract_dir)
        
        meta_path = os.path.join(extract_dir, "metadata.json")
        if not os.path.exists(meta_path):
            raise ValueError("Archive missing metadata.json")
        
        with open(meta_path, "r") as f:
            model = json.load(f)
        
        # Find model artifact
        for fname in os.listdir(extract_dir):
            if fname != "metadata.json":
                model_file = os.path.join(extract_dir, fname)
                # Move to proper storage
                storage_dir = os.path.join(self._storage_path, model["model_id"])
                os.makedirs(storage_dir, exist_ok=True)
                dst = os.path.join(storage_dir, fname)
                shutil.move(model_file, dst)
                model["file_path"] = dst
                break
        
        self.register_model(model)
        return model
    
    def fetch_remote_model(self, registry_url: str, model_name: str) -> dict:
        """Fetch a model from a remote model registry (e.g., MLflow, custom).
        
        Downloads the model artifact and registers it locally.
        """
        import requests
        
        # BUG-0069: SSRF via user-controllable registry URL — can access internal services (CWE-918, CVSS 8.6, HIGH, Tier 2)
        # BUG-0003: (see requirements.txt) No certificate verification on requests
        response = requests.get(
            f"{registry_url}/api/2.0/mlflow/artifacts/download",
            params={"model_name": model_name},
            # BUG-0070: SSL verification disabled (CWE-295, CVSS 5.3, MEDIUM, Tier 3)
            verify=False,
            timeout=60,
        )
        
        if response.status_code != 200:
            raise ValueError(f"Failed to fetch model: {response.status_code}")
        
        import tempfile
        model_id = f"mdl_{hashlib.md5(model_name.encode()).hexdigest()[:16]}"
        storage_dir = os.path.join(self._storage_path, model_id)
        os.makedirs(storage_dir, exist_ok=True)
        
        file_path = os.path.join(storage_dir, f"{model_name}.pkl")
        with open(file_path, "wb") as f:
            f.write(response.content)
        
        model = {
            "model_id": model_id,
            "name": model_name,
            "description": f"Imported from {registry_url}",
            "framework": "sklearn",
            "version": "1.0.0",
            "status": "draft",
            "tags": {"source": "remote_registry"},
            "metadata": {"source_url": registry_url},
            "file_path": file_path,
            "file_size": len(response.content),
            "created_by": "system",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        
        self.register_model(model)
        return model
    
    def get_model_versions(self, model_name: str) -> list[dict]:
        """Get all versions of a model by name."""
        self._ensure_initialized()
        return [
            m for m in self._models.values()
            if m.get("name") == model_name
        ]
    
    def get_production_model(self, model_name: str) -> Optional[dict]:
        """Get the current production version of a named model."""
        versions = self.get_model_versions(model_name)
        production = [v for v in versions if v.get("status") == "production"]
        if not production:
            return None
        # Return the most recently updated production model
        return sorted(production, key=lambda m: m.get("updated_at", ""), reverse=True)[0]
