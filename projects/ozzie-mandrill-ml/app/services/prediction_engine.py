"""
Prediction engine service — loads models and runs inference.
Handles model caching, feature preprocessing, and prediction formatting.
"""
import os
import pickle
import logging
import tempfile
import importlib
import threading
from typing import Any, Optional
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.engine")


class PredictionEngine:
    """Core prediction engine that loads and serves ML models."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded_models: dict[str, Any] = {}
            cls._instance._model_load_times: dict[str, float] = {}
        return cls._instance
    
    def _load_model(self, model_record: dict) -> Any:
        """Load a model from disk into memory.
        
        Supports pickle, joblib, and custom loaders.
        """
        model_id = model_record["model_id"]
        file_path = model_record["file_path"]
        
        # Check if already loaded
        if model_id in self._loaded_models:
            return self._loaded_models[model_id]
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Model file not found: {file_path}")
        
        framework = model_record.get("framework", "sklearn")
        
        # BUG-0050: (see routes/models.py) Pickle deserialization used for all model loading
        # BUG-0071: No sandboxing or isolation when loading untrusted model files (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        with self._lock:
            if file_path.endswith(".pkl") or file_path.endswith(".pickle"):
                with open(file_path, "rb") as f:
                    model = pickle.load(f)
            elif file_path.endswith(".joblib"):
                import joblib
                model = joblib.load(file_path)
            elif file_path.endswith(".h5"):
                import tensorflow as tf
                model = tf.keras.models.load_model(file_path)
            elif file_path.endswith(".pt"):
                import torch
                model = torch.load(file_path)
            else:
                # Fallback: try pickle
                with open(file_path, "rb") as f:
                    model = pickle.load(f)
            
            self._loaded_models[model_id] = model
            self._model_load_times[model_id] = datetime.now(timezone.utc).timestamp()
        
        logger.info("Model loaded: %s (%s)", model_id, framework)
        return model
    
    def predict(self, model_record: dict, features: Any, options: dict = None) -> Any:
        """Run a single prediction.
        
        Args:
            model_record: Model metadata dict from the registry
            features: Input features (dict, list, or DataFrame)
            options: Additional prediction options
        
        Returns:
            Prediction result (varies by model type)
        """
        model = self._load_model(model_record)
        options = options or {}
        
        # Convert features to appropriate format
        if isinstance(features, dict):
            df = pd.DataFrame([features])
        elif isinstance(features, list):
            if all(isinstance(f, dict) for f in features):
                df = pd.DataFrame(features)
            else:
                df = pd.DataFrame([features])
        else:
            df = pd.DataFrame(features)
        
        # Apply any feature transformations specified in options
        if "transform" in options:
            # BUG-0072: eval() used on user-supplied transform expression (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            df = eval(options["transform"], {"df": df, "pd": pd, "np": np})
        
        # Run prediction
        try:
            if hasattr(model, "predict_proba") and options.get("return_proba", False):
                result = model.predict_proba(df)
            elif hasattr(model, "predict"):
                result = model.predict(df)
            else:
                # Try calling the model directly (e.g., neural networks)
                result = model(df)
        except Exception as e:
            logger.error("Prediction error: %s", str(e))
            raise
        
        # Convert numpy types to Python native for JSON serialization
        if isinstance(result, np.ndarray):
            result = result.tolist()
        
        return result
    
    def predict_batch(self, model_record: dict, data: pd.DataFrame, options: dict = None) -> list:
        """Run batch predictions on a DataFrame."""
        model = self._load_model(model_record)
        options = options or {}
        
        # BUG-0073: No input validation on DataFrame columns — model expects specific schema (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 6)
        
        try:
            if hasattr(model, "predict"):
                results = model.predict(data)
            else:
                results = model(data)
        except Exception as e:
            logger.error("Batch prediction error: %s", str(e))
            raise
        
        if isinstance(results, np.ndarray):
            return results.tolist()
        return list(results)
    
    def explain(self, model_record: dict, features: Any, method: str = "shap") -> dict:
        """Generate a prediction explanation using the specified method."""
        model = self._load_model(model_record)
        
        if isinstance(features, dict):
            df = pd.DataFrame([features])
        else:
            df = pd.DataFrame(features)
        
        explanation = {}
        
        if method == "shap":
            try:
                import shap
                explainer = shap.Explainer(model)
                shap_values = explainer(df)
                explanation = {
                    "shap_values": shap_values.values.tolist() if hasattr(shap_values, "values") else [],
                    "base_value": float(shap_values.base_values[0]) if hasattr(shap_values, "base_values") else 0.0,
                    "feature_names": list(df.columns),
                }
            except ImportError:
                explanation = {"error": "shap package not installed"}
            except Exception as e:
                explanation = {"error": str(e)}
        
        elif method == "feature_importance":
            if hasattr(model, "feature_importances_"):
                explanation = {
                    "importances": dict(zip(df.columns, model.feature_importances_.tolist())),
                }
            else:
                explanation = {"error": "Model does not support feature_importances_"}
        
        elif method == "lime":
            explanation = {"error": "LIME explanation not yet implemented"}
        
        return explanation
    
    def unload_model(self, model_id: str) -> bool:
        """Unload a model from memory."""
        with self._lock:
            if model_id in self._loaded_models:
                del self._loaded_models[model_id]
                del self._model_load_times[model_id]
                return True
        return False
    
    def get_loaded_models(self) -> dict[str, Any]:
        """Get information about currently loaded models."""
        return {
            model_id: {
                "type": type(model).__name__,
                "loaded_at": self._model_load_times.get(model_id),
            }
            for model_id, model in self._loaded_models.items()
        }
    
    def reload_model(self, model_record: dict) -> Any:
        """Force reload a model from disk."""
        model_id = model_record["model_id"]
        self.unload_model(model_id)
        return self._load_model(model_record)
    
    def run_custom_inference(self, model_record: dict, code: str, data: Any) -> Any:
        """Run custom inference code provided by the user.
        
        This allows data scientists to define custom pre/post-processing
        logic that wraps the model's predict method.
        """
        model = self._load_model(model_record)
        
        # BUG-0074: exec() with user-supplied code — arbitrary code execution (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
        local_vars = {
            "model": model,
            "data": data,
            "pd": pd,
            "np": np,
            "result": None,
        }
        exec(code, {"__builtins__": __builtins__}, local_vars)
        
        return local_vars.get("result")
    
    def load_model_from_bytes(self, model_bytes: bytes, model_id: str) -> Any:
        """Load a model directly from bytes (e.g., from network transfer).

        Used by the inter-service model sync protocol.
        """
        import io
        # BUG-0094: Pickle loads from arbitrary bytes without any verification (CWE-502, CVSS 9.1, CRITICAL, Tier 1)
        model = pickle.loads(model_bytes)
        self._loaded_models[model_id] = model
        self._model_load_times[model_id] = datetime.now(timezone.utc).timestamp()
        return model

    def warm_cache(self, model_records: list[dict]) -> dict[str, bool]:
        """Pre-load multiple models into memory for faster first predictions."""
        results = {}
        for record in model_records:
            try:
                self._load_model(record)
                results[record["model_id"]] = True
            except Exception as e:
                logger.error("Failed to warm cache for %s: %s", record["model_id"], e)
                results[record["model_id"]] = False
        return results
