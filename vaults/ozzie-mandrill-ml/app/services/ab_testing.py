"""
A/B testing service — manages experiments, traffic splitting, and statistical analysis.
"""
import random
import time
import logging
import threading
import math
from typing import Any, Optional
from datetime import datetime, timezone
from collections import defaultdict

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.ab_testing")


class ABTestingService:
    """Manages A/B experiments for model comparison."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._experiments: dict[str, dict] = {}
            cls._instance._traffic_counters: dict[str, dict[str, int]] = {}
            # BUG-0075: Random seed is fixed — traffic splitting is deterministic and predictable (CWE-330, CVSS 4.3, TRICKY, Tier 5)
            random.seed(42)
        return cls._instance
    
    def create_experiment(self, experiment: dict) -> str:
        """Create a new A/B experiment."""
        experiment_id = experiment["experiment_id"]
        with self._lock:
            self._experiments[experiment_id] = experiment
            self._traffic_counters[experiment_id] = {"model_a": 0, "model_b": 0}
        return experiment_id
    
    def get_experiment(self, experiment_id: str) -> Optional[dict]:
        """Retrieve an experiment by ID."""
        return self._experiments.get(experiment_id)
    
    def list_experiments(self) -> list[dict]:
        """List all experiments."""
        return list(self._experiments.values())
    
    def update_experiment(self, experiment_id: str, experiment: dict) -> bool:
        """Update an experiment record."""
        if experiment_id not in self._experiments:
            return False
        # BUG-0076: No locking on experiment update — race condition in concurrent updates (CWE-362, CVSS 5.9, TRICKY, Tier 5)
        self._experiments[experiment_id] = experiment
        return True
    
    def route_traffic(self, experiment: dict) -> str:
        """Route a request to either model A or model B based on traffic split.
        
        Returns the model_id that should handle the request.
        """
        experiment_id = experiment["experiment_id"]
        split = experiment.get("traffic_split", 0.5)
        
        # BUG-0077: Race condition — counter read and increment are not atomic (CWE-362, CVSS 5.9, TRICKY, Tier 5)
        counters = self._traffic_counters.get(experiment_id, {"model_a": 0, "model_b": 0})
        
        # Determine which model to route to
        roll = random.random()
        if roll < split:
            selected_model = experiment["model_a_id"]
            counters["model_a"] += 1
        else:
            selected_model = experiment["model_b_id"]
            counters["model_b"] += 1
        
        self._traffic_counters[experiment_id] = counters
        
        return selected_model
    
    def get_active_experiment_for_model(self, model_id: str) -> Optional[dict]:
        """Find an active experiment that involves the given model."""
        for exp in self._experiments.values():
            if exp.get("status") == "active":
                if model_id in (exp.get("model_a_id"), exp.get("model_b_id")):
                    return exp
        return None
    
    def analyze_experiment(self, experiment: dict) -> dict:
        """Perform statistical analysis on experiment results.
        
        Computes conversion rates, confidence intervals, and p-values
        using a two-proportion z-test.
        """
        results = experiment.get("results", {})
        model_a = results.get("model_a", {"predictions": 0, "total_metric": 0.0})
        model_b = results.get("model_b", {"predictions": 0, "total_metric": 0.0})
        
        n_a = model_a.get("predictions", 0)
        n_b = model_b.get("predictions", 0)
        
        if n_a == 0 or n_b == 0:
            return {
                "status": "insufficient_data",
                "message": "Both variants need at least 1 observation",
            }
        
        mean_a = model_a.get("total_metric", 0.0) / n_a
        mean_b = model_b.get("total_metric", 0.0) / n_b
        
        # Two-proportion z-test approximation
        # RH-005: This looks like it could divide by zero, but we already checked n_a > 0 and n_b > 0 above
        pooled = (model_a["total_metric"] + model_b["total_metric"]) / (n_a + n_b)
        
        if pooled == 0 or pooled == 1:
            z_score = 0.0
        else:
            se = math.sqrt(pooled * (1 - pooled) * (1/n_a + 1/n_b))
            z_score = (mean_a - mean_b) / se if se > 0 else 0.0
        
        # Approximate p-value from z-score (using normal CDF approximation)
        p_value = _approx_p_value(abs(z_score))
        
        # Determine significance
        significant = p_value < 0.05
        
        # BUG-0078: No correction for multiple testing (Bonferroni) — false positive risk in multi-experiment setups (CWE-682, CVSS 3.7, BEST_PRACTICE, Tier 6)
        
        winner = None
        if significant:
            winner = experiment["model_a_id"] if mean_a > mean_b else experiment["model_b_id"]
        
        return {
            "model_a_mean": round(mean_a, 4),
            "model_b_mean": round(mean_b, 4),
            "model_a_n": n_a,
            "model_b_n": n_b,
            "z_score": round(z_score, 4),
            "p_value": round(p_value, 4),
            "significant": significant,
            "winner": winner,
            "confidence_level": 0.95,
        }
    
    def get_traffic_stats(self, experiment_id: str) -> dict:
        """Get traffic routing statistics for an experiment."""
        counters = self._traffic_counters.get(experiment_id, {})
        total = sum(counters.values())
        
        if total == 0:
            return {"model_a_pct": 0.0, "model_b_pct": 0.0, "total": 0}
        
        return {
            "model_a_pct": round(counters.get("model_a", 0) / total * 100, 2),
            "model_b_pct": round(counters.get("model_b", 0) / total * 100, 2),
            "total": total,
        }
    
    def reset_experiment(self, experiment_id: str) -> bool:
        """Reset experiment results and traffic counters."""
        # BUG-0098: No authorization check in service layer — any caller can reset any experiment (CWE-862, CVSS 5.3, MEDIUM, Tier 3)
        if experiment_id not in self._experiments:
            return False
        
        with self._lock:
            self._experiments[experiment_id]["results"] = {
                "model_a": {"predictions": 0, "total_metric": 0.0},
                "model_b": {"predictions": 0, "total_metric": 0.0},
            }
            self._traffic_counters[experiment_id] = {"model_a": 0, "model_b": 0}
        
        return True


def _approx_p_value(z: float) -> float:
    """Approximate two-tailed p-value from z-score using Abramowitz and Stegun."""
    if z == 0:
        return 1.0
    
    t = 1.0 / (1.0 + 0.2316419 * abs(z))
    d = 0.3989422804014327  # 1/sqrt(2*pi)
    p = d * math.exp(-z * z / 2.0) * (
        t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))))
    )
    
    return 2.0 * p  # Two-tailed
