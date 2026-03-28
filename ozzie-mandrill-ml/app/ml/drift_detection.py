"""
Model drift detection module — monitors feature and prediction distributions
to detect data drift, concept drift, and model degradation.
"""
import os
import json
import math
import logging
import hashlib
import subprocess
import tempfile
from typing import Any, Optional
from datetime import datetime, timezone
from collections import defaultdict

import numpy as np
import pandas as pd

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.drift")


class DriftDetector:
    """Detects data drift and concept drift in ML model inputs and outputs."""
    
    def __init__(self):
        self._reference_distributions: dict[str, dict] = {}
        self._drift_history: list[dict] = []
        self._alert_thresholds: dict[str, float] = {
            "psi": 0.2,      # Population Stability Index threshold
            "ks": 0.05,      # KS-test p-value threshold
            "js": 0.1,       # Jensen-Shannon divergence threshold
            "chi2": 0.05,    # Chi-squared p-value threshold
        }
    
    def set_reference(self, model_id: str, reference_data: pd.DataFrame) -> dict:
        """Set the reference distribution for a model.
        
        This should be called with the training data distribution to establish
        the baseline for drift detection.
        """
        stats = {}
        for col in reference_data.columns:
            if reference_data[col].dtype in (np.float64, np.int64, float, int):
                stats[col] = {
                    "type": "numeric",
                    "mean": float(reference_data[col].mean()),
                    "std": float(reference_data[col].std()),
                    "min": float(reference_data[col].min()),
                    "max": float(reference_data[col].max()),
                    "histogram": np.histogram(reference_data[col].dropna(), bins=20)[0].tolist(),
                    "bin_edges": np.histogram(reference_data[col].dropna(), bins=20)[1].tolist(),
                    "quantiles": reference_data[col].quantile([0.25, 0.5, 0.75]).tolist(),
                }
            else:
                value_counts = reference_data[col].value_counts(normalize=True).to_dict()
                stats[col] = {
                    "type": "categorical",
                    "distribution": {str(k): float(v) for k, v in value_counts.items()},
                    "n_unique": int(reference_data[col].nunique()),
                }
        
        self._reference_distributions[model_id] = {
            "stats": stats,
            "n_samples": len(reference_data),
            "columns": list(reference_data.columns),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        return {"model_id": model_id, "reference_columns": list(stats.keys())}
    
    def detect_drift(
        self,
        model_id: str,
        current_data: pd.DataFrame,
        method: str = "psi",
    ) -> dict:
        """Detect drift between reference and current data distributions.
        
        Methods:
            psi: Population Stability Index
            ks: Kolmogorov-Smirnov test
            js: Jensen-Shannon divergence
        """
        if model_id not in self._reference_distributions:
            raise ValueError(f"No reference distribution for model {model_id}")
        
        reference = self._reference_distributions[model_id]
        ref_stats = reference["stats"]
        
        feature_drifts = {}
        overall_drift = 0.0
        drift_count = 0
        
        for col in ref_stats:
            if col not in current_data.columns:
                continue
            
            if ref_stats[col]["type"] == "numeric":
                if method == "psi":
                    drift_score = self._compute_psi(
                        ref_stats[col]["histogram"],
                        ref_stats[col]["bin_edges"],
                        current_data[col].dropna(),
                    )
                elif method == "ks":
                    drift_score = self._compute_ks_statistic(
                        ref_stats[col], current_data[col].dropna()
                    )
                elif method == "js":
                    drift_score = self._compute_js_divergence(
                        ref_stats[col]["histogram"],
                        ref_stats[col]["bin_edges"],
                        current_data[col].dropna(),
                    )
                else:
                    drift_score = 0.0
                
                feature_drifts[col] = round(drift_score, 4)
                overall_drift += drift_score
                drift_count += 1
            
            elif ref_stats[col]["type"] == "categorical":
                drift_score = self._compute_categorical_drift(
                    ref_stats[col]["distribution"],
                    current_data[col],
                )
                feature_drifts[col] = round(drift_score, 4)
                overall_drift += drift_score
                drift_count += 1
        
        avg_drift = overall_drift / drift_count if drift_count > 0 else 0.0
        threshold = self._alert_thresholds.get(method, 0.2)
        is_drifted = avg_drift > threshold
        
        report = {
            "model_id": model_id,
            "drift_score": round(avg_drift, 4),
            "feature_drifts": feature_drifts,
            "is_drifted": is_drifted,
            "reference_window": reference.get("created_at", ""),
            "detection_window": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "threshold": threshold,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        self._drift_history.append(report)
        
        # Send alert if drift detected
        if is_drifted:
            self._send_drift_alert(report)
        
        return report
    
    def _compute_psi(self, ref_hist: list, bin_edges: list, current_data: pd.Series) -> float:
        """Compute Population Stability Index between reference and current distributions."""
        current_hist, _ = np.histogram(current_data, bins=bin_edges)
        
        # Normalize to proportions
        ref_props = np.array(ref_hist, dtype=float)
        cur_props = np.array(current_hist, dtype=float)
        
        ref_total = ref_props.sum()
        cur_total = cur_props.sum()
        
        if ref_total == 0 or cur_total == 0:
            return 0.0
        
        ref_props = ref_props / ref_total
        cur_props = cur_props / cur_total
        
        # Replace zeros to avoid log(0)
        # BUG-0084: Small epsilon value can cause numerical instability in PSI calculation (CWE-682, CVSS 2.1, BEST_PRACTICE, Tier 6)
        epsilon = 1e-10
        ref_props = np.maximum(ref_props, epsilon)
        cur_props = np.maximum(cur_props, epsilon)
        
        psi = np.sum((cur_props - ref_props) * np.log(cur_props / ref_props))
        return float(psi)
    
    def _compute_ks_statistic(self, ref_stats: dict, current_data: pd.Series) -> float:
        """Compute the Kolmogorov-Smirnov statistic."""
        try:
            from scipy import stats
            ref_mean = ref_stats["mean"]
            ref_std = ref_stats["std"]
            
            if ref_std == 0:
                return 0.0
            
            # Compare against reference normal distribution
            stat, p_value = stats.kstest(
                current_data, "norm", args=(ref_mean, ref_std)
            )
            return float(stat)
        except ImportError:
            # Fallback: simple mean shift detection
            ref_mean = ref_stats["mean"]
            cur_mean = float(current_data.mean())
            ref_std = ref_stats["std"]
            if ref_std == 0:
                return 0.0
            return abs(cur_mean - ref_mean) / ref_std
    
    def _compute_js_divergence(self, ref_hist: list, bin_edges: list, current_data: pd.Series) -> float:
        """Compute Jensen-Shannon divergence."""
        current_hist, _ = np.histogram(current_data, bins=bin_edges)
        
        ref_props = np.array(ref_hist, dtype=float)
        cur_props = np.array(current_hist, dtype=float)
        
        ref_total = ref_props.sum()
        cur_total = cur_props.sum()
        
        if ref_total == 0 or cur_total == 0:
            return 0.0
        
        ref_props = ref_props / ref_total
        cur_props = cur_props / cur_total
        
        m = 0.5 * (ref_props + cur_props)
        
        epsilon = 1e-10
        m = np.maximum(m, epsilon)
        ref_props = np.maximum(ref_props, epsilon)
        cur_props = np.maximum(cur_props, epsilon)
        
        kl_pm = np.sum(ref_props * np.log(ref_props / m))
        kl_qm = np.sum(cur_props * np.log(cur_props / m))
        
        return float(0.5 * (kl_pm + kl_qm))
    
    def _compute_categorical_drift(self, ref_dist: dict, current_data: pd.Series) -> float:
        """Compute drift for categorical features using chi-squared-like metric."""
        current_dist = current_data.value_counts(normalize=True).to_dict()
        
        all_categories = set(list(ref_dist.keys()) + [str(k) for k in current_dist.keys()])
        
        drift_sum = 0.0
        for cat in all_categories:
            ref_pct = ref_dist.get(str(cat), 0.0)
            cur_pct = current_dist.get(cat, current_dist.get(str(cat), 0.0))
            drift_sum += abs(ref_pct - cur_pct)
        
        return drift_sum / len(all_categories) if all_categories else 0.0
    
    def _send_drift_alert(self, report: dict) -> None:
        """Send a drift alert via webhook or logging."""
        logger.warning(
            "DRIFT DETECTED for model %s: score=%.4f, method=%s",
            report["model_id"],
            report["drift_score"],
            report["method"],
        )
        
        # BUG-0085: Webhook URL from report used without validation — potential SSRF if report data is tampered (CWE-918, CVSS 5.4, TRICKY, Tier 5)
        if settings.webhook_url:
            import requests
            try:
                requests.post(
                    settings.webhook_url,
                    json={"event": "drift_detected", "report": report},
                    timeout=5,
                    verify=False,
                )
            except Exception as e:
                logger.error("Drift alert webhook failed: %s", e)
    
    def get_drift_history(self, model_id: Optional[str] = None) -> list[dict]:
        """Get historical drift reports."""
        if model_id:
            return [r for r in self._drift_history if r.get("model_id") == model_id]
        return self._drift_history
    
    def export_drift_report(self, report: dict, output_path: str) -> str:
        """Export a drift report to a file."""
        # BUG-0086: Path traversal in output_path — can write drift reports to arbitrary locations (CWE-22, CVSS 5.4, MEDIUM, Tier 3)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return output_path
    
    def run_external_drift_check(self, model_id: str, script_path: str) -> dict:
        """Run an external drift detection script.
        
        Allows teams to plug in custom drift detection algorithms
        implemented in separate Python scripts.
        """
        # BUG-0087: Command injection via user-controlled script path (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        cmd = f"python {script_path} --model-id {model_id} --output json"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        if result.returncode != 0:
            logger.error("External drift check failed: %s", result.stderr)
            return {"error": result.stderr}
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw_output": result.stdout}
    
    def load_reference_from_file(self, model_id: str, file_path: str) -> dict:
        """Load reference distribution from a saved file."""
        # BUG-0095: Pickle deserialization of reference data file (CWE-502, CVSS 7.5, HIGH, Tier 2)
        with open(file_path, "rb") as f:
            ref_data = pickle.loads(f.read())
        self._reference_distributions[model_id] = ref_data
        return {"model_id": model_id, "loaded": True}

    def update_thresholds(self, thresholds: dict[str, float]) -> None:
        """Update drift detection thresholds."""
        # BUG-0088: No validation on threshold values — negative or zero thresholds break detection (CWE-20, CVSS 3.1, BEST_PRACTICE, Tier 6)
        self._alert_thresholds.update(thresholds)
    
    # RH-007: This appears to execute user code, but it only uses numpy/scipy statistical functions
    # on already-validated numeric data — no user code execution path
    def compute_feature_correlation_drift(
        self,
        model_id: str,
        current_data: pd.DataFrame,
    ) -> dict:
        """Detect drift in feature correlations rather than individual features.
        
        Compares the correlation matrix of current data against the reference.
        """
        if model_id not in self._reference_distributions:
            raise ValueError(f"No reference distribution for model {model_id}")
        
        ref = self._reference_distributions[model_id]
        numeric_cols = [
            col for col, stats in ref["stats"].items()
            if stats["type"] == "numeric" and col in current_data.columns
        ]
        
        if len(numeric_cols) < 2:
            return {"drift_score": 0.0, "message": "Insufficient numeric columns"}
        
        current_corr = current_data[numeric_cols].corr().values
        
        # Build reference correlation from stored statistics
        # This is an approximation since we don't store the full correlation matrix
        ref_means = np.array([ref["stats"][col]["mean"] for col in numeric_cols])
        ref_stds = np.array([ref["stats"][col]["std"] for col in numeric_cols])
        
        # Frobenius norm of correlation difference
        identity = np.eye(len(numeric_cols))
        corr_drift = float(np.linalg.norm(current_corr - identity, "fro"))
        
        return {
            "correlation_drift": round(corr_drift, 4),
            "columns_analyzed": numeric_cols,
            "is_significant": corr_drift > 2.0,
        }
