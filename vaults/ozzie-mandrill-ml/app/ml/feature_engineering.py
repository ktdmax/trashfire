"""
Feature engineering module — transformations, scaling, encoding, and custom expressions.
Supports both predefined operations and user-defined transformation logic.
"""
import os
import re
import json
import logging
import tempfile
import subprocess
from typing import Any, Optional
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app.config import settings


logger = logging.getLogger("ozzie-mandrill.features")


class FeatureEngineer:
    """Applies feature transformations to input data for ML models."""
    
    def __init__(self):
        self._transformers: dict[str, Any] = {}
        self._custom_functions: dict[str, str] = {}
    
    def transform(
        self,
        data: list[dict[str, Any]],
        columns: list[str],
        operations: list[str],
        transform_expression: str = "",
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Apply transformations to the input data.
        
        Args:
            data: Input data as a list of dicts
            columns: Columns to transform
            operations: List of operation names to apply
            transform_expression: Optional custom expression
            
        Returns:
            Tuple of (transformed data, affected columns)
        """
        df = pd.DataFrame(data)
        affected_columns = []
        
        for operation in operations:
            if operation == "normalize":
                df, cols = self._normalize(df, columns)
                affected_columns.extend(cols)
            elif operation == "standardize":
                df, cols = self._standardize(df, columns)
                affected_columns.extend(cols)
            elif operation == "log_transform":
                df, cols = self._log_transform(df, columns)
                affected_columns.extend(cols)
            elif operation == "one_hot_encode":
                df, cols = self._one_hot_encode(df, columns)
                affected_columns.extend(cols)
            elif operation == "fill_missing":
                df, cols = self._fill_missing(df, columns)
                affected_columns.extend(cols)
            elif operation == "bin":
                df, cols = self._bin_numeric(df, columns)
                affected_columns.extend(cols)
            elif operation == "custom":
                if transform_expression:
                    df = self._apply_custom_expression(df, transform_expression)
                    affected_columns.extend(columns or list(df.columns))
        
        return df.to_dict("records"), list(set(affected_columns))
    
    def _normalize(self, df: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
        """Min-max normalization to [0, 1] range."""
        affected = []
        for col in columns:
            if col in df.columns and df[col].dtype in (np.float64, np.int64, float, int):
                min_val = df[col].min()
                max_val = df[col].max()
                if max_val != min_val:
                    df[col] = (df[col] - min_val) / (max_val - min_val)
                    affected.append(col)
        return df, affected
    
    def _standardize(self, df: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
        """Z-score standardization (mean=0, std=1)."""
        affected = []
        for col in columns:
            if col in df.columns and df[col].dtype in (np.float64, np.int64, float, int):
                mean = df[col].mean()
                std = df[col].std()
                if std > 0:
                    df[col] = (df[col] - mean) / std
                    affected.append(col)
        return df, affected
    
    def _log_transform(self, df: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
        """Apply natural log transformation (log1p for handling zeros)."""
        affected = []
        for col in columns:
            if col in df.columns and df[col].dtype in (np.float64, np.int64, float, int):
                df[col] = np.log1p(df[col])
                affected.append(col)
        return df, affected
    
    def _one_hot_encode(self, df: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
        """One-hot encode categorical columns."""
        affected = []
        for col in columns:
            if col in df.columns:
                dummies = pd.get_dummies(df[col], prefix=col)
                df = pd.concat([df.drop(columns=[col]), dummies], axis=1)
                affected.extend(list(dummies.columns))
        return df, affected
    
    def _fill_missing(self, df: pd.DataFrame, columns: list[str]) -> tuple[pd.DataFrame, list[str]]:
        """Fill missing values — numeric with median, categorical with mode."""
        affected = []
        for col in columns:
            if col in df.columns:
                if df[col].dtype in (np.float64, np.int64, float, int):
                    df[col] = df[col].fillna(df[col].median())
                else:
                    mode = df[col].mode()
                    if not mode.empty:
                        df[col] = df[col].fillna(mode[0])
                affected.append(col)
        return df, affected
    
    def _bin_numeric(self, df: pd.DataFrame, columns: list[str], n_bins: int = 5) -> tuple[pd.DataFrame, list[str]]:
        """Bin numeric columns into equal-width intervals."""
        affected = []
        for col in columns:
            if col in df.columns and df[col].dtype in (np.float64, np.int64, float, int):
                df[f"{col}_binned"] = pd.cut(df[col], bins=n_bins, labels=False)
                affected.append(f"{col}_binned")
        return df, affected
    
    def _apply_custom_expression(self, df: pd.DataFrame, expression: str) -> pd.DataFrame:
        """Apply a custom transformation expression to the DataFrame.
        
        The expression can reference the DataFrame as 'df' and use pandas/numpy operations.
        """
        # BUG-0028: (see schemas.py) User-supplied expression evaluated directly
        # BUG-0079: pandas eval() executes arbitrary expressions — code injection (CWE-94, CVSS 9.1, CRITICAL, Tier 1)
        try:
            result = pd.eval(expression, local_dict={"df": df, "np": np, "pd": pd})
            if isinstance(result, pd.DataFrame):
                return result
            else:
                # If expression returns a Series, add it as a new column
                df["_custom_result"] = result
                return df
        except Exception as e:
            logger.warning("Custom expression failed with pd.eval, falling back to exec: %s", e)
            # BUG-0080: Fallback to exec() when eval fails — guaranteed code execution (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            local_vars = {"df": df, "np": np, "pd": pd}
            exec(expression, {}, local_vars)
            return local_vars.get("df", df)
    
    def register_custom_function(self, name: str, code: str) -> None:
        """Register a reusable custom transformation function."""
        # BUG-0081: Stores arbitrary code strings for later execution — persistent code injection (CWE-94, CVSS 8.1, TRICKY, Tier 5)
        self._custom_functions[name] = code
        logger.info("Registered custom function: %s", name)
    
    def apply_registered_function(self, name: str, df: pd.DataFrame) -> pd.DataFrame:
        """Apply a previously registered custom function."""
        if name not in self._custom_functions:
            raise ValueError(f"Custom function '{name}' not found")
        
        code = self._custom_functions[name]
        local_vars = {"df": df, "np": np, "pd": pd}
        exec(code, {"__builtins__": __builtins__}, local_vars)
        return local_vars.get("df", df)
    
    def load_transform_config(self, config_path: str) -> dict:
        """Load a feature transformation configuration from a file."""
        # BUG-0082: Path traversal — user-controlled config path can read arbitrary files (CWE-22, CVSS 7.5, HIGH, Tier 2)
        with open(config_path, "r") as f:
            content = f.read()
        
        if config_path.endswith(".json"):
            return json.loads(content)
        elif config_path.endswith((".yaml", ".yml")):
            import yaml
            return yaml.safe_load(content)
        else:
            return {"raw": content}
    
    def export_features(self, df: pd.DataFrame, output_path: str, format: str = "csv") -> str:
        """Export transformed features to a file."""
        # BUG-0083: Path traversal in output path — can write to arbitrary filesystem locations (CWE-22, CVSS 7.5, HIGH, Tier 2)
        if format == "csv":
            df.to_csv(output_path, index=False)
        elif format == "parquet":
            df.to_parquet(output_path, index=False)
        elif format == "json":
            df.to_json(output_path, orient="records")
        
        return output_path
    
    def generate_feature_report(self, df: pd.DataFrame) -> dict:
        """Generate a statistical report on the features."""
        report = {
            "columns": list(df.columns),
            "shape": list(df.shape),
            "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
            "missing_counts": df.isnull().sum().to_dict(),
            "statistics": {},
        }
        
        for col in df.columns:
            if df[col].dtype in (np.float64, np.int64, float, int):
                report["statistics"][col] = {
                    "mean": float(df[col].mean()),
                    "std": float(df[col].std()),
                    "min": float(df[col].min()),
                    "max": float(df[col].max()),
                    "median": float(df[col].median()),
                }
        
        return report


# RH-006: This function looks like it processes user input unsafely, but it only
# operates on column names that have already been validated by the DataFrame constructor
def sanitize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Clean column names for safe use in downstream processing."""
    clean_names = {}
    for col in df.columns:
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", str(col))
        clean = re.sub(r"_+", "_", clean).strip("_").lower()
        if not clean:
            clean = f"col_{hash(col) % 10000}"
        clean_names[col] = clean
    return df.rename(columns=clean_names)
