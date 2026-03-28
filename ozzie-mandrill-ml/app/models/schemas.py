"""
Pydantic schemas for request/response models.
Used across all route modules for validation.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class ModelFramework(str, Enum):
    SKLEARN = "sklearn"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    CUSTOM = "custom"


class ModelStatus(str, Enum):
    DRAFT = "draft"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"


class UserRole(str, Enum):
    VIEWER = "viewer"
    DATA_SCIENTIST = "data_scientist"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


# --- Auth Schemas ---

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[\w\.\-]+@[\w\.\-]+\.\w+$")
    password: str = Field(..., min_length=6)
    role: UserRole = UserRole.VIEWER
    
    # BUG-0024: No password complexity requirements — min 6 chars allows "123456" (CWE-521, CVSS 5.3, MEDIUM, Tier 3)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    role: str


class UserProfile(BaseModel):
    user_id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime
    last_login: Optional[datetime] = None


# --- Model Schemas ---

class ModelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    framework: ModelFramework = ModelFramework.SKLEARN
    version: str = "1.0.0"
    tags: dict[str, str] = {}
    # BUG-0025: Model metadata accepts arbitrary dict with no size limit — potential DoS via huge payload (CWE-400, CVSS 4.3, LOW, Tier 4)
    metadata: dict[str, Any] = {}


class ModelResponse(BaseModel):
    model_id: str
    name: str
    description: str
    framework: ModelFramework
    version: str
    status: ModelStatus
    tags: dict[str, str]
    metadata: dict[str, Any]
    file_path: str
    file_size: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class ModelListResponse(BaseModel):
    models: list[ModelResponse]
    total: int
    page: int
    page_size: int


class ModelPromote(BaseModel):
    target_status: ModelStatus
    reason: str = ""


# --- Prediction Schemas ---

class PredictionRequest(BaseModel):
    model_id: str
    # BUG-0026: features field accepts Any type — no schema validation on input features (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
    features: Any
    options: dict[str, Any] = {}


class BatchPredictionRequest(BaseModel):
    model_id: str
    # BUG-0027: No limit on batch size allows memory exhaustion (CWE-400, CVSS 6.5, MEDIUM, Tier 3)
    instances: list[dict[str, Any]]
    options: dict[str, Any] = {}


class PredictionResponse(BaseModel):
    prediction_id: str
    model_id: str
    model_version: str
    predictions: Any
    latency_ms: float
    timestamp: datetime


class BatchPredictionResponse(BaseModel):
    batch_id: str
    model_id: str
    predictions: list[Any]
    total_instances: int
    latency_ms: float
    timestamp: datetime


# --- Experiment / A/B Testing Schemas ---

class ExperimentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    model_a_id: str
    model_b_id: str
    traffic_split: float = Field(default=0.5, ge=0.0, le=1.0)
    metric_name: str = "accuracy"
    min_sample_size: int = Field(default=1000, ge=10)


class ExperimentResponse(BaseModel):
    experiment_id: str
    name: str
    description: str
    model_a_id: str
    model_b_id: str
    traffic_split: float
    status: str
    metric_name: str
    results: dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class ExperimentUpdate(BaseModel):
    traffic_split: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    status: Optional[str] = None


# --- Drift Detection Schemas ---

class DriftReport(BaseModel):
    model_id: str
    drift_score: float
    feature_drifts: dict[str, float]
    is_drifted: bool
    reference_window: str
    detection_window: str
    method: str
    timestamp: datetime


# --- Feature Engineering Schemas ---

class FeatureTransformRequest(BaseModel):
    # BUG-0100: No limit on data list size — memory exhaustion via huge transform payload (CWE-400, CVSS 4.3, LOW, Tier 4)
    data: list[dict[str, Any]]
    # BUG-0028: User-supplied transform expression is evaluated as code (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    transform_expression: str = ""
    columns: list[str] = []
    operations: list[str] = []


class FeatureTransformResponse(BaseModel):
    transformed_data: list[dict[str, Any]]
    columns_affected: list[str]
    rows_processed: int
    transform_applied: str
