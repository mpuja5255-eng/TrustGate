"""
Inference and Anomaly Prediction for TRUSTGATE
"""
import os
import json
import joblib
import numpy as np
from typing import Dict, Any, Optional
from app.config import settings
from app.ml.features import extract_features, FEATURE_NAMES

class ModelPredictionResult:
    def __init__(
        self,
        anomaly_score: Optional[float],
        normalized_risk_score: Optional[float],
        is_anomaly: bool,
        threshold: float,
        feature_deviations: Dict[str, Any],
        model_version: str,
        model_status: str = "AVAILABLE"  # AVAILABLE, DEGRADED, SKIPPED
    ):
        self.anomaly_score = anomaly_score
        self.normalized_risk_score = normalized_risk_score
        self.is_anomaly = is_anomaly
        self.threshold = threshold
        self.feature_deviations = feature_deviations
        self.model_version = model_version
        self.model_status = model_status

    def to_dict(self):
        return {
            "anomaly_score": round(self.anomaly_score, 4) if self.anomaly_score is not None else None,
            "normalized_risk_score": round(self.normalized_risk_score, 4) if self.normalized_risk_score is not None else None,
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
            "feature_deviations": self.feature_deviations,
            "model_version": self.model_version,
            "model_status": self.model_status
        }

class RiskPredictor:
    def __init__(self, model_path: Optional[str] = None, meta_path: Optional[str] = None):
        self.model_path = model_path or settings.model_file
        self.meta_path = meta_path or settings.features_meta_file
        self.model = None
        self.metadata = {}
        self.threshold = settings.default_anomaly_threshold
        self.load()

    def load(self):
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
            if os.path.exists(self.meta_path):
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.threshold = self.metadata.get("calibrated_threshold", settings.default_anomaly_threshold)
        except Exception as e:
            self.model = None

    @property
    def is_available(self) -> bool:
        return self.model is not None

    def predict(self, event: Dict[str, Any]) -> ModelPredictionResult:
        """
        Score incoming event against Isolation Forest.
        Gracefully handles failure / degraded mode.
        """
        if not self.is_available:
            return ModelPredictionResult(
                anomaly_score=None,
                normalized_risk_score=None,
                is_anomaly=False,
                threshold=self.threshold,
                feature_deviations={"error": "Model artifact not loaded. Operating in degraded policy-only mode."},
                model_version=settings.model_version,
                model_status="DEGRADED"
            )

        try:
            vector, feat_dict = extract_features(event, record_to_history=True)
            # IsolationForest score_samples: more negative means more anomalous
            raw_score = float(self.model.score_samples(vector)[0])

            # Normalization mapping:
            # Baseline mean score from training is approx -0.548.
            # Scores lower than score_min (-0.654) represent severe behavioral anomalies.
            baseline_normal = self.metadata.get("score_mean", -0.548)
            score_min = self.metadata.get("score_min", -0.654)
            spread = abs(score_min - baseline_normal) or 0.106
            diff = baseline_normal - raw_score
            normalized_risk = float(np.clip(diff / (spread * 1.4), 0.0, 1.0))

            is_anomaly = normalized_risk >= self.threshold

            # Compute feature deviations for explainability
            deviations = {}
            if feat_dict["hour_of_day"] < 6 or feat_dict["hour_of_day"] > 21:
                deviations["temporal_deviation"] = f"Activity at {feat_dict['hour_of_day']}:00 UTC is outside standard business window."
            if feat_dict["requests_5m"] > 10:
                deviations["burst_velocity"] = f"Elevated volume of {feat_dict['requests_5m']} requests in prior 5 minutes."
            if feat_dict["ip_scope_code"] != 0:
                deviations["network_scope"] = f"Source IP is '{feat_dict.get('raw_ip_scope')}' relative to contract whitelist."
            if feat_dict.get("raw_sequence") == "recon_to_bank_patch":
                deviations["sequence_motif"] = "Pre-attack reconnaissance sequence detected (vendor -> bank -> patch)."
            if feat_dict["sensitive_action"] == 1:
                deviations["sensitive_target"] = f"Action touches financial master data ({event.get('action_type')})."

            return ModelPredictionResult(
                anomaly_score=raw_score,
                normalized_risk_score=normalized_risk,
                is_anomaly=is_anomaly,
                threshold=self.threshold,
                feature_deviations=deviations,
                model_version=self.metadata.get("model_version", settings.model_version),
                model_status="AVAILABLE"
            )
        except Exception as e:
            return ModelPredictionResult(
                anomaly_score=None,
                normalized_risk_score=None,
                is_anomaly=False,
                threshold=self.threshold,
                feature_deviations={"exception": str(e)},
                model_version=settings.model_version,
                model_status="DEGRADED"
            )
