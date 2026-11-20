"""
Model Manager for TRUSTGATE
"""
from typing import Dict, Any
from app.ml.predict import RiskPredictor
from app.ml.train import train_and_save_model

class ModelManager:
    _instance = None

    def __init__(self):
        self.predictor = RiskPredictor()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def reload(self):
        self.predictor.load()

    def retrain(self) -> dict:
        meta = train_and_save_model()
        self.reload()
        return meta

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "AVAILABLE" if self.predictor.is_available else "DEGRADED",
            "model_version": self.predictor.metadata.get("model_version", "unknown"),
            "threshold": self.predictor.threshold,
            "trained_at": self.predictor.metadata.get("trained_at", "never"),
            "train_samples": self.predictor.metadata.get("train_samples", 0),
            "algorithm": self.predictor.metadata.get("algorithm", "IsolationForest")
        }
