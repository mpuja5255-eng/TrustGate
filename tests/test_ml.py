"""
Unit Tests for Machine Learning Risk Engine
"""
import pytest
import numpy as np
from app.ml.features import extract_features, FEATURE_NAMES, reset_history
from app.ml.predict import RiskPredictor

def test_feature_extraction_vector_shape():
    reset_history()
    event = {
        "method": "PATCH",
        "endpoint_group": "vendor_bank_details",
        "action_type": "bank_account_update",
        "api_key_id": "key-tb-07",
        "source_ip_scope": "registered",
        "timestamp": "2026-09-03T01:44:30Z",
        "status": 200,
        "approval_ref": None
    }
    vec, feat_dict = extract_features(event)
    assert vec.shape == (1, len(FEATURE_NAMES))
    assert feat_dict["hour_of_day"] == 1
    assert feat_dict["sensitive_action"] == 1
    assert feat_dict["has_approval_ref"] == 0

def test_model_prediction_available():
    predictor = RiskPredictor()
    if predictor.is_available:
        event = {
            "method": "GET",
            "endpoint_group": "vendor_profile",
            "action_type": "vendor_profile_read",
            "api_key_id": "key-tb-07",
            "source_ip_scope": "registered",
            "timestamp": "2026-09-02T12:00:00Z",
            "status": 200
        }
        res = predictor.predict(event)
        assert res.model_status == "AVAILABLE"
        assert res.normalized_risk_score is not None
        assert 0.0 <= res.normalized_risk_score <= 1.0

def test_degraded_mode_when_model_missing():
    # Point to nonexistent model path
    predictor = RiskPredictor(model_path="nonexistent_model.joblib")
    event = {"method": "GET", "timestamp": "2026-09-02T12:00:00Z"}
    res = predictor.predict(event)
    assert res.model_status == "DEGRADED"
    assert res.anomaly_score is None
    assert res.normalized_risk_score is None
    assert res.is_anomaly is False
