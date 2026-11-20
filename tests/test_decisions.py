"""
Unit Tests for Decision Coordinator and Explainability
"""
from app.policy.engine import PolicyEvaluationResult
from app.ml.predict import ModelPredictionResult
from app.decisions.coordinator import DecisionCoordinator
from app.explainability.explanations import build_structured_explanation

def test_ml_cannot_override_policy_block():
    """Invariant: Even if ML score is 0.0 (completely safe), policy BLOCK must prevail"""
    policy_res = PolicyEvaluationResult("BLOCK", ["POLICY_PROHIBITED_ENDPOINT"], ["Endpoint is blacklisted"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=-0.30,
        normalized_risk_score=0.0,  # Safe
        is_anomaly=False,
        threshold=0.65,
        feature_deviations={},
        model_version="iforest-v1"
    )
    event = {"request_id": "req-block-test"}

    decision = DecisionCoordinator.coordinate(policy_res, ml_res, event)
    assert decision.final_action == "BLOCK"
    assert decision.execution_status == "REJECTED"

def test_ml_cannot_override_policy_hold():
    """Invariant: If policy mandates HOLD (missing approval), low ML score cannot ALLOW"""
    policy_res = PolicyEvaluationResult("HOLD", ["FINANCE_APPROVAL_REQUIRED"], ["Missing approval"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=-0.35,
        normalized_risk_score=0.10,  # Low anomaly
        is_anomaly=False,
        threshold=0.65,
        feature_deviations={},
        model_version="iforest-v1"
    )
    event = {"request_id": "req-hold-test"}

    decision = DecisionCoordinator.coordinate(policy_res, ml_res, event)
    assert decision.final_action == "HOLD"
    assert decision.execution_status == "QUEUED_IN_HOLD"

def test_policy_allow_with_high_ml_anomaly_escalates_to_hold():
    """Behavioral anomaly escalation"""
    policy_res = PolicyEvaluationResult("ALLOW", ["POLICY_ALLOWED"], ["Scope verified"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=-0.65,
        normalized_risk_score=0.88,  # High anomaly!
        is_anomaly=True,
        threshold=0.65,
        feature_deviations={"burst": "High frequency burst"},
        model_version="iforest-v1"
    )
    event = {"request_id": "req-anom-test"}

    decision = DecisionCoordinator.coordinate(policy_res, ml_res, event)
    assert decision.final_action == "HOLD"
    assert decision.execution_status == "QUEUED_IN_HOLD"
    assert "BEHAVIORAL_ANOMALY_HOLD" in decision.primary_reason

def test_policy_allow_with_normal_ml_allows():
    policy_res = PolicyEvaluationResult("ALLOW", ["POLICY_ALLOWED"], ["Scope verified"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=-0.38,
        normalized_risk_score=0.20,
        is_anomaly=False,
        threshold=0.65,
        feature_deviations={},
        model_version="iforest-v1"
    )
    event = {"request_id": "req-safe-test"}

    decision = DecisionCoordinator.coordinate(policy_res, ml_res, event)
    assert decision.final_action == "ALLOW"
    assert decision.execution_status == "EXECUTED"

def test_policy_allow_with_degraded_ml():
    policy_res = PolicyEvaluationResult("ALLOW", ["POLICY_ALLOWED"], ["Scope verified"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=None,
        normalized_risk_score=None,
        is_anomaly=False,
        threshold=0.65,
        feature_deviations={},
        model_version="iforest-v1",
        model_status="DEGRADED"
    )
    event = {"request_id": "req-degraded-test"}

    decision = DecisionCoordinator.coordinate(policy_res, ml_res, event)
    assert decision.final_action == "ALLOW"
    assert decision.degraded_mode is True
    assert "DEGRADED_MODE_WARNING" in decision.primary_reason

def test_structured_explanation_has_all_four_tiers():
    event = {
        "event_id": "evt-exp-01",
        "request_id": "req-exp-01",
        "timestamp": "2026-09-03T01:44:30Z",
        "method": "PATCH",
        "endpoint": "/v2/vendors/V-0412/bank-details",
        "api_key_id": "key-tb-07",
        "source_ip": "10.20.4.77",
        "vendor_id": "V-0412"
    }
    policy_res = PolicyEvaluationResult("HOLD", ["FINANCE_APPROVAL_REQUIRED"], ["Missing approval"], "1.0.0")
    ml_res = ModelPredictionResult(
        anomaly_score=-0.60,
        normalized_risk_score=0.75,
        is_anomaly=True,
        threshold=0.65,
        feature_deviations={"temporal": "01:00 AM off hours"},
        model_version="iforest-v1"
    )
    coord_res = DecisionCoordinator.coordinate(policy_res, ml_res, event)

    explanation = build_structured_explanation(event, policy_res, ml_res, coord_res)

    assert "observed_facts" in explanation
    assert "policy_findings" in explanation
    assert "ml_behavioral_findings" in explanation
    assert "actionable_inferences" in explanation
    assert len(explanation["observed_facts"]) > 0
    assert len(explanation["actionable_inferences"]) > 0
