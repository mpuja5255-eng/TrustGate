"""
Decision Coordinator for TRUSTGATE
Merges Deterministic Policy Evaluation and Machine Learning Anomaly Signals.
Invariant: ML never grants permission.
"""
from typing import Dict, Any, Tuple
from app.policy.engine import PolicyEvaluationResult
from app.ml.predict import ModelPredictionResult

class DecisionCoordinatorResult:
    def __init__(
        self,
        final_action: str,         # ALLOW, HOLD, BLOCK
        execution_status: str,     # EXECUTED, QUEUED_IN_HOLD, REJECTED
        primary_reason: str,
        degraded_mode: bool = False
    ):
        self.final_action = final_action
        self.execution_status = execution_status
        self.primary_reason = primary_reason
        self.degraded_mode = degraded_mode

    def to_dict(self):
        return {
            "final_action": self.final_action,
            "execution_status": self.execution_status,
            "primary_reason": self.primary_reason,
            "degraded_mode": self.degraded_mode
        }

class DecisionCoordinator:
    @staticmethod
    def coordinate(
        policy_res: PolicyEvaluationResult,
        ml_res: ModelPredictionResult,
        event: Dict[str, Any]
    ) -> DecisionCoordinatorResult:
        """
        Apply precedence rules:
        Policy BLOCK > Policy HOLD > ML Anomaly HOLD > Policy ALLOW
        """
        # Rule 1: Deterministic Policy BLOCK
        if policy_res.result == "BLOCK":
            return DecisionCoordinatorResult(
                final_action="BLOCK",
                execution_status="REJECTED",
                primary_reason=f"POLICY_VIOLATION: {', '.join(policy_res.reason_codes)}"
            )

        # Rule 2: Deterministic Policy HOLD (e.g. missing 4-eyes approval, unregistered host)
        if policy_res.result == "HOLD":
            reasons = ", ".join(policy_res.reason_codes)
            if ml_res.is_anomaly:
                reasons += f" [ELEVATED_RISK: Anomaly score {ml_res.normalized_risk_score:.2f} >= threshold {ml_res.threshold}]"
            return DecisionCoordinatorResult(
                final_action="HOLD",
                execution_status="QUEUED_IN_HOLD",
                primary_reason=f"POLICY_MANDATORY_HOLD: {reasons}"
            )

        # Rule 3: Policy ALLOW, but ML is DEGRADED
        if policy_res.result == "ALLOW" and ml_res.model_status == "DEGRADED":
            return DecisionCoordinatorResult(
                final_action="ALLOW",
                execution_status="EXECUTED",
                primary_reason="DEGRADED_MODE_WARNING: Permitted by deterministic policy; ML risk engine offline",
                degraded_mode=True
            )

        # Rule 4: Policy ALLOW, but ML detected high behavioral anomaly
        if policy_res.result == "ALLOW" and ml_res.is_anomaly:
            return DecisionCoordinatorResult(
                final_action="HOLD",
                execution_status="QUEUED_IN_HOLD",
                primary_reason=f"BEHAVIORAL_ANOMALY_HOLD: Normalized risk score {ml_res.normalized_risk_score:.2f} exceeds threshold {ml_res.threshold}"
            )

        # Rule 5: Policy ALLOW and ML is normal
        if policy_res.result == "ALLOW":
            risk_val = f"{ml_res.normalized_risk_score:.2f}" if ml_res.normalized_risk_score is not None else "0.0"
            return DecisionCoordinatorResult(
                final_action="ALLOW",
                execution_status="EXECUTED",
                primary_reason=f"AUTHORIZED: Verified policy compliance and normal behavioral risk profile ({risk_val})"
            )

        # Fail-secure default
        return DecisionCoordinatorResult(
            final_action="HOLD",
            execution_status="QUEUED_IN_HOLD",
            primary_reason="FAIL_SECURE_HOLD: Indeterminate evaluation state"
        )
