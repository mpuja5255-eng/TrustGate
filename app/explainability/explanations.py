"""
Structured Explainability Engine for TRUSTGATE
Separates:
1. Observed Fact: Directly present in the event or evidence.
2. Policy Finding: Configured rule satisfied or violated.
3. ML Finding: Behavioral anomaly signal and deviations.
4. Actionable Inference: Objective conclusion for SOC triage.
"""
from typing import Dict, Any, List, Optional
from app.policy.engine import PolicyEvaluationResult
from app.ml.predict import ModelPredictionResult
from app.decisions.coordinator import DecisionCoordinatorResult
from app.correlation.vendor_change_matcher import CorrelationResult

def build_structured_explanation(
    event: Dict[str, Any],
    policy_res: PolicyEvaluationResult,
    ml_res: ModelPredictionResult,
    coord_res: DecisionCoordinatorResult,
    correlation: Optional[CorrelationResult] = None
) -> Dict[str, Any]:
    """
    Construct unambiguous, auditable 4-part explanation.
    """
    observed_facts: List[str] = []
    policy_findings: List[str] = list(policy_res.policy_findings)
    ml_findings: List[str] = []
    actionable_inferences: List[str] = []

    # 1. Observed Facts
    observed_facts.append(
        f"API request '{event.get('request_id')}' submitted at {event.get('timestamp')} via "
        f"{event.get('method')} '{event.get('endpoint')}' by key '{event.get('api_key_id')}' "
        f"from source IP {event.get('source_ip')}."
    )
    if event.get("vendor_id"):
        observed_facts.append(f"Target vendor identifier: '{event.get('vendor_id')}'.")
    if event.get("approval_ref"):
        observed_facts.append(f"Provided approval reference string: '{event.get('approval_ref')}'.")
    else:
        observed_facts.append("No approval reference token accompanied this request.")

    # Correlated facts from E19
    if correlation and correlation.is_correlated and correlation.vendor_change:
        vc = correlation.vendor_change
        observed_facts.append(
            f"Correlated with {vc.get('evidence_ref')} master change {vc.get('change_id')}: "
            f"Field '{vc.get('field')}' modified from '{vc.get('old_value_masked')}' to "
            f"'{vc.get('new_value_masked')}' by user '{vc.get('changed_by')}'."
        )
        if correlation.discrepancy:
            observed_facts.append(f"Discrepancy detected: {correlation.notes}")

    # 2. Policy Findings
    if policy_res.approval_details:
        ad = policy_res.approval_details
        policy_findings.append(f"Approval registry verification details: Status='{ad.get('status')}', Approver='{ad.get('approver_id')}'.")

    # 3. ML Findings
    if ml_res.model_status == "AVAILABLE":
        ml_findings.append(
            f"Isolation Forest model ({ml_res.model_version}) produced risk score {ml_res.normalized_risk_score:.2f} "
            f"(calibrated threshold = {ml_res.threshold:.2f}, anomaly = {ml_res.is_anomaly})."
        )
        for k, v in ml_res.feature_deviations.items():
            ml_findings.append(f"Deviation [{k}]: {v}")
    elif ml_res.model_status == "DEGRADED":
        ml_findings.append("Behavioral model is in DEGRADED mode. Risk score is unavailable.")

    # 4. Actionable Inferences
    if coord_res.final_action == "BLOCK":
        actionable_inferences.append(
            "Transaction was REJECTED immediately due to mandatory policy violation. "
            "ML anomaly score cannot override prohibited endpoints or unauthorized capability scope."
        )
    elif coord_res.final_action == "HOLD":
        if "APPROVAL_NOT_PROVIDED" in policy_res.reason_codes or "FINANCE_APPROVAL_REQUIRED" in policy_res.reason_codes:
            actionable_inferences.append(
                "Transaction was HELD because bank account modifications require independent Finance approval. "
                "The ML score supplies behavioral context for investigation but cannot waive the 4-eyes approval requirement."
            )
        elif ml_res.is_anomaly:
            actionable_inferences.append(
                "Transaction was HELD due to high behavioral anomaly (unusual request velocity, off-hours timing, or reconnaissance sequence) "
                "despite general policy compliance. Recommended action: verify intent with vendor point of contact."
            )
        else:
            actionable_inferences.append(
                "Transaction was HELD pending human review under fail-secure policy guidelines."
            )
    else:
        actionable_inferences.append(
            "Transaction was APPROVED and dispatched for execution. Operation verified compliant with registered capability contract "
            "and standard behavioral baseline."
        )

    return {
        "event_id": event.get("event_id"),
        "request_id": event.get("request_id"),
        "final_action": coord_res.final_action,
        "execution_status": coord_res.execution_status,
        "primary_reason": coord_res.primary_reason,
        "observed_facts": observed_facts,
        "policy_findings": policy_findings,
        "ml_behavioral_findings": ml_findings,
        "actionable_inferences": actionable_inferences
    }
