"""
Deterministic Policy Engine for TRUSTGATE
"""
import ipaddress
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.policy.contracts import ContractManager
from app.policy.rules import PolicyRules

class PolicyEvaluationResult:
    def __init__(
        self,
        result: str,  # ALLOW, HOLD, BLOCK
        reason_codes: List[str],
        policy_findings: List[str],
        policy_version: str,
        approval_details: Optional[Dict[str, Any]] = None
    ):
        self.result = result
        self.reason_codes = reason_codes
        self.policy_findings = policy_findings
        self.policy_version = policy_version
        self.approval_details = approval_details

    def to_dict(self):
        return {
            "result": self.result,
            "reason_codes": self.reason_codes,
            "policy_findings": self.policy_findings,
            "policy_version": self.policy_version,
            "approval_details": self.approval_details
        }

class PolicyEngine:
    def __init__(self, contracts_path: Optional[str] = None, policy_path: Optional[str] = None):
        self.contracts = ContractManager(contracts_path)
        self.rules = PolicyRules(policy_path)

    def evaluate(self, event: Dict[str, Any], db: Session) -> PolicyEvaluationResult:
        api_key_id = event.get("api_key_id", "")
        endpoint = event.get("endpoint", "")
        method = event.get("method", "GET").upper()
        source_ip = event.get("source_ip", "")
        action_type = event.get("action_type", "")
        vendor_id = event.get("vendor_id")
        approval_ref = event.get("approval_ref")
        timestamp = event.get("timestamp", "")

        reason_codes = []
        policy_findings = []

        # 1. Prohibited Endpoints Check
        if self.rules.is_prohibited_endpoint(endpoint):
            reason_codes.append("POLICY_PROHIBITED_ENDPOINT")
            policy_findings.append(f"Target endpoint '{endpoint}' is on the restricted blacklist.")
            return PolicyEvaluationResult("BLOCK", reason_codes, policy_findings, self.rules.version)

        # 2. Integration Identity & Contract Verification
        if not self.contracts.is_key_registered(api_key_id):
            reason_codes.append("UNKNOWN_API_KEY")
            policy_findings.append(f"API key '{api_key_id}' is not in the connected-software register (E04).")
            return PolicyEvaluationResult("BLOCK", reason_codes, policy_findings, self.rules.version)

        if not self.contracts.is_active(api_key_id):
            reason_codes.append("INTEGRATION_INACTIVE")
            policy_findings.append(f"Integration '{api_key_id}' is deactivated or expired in register.")
            return PolicyEvaluationResult("BLOCK", reason_codes, policy_findings, self.rules.version)

        # 3. Network Boundary Evaluation
        allowed_ips = self.contracts.get_allowed_ips(api_key_id)
        is_ip_allowed = False
        try:
            ip_obj = ipaddress.ip_address(source_ip)
            for cidr in allowed_ips:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    is_ip_allowed = True
                    break
        except Exception:
            is_ip_allowed = False

        if not is_ip_allowed:
            reason_codes.append("UNREGISTERED_SOURCE_IP")
            policy_findings.append(f"Source IP '{source_ip}' is outside registered CIDR blocks {allowed_ips} (E04/E10).")

        # 4. Capability Scope Mapping
        capabilities = self.contracts.get_allowed_capabilities(api_key_id)
        required_capability = None
        if "contacts" in endpoint:
            required_capability = "write:contacts" if method in ("POST", "PUT", "PATCH", "DELETE") else "read:vendors"
        elif "payments" in endpoint:
            required_capability = "write:payments" if method in ("POST", "PUT", "PATCH", "DELETE") else "read:payments"
        elif "invoices" in endpoint:
            required_capability = "write:invoices" if method in ("POST", "PUT", "PATCH", "DELETE") else "read:invoices"
        elif "vendors" in endpoint:
            required_capability = "write:vendors" if method in ("POST", "PUT", "PATCH", "DELETE") else "read:vendors"

        if required_capability and required_capability not in capabilities:
            reason_codes.append("CAPABILITY_NOT_PERMITTED")
            policy_findings.append(f"Integration lacks required scope '{required_capability}'. Registered: {capabilities}.")
            return PolicyEvaluationResult("BLOCK", reason_codes, policy_findings, self.rules.version)

        # 5. Sensitive Operations & Independent Approval Verification
        approval_details = None
        if self.rules.is_sensitive_action(action_type):
            rule = self.rules.get_sensitive_rule(action_type)
            is_valid, app_reason, app_details = self.rules.verify_approval(
                approval_ref=approval_ref,
                vendor_id=vendor_id,
                action_type=action_type,
                event_timestamp=timestamp,
                db=db
            )
            approval_details = app_details

            if not is_valid:
                reason_codes.append(app_reason)
                if app_reason == "APPROVAL_NOT_PROVIDED":
                    policy_findings.append(f"Sensitive action '{action_type}' requires independent Finance approval; none was supplied.")
                    action = rule.get("action_on_missing_approval", "HOLD")
                    return PolicyEvaluationResult(action, reason_codes, policy_findings, self.rules.version)
                else:
                    policy_findings.append(f"Independent approval check failed with reason '{app_reason}'.")
                    action = rule.get("action_on_invalid_approval", "BLOCK")
                    return PolicyEvaluationResult(action, reason_codes, policy_findings, self.rules.version, approval_details)
            else:
                reason_codes.append("FINANCE_APPROVAL_VERIFIED")
                policy_findings.append(f"Verified independent Finance approval '{approval_ref}' by approver '{app_details.get('approver_id')}'.")

        # If IP was unregistered, policy dictates HOLD
        if "UNREGISTERED_SOURCE_IP" in reason_codes:
            return PolicyEvaluationResult("HOLD", reason_codes, policy_findings, self.rules.version, approval_details)

        # Passed all deterministic checks
        reason_codes.append("POLICY_ALLOWED")
        policy_findings.append("Operation complies with registered contract scope and deterministic policy requirements.")
        return PolicyEvaluationResult("ALLOW", reason_codes, policy_findings, self.rules.version, approval_details)
