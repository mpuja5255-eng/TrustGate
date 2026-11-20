"""
Policy Rule Evaluator for TRUSTGATE
"""
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
from app.config import settings
from app.database.models import ApprovalModel

class PolicyRules:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or settings.policy_file
        self.config: Dict[str, Any] = {}
        self.load()

    def load(self):
        if os.path.exists(self.policy_path):
            with open(self.policy_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "policy_version": "1.0.0",
                "prohibited_endpoints": ["/v2/admin/export"],
                "sensitive_action_rules": {}
            }

    @property
    def version(self) -> str:
        return self.config.get("policy_version", "1.0.0")

    def is_prohibited_endpoint(self, endpoint: str) -> bool:
        prohibited = self.config.get("prohibited_endpoints", [])
        for p in prohibited:
            if endpoint.startswith(p) or p in endpoint:
                return True
        return False

    def is_sensitive_action(self, action_type: str) -> bool:
        rules = self.config.get("sensitive_action_rules", {})
        return action_type in rules

    def get_sensitive_rule(self, action_type: str) -> Optional[Dict[str, Any]]:
        rules = self.config.get("sensitive_action_rules", {})
        return rules.get(action_type)

    def verify_approval(
        self,
        approval_ref: Optional[str],
        vendor_id: Optional[str],
        action_type: str,
        event_timestamp: str,
        db: Session
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Verify independent Finance approval against the database.
        Returns: (is_valid, reason_code, approval_details)
        """
        rule = self.get_sensitive_rule(action_type)
        if not rule or not rule.get("requires_approval", False):
            return True, "NO_APPROVAL_REQUIRED", None

        if not approval_ref or not approval_ref.strip():
            return False, "APPROVAL_NOT_PROVIDED", None

        # Query approval record
        approval = db.query(ApprovalModel).filter(ApprovalModel.approval_id == approval_ref.strip()).first()
        if not approval:
            return False, "APPROVAL_NOT_FOUND_IN_REGISTRY", None

        # Verify status
        if approval.status != "APPROVED":
            return False, f"APPROVAL_STATUS_{approval.status}", {
                "approval_id": approval.approval_id,
                "status": approval.status
            }

        # Verify vendor alignment
        if vendor_id and approval.vendor_id != vendor_id:
            return False, "APPROVAL_VENDOR_MISMATCH", {
                "approval_id": approval.approval_id,
                "expected_vendor": vendor_id,
                "approval_vendor": approval.vendor_id
            }

        # Verify validity window
        try:
            ev_dt = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
            v_from = datetime.fromisoformat(approval.valid_from.replace("Z", "+00:00"))
            v_until = datetime.fromisoformat(approval.valid_until.replace("Z", "+00:00"))
            if ev_dt < v_from or ev_dt > v_until:
                return False, "APPROVAL_OUTSIDE_VALIDITY_WINDOW", {
                    "approval_id": approval.approval_id,
                    "event_time": event_timestamp,
                    "valid_from": approval.valid_from,
                    "valid_until": approval.valid_until
                }
        except Exception:
            pass

        return True, "APPROVAL_VERIFIED", {
            "approval_id": approval.approval_id,
            "approver_id": approval.approver_id,
            "status": approval.status,
            "evidence_ref": approval.evidence_ref
        }
