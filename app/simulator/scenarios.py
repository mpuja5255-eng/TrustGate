"""
Scenario Catalog for TRUSTGATE Simulation Lab
"""
from typing import Dict, Any, List

SCENARIO_CATALOG: Dict[str, Dict[str, Any]] = {
    "SCN-01": {
        "id": "SCN-01",
        "name": "Normal Contact Update",
        "description": "Routine authorized vendor contact update during business hours from registered host.",
        "ground_truth": "LEGITIMATE",
        "expected_action": "ALLOW",
        "scenario_type": "standard_legitimate"
    },
    "SCN-02": {
        "id": "SCN-02",
        "name": "Normal Invoice Lookup",
        "description": "Routine GET request for vendor invoice details.",
        "ground_truth": "LEGITIMATE",
        "expected_action": "ALLOW",
        "scenario_type": "standard_legitimate"
    },
    "SCN-03": {
        "id": "SCN-03",
        "name": "Approved Bank Update",
        "description": "Bank account modification with valid, verified independent Finance approval.",
        "ground_truth": "LEGITIMATE",
        "expected_action": "ALLOW",
        "scenario_type": "approved_sensitive"
    },
    "SCN-04": {
        "id": "SCN-04",
        "name": "Bank Update with No Approval",
        "description": "Replay of 3 September incident (E18/E19): unapproved bank account PATCH by key-tb-07.",
        "ground_truth": "ATTACK",
        "expected_action": "HOLD",
        "scenario_type": "unauthorized_modification"
    },
    "SCN-05": {
        "id": "SCN-05",
        "name": "Prohibited Endpoint Access",
        "description": "Integration attempts to access /v2/admin/export in violation of capability boundary.",
        "ground_truth": "ATTACK",
        "expected_action": "BLOCK",
        "scenario_type": "capability_violation"
    },
    "SCN-06": {
        "id": "SCN-06",
        "name": "Unregistered Source Host Burst",
        "description": "Valid credential key-tb-07 sending burst from unregistered external IP subnet.",
        "ground_truth": "SUSPICIOUS",
        "expected_action": "HOLD",
        "scenario_type": "network_perimeter_anomaly"
    },
    "SCN-07": {
        "id": "SCN-07",
        "name": "Rapid Reconnaissance Sequence",
        "description": "Rapid vendor traversal: vendor lookup -> bank lookup -> scheduled payments -> update.",
        "ground_truth": "SUSPICIOUS",
        "expected_action": "HOLD",
        "scenario_type": "reconnaissance_sweep"
    },
    "SCN-08": {
        "id": "SCN-08",
        "name": "Replayed Request Nonce",
        "description": "Replay of existing transaction request_id with duplicate timestamp.",
        "ground_truth": "ATTACK",
        "expected_action": "BLOCK",
        "scenario_type": "replay_attack"
    },
    "SCN-09": {
        "id": "SCN-09",
        "name": "Malformed Event Payload",
        "description": "Missing required fields or invalid HTTP method/timestamp.",
        "ground_truth": "INVALID",
        "expected_action": "INVALID",
        "scenario_type": "schema_corruption"
    },
    "SCN-10": {
        "id": "SCN-10",
        "name": "Legitimate Month-End Batch Job",
        "description": "High-volume authorized invoice synchronization during scheduled batch window.",
        "ground_truth": "LEGITIMATE",
        "expected_action": "ALLOW",
        "scenario_type": "legitimate_edge_case"
    },
    "SCN-11": {
        "id": "SCN-11",
        "name": "Approval Service Unavailable",
        "description": "Finance approval registry timeout during sensitive bank change.",
        "ground_truth": "DEPENDENCY_FAILURE",
        "expected_action": "HOLD",
        "scenario_type": "fail_secure_dependency"
    },
    "SCN-12": {
        "id": "SCN-12",
        "name": "ML Service Unavailable",
        "description": "ML anomaly engine offline; system operates in policy-only degraded mode.",
        "ground_truth": "DEGRADED_MODE",
        "expected_action": "ALLOW",
        "scenario_type": "degraded_resilience"
    }
}
