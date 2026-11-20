"""
Feature Engineering Pipeline for TRUSTGATE Behavioral Detection
"""
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

# Global sliding history buffer to calculate rolling 5m and 15m statistics
# Stores: {"timestamp": dt, "api_key_id": key, "endpoint": ep, "status": code}
_HISTORY_BUFFER: List[Dict[str, Any]] = []

def reset_history():
    global _HISTORY_BUFFER
    _HISTORY_BUFFER = []

def record_history_event(event: Dict[str, Any]):
    global _HISTORY_BUFFER
    try:
        ts = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    _HISTORY_BUFFER.append({
        "timestamp": ts,
        "api_key_id": event.get("api_key_id", ""),
        "endpoint": event.get("endpoint", ""),
        "status": int(event.get("status", 200)),
        "method": event.get("method", "GET"),
        "action_type": event.get("action_type", "")
    })

    # Prune history older than 60 minutes
    cutoff = ts - timedelta(minutes=60)
    _HISTORY_BUFFER = [h for h in _HISTORY_BUFFER if h["timestamp"] >= cutoff]

def compute_rolling_stats(api_key_id: str, current_ts: datetime) -> Tuple[int, int, int, str]:
    """
    Computes:
    - requests_5m
    - unique_endpoints_15m
    - failed_requests_5m
    - sequence_pattern
    """
    w5 = current_ts - timedelta(minutes=5)
    w15 = current_ts - timedelta(minutes=15)

    key_events_5m = [h for h in _HISTORY_BUFFER if h["api_key_id"] == api_key_id and w5 <= h["timestamp"] <= current_ts]
    key_events_15m = [h for h in _HISTORY_BUFFER if h["api_key_id"] == api_key_id and w15 <= h["timestamp"] <= current_ts]

    requests_5m = len(key_events_5m)
    unique_endpoints_15m = len(set(h["endpoint"] for h in key_events_15m))
    failed_requests_5m = sum(1 for h in key_events_5m if h["status"] >= 400)

    # Derive sequence pattern from the last 4 actions of this key
    recent_actions = [h["action_type"] for h in key_events_15m[-4:]]
    if len(recent_actions) >= 3 and "vendor_profile_read" in recent_actions and "bank_account_read" in recent_actions and ("bank_account_update" in recent_actions or recent_actions[-1] == "bank_account_update"):
        sequence_pattern = "recon_to_bank_patch"
    elif len(recent_actions) >= 2 and all("read" in a for a in recent_actions):
        sequence_pattern = "read_sweep"
    else:
        sequence_pattern = "standard_single_call"

    return requests_5m, unique_endpoints_15m, failed_requests_5m, sequence_pattern

# Categorical Vocabularies
METHOD_VOCAB = {"GET": 0, "POST": 1, "PATCH": 2, "PUT": 3, "DELETE": 4, "OTHER": 5}
ENDPOINT_GROUP_VOCAB = {
    "vendor_profile": 0,
    "vendor_contacts": 1,
    "vendor_bank_details": 2,
    "vendor_payments": 3,
    "invoices": 4,
    "administrative_privileged": 5,
    "unknown": 6
}
ACTION_TYPE_VOCAB = {
    "vendor_profile_read": 0,
    "vendor_profile_update": 1,
    "contact_read": 2,
    "contact_update": 3,
    "bank_account_read": 4,
    "bank_account_update": 5,
    "invoice_read": 6,
    "invoice_update": 7,
    "payment_schedule_read": 8,
    "privileged_operation": 9,
    "generic_api_call": 10
}
KEY_VOCAB = {"key-tb-07": 0, "key-ops-01": 1, "key-finance-02": 2, "OTHER": 3}
IP_SCOPE_VOCAB = {"registered": 0, "unregistered": 1, "unknown": 2}
SEQUENCE_VOCAB = {"standard_single_call": 0, "read_sweep": 1, "recon_to_bank_patch": 2}

FEATURE_NAMES = [
    "method_code",
    "endpoint_group_code",
    "action_type_code",
    "api_key_code",
    "ip_scope_code",
    "hour_of_day",
    "is_weekend",
    "requests_5m",
    "unique_endpoints_15m",
    "sensitive_action",
    "has_approval_ref",
    "failed_requests_5m",
    "sequence_code"
]

def extract_features(event: Dict[str, Any], record_to_history: bool = True) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Extract numeric feature vector from event.
    Returns: (vector of shape (1, 13), feature_dict)
    """
    method = event.get("method", "GET").upper()
    endpoint_group = event.get("endpoint_group", "unknown")
    action_type = event.get("action_type", "generic_api_call")
    api_key_id = event.get("api_key_id", "OTHER")
    source_ip_scope = event.get("source_ip_scope", "unknown")
    approval_ref = event.get("approval_ref")

    try:
        dt = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)

    hour_of_day = dt.hour
    is_weekend = 1 if dt.weekday() >= 5 else 0

    requests_5m, unique_endpoints_15m, failed_requests_5m, sequence_pattern = compute_rolling_stats(api_key_id, dt)

    if record_to_history:
        record_history_event(event)

    sensitive_action = 1 if action_type in ("bank_account_update", "tax_id_update", "high_value_payment_schedule") else 0
    has_approval_ref = 1 if approval_ref and approval_ref.strip() else 0

    feat_dict = {
        "method_code": METHOD_VOCAB.get(method, METHOD_VOCAB["OTHER"]),
        "endpoint_group_code": ENDPOINT_GROUP_VOCAB.get(endpoint_group, ENDPOINT_GROUP_VOCAB["unknown"]),
        "action_type_code": ACTION_TYPE_VOCAB.get(action_type, ACTION_TYPE_VOCAB["generic_api_call"]),
        "api_key_code": KEY_VOCAB.get(api_key_id, KEY_VOCAB["OTHER"]),
        "ip_scope_code": IP_SCOPE_VOCAB.get(source_ip_scope, IP_SCOPE_VOCAB["unknown"]),
        "hour_of_day": hour_of_day,
        "is_weekend": is_weekend,
        "requests_5m": requests_5m,
        "unique_endpoints_15m": unique_endpoints_15m,
        "sensitive_action": sensitive_action,
        "has_approval_ref": has_approval_ref,
        "failed_requests_5m": failed_requests_5m,
        "sequence_code": SEQUENCE_VOCAB.get(sequence_pattern, 0),
        # Context strings for explainability
        "raw_method": method,
        "raw_endpoint_group": endpoint_group,
        "raw_sequence": sequence_pattern,
        "raw_ip_scope": source_ip_scope
    }

    vector = np.array([feat_dict[fn] for fn in FEATURE_NAMES], dtype=float).reshape(1, -1)
    return vector, feat_dict
