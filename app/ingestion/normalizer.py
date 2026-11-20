"""
Event Normalizer for TRUSTGATE
"""
import re
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

def normalize_timestamp(ts_str: str = None) -> str:
    """Normalize input timestamp string to UTC ISO8601 string (e.g. 2026-09-03T01:44:30Z)"""
    if not ts_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_endpoint_semantics(endpoint: str, method: str) -> Dict[str, Any]:
    """Extract vendor_id, endpoint_group, and action_type from URL path"""
    endpoint = endpoint.strip()
    vendor_id = None
    endpoint_group = "unknown"
    action_type = "generic_api_call"

    # Pattern: /v2/vendors/(V-\w+)/bank-details
    bank_match = re.search(r"/v2/vendors/([^/]+)/bank-details", endpoint)
    if bank_match:
        vendor_id = bank_match.group(1)
        endpoint_group = "vendor_bank_details"
        action_type = "bank_account_update" if method in ("PATCH", "PUT", "POST") else "bank_account_read"
        return {"vendor_id": vendor_id, "endpoint_group": endpoint_group, "action_type": action_type}

    # Pattern: /v2/vendors/(V-\w+)/contacts
    contact_match = re.search(r"/v2/vendors/([^/]+)/contacts", endpoint)
    if contact_match:
        vendor_id = contact_match.group(1)
        endpoint_group = "vendor_contacts"
        action_type = "contact_update" if method in ("PATCH", "PUT", "POST") else "contact_read"
        return {"vendor_id": vendor_id, "endpoint_group": endpoint_group, "action_type": action_type}

    # Pattern: /v2/vendors/(V-\w+)/scheduled-payments
    payment_match = re.search(r"/v2/vendors/([^/]+)/scheduled-payments", endpoint)
    if payment_match:
        vendor_id = payment_match.group(1)
        endpoint_group = "vendor_payments"
        action_type = "payment_schedule_read"
        return {"vendor_id": vendor_id, "endpoint_group": endpoint_group, "action_type": action_type}

    # Pattern: /v2/vendors/(V-\w+)
    profile_match = re.search(r"/v2/vendors/([^/]+)", endpoint)
    if profile_match:
        vendor_id = profile_match.group(1)
        endpoint_group = "vendor_profile"
        action_type = "vendor_profile_update" if method in ("PATCH", "PUT", "POST") else "vendor_profile_read"
        return {"vendor_id": vendor_id, "endpoint_group": endpoint_group, "action_type": action_type}

    # Pattern: /v2/invoices/(INV-\w+)
    invoice_match = re.search(r"/v2/invoices/([^/]+)", endpoint)
    if invoice_match:
        endpoint_group = "invoices"
        action_type = "invoice_read" if method == "GET" else "invoice_update"
        return {"vendor_id": None, "endpoint_group": endpoint_group, "action_type": action_type}

    # Prohibited endpoints
    if "/admin" in endpoint or "/export" in endpoint or "/payroll" in endpoint:
        endpoint_group = "administrative_privileged"
        action_type = "privileged_operation"

    return {"vendor_id": vendor_id, "endpoint_group": endpoint_group, "action_type": action_type}

def evaluate_ip_scope(source_ip: str, allowed_cidrs: List[str]) -> str:
    """Evaluate whether source_ip falls into allowed CIDRs"""
    try:
        ip_obj = ipaddress.ip_address(source_ip)
        for cidr in allowed_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return "registered"
        return "unregistered"
    except Exception:
        return "unknown"

def normalize_event(raw: Dict[str, Any], allowed_cidrs: List[str] = None) -> Dict[str, Any]:
    """Create normalized event dictionary from validated payload"""
    timestamp = normalize_timestamp(raw.get("timestamp"))
    semantics = parse_endpoint_semantics(raw.get("endpoint", ""), raw.get("method", "GET"))
    
    vendor_id = raw.get("vendor_id") or semantics["vendor_id"]
    action_type = raw.get("action_type") or semantics["action_type"]
    endpoint_group = semantics["endpoint_group"]
    
    ip_scope = evaluate_ip_scope(raw.get("source_ip", ""), allowed_cidrs or [])

    event_id = raw.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"

    return {
        "event_id": event_id,
        "run_id": raw.get("run_id"),
        "timestamp": timestamp,
        "request_id": raw.get("request_id"),
        "api_key_id": raw.get("api_key_id"),
        "source_ip": raw.get("source_ip"),
        "source_ip_scope": ip_scope,
        "endpoint": raw.get("endpoint"),
        "endpoint_group": endpoint_group,
        "method": raw.get("method", "GET").upper(),
        "status": int(raw.get("status", 200)),
        "vendor_id": vendor_id,
        "action_type": action_type,
        "approval_ref": raw.get("approval_ref") or None,
        "source_evidence": raw.get("source_evidence") or ["API_STREAM"]
    }
