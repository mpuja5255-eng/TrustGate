"""
Unit Tests for Ingestion and Normalization
"""
import pytest
from app.ingestion.validator import RawEventPayload
from app.ingestion.normalizer import (
    normalize_timestamp, parse_endpoint_semantics, evaluate_ip_scope, normalize_event
)

def test_validator_valid_payload():
    payload = {
        "request_id": "req-001",
        "api_key_id": "key-tb-07",
        "source_ip": "10.20.4.77",
        "endpoint": "/v2/vendors/V-0412/bank-details",
        "method": "PATCH",
        "timestamp": "2026-09-03T01:44:30Z"
    }
    validated = RawEventPayload(**payload)
    assert validated.request_id == "req-001"
    assert validated.method == "PATCH"

def test_validator_invalid_method():
    payload = {
        "request_id": "req-001",
        "api_key_id": "key-tb-07",
        "source_ip": "10.20.4.77",
        "endpoint": "/v2/vendors/V-0412",
        "method": "INVALID_VERB"
    }
    with pytest.raises(ValueError):
        RawEventPayload(**payload)

def test_timestamp_normalization():
    norm_ts = normalize_timestamp("2026-09-03T01:44:30Z")
    assert norm_ts == "2026-09-03T01:44:30Z"

def test_endpoint_semantics_bank_details():
    res = parse_endpoint_semantics("/v2/vendors/V-0412/bank-details", "PATCH")
    assert res["vendor_id"] == "V-0412"
    assert res["endpoint_group"] == "vendor_bank_details"
    assert res["action_type"] == "bank_account_update"

def test_ip_scope_evaluation():
    allowed = ["10.20.4.0/24"]
    assert evaluate_ip_scope("10.20.4.77", allowed) == "registered"
    assert evaluate_ip_scope("198.51.100.2", allowed) == "unregistered"
    assert evaluate_ip_scope("not-an-ip", allowed) == "unknown"

def test_normalize_event_e18_case():
    raw = {
        "request_id": "req-5f61b0de8",
        "api_key_id": "key-tb-07",
        "source_ip": "10.20.4.77",
        "endpoint": "/v2/vendors/V-0412/bank-details",
        "method": "PATCH",
        "timestamp": "2026-09-03T01:44:30Z"
    }
    norm = normalize_event(raw, allowed_cidrs=["10.20.4.0/24"])
    assert norm["vendor_id"] == "V-0412"
    assert norm["action_type"] == "bank_account_update"
    assert norm["source_ip_scope"] == "registered"
    assert norm["event_id"].startswith("evt-")
