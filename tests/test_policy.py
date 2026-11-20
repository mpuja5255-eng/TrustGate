"""
Unit Tests for Deterministic Policy Engine
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.models import Base, ApprovalModel
from app.policy.engine import PolicyEngine

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # Add valid approval for V-0220
    appr = ApprovalModel(
        approval_id="APP-TEST-VALID-01",
        vendor_id="V-0220",
        field="bank_account_number",
        approver_id="FIN-LEAD-Sarah",
        status="APPROVED",
        valid_from="2026-09-01T00:00:00Z",
        valid_until="2026-09-30T23:59:59Z"
    )
    # Add expired approval
    appr_expired = ApprovalModel(
        approval_id="APP-TEST-EXPIRED-02",
        vendor_id="V-0220",
        field="bank_account_number",
        approver_id="FIN-LEAD-Sarah",
        status="APPROVED",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-02-01T00:00:00Z"
    )
    db.add(appr)
    db.add(appr_expired)
    db.commit()
    yield db
    db.close()

def test_policy_prohibited_endpoint(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/admin/export",
        "method": "POST",
        "source_ip": "10.20.4.15",
        "action_type": "privileged_operation"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "BLOCK"
    assert "POLICY_PROHIBITED_ENDPOINT" in res.reason_codes

def test_policy_unknown_api_key(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-unknown-attacker",
        "endpoint": "/v2/vendors/V-0100",
        "method": "GET",
        "source_ip": "10.20.4.15",
        "action_type": "vendor_profile_read"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "BLOCK"
    assert "UNKNOWN_API_KEY" in res.reason_codes

def test_policy_unregistered_ip_holds(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/vendors/V-0100",
        "method": "GET",
        "source_ip": "198.51.100.44",  # Outside 10.20.4.0/24
        "action_type": "vendor_profile_read"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "HOLD"
    assert "UNREGISTERED_SOURCE_IP" in res.reason_codes

def test_policy_routine_contact_update_allowed(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-ops-01",
        "endpoint": "/v2/vendors/V-0100/contacts",
        "method": "PATCH",
        "source_ip": "10.20.10.15",
        "action_type": "contact_update",
        "timestamp": "2026-09-02T12:00:00Z"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "ALLOW"
    assert "POLICY_ALLOWED" in res.reason_codes

def test_policy_bank_update_missing_approval_holds(test_db):
    """E18/E19 incident reproduction"""
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/vendors/V-0412/bank-details",
        "method": "PATCH",
        "source_ip": "10.20.4.77",
        "vendor_id": "V-0412",
        "action_type": "bank_account_update",
        "approval_ref": None,
        "timestamp": "2026-09-03T01:44:30Z"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "HOLD"
    assert "APPROVAL_NOT_PROVIDED" in res.reason_codes

def test_policy_bank_update_with_valid_approval_allowed(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/vendors/V-0220/bank-details",
        "method": "PATCH",
        "source_ip": "10.20.4.15",
        "vendor_id": "V-0220",
        "action_type": "bank_account_update",
        "approval_ref": "APP-TEST-VALID-01",
        "timestamp": "2026-09-03T10:00:00Z"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "ALLOW"
    assert "FINANCE_APPROVAL_VERIFIED" in res.reason_codes

def test_policy_bank_update_approval_vendor_mismatch_blocks(test_db):
    """Approval issued for V-0220, but request modifies V-0412"""
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/vendors/V-0412/bank-details",
        "method": "PATCH",
        "source_ip": "10.20.4.15",
        "vendor_id": "V-0412",
        "action_type": "bank_account_update",
        "approval_ref": "APP-TEST-VALID-01",  # Belongs to V-0220!
        "timestamp": "2026-09-03T10:00:00Z"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "BLOCK"
    assert "APPROVAL_VENDOR_MISMATCH" in res.reason_codes

def test_policy_bank_update_expired_approval_blocks(test_db):
    engine = PolicyEngine()
    event = {
        "api_key_id": "key-tb-07",
        "endpoint": "/v2/vendors/V-0220/bank-details",
        "method": "PATCH",
        "source_ip": "10.20.4.15",
        "vendor_id": "V-0220",
        "action_type": "bank_account_update",
        "approval_ref": "APP-TEST-EXPIRED-02",
        "timestamp": "2026-09-03T10:00:00Z"
    }
    res = engine.evaluate(event, test_db)
    assert res.result == "BLOCK"
    assert "APPROVAL_OUTSIDE_VALIDITY_WINDOW" in res.reason_codes
