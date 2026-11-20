"""
API Route Tests for TRUSTGATE Backend
Tests route handlers directly with database sessions, avoiding Python 3.14 AnyIO thread portal issues.
"""
import uuid
import pytest
from app.database.repository import SessionLocal, init_db, seed_case_evidence
from app.api.routes import (
    health_check, get_model_status, process_event, list_events,
    get_event_detail, run_simulation, record_review,
    RawEventPayload, SimulationRequest, ReviewSubmission
)
from app.main import serve_dashboard

@pytest.fixture(scope="module")
def db_session():
    init_db()
    db = SessionLocal()
    seed_case_evidence(db)
    yield db
    db.close()

def test_health_check_route():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "TRUSTGATE"

def test_model_status_route():
    res = get_model_status()
    assert "status" in res
    assert "threshold" in res
    assert res["status"] in ("AVAILABLE", "DEGRADED")

def test_submit_valid_routine_event(db_session):
    uid = uuid.uuid4().hex[:8]
    payload = RawEventPayload(
        request_id=f"api-test-req-norm-{uid}",
        api_key_id="key-ops-01",
        source_ip="10.20.10.15",
        endpoint="/v2/vendors/V-0100/contacts",
        method="PATCH",
        timestamp="2026-09-02T12:00:00Z"
    )
    res = process_event(payload, db=db_session)
    assert res["final_action"] == "ALLOW"
    assert res["execution_status"] == "EXECUTED"
    assert "explanation" in res

def test_submit_unapproved_bank_change_holds(db_session):
    """3 September V-0412 incident reproduction via API"""
    uid = uuid.uuid4().hex[:8]
    payload = RawEventPayload(
        request_id=f"api-test-req-bank-{uid}",
        api_key_id="key-tb-07",
        source_ip="10.20.4.77",
        endpoint="/v2/vendors/V-0412/bank-details",
        method="PATCH",
        timestamp="2026-09-03T01:44:30Z",
        vendor_id="V-0412"
    )
    res = process_event(payload, db=db_session)
    assert res["final_action"] == "HOLD"
    assert res["execution_status"] == "QUEUED_IN_HOLD"
    assert "APPROVAL_NOT_PROVIDED" in res["policy"]["reason_codes"]

def test_submit_prohibited_endpoint_blocks(db_session):
    uid = uuid.uuid4().hex[:8]
    payload = RawEventPayload(
        request_id=f"api-test-req-prohib-{uid}",
        api_key_id="key-tb-07",
        source_ip="10.20.4.15",
        endpoint="/v2/admin/export",
        method="POST",
        timestamp="2026-09-03T02:00:00Z"
    )
    res = process_event(payload, db=db_session)
    assert res["final_action"] == "BLOCK"
    assert res["execution_status"] == "REJECTED"

def test_list_and_get_event_detail(db_session):
    events = list_events(limit=10, db=db_session)
    assert len(events) > 0

    first_id = events[0]["event_id"]
    detail = get_event_detail(first_id, db=db_session)
    assert "event" in detail
    assert "final_decision" in detail
    assert "explanation" in detail["final_decision"]

def test_post_analyst_review(db_session):
    events = list_events(limit=5, db=db_session)
    first_id = events[0]["event_id"]

    sub = ReviewSubmission(
        reviewer="Alice_SOC_Analyst",
        outcome="CONFIRMED_FRAUD",
        action_taken="BLOCK_VENDOR",
        notes="Verified fraud via vendor phone callback"
    )
    res = record_review(first_id, sub, db=db_session)
    assert res["status"] == "success"
    assert res["reviewer"] == "Alice_SOC_Analyst"

def test_simulation_route(db_session):
    req = SimulationRequest(
        scenario_id="SCN-04",
        seed=42,
        num_events=5
    )
    res = run_simulation(req, db=db_session)
    assert "run_id" in res
    assert res["total_events"] == 5
    assert "comparison" in res

def test_benchmark_suite_route(db_session):
    from app.api.routes import run_benchmark, BenchmarkRequest
    req = BenchmarkRequest(seed=42, num_events=50)
    res = run_benchmark(req, db=db_session)
    assert "comparison" in res
    cmp_res = res["comparison"]
    assert "policy_only" in cmp_res
    assert "hybrid" in cmp_res
    assert "accuracy" in cmp_res["policy_only"]
    assert "false_negative_rate" in cmp_res["policy_only"]
    assert "dataset_transparency" in cmp_res

def test_dashboard_route():
    html = serve_dashboard()
    assert "TRUSTGATE" in html
    assert "SOC Analyst Dashboard" in html
