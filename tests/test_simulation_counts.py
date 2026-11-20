"""
Comprehensive Tests for Simulation Event Count Matching & Validation
Verifies exact counts for 5, 9, 10, 25, 50, and 100 events.
"""
import pytest
from app.database.repository import SessionLocal, init_db, seed_case_evidence
from app.api.routes import run_simulation, get_simulation_run, SimulationRequest

@pytest.fixture(scope="module")
def db_session():
    init_db()
    db = SessionLocal()
    seed_case_evidence(db)
    yield db
    db.close()

@pytest.mark.parametrize("event_count", [5, 9, 10, 25, 50, 100])
def test_simulation_event_counts_match_exactly(db_session, event_count):
    """
    Verify that for any requested count (5, 9, 10, 25, 50, 100):
    1. Exactly N events are generated
    2. Exactly N events are processed
    3. Exactly N events appear in the response payload
    4. Request IDs run sequentially from 0000 to N-1
    5. Statistics reflect N events with status COMPLETE
    6. Database telemetry query returns exactly N events
    """
    req = SimulationRequest(
        scenario_id="SCN-04",
        seed=100 + event_count,
        num_events=event_count
    )
    res = run_simulation(req, db=db_session)

    # 1. Total events check
    assert res["total_events"] == event_count, f"Expected total_events to be {event_count}, got {res['total_events']}"

    # 2. Validation Statistics
    stats = res["stats"]
    assert stats["requested_events"] == event_count
    assert stats["generated_events"] == event_count
    assert stats["processed_events"] == event_count
    assert stats["failed_events"] == 0
    assert stats["simulation_status"] == "COMPLETE"
    assert (stats["allowed_events"] + stats["held_events"] + stats["blocked_events"]) == event_count

    # 3. Telemetry events array size
    assert len(res["events"]) == event_count, f"Expected {event_count} events in 'events', got {len(res['events'])}"
    assert len(res["events_sample"]) == event_count, f"Expected {event_count} events in 'events_sample', got {len(res['events_sample'])}"

    # 4. Request IDs sequential format check (from 0000 to N-1)
    first_req_id = res["events"][0]["request_id"]
    last_req_id = res["events"][-1]["request_id"]

    expected_first_suffix = "0000"
    expected_last_suffix = f"{event_count - 1:04d}"

    assert first_req_id.endswith(expected_first_suffix), f"First request_id {first_req_id} should end with {expected_first_suffix}"
    assert last_req_id.endswith(expected_last_suffix), f"Last request_id {last_req_id} should end with {expected_last_suffix}"

    # Ensure all request IDs are unique
    all_req_ids = [e["request_id"] for e in res["events"]]
    assert len(set(all_req_ids)) == event_count, "All request IDs in batch must be unique"

    # 5. Database telemetry persistence check
    run_id = res["run_id"]
    run_detail = get_simulation_run(run_id, db=db_session)
    assert run_detail["total_events"] == event_count
    assert len(run_detail["events"]) == event_count, f"Expected {event_count} persisted events in DB, got {len(run_detail['events'])}"
