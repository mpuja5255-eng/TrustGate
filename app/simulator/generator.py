"""
Reproducible Event Generator for TRUSTGATE Simulation Lab
"""
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from app.simulator.scenarios import SCENARIO_CATALOG

def generate_simulation_batch(
    scenario_id: str,
    seed: int = 42,
    num_events: int = 10,
    run_id: str = None
) -> List[Dict[str, Any]]:
    """
    Generate synthetic event package for a given scenario.
    Enforces deterministic random seed.
    Returns: List of {"run_id": ..., "scenario_id": ..., "seed": ..., "event": ..., "ground_truth": ...}
    """
    if scenario_id not in SCENARIO_CATALOG:
        scenario_id = "SCN-01"

    sc_meta = SCENARIO_CATALOG[scenario_id]
    ground_truth = sc_meta["ground_truth"]
    run_id = run_id or f"run-{uuid.uuid4().hex[:8]}"

    rng = random.Random(seed)
    results = []
    
    # Establish realistic baseline timestamps based on scenario specification
    if scenario_id in ("SCN-01", "SCN-02", "SCN-03"):
        # Standard business hours (10:15 UTC) as documented in catalog
        base_time = datetime(2026, 9, 3, 10, 15, 0, tzinfo=timezone.utc)
    elif scenario_id == "SCN-10":
        # Scheduled month-end batch run (23:00 UTC)
        base_time = datetime(2026, 8, 31, 23, 0, 0, tzinfo=timezone.utc)
    else:
        # Off-hours attacks and recon sweeps (replaying 3 Sept incident at 01:40 UTC)
        base_time = datetime(2026, 9, 3, 1, 40, 0, tzinfo=timezone.utc)

    for i in range(num_events):
        dt = base_time + timedelta(seconds=i * 25)
        ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        req_id = f"sim-req-{seed}-{scenario_id}-{i:04d}"
        ev_id = f"evt-{run_id}-{i:04d}"

        if scenario_id == "SCN-01":
            # Normal Contact Update
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-ops-01",
                "source_ip": "10.20.10.15",
                "endpoint": f"/v2/vendors/V-0{rng.randint(100, 500)}/contacts",
                "method": "PATCH",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": f"V-0{rng.randint(100, 500)}",
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-02":
            # Normal Invoice Lookup
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.15",
                "endpoint": f"/v2/invoices/INV-{rng.randint(1000, 9999)}",
                "method": "GET",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": f"V-0{rng.randint(100, 500)}",
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-03":
            # Approved Bank Update
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.15",
                "endpoint": "/v2/vendors/V-0220/bank-details",
                "method": "PATCH",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": "V-0220",
                "approval_ref": "FIN-APP-2026-09-441",  # Verified in database
                "run_id": run_id
            }

        elif scenario_id == "SCN-04":
            # E18 / E19 Incident Replay: Bank update with NO approval
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.77",
                "endpoint": "/v2/vendors/V-0412/bank-details",
                "method": "PATCH",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": "V-0412",
                "approval_ref": None,  # Missing approval!
                "run_id": run_id
            }

        elif scenario_id == "SCN-05":
            # Prohibited Endpoint
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.15",
                "endpoint": "/v2/admin/export",
                "method": "POST",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": None,
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-06":
            # Unregistered Source Host Burst
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "198.51.100.88",  # External internet IP!
                "endpoint": f"/v2/vendors/V-0{rng.randint(100, 500)}",
                "method": "GET",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": f"V-0{rng.randint(100, 500)}",
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-07":
            # Rapid Reconnaissance Sequence (Vendor -> Bank -> Payments -> Update)
            seq_step = i % 4
            v_id = "V-0412"
            if seq_step == 0:
                endpoint = f"/v2/vendors/{v_id}"
                method = "GET"
            elif seq_step == 1:
                endpoint = f"/v2/vendors/{v_id}/bank-details"
                method = "GET"
            elif seq_step == 2:
                endpoint = f"/v2/vendors/{v_id}/scheduled-payments"
                method = "GET"
            else:
                endpoint = f"/v2/vendors/{v_id}/bank-details"
                method = "PATCH"

            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.77",
                "endpoint": endpoint,
                "method": method,
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": v_id,
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-08":
            # Replayed Request Nonce: Sequential request IDs, with replayed approval token / duplicate nonce flag
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.15",
                "endpoint": "/v2/vendors/V-0100",
                "method": "GET",
                "status": 200,
                "timestamp": "2026-09-03T01:44:30Z",
                "vendor_id": "V-0100",
                "approval_ref": "REPLAY-TOKEN-EXPIRED",
                "run_id": run_id
            }

        elif scenario_id == "SCN-09":
            # Malformed Event Payload
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "",  # Empty key
                "source_ip": "invalid-ip-string",
                "endpoint": "/v2/broken",
                "method": "BAD_VERB",
                "status": 200,
                "timestamp": "invalid-timestamp",
                "vendor_id": None,
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-10":
            # Legitimate Month-End Batch Job
            dt_batch = datetime(2026, 8, 31, 23, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=i * 2)
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-finance-02",
                "source_ip": "10.30.1.20",
                "endpoint": f"/v2/invoices/INV-{1000 + i}",
                "method": "GET",
                "status": 200,
                "timestamp": dt_batch.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "vendor_id": f"V-0{rng.randint(100, 500)}",
                "approval_ref": None,
                "run_id": run_id
            }

        elif scenario_id == "SCN-11":
            # Approval Service Timeout / Failure simulation
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-tb-07",
                "source_ip": "10.20.4.15",
                "endpoint": "/v2/vendors/V-0412/bank-details",
                "method": "PATCH",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": "V-0412",
                "approval_ref": "FIN-APP-TIMEOUT-FAIL",  # Invalid/timeout ref
                "run_id": run_id
            }

        else:  # SCN-12 ML Service Degraded
            ev = {
                "event_id": ev_id,
                "request_id": req_id,
                "api_key_id": "key-ops-01",
                "source_ip": "10.20.10.15",
                "endpoint": "/v2/vendors/V-0100/contacts",
                "method": "PATCH",
                "status": 200,
                "timestamp": ts_str,
                "vendor_id": "V-0100",
                "approval_ref": None,
                "run_id": run_id
            }

        results.append({
            "run_id": run_id,
            "scenario_id": scenario_id,
            "seed": seed,
            "event": ev,
            "ground_truth": ground_truth
        })

    return results

def generate_benchmark_suite(
    seed: int = 42,
    total_events: int = 100,
    run_id: str = None
) -> List[Dict[str, Any]]:
    """
    Generate a balanced multi-scenario evaluation test stream for scientific model comparison.
    Contains both legitimate enterprise operations (60%) and realistic attack patterns (40%).
    Both Model A (Policy-Only) and Model B (Hybrid) are evaluated against this exact same dataset.
    """
    run_id = run_id or f"bench-{uuid.uuid4().hex[:8]}"

    n1 = max(1, int(total_events * 0.20))
    n2 = max(1, int(total_events * 0.20))
    n3 = max(1, int(total_events * 0.10))
    n10 = max(1, int(total_events * 0.10))
    n4 = max(1, int(total_events * 0.10))
    n5 = max(1, int(total_events * 0.10))
    n6 = max(1, int(total_events * 0.10))
    allocated = n1 + n2 + n3 + n10 + n4 + n5 + n6
    n7 = max(1, total_events - allocated)

    suite = []
    suite.extend(generate_simulation_batch("SCN-01", seed=seed, num_events=n1, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-02", seed=seed + 1, num_events=n2, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-03", seed=seed + 2, num_events=n3, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-10", seed=seed + 3, num_events=n10, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-04", seed=seed + 4, num_events=n4, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-05", seed=seed + 5, num_events=n5, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-06", seed=seed + 6, num_events=n6, run_id=run_id))
    suite.extend(generate_simulation_batch("SCN-07", seed=seed + 7, num_events=n7, run_id=run_id))

    # Sort chronologically by timestamp so real-world rolling sequence detection operates faithfully
    suite.sort(key=lambda x: x["event"]["timestamp"])

    for idx, item in enumerate(suite):
        item["event"]["request_id"] = f"bench-req-{seed}-{idx:04d}"

    return suite
