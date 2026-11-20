"""
TRUSTGATE End-to-End Demonstration Script
Executes:
1. Evidence loading and E18/E19 correlation for the 3 September incident
2. Decision coordination and 4-tier structured explanation
3. Policy-Only vs. Hybrid comparative evaluation benchmark
"""
import sys
import os
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.database.repository import init_db, SessionLocal, seed_case_evidence
from app.api.routes import process_event, RawEventPayload, run_simulation, SimulationRequest

def run_demo():
    print("=" * 70)
    print("🛡️  TRUSTGATE DEFENSIVE GATEWAY — END-TO-END DEMO")
    print("=" * 70)

    # 1. Initialize
    init_db()
    db = SessionLocal()
    seed_case_evidence(db)

    # 2. Replay E18/E19 Suspicious Incident (3 September 2026 01:44:30 UTC)
    print("\n[Step 1] Ingesting Suspicious E18 Transaction (Bank Update with No Approval)...")
    e18_incident = RawEventPayload(
        request_id="req-5f61b0de8",
        api_key_id="key-tb-07",
        source_ip="10.20.4.77",
        endpoint="/v2/vendors/V-0412/bank-details",
        method="PATCH",
        status=200,
        timestamp="2026-09-03T01:44:30Z",
        vendor_id="V-0412"
    )

    decision_res = process_event(e18_incident, db=db)

    print(f"-> Decision Reached: [{decision_res['final_action']}]")
    print(f"-> Execution Status: {decision_res['execution_status']}")
    print(f"-> Primary Reason:   {decision_res['primary_reason']}")
    print(f"-> Policy Verdict:   {decision_res['policy']['result']} ({decision_res['policy']['reason_codes']})")
    print(f"-> ML Anomaly Score: {decision_res['ml']['normalized_risk_score']:.2f} (Anomaly Flag: {decision_res['ml']['is_anomaly']})")

    # 3. Print 4-Tier Explanation
    exp = decision_res["explanation"]
    print("\n[Step 2] 4-Tier Structured Explainability Breakdown:")
    print("\n--- 1. Observed Facts (Evidence) ---")
    for f in exp["observed_facts"]:
        print(f"  • {f}")

    print("\n--- 2. Policy Findings (Deterministic) ---")
    for p in exp["policy_findings"]:
        print(f"  • {p}")

    print("\n--- 3. Behavioral Findings (Isolation Forest) ---")
    for m in exp["ml_behavioral_findings"]:
        print(f"  • {m}")

    print("\n--- 4. Actionable Inference (Triage) ---")
    for a in exp["actionable_inferences"]:
        print(f"  • {a}")

    # 4. Run Policy-Only vs. Hybrid Comparison Benchmark
    print("\n" + "=" * 70)
    print("[Step 3] Running Policy-Only vs. Hybrid Comparative Benchmark...")
    print("=" * 70)
    sim_req = SimulationRequest(
        scenario_id="SCN-07",  # Rapid reconnaissance sequence
        seed=42,
        num_events=20
    )
    sim_res = run_simulation(sim_req, db=db)
    cmp_res = sim_res["comparison"]

    pol_only = cmp_res["policy_only"]
    hybrid = cmp_res["hybrid"]
    delta = cmp_res["delta_analysis"]

    print(f"\n{ 'Metric':<22} | {'Mode A (Policy-Only)':<22} | {'Mode B (Hybrid)':<22}")
    print("-" * 70)
    print(f"{ 'Recall (Detection)':<22} | {pol_only['recall']*100:<20.1f}% | {hybrid['recall']*100:<20.1f}%")
    print(f"{ 'Precision':<22} | {pol_only['precision']*100:<20.1f}% | {hybrid['precision']*100:<20.1f}%")
    print(f"{ 'False Positive Rate':<22} | {pol_only['false_positive_rate']*100:<20.1f}% | {hybrid['false_positive_rate']*100:<20.1f}%")
    print(f"{ 'F1-Score':<22} | {pol_only['f1_score']:<20.3f} | {hybrid['f1_score']:<20.3f}")
    print(f"{ 'Missed Detections':<22} | {pol_only['missed_detections']:<22} | {hybrid['missed_detections']:<22}")
    print(f"{ 'Avg Decision Latency':<22} | {pol_only['avg_latency_ms']:<19.2f} ms | {hybrid['avg_latency_ms']:<19.2f} ms")
    print("-" * 70)
    print(f"Differential Verdict: {delta['verdict']}")

    db.close()
    print("\nDemo completed successfully!")

if __name__ == "__main__":
    run_demo()
