"""
REST API Routes for TRUSTGATE Backend
"""
import json
import uuid
import time
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.repository import get_db
from app.database.models import (
    EventModel, PolicyDecisionModel, ModelScoreModel, FinalDecisionModel,
    AnalystReviewModel, SimulationRunModel, EvaluationResultModel, VendorChangeModel
)
from app.ingestion.validator import RawEventPayload
from app.ingestion.normalizer import normalize_event
from app.correlation.vendor_change_matcher import correlate_event_with_vendor_change
from app.policy.engine import PolicyEngine
from app.ml.predict import RiskPredictor
from app.ml.model_manager import ModelManager
from app.decisions.coordinator import DecisionCoordinator
from app.explainability.explanations import build_structured_explanation
from app.simulator.generator import generate_simulation_batch, generate_benchmark_suite
from app.simulator.scenarios import SCENARIO_CATALOG
from app.evaluation.comparison import ModeComparator

router = APIRouter()

policy_engine = PolicyEngine()
risk_predictor = RiskPredictor()

class ReviewSubmission(BaseModel):
    reviewer: str = Field(..., min_length=2)
    outcome: str = Field(..., description="CONFIRMED_FRAUD, BENIGN_ANOMALY, ESCALATED, DISMISSED")
    action_taken: str = Field(..., description="RELEASE_PAYMENT, REVOKE_KEY, BLOCK_VENDOR, NO_ACTION")
    notes: Optional[str] = None

class SimulationRequest(BaseModel):
    scenario_id: str = Field(default="SCN-04", description="Scenario ID from catalog (e.g. SCN-01 to SCN-12 or BENCHMARK_SUITE)")
    seed: int = Field(default=42, description="Random seed for reproducible run")
    num_events: int = Field(default=10, ge=1, le=500, description="Number of events to generate")

class BenchmarkRequest(BaseModel):
    seed: int = Field(default=42, description="Random seed for reproducible benchmark")
    num_events: int = Field(default=100, ge=10, le=500, description="Total events in benchmark suite")

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TRUSTGATE",
        "mode": "simulation",
        "timestamp": time.time()
    }

@router.get("/model/status")
def get_model_status():
    mgr = ModelManager.get_instance()
    return mgr.get_status()

@router.post("/events")
def process_event(payload: RawEventPayload, db: Session = Depends(get_db)):
    """
    Ingest, validate, correlate, evaluate policy, score behavioral risk,
    coordinate decision, generate explanation, and persist audit record.
    """
    raw_dict = payload.model_dump()

    # 1. Check idempotency / replay of existing request_id
    if payload.run_id:
        existing_event = db.query(EventModel).filter(
            EventModel.request_id == payload.request_id,
            EventModel.run_id == payload.run_id
        ).first()
    else:
        existing_event = db.query(EventModel).filter(EventModel.request_id == payload.request_id).first()
    is_replay = existing_event is not None

    # 2. Normalize Event
    allowed_cidrs = ["10.20.4.0/24", "10.20.10.0/24", "10.30.1.0/24"]
    norm = normalize_event(raw_dict, allowed_cidrs=allowed_cidrs)

    # 3. Correlate with Vendor Master Change (E19)
    correlation = correlate_event_with_vendor_change(
        request_id=norm["request_id"],
        vendor_id=norm.get("vendor_id"),
        db=db
    )

    # If correlated vendor change has an approval_ref, and event has none, enrich for evaluation
    if not norm.get("approval_ref") and correlation.is_correlated and correlation.vendor_change:
        norm["approval_ref"] = correlation.vendor_change.get("approval_ref")

    # 4. Evaluate Policy Engine
    pol_res = policy_engine.evaluate(norm, db)
    if is_replay:
        pol_res.result = "BLOCK"
        pol_res.reason_codes.append("REPLAY_NONCE_DETECTED")
        pol_res.policy_findings.append(f"Request ID '{payload.request_id}' has already been processed (duplicate nonce).")

    # 5. Score Behavioral ML Model
    ml_res = risk_predictor.predict(norm)

    # 6. Coordinate Final Decision
    coord_res = DecisionCoordinator.coordinate(pol_res, ml_res, norm)

    # 7. Generate 4-part Structured Explanation
    explanation = build_structured_explanation(norm, pol_res, ml_res, coord_res, correlation)

    # 8. Persist to Database
    # Insert or update event
    event_rec = EventModel(
        event_id=norm["event_id"],
        run_id=norm.get("run_id"),
        timestamp=norm["timestamp"],
        request_id=norm["request_id"],
        api_key_id=norm["api_key_id"],
        source_ip=norm["source_ip"],
        endpoint=norm["endpoint"],
        method=norm["method"],
        status=norm["status"],
        vendor_id=norm.get("vendor_id"),
        action_type=norm["action_type"],
        approval_ref=norm.get("approval_ref"),
        source_evidence=json.dumps(norm.get("source_evidence", []))
    )
    db.merge(event_rec)

    # Persist Policy Decision
    pol_rec = PolicyDecisionModel(
        decision_id=f"pol-{uuid.uuid4().hex[:8]}",
        event_id=norm["event_id"],
        policy_version=pol_res.policy_version,
        policy_result=pol_res.result,
        reason_codes=json.dumps(pol_res.reason_codes)
    )
    db.merge(pol_rec)

    # Persist Model Score
    ml_rec = ModelScoreModel(
        score_id=f"ml-{uuid.uuid4().hex[:8]}",
        event_id=norm["event_id"],
        model_version=ml_res.model_version,
        anomaly_score=ml_res.anomaly_score,
        normalized_risk_score=ml_res.normalized_risk_score,
        threshold=ml_res.threshold,
        is_anomaly=ml_res.is_anomaly,
        feature_deviations=json.dumps(ml_res.feature_deviations),
        model_status=ml_res.model_status
    )
    db.merge(ml_rec)

    # Persist Final Decision
    dec_rec = FinalDecisionModel(
        decision_id=f"dec-{uuid.uuid4().hex[:8]}",
        event_id=norm["event_id"],
        final_action=coord_res.final_action,
        execution_status=coord_res.execution_status,
        explanation=json.dumps(explanation)
    )
    db.merge(dec_rec)

    db.commit()

    return {
        "event_id": norm["event_id"],
        "request_id": norm["request_id"],
        "timestamp": norm["timestamp"],
        "method": norm["method"],
        "endpoint": norm["endpoint"],
        "vendor_id": norm.get("vendor_id"),
        "action_type": norm.get("action_type"),
        "policy": {
            "result": pol_res.result,
            "reason_codes": pol_res.reason_codes
        },
        "ml": {
            "status": ml_res.model_status,
            "model_version": ml_res.model_version,
            "anomaly_score": ml_res.anomaly_score,
            "normalized_risk_score": ml_res.normalized_risk_score,
            "is_anomaly": ml_res.is_anomaly
        },
        "final_action": coord_res.final_action,
        "execution_status": coord_res.execution_status,
        "primary_reason": coord_res.primary_reason,
        "explanation": explanation
    }

@router.get("/events")
def list_events(
    limit: int = 50,
    action: Optional[str] = None,
    api_key_id: Optional[str] = None,
    vendor_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(EventModel, FinalDecisionModel, ModelScoreModel)\
        .outerjoin(FinalDecisionModel, EventModel.event_id == FinalDecisionModel.event_id)\
        .outerjoin(ModelScoreModel, EventModel.event_id == ModelScoreModel.event_id)

    if api_key_id:
        query = query.filter(EventModel.api_key_id == api_key_id)
    if vendor_id:
        query = query.filter(EventModel.vendor_id == vendor_id)
    if action:
        query = query.filter(FinalDecisionModel.final_action == action.upper())

    results = query.order_by(EventModel.created_at.desc()).limit(limit).all()

    items = []
    for ev, dec, ml in results:
        items.append({
            "event_id": ev.event_id,
            "timestamp": ev.timestamp,
            "request_id": ev.request_id,
            "api_key_id": ev.api_key_id,
            "source_ip": ev.source_ip,
            "endpoint": ev.endpoint,
            "method": ev.method,
            "vendor_id": ev.vendor_id,
            "action_type": ev.action_type,
            "approval_ref": ev.approval_ref,
            "final_action": dec.final_action if dec else "PENDING",
            "execution_status": dec.execution_status if dec else "PENDING",
            "risk_score": ml.normalized_risk_score if ml else None,
            "is_anomaly": ml.is_anomaly if ml else False
        })
    return items

@router.get("/events/{event_id}")
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    event = db.query(EventModel).filter(EventModel.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    dec = db.query(FinalDecisionModel).filter(FinalDecisionModel.event_id == event_id).first()
    pol = db.query(PolicyDecisionModel).filter(PolicyDecisionModel.event_id == event_id).first()
    ml = db.query(ModelScoreModel).filter(ModelScoreModel.event_id == event_id).first()
    reviews = db.query(AnalystReviewModel).filter(AnalystReviewModel.event_id == event_id).all()
    vchange = db.query(VendorChangeModel).filter(VendorChangeModel.request_id == event.request_id).first()

    return {
        "event": {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "request_id": event.request_id,
            "api_key_id": event.api_key_id,
            "source_ip": event.source_ip,
            "endpoint": event.endpoint,
            "method": event.method,
            "status": event.status,
            "vendor_id": event.vendor_id,
            "action_type": event.action_type,
            "approval_ref": event.approval_ref,
            "source_evidence": json.loads(event.source_evidence)
        },
        "vendor_change": {
            "change_id": vchange.change_id,
            "field": vchange.field,
            "old_value_masked": vchange.old_value_masked,
            "new_value_masked": vchange.new_value_masked,
            "changed_by": vchange.changed_by,
            "approval_ref": vchange.approval_ref
        } if vchange else None,
        "policy_decision": {
            "policy_version": pol.policy_version,
            "policy_result": pol.policy_result,
            "reason_codes": json.loads(pol.reason_codes)
        } if pol else None,
        "model_score": {
            "model_version": ml.model_version,
            "anomaly_score": ml.anomaly_score,
            "normalized_risk_score": ml.normalized_risk_score,
            "threshold": ml.threshold,
            "is_anomaly": ml.is_anomaly,
            "feature_deviations": json.loads(ml.feature_deviations),
            "model_status": ml.model_status
        } if ml else None,
        "final_decision": {
            "final_action": dec.final_action,
            "execution_status": dec.execution_status,
            "explanation": json.loads(dec.explanation) if dec else None
        } if dec else None,
        "reviews": [
            {
                "review_id": r.review_id,
                "reviewer": r.reviewer,
                "outcome": r.outcome,
                "action_taken": r.action_taken,
                "notes": r.notes,
                "reviewed_at": r.reviewed_at.isoformat()
            } for r in reviews
        ]
    }

@router.get("/decisions/{decision_id}")
def get_decision(decision_id: str, db: Session = Depends(get_db)):
    dec = db.query(FinalDecisionModel).filter(FinalDecisionModel.decision_id == decision_id).first()
    if not dec:
        raise HTTPException(status_code=404, detail="Decision not found")
    return {
        "decision_id": dec.decision_id,
        "event_id": dec.event_id,
        "final_action": dec.final_action,
        "execution_status": dec.execution_status,
        "explanation": json.loads(dec.explanation)
    }

@router.post("/simulate")
def run_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    """
    Generate and execute a batch of simulated events for a scenario.
    Records simulation run and benchmarks policy vs. hybrid decisions.
    """
    run_id = f"sim-{req.scenario_id.lower()}-{uuid.uuid4().hex[:6]}"
    if req.scenario_id == "BENCHMARK_SUITE":
        batch = generate_benchmark_suite(
            seed=req.seed,
            total_events=req.num_events,
            run_id=run_id
        )
        scenario_meta = {
            "id": "BENCHMARK_SUITE",
            "name": "Standardized Multi-Scenario Benchmark Suite",
            "description": "Balanced cross-scenario benchmark (60% legitimate, 40% attack/anomaly) evaluating Model A vs. Model B on identical data streams.",
            "scenario_type": "scientific_benchmark"
        }
    else:
        batch = generate_simulation_batch(
            scenario_id=req.scenario_id,
            seed=req.seed,
            num_events=req.num_events,
            run_id=run_id
        )
        scenario_meta = SCENARIO_CATALOG.get(req.scenario_id, {})

    # Record simulation run
    sim_run = SimulationRunModel(
        run_id=run_id,
        scenario=req.scenario_id,
        seed=req.seed,
        total_events=len(batch)
    )
    db.add(sim_run)
    db.commit()

    # Process all events through pipeline
    processed_results = []
    failed_events_count = 0

    for item in batch:
        raw_event = item["event"]
        try:
            payload = RawEventPayload(**raw_event)
            res = process_event(payload, db=db)
            res["ground_truth"] = item["ground_truth"]
            processed_results.append(res)
        except Exception as ex:
            failed_events_count += 1
            # Capture malformed/invalid event gracefully without crashing batch
            processed_results.append({
                "event_id": raw_event.get("event_id") or f"err-{uuid.uuid4().hex[:8]}",
                "request_id": raw_event.get("request_id", "unknown"),
                "timestamp": raw_event.get("timestamp", ""),
                "method": raw_event.get("method", "INVALID"),
                "endpoint": raw_event.get("endpoint", "/invalid"),
                "vendor_id": raw_event.get("vendor_id"),
                "policy": {
                    "result": "INVALID",
                    "reason_codes": ["MALFORMED_PAYLOAD_SCHEMA_ERROR"]
                },
                "ml": {
                    "status": "SKIPPED",
                    "model_version": "N/A",
                    "anomaly_score": None,
                    "normalized_risk_score": None,
                    "is_anomaly": False
                },
                "final_action": "INVALID",
                "execution_status": "REJECTED",
                "primary_reason": f"SCHEMA_VALIDATION_ERROR: {str(ex)}",
                "explanation": {
                    "observed_facts": [f"Malformed payload rejected: {str(ex)}"],
                    "policy_findings": ["SCHEMA_VALIDATION_FAILED"],
                    "ml_behavioral_findings": [],
                    "actionable_inferences": ["Event rejected at ingestion boundary."]
                },
                "ground_truth": item.get("ground_truth", "INVALID")
            })

    # Run evaluation comparison
    comparator = ModeComparator(db)
    comparison = comparator.run_comparison(batch, run_id=run_id)

    # Event count validation statistics
    requested_events = req.num_events
    generated_events = len(batch)
    processed_events = len(processed_results)
    allowed_events = sum(1 for r in processed_results if r.get("final_action") == "ALLOW")
    held_events = sum(1 for r in processed_results if r.get("final_action") == "HOLD")
    blocked_events = sum(1 for r in processed_results if r.get("final_action") in ("BLOCK", "INVALID"))
    failed_events = failed_events_count

    if processed_events == requested_events and failed_events == 0:
        sim_status = "COMPLETE"
        status_msg = f"All {requested_events} requested events successfully generated, processed, and evaluated."
    elif processed_events > 0:
        sim_status = "PARTIAL"
        status_msg = f"Processed {processed_events} of {requested_events} events ({failed_events} failed validation)."
    else:
        sim_status = "FAILED"
        status_msg = "Simulation failed to process any events."

    stats = {
        "requested_events": requested_events,
        "generated_events": generated_events,
        "processed_events": processed_events,
        "allowed_events": allowed_events,
        "held_events": held_events,
        "blocked_events": blocked_events,
        "failed_events": failed_events,
        "simulation_status": sim_status,
        "status_message": status_msg
    }

    return {
        "run_id": run_id,
        "scenario": scenario_meta,
        "total_events": len(batch),
        "stats": stats,
        "comparison": comparison,
        "events": processed_results,
        "events_sample": processed_results  # Backward-compatible alias with all events
    }

@router.post("/benchmark")
def run_benchmark(req: BenchmarkRequest = BenchmarkRequest(), db: Session = Depends(get_db)):
    """
    Run scientifically rigorous comparative benchmark of Model A (Policy-Only)
    vs Model B (Hybrid Architecture) on identical balanced test streams.
    """
    sim_req = SimulationRequest(
        scenario_id="BENCHMARK_SUITE",
        seed=req.seed,
        num_events=req.num_events
    )
    return run_simulation(sim_req, db=db)

@router.get("/simulate/{run_id}")
def get_simulation_run(run_id: str, db: Session = Depends(get_db)):
    sim_run = db.query(SimulationRunModel).filter(SimulationRunModel.run_id == run_id).first()
    if not sim_run:
        raise HTTPException(status_code=404, detail="Simulation run not found")

    events = db.query(EventModel, FinalDecisionModel)\
        .outerjoin(FinalDecisionModel, EventModel.event_id == FinalDecisionModel.event_id)\
        .filter(EventModel.run_id == run_id)\
        .order_by(EventModel.timestamp.asc()).all()

    evals = db.query(EvaluationResultModel).filter(EvaluationResultModel.run_id == run_id).all()

    return {
        "run_id": sim_run.run_id,
        "scenario": sim_run.scenario,
        "seed": sim_run.seed,
        "total_events": sim_run.total_events,
        "evaluations": [
            {
                "mode": e.mode,
                "precision": e.precision,
                "recall": e.recall,
                "false_positive_rate": e.false_positive_rate,
                "f1_score": e.f1_score,
                "avg_latency_ms": e.avg_latency_ms
            } for e in evals
        ],
        "events": [
            {
                "event_id": ev.event_id,
                "request_id": ev.request_id,
                "timestamp": ev.timestamp,
                "endpoint": ev.endpoint,
                "method": ev.method,
                "final_action": dec.final_action if dec else "UNKNOWN"
            } for ev, dec in events
        ]
    }

@router.get("/evaluate/{run_id}")
def get_evaluation(run_id: str, db: Session = Depends(get_db)):
    evals = db.query(EvaluationResultModel).filter(EvaluationResultModel.run_id == run_id).all()
    if not evals:
        raise HTTPException(status_code=404, detail="No evaluation results found for run")

    res = {}
    for e in evals:
        res[e.mode] = {
            "precision": e.precision,
            "recall": e.recall,
            "false_positive_rate": e.false_positive_rate,
            "f1_score": e.f1_score,
            "tp": e.tp,
            "fp": e.fp,
            "tn": e.tn,
            "fn": e.fn,
            "avg_latency_ms": e.avg_latency_ms
        }
    return res

@router.post("/reviews/{event_id}")
def record_review(event_id: str, sub: ReviewSubmission, db: Session = Depends(get_db)):
    event = db.query(EventModel).filter(EventModel.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    rev = AnalystReviewModel(
        review_id=f"rev-{uuid.uuid4().hex[:8]}",
        event_id=event_id,
        reviewer=sub.reviewer,
        outcome=sub.outcome,
        action_taken=sub.action_taken,
        notes=sub.notes
    )
    db.add(rev)
    db.commit()

    return {
        "status": "success",
        "review_id": rev.review_id,
        "event_id": event_id,
        "reviewer": rev.reviewer,
        "outcome": rev.outcome
    }
