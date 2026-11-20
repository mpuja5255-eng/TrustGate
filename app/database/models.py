"""
SQLAlchemy Database Models for TRUSTGATE
"""
from datetime import datetime, timezone
import json
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, ForeignKey, Boolean
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def utcnow():
    return datetime.now(timezone.utc)

class IntegrationModel(Base):
    __tablename__ = "integrations"

    api_key_id = Column(String(64), primary_key=True)
    integration_name = Column(String(128), nullable=False)
    allowed_capabilities = Column(Text, nullable=False)  # JSON list
    permitted_fields = Column(Text, nullable=False)      # JSON list
    allowed_ips = Column(Text, nullable=False)           # JSON list of CIDRs
    active = Column(Boolean, default=True, nullable=False)
    expiry = Column(String(64), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    events = relationship("EventModel", back_populates="integration")

class EventModel(Base):
    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True)
    run_id = Column(String(64), nullable=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)  # ISO UTC
    request_id = Column(String(64), nullable=False, index=True)
    api_key_id = Column(String(64), ForeignKey("integrations.api_key_id"), nullable=False)
    source_ip = Column(String(64), nullable=False)
    endpoint = Column(String(256), nullable=False)
    method = Column(String(16), nullable=False)
    status = Column(Integer, default=200, nullable=False)
    vendor_id = Column(String(64), nullable=True, index=True)
    action_type = Column(String(64), nullable=False)
    approval_ref = Column(String(64), nullable=True)
    source_evidence = Column(Text, default="[]", nullable=False)  # JSON list e.g. ["E18"]
    created_at = Column(DateTime, default=utcnow, nullable=False)

    integration = relationship("IntegrationModel", back_populates="events")
    policy_decision = relationship("PolicyDecisionModel", back_populates="event", uselist=False)
    model_score = relationship("ModelScoreModel", back_populates="event", uselist=False)
    final_decision = relationship("FinalDecisionModel", back_populates="event", uselist=False)
    analyst_reviews = relationship("AnalystReviewModel", back_populates="event")

class VendorChangeModel(Base):
    __tablename__ = "vendor_changes"

    change_id = Column(String(64), primary_key=True)
    timestamp = Column(String(64), nullable=False)
    request_id = Column(String(64), nullable=True, index=True)
    vendor_id = Column(String(64), nullable=False, index=True)
    field = Column(String(64), nullable=False)
    old_value_masked = Column(String(128), nullable=True)
    new_value_masked = Column(String(128), nullable=False)
    changed_by = Column(String(64), nullable=False)
    approval_ref = Column(String(64), nullable=True)
    evidence_ref = Column(String(64), default="E19", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class ApprovalModel(Base):
    __tablename__ = "approvals"

    approval_id = Column(String(64), primary_key=True)
    vendor_id = Column(String(64), nullable=False, index=True)
    field = Column(String(64), nullable=False)
    approver_id = Column(String(64), nullable=False)
    status = Column(String(32), default="APPROVED", nullable=False)  # APPROVED, REVOKED, EXPIRED
    valid_from = Column(String(64), nullable=False)
    valid_until = Column(String(64), nullable=False)
    evidence_ref = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class PolicyDecisionModel(Base):
    __tablename__ = "policy_decisions"

    decision_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), unique=True, nullable=False)
    policy_version = Column(String(32), nullable=False)
    policy_result = Column(String(16), nullable=False)  # ALLOW, HOLD, BLOCK
    reason_codes = Column(Text, default="[]", nullable=False)  # JSON list
    evaluated_at = Column(DateTime, default=utcnow, nullable=False)

    event = relationship("EventModel", back_populates="policy_decision")

class ModelScoreModel(Base):
    __tablename__ = "model_scores"

    score_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), unique=True, nullable=False)
    model_version = Column(String(32), nullable=False)
    anomaly_score = Column(Float, nullable=True)          # Raw IsolationForest score
    normalized_risk_score = Column(Float, nullable=True)  # 0.0 to 1.0
    threshold = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, default=False, nullable=False)
    feature_deviations = Column(Text, default="{}", nullable=False)  # JSON map
    model_status = Column(String(32), default="AVAILABLE", nullable=False)  # AVAILABLE, DEGRADED, SKIPPED
    scored_at = Column(DateTime, default=utcnow, nullable=False)

    event = relationship("EventModel", back_populates="model_score")

class FinalDecisionModel(Base):
    __tablename__ = "final_decisions"

    decision_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), unique=True, nullable=False)
    final_action = Column(String(16), nullable=False)  # ALLOW, HOLD, BLOCK
    execution_status = Column(String(32), nullable=False)  # EXECUTED, QUEUED_IN_HOLD, REJECTED
    explanation = Column(Text, nullable=False)  # JSON 4-part structure
    created_at = Column(DateTime, default=utcnow, nullable=False)

    event = relationship("EventModel", back_populates="final_decision")

class AnalystReviewModel(Base):
    __tablename__ = "analyst_reviews"

    review_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("events.event_id"), nullable=False)
    reviewer = Column(String(64), nullable=False)
    outcome = Column(String(32), nullable=False)  # CONFIRMED_FRAUD, BENIGN_ANOMALY, ESCALATED, DISMISSED
    action_taken = Column(String(32), nullable=False)  # RELEASE_PAYMENT, REVOKE_KEY, BLOCK_VENDOR, NO_ACTION
    notes = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, default=utcnow, nullable=False)

    event = relationship("EventModel", back_populates="analyst_reviews")

class SimulationRunModel(Base):
    __tablename__ = "simulation_runs"

    run_id = Column(String(64), primary_key=True)
    scenario = Column(String(64), nullable=False)
    seed = Column(Integer, nullable=False)
    dataset_version = Column(String(32), default="v1.0", nullable=False)
    total_events = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class EvaluationResultModel(Base):
    __tablename__ = "evaluation_results"

    eval_id = Column(String(64), primary_key=True)
    run_id = Column(String(64), ForeignKey("simulation_runs.run_id"), nullable=False)
    mode = Column(String(32), nullable=False)  # POLICY_ONLY, HYBRID
    total_events = Column(Integer, nullable=False)
    tp = Column(Integer, default=0, nullable=False)
    fp = Column(Integer, default=0, nullable=False)
    tn = Column(Integer, default=0, nullable=False)
    fn = Column(Integer, default=0, nullable=False)
    accuracy = Column(Float, default=0.0, nullable=True)
    precision = Column(Float, default=0.0, nullable=False)
    recall = Column(Float, default=0.0, nullable=False)
    false_positive_rate = Column(Float, default=0.0, nullable=False)
    false_negative_rate = Column(Float, default=0.0, nullable=True)
    f1_score = Column(Float, default=0.0, nullable=False)
    missed_detections = Column(Integer, default=0, nullable=False)
    avg_latency_ms = Column(Float, default=0.0, nullable=False)
    evaluated_at = Column(DateTime, default=utcnow, nullable=False)
