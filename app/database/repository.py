"""
Database session management and repository operations for TRUSTGATE
"""
import json
import os
import csv
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings
from app.database.models import (
    Base, IntegrationModel, EventModel, VendorChangeModel, ApprovalModel,
    PolicyDecisionModel, ModelScoreModel, FinalDecisionModel,
    AnalystReviewModel, SimulationRunModel, EvaluationResultModel
)

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    os.makedirs(os.path.dirname(settings.database_url.replace("sqlite:///", "")), exist_ok=True)
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            from sqlalchemy import text
            cols = [c[1] for c in conn.execute(text("PRAGMA table_info(evaluation_results)")).fetchall()]
            if cols and "accuracy" not in cols:
                conn.execute(text("ALTER TABLE evaluation_results ADD COLUMN accuracy FLOAT DEFAULT 0.0"))
            if cols and "false_negative_rate" not in cols:
                conn.execute(text("ALTER TABLE evaluation_results ADD COLUMN false_negative_rate FLOAT DEFAULT 0.0"))
            conn.commit()
    except Exception:
        pass
    seed_integrations()
    seed_approvals()

def seed_integrations():
    db = SessionLocal()
    try:
        if os.path.exists(settings.contracts_file):
            with open(settings.contracts_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                integrations = data.get("integrations", {})
                for key_id, details in integrations.items():
                    existing = db.query(IntegrationModel).filter(IntegrationModel.api_key_id == key_id).first()
                    if not existing:
                        record = IntegrationModel(
                            api_key_id=key_id,
                            integration_name=details.get("integration_name", key_id),
                            allowed_capabilities=json.dumps(details.get("allowed_capabilities", [])),
                            permitted_fields=json.dumps(details.get("permitted_fields", [])),
                            allowed_ips=json.dumps(details.get("allowed_ips", [])),
                            active=details.get("active", True),
                            expiry=details.get("expiry", "2099-12-31T23:59:59Z"),
                            notes=details.get("notes", "")
                        )
                        db.add(record)
                db.commit()
    finally:
        db.close()

def seed_approvals():
    db = SessionLocal()
    try:
        # Verified Finance Approval for legitimate comparison test
        existing = db.query(ApprovalModel).filter(ApprovalModel.approval_id == "FIN-APP-2026-09-441").first()
        if not existing:
            approval = ApprovalModel(
                approval_id="FIN-APP-2026-09-441",
                vendor_id="V-0220",
                field="bank_account_number",
                approver_id="FIN-LEAD-SarahChen",
                status="APPROVED",
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-09-30T23:59:59Z",
                evidence_ref="E10-SEC-04-SIGNED"
            )
            db.add(approval)
            db.commit()
    finally:
        db.close()

def seed_case_evidence(db: Session):
    """Load E18 and E19 files into database if not already loaded"""
    e18_path = os.path.join(settings.raw_data_dir, "E18_api_logs.csv")
    e19_path = os.path.join(settings.raw_data_dir, "E19_vendor_changes.csv")

    if os.path.exists(e19_path):
        with open(e19_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                change_id = row.get("change_id")
                if not db.query(VendorChangeModel).filter(VendorChangeModel.change_id == change_id).first():
                    vc = VendorChangeModel(
                        change_id=change_id,
                        timestamp=row.get("timestamp"),
                        request_id=row.get("request_id"),
                        vendor_id=row.get("vendor_id"),
                        field=row.get("field"),
                        old_value_masked=row.get("old_value_masked"),
                        new_value_masked=row.get("new_value_masked"),
                        changed_by=row.get("changed_by"),
                        approval_ref=row.get("approval_ref") or None,
                        evidence_ref="E19"
                    )
                    db.add(vc)
            db.commit()
