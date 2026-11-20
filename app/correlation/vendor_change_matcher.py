"""
Vendor Master Change Correlator for TRUSTGATE
Correlates incoming API requests (e.g. E18) with Vendor Master change records (e.g. E19)
via request_id.
"""
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import VendorChangeModel

class CorrelationResult:
    def __init__(
        self,
        is_correlated: bool,
        vendor_change: Optional[Dict[str, Any]] = None,
        notes: str = "",
        discrepancy: bool = False
    ):
        self.is_correlated = is_correlated
        self.vendor_change = vendor_change
        self.notes = notes
        self.discrepancy = discrepancy

    def to_dict(self):
        return {
            "is_correlated": self.is_correlated,
            "vendor_change": self.vendor_change,
            "notes": self.notes,
            "discrepancy": self.discrepancy
        }

def correlate_event_with_vendor_change(
    request_id: str,
    vendor_id: Optional[str],
    db: Session
) -> CorrelationResult:
    """
    Search for vendor_change row with matching request_id.
    Validates whether the vendor_id aligns with the change record.
    """
    if not request_id:
        return CorrelationResult(is_correlated=False, notes="No request_id provided for correlation")

    record = db.query(VendorChangeModel).filter(VendorChangeModel.request_id == request_id).first()
    if not record:
        return CorrelationResult(is_correlated=False, notes=f"No vendor change record found matching request_id '{request_id}'")

    change_data = {
        "change_id": record.change_id,
        "timestamp": record.timestamp,
        "request_id": record.request_id,
        "vendor_id": record.vendor_id,
        "field": record.field,
        "old_value_masked": record.old_value_masked,
        "new_value_masked": record.new_value_masked,
        "changed_by": record.changed_by,
        "approval_ref": record.approval_ref,
        "evidence_ref": record.evidence_ref
    }

    # Verify if target vendor matches
    discrepancy = False
    notes = f"Correlated with {record.evidence_ref} change record {record.change_id} for field '{record.field}'"
    if vendor_id and record.vendor_id and vendor_id != record.vendor_id:
        discrepancy = True
        notes += f" [WARNING: Vendor mismatch - API vendor '{vendor_id}' vs Change record vendor '{record.vendor_id}']"

    return CorrelationResult(
        is_correlated=True,
        vendor_change=change_data,
        notes=notes,
        discrepancy=discrepancy
    )
