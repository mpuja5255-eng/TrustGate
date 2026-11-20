"""
Event Parser for CSV logs and batch payloads
"""
import csv
from typing import List, Dict, Any
from app.ingestion.normalizer import normalize_event

def parse_e18_csv(csv_path: str) -> List[Dict[str, Any]]:
    """Parse E18 API logs and return list of normalized event dictionaries"""
    events = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_event = {
                "event_id": row.get("event_id"),
                "timestamp": row.get("timestamp"),
                "request_id": row.get("request_id"),
                "api_key_id": row.get("api_key_id"),
                "source_ip": row.get("source_ip"),
                "endpoint": row.get("endpoint"),
                "method": row.get("method"),
                "status": int(row.get("status", 200)),
                "vendor_id": row.get("vendor_id") or None,
                "source_evidence": ["E18"]
            }
            normalized = normalize_event(raw_event, allowed_cidrs=["10.20.4.0/24", "10.20.10.0/24", "10.30.1.0/24"])
            events.append(normalized)
    return events
