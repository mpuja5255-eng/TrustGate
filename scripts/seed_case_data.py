"""
Generate synthetic case evidence files reflecting the SENTINEL-X investigation.
Files produced:
- data/raw/E04_connected_software.csv
- data/raw/E10_policy_requirements.json
- data/raw/E15_network_flows.csv
- data/raw/E18_api_logs.csv
- data/raw/E19_vendor_changes.csv
"""
import csv
import json
import os
from datetime import datetime, timezone

def generate_case_data(base_dir="."):
    raw_dir = os.path.join(base_dir, "data", "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # 1. E04 Connected Software Register
    e04_path = os.path.join(raw_dir, "E04_connected_software.csv")
    with open(e04_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["api_key_id", "software_name", "vendor_owner", "scopes", "allowed_cidrs", "status", "created_date"])
        writer.writerow(["key-tb-07", "Third-Party ERP Sync Gateway", "TechBridge Solutions", "read:vendors,read:invoices,read:payments,write:contacts,write:vendors", "10.20.4.0/24", "ACTIVE", "2025-01-15"])
        writer.writerow(["key-ops-01", "Vendor Contact Self-Service", "Internal Ops", "read:vendors,write:contacts", "10.20.10.0/24", "ACTIVE", "2025-03-20"])
        writer.writerow(["key-finance-02", "Reconciliation Engine", "Internal Finance", "read:vendors,read:invoices,write:payments", "10.30.1.0/24", "ACTIVE", "2025-02-10"])

    # 2. E10 Policy Requirements
    e10_path = os.path.join(raw_dir, "E10_policy_requirements.json")
    with open(e10_path, "w", encoding="utf-8") as f:
        json.dump({
            "policy_id": "POL-2026-FIN-001",
            "title": "Mandatory Controls for Electronic Bank Account Updates",
            "effective_date": "2026-01-01",
            "rules": [
                {
                    "rule_id": "E10-SEC-01",
                    "description": "Integration clients must operate within approved CIDR ranges specified in E04."
                },
                {
                    "rule_id": "E10-SEC-04",
                    "description": "Any modification to vendor bank account numbers requires verified independent Finance approval before execution."
                },
                {
                    "rule_id": "E10-SEC-09",
                    "description": "API mutations targeting administrative or batch payment execution endpoints are strictly prohibited."
                }
            ]
        }, f, indent=2)

    # 3. E15 Network Flow Context
    e15_path = os.path.join(raw_dir, "E15_network_flows.csv")
    with open(e15_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "bytes", "host_label"])
        writer.writerow(["2026-09-03T01:40:00Z", "10.20.4.77", "10.100.1.50", "443", "TCP", "1420", "erp-sync-worker-01 (unverified)"])
        writer.writerow(["2026-09-03T01:44:30Z", "10.20.4.77", "10.100.1.50", "443", "TCP", "4820", "erp-sync-worker-01 (unverified)"])
        writer.writerow(["2026-09-03T01:46:12Z", "10.20.4.77", "198.51.100.22", "8080", "TCP", "125000", "external-relay (unverified)"])

    # 4. E18 API Logs (1–7 September 2026)
    e18_path = os.path.join(raw_dir, "E18_api_logs.csv")
    with open(e18_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["event_id", "timestamp", "request_id", "api_key_id", "source_ip", "endpoint", "method", "status", "vendor_id"])
        
        # Day 1-2 Normal Activity
        writer.writerow(["evt-001", "2026-09-01T09:12:00Z", "req-101", "key-ops-01", "10.20.10.15", "/v2/vendors/V-0100", "GET", 200, "V-0100"])
        writer.writerow(["evt-002", "2026-09-01T10:15:30Z", "req-102", "key-ops-01", "10.20.10.15", "/v2/vendors/V-0100/contacts", "PATCH", 200, "V-0100"])
        writer.writerow(["evt-003", "2026-09-02T14:22:10Z", "req-103", "key-tb-07", "10.20.4.12", "/v2/vendors/V-0220", "GET", 200, "V-0220"])
        writer.writerow(["evt-004", "2026-09-02T14:25:00Z", "req-104", "key-tb-07", "10.20.4.12", "/v2/invoices/INV-9092", "GET", 200, "V-0220"])
        
        # Day 3: The Suspicious Incident (Off-hours, recon sequence, bank update)
        # 01:42 - Recon 1
        writer.writerow(["evt-e18-0903-0142", "2026-09-03T01:42:10Z", "req-5f61b0de1", "key-tb-07", "10.20.4.77", "/v2/vendors/V-0412", "GET", 200, "V-0412"])
        # 01:43 - Recon 2
        writer.writerow(["evt-e18-0903-0143", "2026-09-03T01:43:05Z", "req-5f61b0de4", "key-tb-07", "10.20.4.77", "/v2/vendors/V-0412/bank-details", "GET", 200, "V-0412"])
        # 01:43:40 - Recon 3
        writer.writerow(["evt-e18-0903-0143b", "2026-09-03T01:43:40Z", "req-5f61b0de6", "key-tb-07", "10.20.4.77", "/v2/vendors/V-0412/scheduled-payments", "GET", 200, "V-0412"])
        # 01:44:30 - Attack Vector: Bank Account Modification (Unapproved!)
        writer.writerow(["evt-e18-0903-0144", "2026-09-03T01:44:30Z", "req-5f61b0de8", "key-tb-07", "10.20.4.77", "/v2/vendors/V-0412/bank-details", "PATCH", 200, "V-0412"])
        
        # Day 4-7 Normal Activity
        writer.writerow(["evt-005", "2026-09-04T11:00:00Z", "req-105", "key-finance-02", "10.30.1.20", "/v2/invoices/INV-9095", "GET", 200, "V-0300"])
        writer.writerow(["evt-006", "2026-09-05T09:30:15Z", "req-106", "key-ops-01", "10.20.10.15", "/v2/vendors/V-0105/contacts", "PATCH", 200, "V-0105"])
        writer.writerow(["evt-007", "2026-09-07T16:45:00Z", "req-107", "key-tb-07", "10.20.4.15", "/v2/vendors/V-0412", "GET", 200, "V-0412"])

    # 5. E19 Vendor Master Changes
    e19_path = os.path.join(raw_dir, "E19_vendor_changes.csv")
    with open(e19_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["change_id", "timestamp", "request_id", "vendor_id", "field", "old_value_masked", "new_value_masked", "changed_by", "approval_ref"])
        writer.writerow(["chg-001", "2026-09-01T10:15:30Z", "req-102", "V-0100", "phone", "+1-555-0100", "+1-555-0199", "API:key-ops-01", "APP-OPS-8812"])
        # E19 row corresponding to E18 01:44:30 PATCH: Notice approval_ref is BLANK / null
        writer.writerow(["chg-002", "2026-09-03T01:44:30Z", "req-5f61b0de8", "V-0412", "bank_account_number", "****-1192", "****-8841", "API:key-tb-07", ""])
        # Legitimate bank change with verified Finance approval for comparison
        writer.writerow(["chg-003", "2026-09-04T14:10:00Z", "req-108", "V-0220", "bank_account_number", "****-3341", "****-9902", "UI:finance_admin_1", "FIN-APP-2026-09-441"])
        # UI bank change with blank approval reference (showing evidence characteristic)
        writer.writerow(["chg-004", "2026-09-05T16:20:00Z", "req-109", "V-0300", "bank_account_number", "****-7711", "****-4422", "UI:procure_user_4", ""])

    print(f"Case data successfully generated in {raw_dir}")

if __name__ == "__main__":
    generate_case_data()
