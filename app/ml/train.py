"""
Isolation Forest Training and Calibration Pipeline for TRUSTGATE
"""
import os
import sys
import json
import joblib
import numpy as np
import random
from datetime import datetime, timezone, timedelta
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from app.config import settings
from app.ml.features import extract_features, FEATURE_NAMES, reset_history

def generate_normal_baseline_dataset(num_samples: int = 1200, seed: int = 42) -> np.ndarray:
    """
    Generate synthetic legitimate operations during regular business operations.
    Scenarios:
    - Normal vendor profile and invoice lookups
    - Routine contact details updates
    - Operating on registered subnets
    - Normal business hours (08:00 - 18:00 UTC)
    - Low to moderate request bursts (1 - 5 requests in 5 minutes)
    """
    random.seed(seed)
    np.random.seed(seed)
    reset_history()

    base_time = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)
    feature_matrix = []

    for i in range(num_samples):
        # Business hours 8am to 6pm, weekdays primarily
        hour = random.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17])
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        delta_days = random.randint(0, 30)
        dt = base_time + timedelta(days=delta_days, hours=hour - 9, minutes=minute, seconds=second)
        
        key = random.choice(["key-tb-07", "key-ops-01", "key-finance-02"])
        
        # Routine endpoints
        op_choice = random.random()
        if op_choice < 0.45:
            # Invoice read
            event = {
                "event_id": f"train-norm-{i}",
                "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "request_id": f"req-tr-{i}",
                "api_key_id": key,
                "source_ip": "10.20.4.15" if key == "key-tb-07" else ("10.20.10.15" if key == "key-ops-01" else "10.30.1.20"),
                "source_ip_scope": "registered",
                "endpoint": f"/v2/invoices/INV-{random.randint(1000, 9999)}",
                "endpoint_group": "invoices",
                "method": "GET",
                "status": 200,
                "action_type": "invoice_read"
            }
        elif op_choice < 0.80:
            # Vendor profile read
            v_id = f"V-0{random.randint(100, 900)}"
            event = {
                "event_id": f"train-norm-{i}",
                "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "request_id": f"req-tr-{i}",
                "api_key_id": key,
                "source_ip": "10.20.4.15" if key == "key-tb-07" else ("10.20.10.15" if key == "key-ops-01" else "10.30.1.20"),
                "source_ip_scope": "registered",
                "endpoint": f"/v2/vendors/{v_id}",
                "endpoint_group": "vendor_profile",
                "method": "GET",
                "status": 200,
                "action_type": "vendor_profile_read"
            }
        else:
            # Contact update
            v_id = f"V-0{random.randint(100, 900)}"
            event = {
                "event_id": f"train-norm-{i}",
                "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "request_id": f"req-tr-{i}",
                "api_key_id": "key-ops-01",
                "source_ip": "10.20.10.15",
                "source_ip_scope": "registered",
                "endpoint": f"/v2/vendors/{v_id}/contacts",
                "endpoint_group": "vendor_contacts",
                "method": "PATCH",
                "status": 200,
                "action_type": "contact_update"
            }

        vec, _ = extract_features(event, record_to_history=True)
        feature_matrix.append(vec.flatten())

    return np.array(feature_matrix)

def train_and_save_model(output_model_path: str = None, output_meta_path: str = None) -> dict:
    """Train Isolation Forest and persist model artifact and metadata"""
    model_path = output_model_path or settings.model_file
    meta_path = output_meta_path or settings.features_meta_file
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    X_train = generate_normal_baseline_dataset(num_samples=1500, seed=42)

    model = IsolationForest(
        n_estimators=150,
        max_samples=256,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)

    # Calculate baseline scores on training data for calibration
    raw_scores = model.score_samples(X_train)
    min_score = float(np.min(raw_scores))
    max_score = float(np.max(raw_scores))
    mean_score = float(np.mean(raw_scores))

    # Save model
    joblib.dump(model, model_path)

    metadata = {
        "model_version": settings.model_version,
        "algorithm": "IsolationForest",
        "n_estimators": 150,
        "max_samples": 256,
        "contamination": 0.05,
        "feature_names": FEATURE_NAMES,
        "train_samples": len(X_train),
        "score_min": min_score,
        "score_max": max_score,
        "score_mean": mean_score,
        "calibrated_threshold": settings.default_anomaly_threshold,
        "trained_at": datetime.now(timezone.utc).isoformat()
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model trained and saved to {model_path}")
    return metadata

if __name__ == "__main__":
    train_and_save_model()
