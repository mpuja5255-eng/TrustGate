"""
Metrics Calculations for TRUSTGATE Evaluation
"""
from typing import Dict, Any, List

def calculate_confusion_metrics(eval_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute Accuracy, Precision, Recall, F1, FPR, FNR, and review volume.
    Convention:
    - Target Positive (True Suspicious/Attack): Ground truth in ('ATTACK', 'SUSPICIOUS', 'DEPENDENCY_FAILURE')
    - Target Negative (True Legitimate): Ground truth in ('LEGITIMATE', 'DEGRADED_MODE')
    - System Flagged as Suspicious: Decision in ('HOLD', 'BLOCK', 'INVALID')
    - System Allowed: Decision in ('ALLOW')
    """
    tp = 0  # Suspicious event correctly HELD or BLOCKED
    fp = 0  # Legitimate event incorrectly HELD or BLOCKED
    tn = 0  # Legitimate event correctly ALLOWED
    fn = 0  # Suspicious event missed (ALLOWED)

    latencies = []
    num_attacks = 0
    num_normal = 0

    for r in eval_records:
        gt = r.get("ground_truth", "LEGITIMATE")
        action = r.get("final_action", "ALLOW")
        latency = r.get("latency_ms", 1.0)
        latencies.append(latency)

        is_true_suspicious = gt in ("ATTACK", "SUSPICIOUS", "DEPENDENCY_FAILURE")
        if is_true_suspicious:
            num_attacks += 1
        else:
            num_normal += 1

        is_flagged = action in ("HOLD", "BLOCK", "INVALID")

        if is_true_suspicious and is_flagged:
            tp += 1
        elif not is_true_suspicious and is_flagged:
            fp += 1
        elif not is_true_suspicious and not is_flagged:
            tn += 1
        elif is_true_suspicious and not is_flagged:
            fn += 1

    total = len(eval_records)
    
    # Accurate metrics with zero-division protection
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "total_events": total,
        "attack_events": num_attacks,
        "normal_events": num_normal,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "f1_score": round(f1, 4),
        "missed_detections": fn,
        "review_volume": tp + fp,
        "avg_latency_ms": round(avg_latency, 3)
    }
