"""
Unit Tests for Evaluation and Comparison Module
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.models import Base
from app.evaluation.metrics import calculate_confusion_metrics
from app.evaluation.comparison import ModeComparator
from app.simulator.generator import generate_simulation_batch

def test_confusion_metrics_calculation():
    records = [
        {"ground_truth": "ATTACK", "final_action": "HOLD", "latency_ms": 1.2},  # TP
        {"ground_truth": "ATTACK", "final_action": "BLOCK", "latency_ms": 1.1}, # TP
        {"ground_truth": "LEGITIMATE", "final_action": "ALLOW", "latency_ms": 0.5}, # TN
        {"ground_truth": "LEGITIMATE", "final_action": "HOLD", "latency_ms": 0.8},  # FP
        {"ground_truth": "ATTACK", "final_action": "ALLOW", "latency_ms": 0.6},  # FN (missed)
    ]
    metrics = calculate_confusion_metrics(records)
    assert metrics["tp"] == 2
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    assert metrics["fn"] == 1
    assert metrics["accuracy"] == round((2 + 1) / 5, 4)
    assert metrics["precision"] == round(2 / (2 + 1), 4)
    assert metrics["recall"] == round(2 / (2 + 1), 4)
    assert metrics["false_positive_rate"] == round(1 / (1 + 1), 4)
    assert metrics["false_negative_rate"] == round(1 / (1 + 2), 4)

def test_confusion_metrics_zero_division_safety():
    empty_records = []
    m0 = calculate_confusion_metrics(empty_records)
    assert m0["total_events"] == 0
    assert m0["precision"] == 0.0
    assert m0["recall"] == 0.0
    assert m0["accuracy"] == 0.0
    assert m0["false_positive_rate"] == 0.0
    assert m0["false_negative_rate"] == 0.0
    assert m0["f1_score"] == 0.0

def test_mode_comparator_runs():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    comparator = ModeComparator(db)
    batch = generate_simulation_batch(scenario_id="SCN-04", seed=42, num_events=4)
    res = comparator.run_comparison(batch)

    assert "policy_only" in res
    assert "hybrid" in res
    assert "delta_analysis" in res
    assert res["total_events"] == 4
    db.close()
