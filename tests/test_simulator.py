"""
Unit Tests for Simulation Engine
"""
from app.simulator.scenarios import SCENARIO_CATALOG
from app.simulator.generator import generate_simulation_batch

def test_all_twelve_scenarios_generate_events():
    for sc_id in SCENARIO_CATALOG.keys():
        batch = generate_simulation_batch(scenario_id=sc_id, seed=123, num_events=3)
        assert len(batch) == 3
        for item in batch:
            assert "run_id" in item
            assert "scenario_id" in item
            assert "event" in item
            assert "ground_truth" in item
            # Ground truth must NOT leak into event dictionary
            assert "ground_truth" not in item["event"]
            assert item["event"]["request_id"] != ""

def test_seed_reproducibility():
    batch1 = generate_simulation_batch(scenario_id="SCN-04", seed=42, num_events=5)
    batch2 = generate_simulation_batch(scenario_id="SCN-04", seed=42, num_events=5)

    for i in range(5):
        assert batch1[i]["event"]["request_id"] == batch2[i]["event"]["request_id"]
        assert batch1[i]["event"]["endpoint"] == batch2[i]["event"]["endpoint"]
        assert batch1[i]["event"]["timestamp"] == batch2[i]["event"]["timestamp"]
