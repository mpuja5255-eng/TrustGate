"""
TRUSTGATE Application Configuration
"""
import os
from pydantic import BaseModel

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

class Settings(BaseModel):
    app_name: str = "TRUSTGATE"
    app_version: str = "1.0.0"
    mode: str = "simulation"  # simulation | shadow | enforcement
    
    # Paths
    base_dir: str = BASE_DIR
    data_dir: str = os.path.join(BASE_DIR, "data")
    raw_data_dir: str = os.path.join(BASE_DIR, "data", "raw")
    processed_data_dir: str = os.path.join(BASE_DIR, "data", "processed")
    models_dir: str = os.path.join(BASE_DIR, "data", "models")
    simulated_dir: str = os.path.join(BASE_DIR, "data", "simulated")
    configs_dir: str = os.path.join(BASE_DIR, "configs")
    
    # Config files
    contracts_file: str = os.path.join(BASE_DIR, "configs", "capability_contracts.json")
    policy_file: str = os.path.join(BASE_DIR, "configs", "policy_config.json")
    
    # Database
    database_url: str = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'trustgate.db')}"
    
    # ML settings
    default_anomaly_threshold: float = 0.65  # normalized score >= 0.65 is anomalous
    model_version: str = "iforest-v1.0"
    model_file: str = os.path.join(BASE_DIR, "data", "models", "iforest_model.joblib")
    features_meta_file: str = os.path.join(BASE_DIR, "data", "models", "features_meta.json")

settings = Settings()
