"""
Capability Contract Manager for TRUSTGATE
"""
import json
import os
from typing import Dict, Any, Optional
from app.config import settings

class ContractManager:
    def __init__(self, contracts_path: Optional[str] = None):
        self.contracts_path = contracts_path or settings.contracts_file
        self._contracts: Dict[str, Any] = {}
        self.load()

    def load(self):
        if os.path.exists(self.contracts_path):
            with open(self.contracts_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._contracts = data.get("integrations", {})
        else:
            self._contracts = {}

    def get_integration(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        return self._contracts.get(api_key_id)

    def is_key_registered(self, api_key_id: str) -> bool:
        return api_key_id in self._contracts

    def is_active(self, api_key_id: str) -> bool:
        cfg = self.get_integration(api_key_id)
        if not cfg:
            return False
        return cfg.get("active", False)

    def get_allowed_capabilities(self, api_key_id: str) -> list:
        cfg = self.get_integration(api_key_id)
        if not cfg:
            return []
        return cfg.get("allowed_capabilities", [])

    def get_allowed_ips(self, api_key_id: str) -> list:
        cfg = self.get_integration(api_key_id)
        if not cfg:
            return []
        return cfg.get("allowed_ips", [])

    def get_permitted_fields(self, api_key_id: str) -> list:
        cfg = self.get_integration(api_key_id)
        if not cfg:
            return []
        return cfg.get("permitted_fields", [])
