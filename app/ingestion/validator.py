"""
Payload Validation for TRUSTGATE
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator

class RawEventPayload(BaseModel):
    request_id: str = Field(..., min_length=1, description="Unique correlation request ID")
    api_key_id: str = Field(..., min_length=1, description="Client API key identifier")
    source_ip: str = Field(..., min_length=7, description="IPv4 or IPv6 address")
    endpoint: str = Field(..., min_length=1, description="API target endpoint path")
    method: str = Field(..., min_length=3, max_length=10, description="HTTP method e.g. GET, POST, PATCH")
    timestamp: Optional[str] = Field(None, description="ISO8601 timestamp string")
    status: Optional[int] = Field(200, description="Response HTTP status code")
    vendor_id: Optional[str] = Field(None, description="Target Vendor ID if applicable")
    action_type: Optional[str] = Field(None, description="Explicit business action type")
    approval_ref: Optional[str] = Field(None, description="Optional approval reference token")
    payload_body: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Request body payload")
    source_evidence: Optional[List[str]] = Field(default_factory=list, description="Associated evidence tags")
    run_id: Optional[str] = Field(None, description="Optional simulation run ID")

    @field_validator("method")
    def validate_method(cls, v):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"HTTP method '{v}' is not supported")
        return v_upper

    @field_validator("timestamp")
    def validate_timestamp(cls, v):
        if v:
            # Must be valid parseable ISO string
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except Exception:
                raise ValueError(f"Timestamp '{v}' is not a valid ISO 8601 string")
        return v
