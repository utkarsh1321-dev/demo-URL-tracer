"""
schemas.py — Pydantic schemas for request validation and API responses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Common inbound HTTP request record
# ─────────────────────────────────────────────

class HTTPRequest(BaseModel):
    """Canonical record structure shared across all modules."""
    timestamp: Optional[str] = None
    source_ip: str = Field(..., example="10.0.0.5")
    destination_ip: Optional[str] = Field(None, example="192.168.1.1")
    method: Optional[str] = Field(None, example="GET")
    host: Optional[str] = Field(None, example="example.internal")
    url: Optional[str] = Field(None, example="/search?q=test")
    user_agent: Optional[str] = Field(None, example="Mozilla/5.0")
    status_code: Optional[int] = Field(None, example=200)
    response_size: Optional[int] = Field(None, example=1234)


# ─────────────────────────────────────────────
# Detection result
# ─────────────────────────────────────────────

class DetectionResult(BaseModel):
    attack_type: str
    severity: str                   # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float
    detection_method: str           # RULE | ML | HYBRID
    result: str                     # ATTEMPT | POTENTIAL_SUCCESS


# ─────────────────────────────────────────────
# ML prediction
# ─────────────────────────────────────────────

class MLPrediction(BaseModel):
    prediction: str
    confidence: float


# ─────────────────────────────────────────────
# Upload responses
# ─────────────────────────────────────────────

class UploadResponse(BaseModel):
    status: str
    upload_id: int
    records_processed: int
    attacks_detected: int
    high_risk_ips: int
    message: Optional[str] = None


# ─────────────────────────────────────────────
# Attack / Detection API
# ─────────────────────────────────────────────

class DetectionOut(BaseModel):
    id: int
    request_id: int
    attack_type: str
    severity: str
    confidence: float
    detection_method: str
    result: str
    source_ip: Optional[str]
    url: Optional[str]
    host: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class AttackListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[DetectionOut]


# ─────────────────────────────────────────────
# IP Analysis API
# ─────────────────────────────────────────────

class IPAnalysisOut(BaseModel):
    id: int
    ip_address: str
    risk_score: int
    risk_level: str
    attack_count: int
    request_count: int
    attack_types: Optional[str]
    last_seen: Optional[datetime]
    geo_country: Optional[str]
    geo_city: Optional[str]
    isp: Optional[str]
    first_seen: Optional[datetime]

    class Config:
        from_attributes = True


class IPListResponse(BaseModel):
    total: int
    items: list[IPAnalysisOut]


# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────

class AttackTypeStat(BaseModel):
    attack_type: str
    count: int


class SeverityStat(BaseModel):
    severity: str
    count: int


class TopIP(BaseModel):
    ip_address: str
    risk_score: int
    risk_level: str
    attack_count: int


class DashboardResponse(BaseModel):
    total_requests: int
    total_attacks: int
    high_risk_ips: int
    critical_ips: int
    attacks_by_type: list[AttackTypeStat]
    attacks_by_severity: list[SeverityStat]
    top_attacking_ips: list[TopIP]
    recent_detections: list[DetectionOut]
    potential_success_count: int


# ─────────────────────────────────────────────
# Generic error
# ─────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
