"""Pydantic models for API requests and responses."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Request model for analysis submission."""

    platform: str = Field(default="auto", description="Target platform (auto, windows, linux)")
    arch: str = Field(default="auto", description="Target architecture (auto, x86, x86_64, arm, arm64)")
    timeout: int = Field(default=60, ge=1, le=300, description="Execution timeout in seconds")


class AnalysisStatusResponse(BaseModel):
    """Response model for analysis status."""

    session_id: str
    status: str  # pending, running, completed, failed
    created_at: datetime
    sample: Optional[dict[str, Any]] = None
    analysis: Optional[dict[str, Any]] = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    outputs: Optional[dict[str, str]] = None


class FindingResponse(BaseModel):
    """Response model for a technique finding."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    evidence_count: int


class AnalysisListResponse(BaseModel):
    """Response model for analysis list."""

    items: list[dict[str, Any]]
    total: int
    page: int
    per_page: int
    pages: int


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    version: str
    uptime_seconds: float
