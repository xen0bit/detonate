"""SQLAlchemy ORM models for analysis data."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    REAL,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Analysis(Base):
    """Analysis session record."""

    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), unique=True, nullable=False, index=True)
    sample_sha256 = Column(String(64), nullable=False, index=True)
    sample_md5 = Column(String(32), nullable=True)
    sample_path = Column(String(1024), nullable=False)
    sample_size = Column(Integer, nullable=False)
    file_type = Column(String(64), nullable=True)
    platform = Column(String(16), nullable=False)
    architecture = Column(String(16), nullable=False)
    status = Column(String(16), nullable=False, index=True, default="pending")
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), server_default="CURRENT_TIMESTAMP", index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(REAL, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")
    api_calls = relationship("APICall", back_populates="analysis", cascade="all, delete-orphan")
    strings = relationship("String", back_populates="analysis", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_analyses_status_created", "status", "created_at"),
    )


class Finding(Base):
    """ATT&CK technique finding."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)
    technique_id = Column(String(16), nullable=False, index=True)
    technique_name = Column(String(256), nullable=False)
    tactic = Column(String(64), nullable=False, index=True)
    confidence = Column(String(16), nullable=False)  # high, medium, low
    confidence_score = Column(REAL, nullable=False)
    evidence_count = Column(Integer, nullable=False)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence_valid",
        ),
        CheckConstraint(
            "confidence_score >= 0.0 AND confidence_score <= 1.0",
            name="ck_findings_confidence_score_range",
        ),
        CheckConstraint(
            "evidence_count >= 0",
            name="ck_findings_evidence_count_positive",
        ),
        CheckConstraint(
            "last_seen >= first_seen",
            name="ck_findings_last_seen_gte_first_seen",
        ),
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="findings")


class APICall(Base):
    """Captured API call or syscall."""

    __tablename__ = "api_calls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)
    sequence_number = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    api_name = Column(String(128), nullable=True, index=True)
    syscall_name = Column(String(128), nullable=True)
    address = Column(String(32), nullable=True)
    params_json = Column(JSON, nullable=True)
    return_value = Column(String(256), nullable=True)
    technique_id = Column(String(16), nullable=True, index=True)
    confidence = Column(String(16), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(api_name IS NOT NULL AND syscall_name IS NULL) OR (api_name IS NULL AND syscall_name IS NOT NULL)",
            name="ck_apicalls_exactly_one_api_or_syscall",
        ),
        Index("idx_apicalls_analysis_timeline", "analysis_id", "timestamp"),
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="api_calls")


class String(Base):
    """Extracted strings from analysis."""

    __tablename__ = "strings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)
    value = Column(Text, nullable=False)
    address = Column(String(32), nullable=True)
    context = Column(String(64), nullable=True)

    # Relationships
    analysis = relationship("Analysis", back_populates="strings")
