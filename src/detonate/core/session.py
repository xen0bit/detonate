"""Analysis session management."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class StateError(Exception):
    """Raised on invalid state transition."""

    pass


@dataclass
class APICallRecord:
    """Record of a single API call or syscall."""

    timestamp: datetime
    api_name: str | None
    syscall_name: str | None
    params: dict[str, Any]
    return_value: Any
    address: str
    technique_id: str | None = None
    confidence: str | None = None
    sequence_number: int = 0


@dataclass
class TechniqueMatch:
    """ATT&CK technique match with confidence."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: str  # high, medium, low
    confidence_score: float
    evidence_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[APICallRecord] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    session_id: str
    sample_sha256: str
    sample_md5: str | None
    sample_path: str
    sample_size: int
    file_type: str | None
    platform: str
    architecture: str
    status: str  # completed, failed, timeout
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    api_calls: list[APICallRecord]
    findings: list[TechniqueMatch]
    strings: list[str]


class AnalysisSession:
    """Manages a single analysis session."""

    def __init__(
        self,
        sample_path: str,
        sample_sha256: str,
        platform: str,
        architecture: str,
        sample_md5: str | None = None,
        file_type: str | None = None,
    ):
        """
        Initialize analysis session.

        Args:
            sample_path: Path to sample file
            sample_sha256: SHA256 hash of sample
            platform: Target platform (windows/linux)
            architecture: Target architecture
            sample_md5: Optional MD5 hash
            file_type: Optional file type description
        """
        self.session_id = str(uuid.uuid4())
        self.sample_path = sample_path
        self.sample_sha256 = sample_sha256
        self.sample_md5 = sample_md5
        self.file_type = file_type
        self.platform = platform
        self.architecture = architecture

        # Get sample size
        from pathlib import Path
        self.sample_size = Path(sample_path).stat().st_size

        # Session state
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.api_calls: list[APICallRecord] = []
        self.findings: dict[str, TechniqueMatch] = {}  # keyed by technique_id
        self.strings: list[str] = []
        self.status: str = "pending"
        self.error_message: str | None = None
        self._call_sequence: int = 0  # Sequence counter for ordering events

    def start(self) -> None:
        """Start the analysis session."""
        if self.status != "pending":
            raise StateError(
                f"Cannot start session: invalid transition from '{self.status}' to 'running'"
            )
        self.started_at = datetime.now(timezone.utc)
        self.status = "running"

    def complete(self) -> None:
        """Mark the session as completed."""
        if self.status != "running":
            raise StateError(
                f"Cannot complete session: invalid transition from '{self.status}' to 'completed'"
            )
        self.completed_at = datetime.now(timezone.utc)
        self.status = "completed"

    def fail(self, error_message: str) -> None:
        """Mark the session as failed with an error message."""
        if self.status != "running":
            raise StateError(
                f"Cannot fail session: invalid transition from '{self.status}' to 'failed'"
            )
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = error_message
        self.status = "failed"

    def add_api_call(self, record: APICallRecord) -> None:
        """Add an API call record."""
        self.api_calls.append(record)

    def add_string(self, value: str) -> None:
        """Add an extracted string."""
        if value and value not in self.strings:
            self.strings.append(value)

    def add_technique_evidence(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        confidence: str,
        confidence_score: float,
        api_call: APICallRecord,
    ) -> None:
        """Add evidence for a technique match."""
        if technique_id not in self.findings:
            self.findings[technique_id] = TechniqueMatch(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence=confidence,
                confidence_score=confidence_score,
                evidence_count=1,
                first_seen=api_call.timestamp,
                last_seen=api_call.timestamp,
                evidence=[api_call],
            )
        else:
            finding = self.findings[technique_id]
            finding.evidence_count += 1
            finding.last_seen = api_call.timestamp
            finding.evidence.append(api_call)

    def to_result(self) -> AnalysisResult:
        """Convert session to AnalysisResult."""
        duration = None
        if self.started_at and self.completed_at:
            duration = (self.completed_at - self.started_at).total_seconds()

        return AnalysisResult(
            session_id=self.session_id,
            sample_sha256=self.sample_sha256,
            sample_md5=self.sample_md5,
            sample_path=self.sample_path,
            sample_size=self.sample_size,
            file_type=self.file_type,
            platform=self.platform,
            architecture=self.architecture,
            status=self.status,
            error_message=self.error_message,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=duration,
            api_calls=self.api_calls,
            findings=list(self.findings.values()),
            strings=self.strings,
        )
