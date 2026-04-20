"""Database CRUD operations."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, joinedload

from .models import Analysis, Finding, APICall, String


VALID_STATUSES = {"pending", "running", "completed", "failed"}
VALID_CONFIDENCES = {"high", "medium", "low"}
VALID_TRANSITIONS = {
    "pending": {"running", "failed"},
    "running": {"completed", "failed"},
    "completed": set(),  # Terminal state
    "failed": set(),  # Terminal state
}
MAX_LIST_LIMIT = 100
DEFAULT_LIST_LIMIT = 20


@dataclass
class ListResult:
    """Pagination result for list operations."""
    items: List[Analysis]
    total: int
    page: int
    per_page: int
    pages: int


class DatabaseStore:
    """Database operations wrapper."""

    def __init__(self, db_path: str):
        """
        Initialize database store.

        Args:
            db_path: Path to SQLite database
        """
        self.engine = create_engine(f"sqlite:///{db_path}")

    def create_analysis(
        self,
        session_id: str,
        sample_sha256: str,
        sample_path: str,
        sample_size: int,
        platform: str,
        architecture: str,
        sample_md5: Optional[str] = None,
        file_type: Optional[str] = None,
    ) -> Analysis:
        """Create a new analysis record."""
        with Session(self.engine) as session:
            analysis = Analysis(
                session_id=session_id,
                sample_sha256=sample_sha256,
                sample_md5=sample_md5,
                sample_path=sample_path,
                sample_size=sample_size,
                file_type=file_type,
                platform=platform,
                architecture=architecture,
                status="pending",
                created_at=datetime.now(timezone.utc),
            )
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
            return analysis

    def update_analysis_status(
        self,
        session_id: str,
        status: str,
        error_message: Optional[str] = None,
        completed_at: Optional[datetime] = None,
        duration_seconds: Optional[float] = None,
    ) -> None:
        """
        Update analysis status with state transition validation.

        Args:
            session_id: Analysis session UUID
            status: New status (pending, running, completed, failed)
            error_message: Error message if status is failed
            completed_at: Completion timestamp (auto-set if transitioning to completed/failed)
            duration_seconds: Execution duration in seconds

        Raises:
            ValueError: If status is invalid or transition is not allowed
            KeyError: If analysis not found
        """
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of: {VALID_STATUSES}")

        with Session(self.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == session_id)
            analysis = session.scalar(stmt)
            if analysis is None:
                raise KeyError(f"Analysis '{session_id}' not found")

            # Validate state transition
            current_status = analysis.status
            if status not in VALID_TRANSITIONS.get(current_status, set()):
                raise ValueError(
                    f"Invalid state transition from '{current_status}' to '{status}'. "
                    f"Allowed transitions: {VALID_TRANSITIONS.get(current_status, set())}"
                )

            analysis.status = status
            if error_message:
                analysis.error_message = error_message

            # Auto-set completed_at when transitioning to terminal states
            if status in ("completed", "failed"):
                analysis.completed_at = completed_at or datetime.now(timezone.utc)

            if duration_seconds is not None:
                analysis.duration_seconds = duration_seconds

            session.commit()

    def add_finding(
        self,
        analysis_id: int,
        technique_id: str,
        technique_name: str,
        tactic: str,
        confidence: str,
        confidence_score: float,
        evidence_count: int,
        first_seen: datetime,
        last_seen: datetime,
    ) -> Finding:
        """
        Add a technique finding with validation.

        Args:
            analysis_id: Parent analysis ID
            technique_id: ATT&CK technique ID (e.g., T1059.001)
            technique_name: ATT&CK technique name
            tactic: ATT&CK tactic name
            confidence: Confidence level (high, medium, low)
            confidence_score: Numeric confidence (0.0-1.0)
            evidence_count: Number of supporting API calls (>= 0)
            first_seen: First occurrence timestamp
            last_seen: Last occurrence timestamp

        Returns:
            Created Finding record

        Raises:
            ValueError: If validation fails
        """
        # Validate confidence level
        if confidence not in VALID_CONFIDENCES:
            raise ValueError(
                f"Invalid confidence '{confidence}'. Must be one of: {VALID_CONFIDENCES}"
            )

        # Validate confidence score range
        if not (0.0 <= confidence_score <= 1.0):
            raise ValueError(
                f"confidence_score must be between 0.0 and 1.0, got {confidence_score}"
            )

        # Validate evidence count
        if evidence_count < 0:
            raise ValueError(
                f"evidence_count must be >= 0, got {evidence_count}"
            )

        # Validate temporal consistency
        if last_seen < first_seen:
            raise ValueError(
                f"last_seen ({last_seen}) must be >= first_seen ({first_seen})"
            )

        with Session(self.engine) as session:
            finding = Finding(
                analysis_id=analysis_id,
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence=confidence,
                confidence_score=confidence_score,
                evidence_count=evidence_count,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding

    def add_api_call(
        self,
        analysis_id: int,
        timestamp: datetime,
        api_name: Optional[str],
        syscall_name: Optional[str],
        address: Optional[str],
        params_json: Optional[dict | str],
        return_value: Optional[str],
        technique_id: Optional[str] = None,
        confidence: Optional[str] = None,
        sequence_number: Optional[int] = None,
    ) -> APICall:
        """
        Add an API call record.

        Args:
            analysis_id: Parent analysis ID
            timestamp: Call timestamp
            api_name: Windows API name (mutually exclusive with syscall_name)
            syscall_name: Linux syscall name (mutually exclusive with api_name)
            address: Call address in hex
            params_json: Parameters as dict or JSON string
            return_value: Return value stringified
            technique_id: Mapped ATT&CK technique ID
            confidence: Mapping confidence level
            sequence_number: Order within analysis (auto-incremented if not provided)

        Returns:
            Created APICall record

        Raises:
            ValueError: If both api_name and syscall_name are set or neither is set
        """
        # Validate mutually exclusive constraint
        if (api_name is None) == (syscall_name is None):
            raise ValueError(
                "Exactly one of api_name or syscall_name must be provided"
            )

        if confidence is not None and confidence not in VALID_CONFIDENCES:
            raise ValueError(
                f"Invalid confidence '{confidence}'. Must be one of: {VALID_CONFIDENCES}"
            )

        with Session(self.engine) as session:
            # Auto-assign sequence number if not provided
            if sequence_number is None:
                max_seq_stmt = select(APICall.sequence_number).where(
                    APICall.analysis_id == analysis_id
                )
                max_seq = session.scalar(max_seq_stmt)
                sequence_number = (max_seq or 0) + 1

            # Convert params to dict if JSON string provided
            if isinstance(params_json, str):
                import json
                try:
                    params_json = json.loads(params_json)
                except json.JSONDecodeError:
                    pass  # Let SQLite handle invalid JSON

            api_call = APICall(
                analysis_id=analysis_id,
                sequence_number=sequence_number,
                timestamp=timestamp,
                api_name=api_name,
                syscall_name=syscall_name,
                address=address,
                params_json=params_json,
                return_value=return_value,
                technique_id=technique_id,
                confidence=confidence,
            )
            session.add(api_call)
            session.commit()
            session.refresh(api_call)
            return api_call

    def add_string(
        self,
        analysis_id: int,
        value: str,
        address: Optional[str] = None,
        context: Optional[str] = None,
    ) -> String:
        """Add an extracted string."""
        with Session(self.engine) as session:
            string = String(
                analysis_id=analysis_id,
                value=value,
                address=address,
                context=context,
            )
            session.add(string)
            session.commit()
            session.refresh(string)
            return string

    def get_analysis(self, session_id: str) -> Optional[Analysis]:
        """Get analysis by session ID."""
        with Session(self.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == session_id)
            return session.scalar(stmt)

    def get_analysis_with_data(
        self,
        session_id: str,
        include_findings: bool = True,
        include_api_calls: bool = True,
        include_strings: bool = True,
    ) -> Optional[Analysis]:
        """
        Get analysis by session ID with eagerly loaded related data.

        Args:
            session_id: Analysis session UUID
            include_findings: Eager load findings relationship
            include_api_calls: Eager load api_calls relationship
            include_strings: Eager load strings relationship

        Returns:
            Analysis object with related data loaded, or None if not found
        """
        with Session(self.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == session_id)

            # Apply eager loading to prevent N+1 queries
            if include_findings:
                stmt = stmt.options(joinedload(Analysis.findings))
            if include_api_calls:
                stmt = stmt.options(joinedload(Analysis.api_calls))
            if include_strings:
                stmt = stmt.options(joinedload(Analysis.strings))

            result = session.scalar(stmt)
            return result

    def list_analyses(
        self,
        status: Optional[str] = None,
        platform: Optional[str] = None,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        include_findings: bool = False,
        include_api_calls: bool = False,
    ) -> ListResult:
        """
        List analyses with pagination and optional eager loading.

        Args:
            status: Filter by status
            platform: Filter by platform
            limit: Max results (capped at MAX_LIST_LIMIT)
            offset: Result offset for pagination
            include_findings: Eager load findings relationship
            include_api_calls: Eager load api_calls relationship

        Returns:
            ListResult with items and pagination metadata
        """
        # Enforce limit bounds
        limit = max(1, min(limit, MAX_LIST_LIMIT))

        with Session(self.engine) as session:
            stmt = select(Analysis)

            # Apply eager loading to prevent N+1 queries
            if include_findings:
                stmt = stmt.options(joinedload(Analysis.findings))
            if include_api_calls:
                stmt = stmt.options(joinedload(Analysis.api_calls))

            if status:
                if status not in VALID_STATUSES:
                    raise ValueError(f"Invalid status '{status}'. Must be one of: {VALID_STATUSES}")
                stmt = stmt.where(Analysis.status == status)
            if platform:
                if platform not in ("windows", "linux"):
                    raise ValueError(f"Invalid platform '{platform}'. Must be 'windows' or 'linux'")
                stmt = stmt.where(Analysis.platform == platform)

            # Get total count for pagination
            from sqlalchemy import func
            count_stmt = select(func.count()).select_from(Analysis)
            if status:
                count_stmt = count_stmt.where(Analysis.status == status)
            if platform:
                count_stmt = count_stmt.where(Analysis.platform == platform)
            total = session.scalar(count_stmt) or 0

            # Get paginated results
            stmt = stmt.order_by(Analysis.created_at.desc())
            stmt = stmt.offset(offset).limit(limit)
            items = list(session.scalars(stmt).unique())

            # Calculate pagination metadata
            page = (offset // limit) + 1 if limit > 0 else 1
            pages = (total + limit - 1) // limit if limit > 0 else 1

            return ListResult(
                items=items,
                total=total,
                page=page,
                per_page=limit,
                pages=pages,
            )
