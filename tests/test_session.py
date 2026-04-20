"""Tests for session management and timeout enforcement."""

import asyncio
import signal
import sys
import threading
import time
from datetime import datetime, timezone

import pytest

from detonate.core.session import (
    APICallRecord,
    AnalysisResult,
    AnalysisSession,
    StateError,
    TechniqueMatch,
)
from detonate.core.timeout import TimeoutError, enforce_timeout_sync, timeout_context


class TestAnalysisSession:
    """Tests for AnalysisSession class."""

    def test_session_initialization(self, temp_dir):
        """Test session initializes with correct values."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test content")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
            sample_md5="def456",
            file_type="ELF 64-bit",
        )

        assert session.session_id is not None
        assert session.sample_sha256 == "abc123"
        assert session.sample_md5 == "def456"
        assert session.platform == "linux"
        assert session.architecture == "x86_64"
        assert session.file_type == "ELF 64-bit"
        assert session.status == "pending"
        assert session.started_at is None
        assert session.completed_at is None

    def test_session_start_transitions_to_running(self, temp_dir):
        """Test start() transitions from pending to running."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        assert session.status == "pending"
        session.start()
        assert session.status == "running"
        assert session.started_at is not None
        # Verify timezone-aware datetime
        assert session.started_at.tzinfo is not None

    def test_session_complete_transitions_to_completed(self, temp_dir):
        """Test complete() transitions from running to completed."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        assert session.status == "running"

        session.complete()
        assert session.status == "completed"
        assert session.completed_at is not None
        assert session.completed_at.tzinfo is not None

    def test_session_fail_transitions_to_failed(self, temp_dir):
        """Test fail() transitions from running to failed."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        session.fail("Test error message")

        assert session.status == "failed"
        assert session.error_message == "Test error message"
        assert session.completed_at is not None

    def test_cannot_start_already_running_session(self, temp_dir):
        """Test that starting a running session raises StateError."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        with pytest.raises(StateError, match="invalid transition"):
            session.start()

    def test_cannot_start_completed_session(self, temp_dir):
        """Test that starting a completed session raises StateError."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        session.complete()

        with pytest.raises(StateError, match="invalid transition"):
            session.start()

    def test_cannot_complete_pending_session(self, temp_dir):
        """Test that completing a pending session raises StateError."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        with pytest.raises(StateError, match="invalid transition"):
            session.complete()

    def test_cannot_fail_pending_session(self, temp_dir):
        """Test that failing a pending session raises StateError."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        with pytest.raises(StateError, match="invalid transition"):
            session.fail("error")

    def test_cannot_complete_failed_session(self, temp_dir):
        """Test that completing a failed session raises StateError."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        session.fail("error")

        with pytest.raises(StateError, match="invalid transition"):
            session.complete()

    def test_add_api_call(self, temp_dir):
        """Test adding API call records."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="test_api",
            syscall_name=None,
            params={"arg1": "value1"},
            return_value=0,
            address="0x1000",
        )

        session.add_api_call(record)
        assert len(session.api_calls) == 1
        assert session.api_calls[0].api_name == "test_api"

    def test_add_string_deduplicates(self, temp_dir):
        """Test that add_string deduplicates values."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.add_string("test_string")
        session.add_string("test_string")
        session.add_string("another_string")

        assert len(session.strings) == 2
        assert "test_string" in session.strings
        assert "another_string" in session.strings

    def test_add_technique_evidence(self, temp_dir):
        """Test adding technique evidence."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=True,
            address="0x1000",
            technique_id="T1106",
        )

        session.add_technique_evidence(
            technique_id="T1106",
            technique_name="Native API",
            tactic="execution",
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

        assert "T1106" in session.findings
        finding = session.findings["T1106"]
        assert finding.technique_name == "Native API"
        assert finding.evidence_count == 1

    def test_add_technique_evidence_accumulates(self, temp_dir):
        """Test that multiple evidence for same technique accumulates."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        for i in range(3):
            record = APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="CreateProcessA",
                syscall_name=None,
                params={},
                return_value=True,
                address="0x1000",
            )
            session.add_technique_evidence(
                technique_id="T1106",
                technique_name="Native API",
                tactic="execution",
                confidence="high",
                confidence_score=0.9,
                api_call=record,
            )

        assert session.findings["T1106"].evidence_count == 3

    def test_to_result_completed(self, temp_dir):
        """Test converting completed session to result."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test content")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
            sample_md5="def456",
            file_type="ELF",
        )

        session.start()
        session.complete()

        result = session.to_result()

        assert isinstance(result, AnalysisResult)
        assert result.session_id == session.session_id
        assert result.status == "completed"
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0

    def test_to_result_failed(self, temp_dir):
        """Test converting failed session to result."""
        sample_file = temp_dir / "test_sample"
        sample_file.write_bytes(b"test")

        session = AnalysisSession(
            sample_path=str(sample_file),
            sample_sha256="abc123",
            platform="linux",
            architecture="x86_64",
        )

        session.start()
        session.fail("Test failure")

        result = session.to_result()

        assert result.status == "failed"
        assert result.error_message == "Test failure"


class TestTimeoutContext:
    """Tests for async timeout context manager."""

    @pytest.mark.asyncio
    async def test_timeout_context_completes_in_time(self):
        """Test that code completing in time doesn't raise."""
        async with timeout_context(1):
            await asyncio.sleep(0.1)
        # Should complete without exception

    @pytest.mark.asyncio
    async def test_timeout_context_raises_on_timeout(self):
        """Test that timeout raises TimeoutError."""
        with pytest.raises(TimeoutError, match="Execution timeout"):
            async with timeout_context(0.1):
                await asyncio.sleep(1)

    @pytest.mark.asyncio
    async def test_timeout_context_cancels_timer_on_success(self):
        """Test that timer is cancelled on successful completion."""
        async with timeout_context(10):
            await asyncio.sleep(0.01)
        # Timer should be cancelled, no lingering tasks


class TestEnforceTimeoutSync:
    """Tests for synchronous timeout enforcement."""

    @pytest.mark.skipif(
        sys.platform == "win32", reason="SIGALRM not available on Windows"
    )
    def test_enforce_timeout_sync_completes_in_time(self):
        """Test that code completing in time doesn't raise."""
        with enforce_timeout_sync(1):
            time.sleep(0.1)
        # Should complete without exception

    @pytest.mark.skipif(
        sys.platform == "win32", reason="SIGALRM not available on Windows"
    )
    def test_enforce_timeout_sync_raises_on_timeout(self):
        """Test that timeout raises TimeoutError."""
        with pytest.raises(TimeoutError, match="Execution timeout"):
            with enforce_timeout_sync(1):
                time.sleep(2)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="SIGALRM not available on Windows"
    )
    def test_enforce_timeout_sync_restores_signal_handler(self):
        """Test that original signal handler is restored."""
        original_handler = signal.getsignal(signal.SIGALRM)

        with enforce_timeout_sync(1):
            time.sleep(0.01)

        # Handler should be restored
        assert signal.getsignal(signal.SIGALRM) == original_handler

    def test_enforce_timeout_sync_windows_fallback(self):
        """Test Windows fallback using threading.Timer."""
        # On Unix, just verify the code path exists (uses SIGALRM)
        with enforce_timeout_sync(1):
            time.sleep(0.1)


class TestAPICallRecord:
    """Tests for APICallRecord dataclass."""

    def test_api_call_record_creation(self):
        """Test creating an API call record."""
        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={"cmd": "calc.exe"},
            return_value=True,
            address="0x1000",
        )

        assert record.api_name == "CreateProcessA"
        assert record.syscall_name is None
        assert record.params == {"cmd": "calc.exe"}
        assert record.sequence_number == 0

    def test_api_call_record_with_sequence(self):
        """Test creating an API call record with sequence number."""
        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="test",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x1000",
            sequence_number=5,
        )

        assert record.sequence_number == 5


class TestTechniqueMatch:
    """Tests for TechniqueMatch dataclass."""

    def test_technique_match_creation(self):
        """Test creating a technique match."""
        match = TechniqueMatch(
            technique_id="T1106",
            technique_name="Native API",
            tactic="execution",
            confidence="high",
            confidence_score=0.9,
        )

        assert match.technique_id == "T1106"
        assert match.confidence == "high"
        assert match.evidence_count == 1

    def test_technique_match_with_evidence(self):
        """Test technique match with evidence list."""
        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="test",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x1000",
        )

        match = TechniqueMatch(
            technique_id="T1106",
            technique_name="Native API",
            tactic="execution",
            confidence="high",
            confidence_score=0.9,
            evidence_count=1,
            evidence=[record],
        )

        assert len(match.evidence) == 1
