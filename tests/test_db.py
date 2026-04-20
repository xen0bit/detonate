"""Database layer tests."""

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from detonate.db import DatabaseStore, init_database, Analysis, Finding, APICall, String


class TestInitDatabase:
    """Test database initialization."""

    def test_init_creates_tables(self, db_path):
        """Database initialization creates all tables."""
        init_database(db_path)

        # Verify tables exist by querying sqlite_master
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "analyses" in tables
        assert "findings" in tables
        assert "api_calls" in tables
        assert "strings" in tables

    def test_init_creates_parent_directory(self, temp_dir):
        """Database initialization creates parent directories if needed."""
        nested_path = temp_dir / "nested" / "path" / "test.db"
        assert not nested_path.parent.exists()

        init_database(nested_path)

        assert nested_path.exists()


class TestCreateAnalysis:
    """Test analysis creation."""

    def test_create_analysis_minimal(self, db_path):
        """Create analysis with minimal required fields."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            sample_sha256="a" * 64,
            sample_path="/samples/malware.exe",
            sample_size=12345,
            platform="windows",
            architecture="x86",
        )

        assert analysis.session_id == "550e8400-e29b-41d4-a716-446655440000"
        assert analysis.sample_sha256 == "a" * 64
        assert analysis.sample_path == "/samples/malware.exe"
        assert analysis.sample_size == 12345
        assert analysis.platform == "windows"
        assert analysis.architecture == "x86"
        assert analysis.status == "pending"
        assert analysis.sample_md5 is None
        assert analysis.file_type is None
        assert analysis.error_message is None
        assert analysis.completed_at is None
        assert analysis.duration_seconds is None
        assert analysis.created_at is not None

    def test_create_analysis_full(self, db_path):
        """Create analysis with all fields populated."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="550e8400-e29b-41d4-a716-446655440001",
            sample_sha256="b" * 64,
            sample_md5="c" * 32,
            sample_path="/samples/elf.bin",
            sample_size=67890,
            platform="linux",
            architecture="x86_64",
            file_type="ELF 64-bit LSB executable",
        )

        assert analysis.sample_md5 == "c" * 32
        assert analysis.file_type == "ELF 64-bit LSB executable"
        assert analysis.platform == "linux"
        assert analysis.architecture == "x86_64"

    def test_create_analysis_unique_session_id(self, db_path):
        """Session ID must be unique."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        store.create_analysis(
            session_id="duplicate-session-id",
            sample_sha256="a" * 64,
            sample_path="/samples/first.exe",
            sample_size=100,
            platform="windows",
            architecture="x86",
        )

        # Attempting to create another analysis with same session_id should fail
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            store.create_analysis(
                session_id="duplicate-session-id",
                sample_sha256="b" * 64,
                sample_path="/samples/second.exe",
                sample_size=200,
                platform="linux",
                architecture="x86_64",
            )


class TestUpdateAnalysisStatus:
    """Test analysis status updates."""

    def test_update_status_to_running(self, db_path):
        """Update analysis status from pending to running."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        store.update_analysis_status("test-session", "running")

        analysis = store.get_analysis("test-session")
        assert analysis.status == "running"

    def test_update_status_to_completed(self, db_path):
        """Update analysis status to completed with duration."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        # Must transition through running state first
        store.update_analysis_status("test-session", "running")

        completed_at = datetime(2026, 4, 20, 18, 45, 45, tzinfo=timezone.utc)
        store.update_analysis_status(
            "test-session",
            "completed",
            completed_at=completed_at,
            duration_seconds=45.2,
        )

        analysis = store.get_analysis("test-session")
        assert analysis.status == "completed"
        # SQLite doesn't preserve timezone info, compare naive datetime
        assert analysis.completed_at == completed_at.replace(tzinfo=None)
        assert analysis.duration_seconds == 45.2

    def test_update_status_to_failed(self, db_path):
        """Update analysis status to failed with error message."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        store.update_analysis_status(
            "test-session",
            "failed",
            error_message="Timeout after 60 seconds",
        )

        analysis = store.get_analysis("test-session")
        assert analysis.status == "failed"
        assert analysis.error_message == "Timeout after 60 seconds"

    def test_update_nonexistent_analysis(self, db_path):
        """Updating nonexistent analysis should raise KeyError."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        # Should raise KeyError for nonexistent analysis
        with pytest.raises(KeyError):
            store.update_analysis_status("nonexistent-session", "completed")


class TestFindings:
    """Test technique finding operations."""

    def test_add_finding(self, db_path):
        """Add a technique finding to an analysis."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        first_seen = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)
        last_seen = datetime(2026, 4, 20, 18, 45, 5, tzinfo=timezone.utc)

        finding = store.add_finding(
            analysis_id=analysis.id,
            technique_id="T1055.001",
            technique_name="Dynamic-link Library Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.95,
            evidence_count=5,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        assert finding.technique_id == "T1055.001"
        assert finding.technique_name == "Dynamic-link Library Injection"
        assert finding.tactic == "defense-evasion"
        assert finding.confidence == "high"
        assert finding.confidence_score == 0.95
        assert finding.evidence_count == 5
        # SQLite doesn't preserve timezone info, compare naive datetime
        assert finding.first_seen == first_seen.replace(tzinfo=None)
        assert finding.last_seen == last_seen.replace(tzinfo=None)

    def test_add_multiple_findings(self, db_path):
        """Add multiple findings to same analysis."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        base_time = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)

        store.add_finding(
            analysis_id=analysis.id,
            technique_id="T1055.001",
            technique_name="Dynamic-link Library Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.95,
            evidence_count=5,
            first_seen=base_time,
            last_seen=base_time,
        )

        store.add_finding(
            analysis_id=analysis.id,
            technique_id="T1547.001",
            technique_name="Registry Run Keys",
            tactic="persistence",
            confidence="high",
            confidence_score=0.88,
            evidence_count=3,
            first_seen=base_time,
            last_seen=base_time,
        )

        # Verify both findings exist
        from sqlalchemy.orm import Session
        with Session(store.engine) as session:
            stmt = select(Finding).where(Finding.analysis_id == analysis.id)
            findings = list(session.scalars(stmt))

        assert len(findings) == 2
        technique_ids = {f.technique_id for f in findings}
        assert "T1055.001" in technique_ids
        assert "T1547.001" in technique_ids


class TestAPICalls:
    """Test API call logging."""

    def test_add_api_call_windows(self, db_path):
        """Add a Windows API call."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        timestamp = datetime(2026, 4, 20, 18, 45, 0, 123000, tzinfo=timezone.utc)
        params = {"lpCommandLine": "powershell -enc base64data"}

        api_call = store.add_api_call(
            analysis_id=analysis.id,
            timestamp=timestamp,
            api_name="CreateProcessA",
            syscall_name=None,
            address="0x77DD1234",
            params_json=params,  # Pass dict directly, not JSON string
            return_value="True",
            technique_id="T1059.001",
            confidence="high",
        )

        assert api_call.api_name == "CreateProcessA"
        assert api_call.syscall_name is None
        assert api_call.address == "0x77DD1234"
        assert api_call.params_json == params
        assert api_call.return_value == "True"
        assert api_call.technique_id == "T1059.001"
        assert api_call.confidence == "high"
        assert api_call.sequence_number == 1

    def test_add_api_call_linux_syscall(self, db_path):
        """Add a Linux syscall."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="b" * 64,
            sample_path="/samples/test.elf",
            sample_size=2000,
            platform="linux",
            architecture="x86_64",
        )

        timestamp = datetime(2026, 4, 20, 18, 45, 0, 456000, tzinfo=timezone.utc)
        params = {"filename": "/bin/bash", "argv": ["bash", "-c", "id"]}

        api_call = store.add_api_call(
            analysis_id=analysis.id,
            timestamp=timestamp,
            api_name=None,
            syscall_name="execve",
            address="0x400123",
            params_json=params,  # Pass dict directly
            return_value="0",
            technique_id="T1059.004",
            confidence="high",
        )

        assert api_call.api_name is None
        assert api_call.syscall_name == "execve"
        assert api_call.params_json == params
        assert api_call.sequence_number == 1

    def test_add_api_call_without_mapping(self, db_path):
        """Add API call without ATT&CK mapping."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        timestamp = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)

        api_call = store.add_api_call(
            analysis_id=analysis.id,
            timestamp=timestamp,
            api_name="GetTickCount",
            syscall_name=None,
            address="0x77DD5678",
            params_json=None,
            return_value="12345678",
            technique_id=None,
            confidence=None,
        )

        assert api_call.api_name == "GetTickCount"
        assert api_call.technique_id is None
        assert api_call.confidence is None


class TestStrings:
    """Test string extraction storage."""

    def test_add_string(self, db_path):
        """Add an extracted string."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        string = store.add_string(
            analysis_id=analysis.id,
            value="powershell -enc",
            address="0x00401234",
            context="api_param",
        )

        assert string.value == "powershell -enc"
        assert string.address == "0x00401234"
        assert string.context == "api_param"

    def test_add_string_minimal(self, db_path):
        """Add string with only required fields."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        string = store.add_string(
            analysis_id=analysis.id,
            value="http://malicious-domain.com/beacon",
        )

        assert string.value == "http://malicious-domain.com/beacon"
        assert string.address is None
        assert string.context is None

    def test_add_string_with_unicode(self, db_path):
        """Add string containing unicode characters."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        string = store.add_string(
            analysis_id=analysis.id,
            value="C:\\Users\\Пользователь\\file.txt",
            address="0x00401234",
            context="file_path",
        )

        assert string.value == "C:\\Users\\Пользователь\\file.txt"


class TestGetAnalysis:
    """Test analysis retrieval."""

    def test_get_analysis_exists(self, db_path):
        """Get existing analysis by session ID."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        created = store.create_analysis(
            session_id="test-session-123",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        retrieved = store.get_analysis("test-session-123")

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.session_id == created.session_id

    def test_get_analysis_not_found(self, db_path):
        """Get nonexistent analysis returns None."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        retrieved = store.get_analysis("nonexistent-session")

        assert retrieved is None


class TestListAnalyses:
    """Test analysis listing with filters."""

    def test_list_analyses_empty(self, db_path):
        """List analyses when database is empty."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        result = store.list_analyses()

        assert result.items == []
        assert result.total == 0
        assert result.page == 1
        assert result.per_page == 20
        assert result.pages == 0

    def test_list_analyses_all(self, db_path):
        """List all analyses without filters."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        for i in range(5):
            store.create_analysis(
                session_id=f"session-{i}",
                sample_sha256=chr(ord("a") + i) * 64,
                sample_path=f"/samples/test{i}.exe",
                sample_size=1000 + i * 100,
                platform="windows" if i % 2 == 0 else "linux",
                architecture="x86" if i % 2 == 0 else "x86_64",
            )

        result = store.list_analyses()

        assert len(result.items) == 5
        assert result.total == 5
        # Should be ordered by created_at descending (most recent first)
        assert result.items[0].session_id == "session-4"
        assert result.items[4].session_id == "session-0"

    def test_list_analyses_filter_by_status(self, db_path):
        """List analyses filtered by status."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        store.create_analysis(
            session_id="completed-1",
            sample_sha256="a" * 64,
            sample_path="/samples/test1.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )
        store.update_analysis_status("completed-1", "running")
        store.update_analysis_status("completed-1", "completed")

        store.create_analysis(
            session_id="failed-1",
            sample_sha256="b" * 64,
            sample_path="/samples/test2.exe",
            sample_size=2000,
            platform="windows",
            architecture="x86",
        )
        store.update_analysis_status("failed-1", "running")
        store.update_analysis_status("failed-1", "failed", error_message="Error")

        store.create_analysis(
            session_id="pending-1",
            sample_sha256="c" * 64,
            sample_path="/samples/test3.exe",
            sample_size=3000,
            platform="linux",
            architecture="x86_64",
        )

        completed = store.list_analyses(status="completed")
        assert len(completed.items) == 1
        assert completed.items[0].session_id == "completed-1"

        failed = store.list_analyses(status="failed")
        assert len(failed.items) == 1
        assert failed.items[0].session_id == "failed-1"

        pending = store.list_analyses(status="pending")
        assert len(pending.items) == 1
        assert pending.items[0].session_id == "pending-1"

    def test_list_analyses_filter_by_platform(self, db_path):
        """List analyses filtered by platform."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        for i in range(3):
            store.create_analysis(
                session_id=f"windows-{i}",
                sample_sha256=chr(ord("a") + i) * 64,
                sample_path=f"/samples/win{i}.exe",
                sample_size=1000,
                platform="windows",
                architecture="x86",
            )

        for i in range(2):
            store.create_analysis(
                session_id=f"linux-{i}",
                sample_sha256=chr(ord("A") + i) * 64,
                sample_path=f"/samples/lin{i}.elf",
                sample_size=2000,
                platform="linux",
                architecture="x86_64",
            )

        windows = store.list_analyses(platform="windows")
        assert len(windows.items) == 3
        assert all(a.platform == "windows" for a in windows.items)

        linux = store.list_analyses(platform="linux")
        assert len(linux.items) == 2
        assert all(a.platform == "linux" for a in linux.items)

    def test_list_analyses_pagination(self, db_path):
        """List analyses with pagination."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        for i in range(25):
            store.create_analysis(
                session_id=f"session-{i:02d}",
                sample_sha256=chr(ord("a") + (i % 26)) * 64,
                sample_path=f"/samples/test{i}.exe",
                sample_size=1000,
                platform="windows",
                architecture="x86",
            )

        # First page
        page1 = store.list_analyses(limit=10, offset=0)
        assert len(page1.items) == 10
        assert page1.page == 1
        assert page1.total == 25
        assert page1.items[0].session_id == "session-24"

        # Second page
        page2 = store.list_analyses(limit=10, offset=10)
        assert len(page2.items) == 10
        assert page2.page == 2
        assert page2.items[0].session_id == "session-14"

        # Third page
        page3 = store.list_analyses(limit=10, offset=20)
        assert len(page3.items) == 5
        assert page3.page == 3
        assert page3.items[0].session_id == "session-04"


class TestCascadeDelete:
    """Test cascade delete behavior."""

    def test_delete_analysis_cascades_to_findings(self, db_path):
        """Deleting analysis removes associated findings."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        base_time = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)
        store.add_finding(
            analysis_id=analysis.id,
            technique_id="T1055.001",
            technique_name="DLL Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.9,
            evidence_count=5,
            first_seen=base_time,
            last_seen=base_time,
        )

        # Delete the analysis
        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.id == analysis.id)
            analysis_obj = session.scalar(stmt)
            session.delete(analysis_obj)
            session.commit()

        # Verify findings are also deleted
        with Session(store.engine) as session:
            stmt = select(Finding).where(Finding.analysis_id == analysis.id)
            findings = list(session.scalars(stmt))

        assert len(findings) == 0

    def test_delete_analysis_cascades_to_api_calls(self, db_path):
        """Deleting analysis removes associated API calls."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        timestamp = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)
        for i in range(5):
            store.add_api_call(
                analysis_id=analysis.id,
                timestamp=timestamp,
                api_name=f"ApiCall{i}",
                syscall_name=None,
                address=f"0x{i:08x}",
                params_json=None,
                return_value="0",
            )

        # Delete the analysis
        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.id == analysis.id)
            analysis_obj = session.scalar(stmt)
            session.delete(analysis_obj)
            session.commit()

        # Verify API calls are also deleted
        with Session(store.engine) as session:
            stmt = select(APICall).where(APICall.analysis_id == analysis.id)
            api_calls = list(session.scalars(stmt))

        assert len(api_calls) == 0

    def test_delete_analysis_cascades_to_strings(self, db_path):
        """Deleting analysis removes associated strings."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        for i in range(3):
            store.add_string(
                analysis_id=analysis.id,
                value=f"string_{i}",
                address=f"0x{i:08x}",
            )

        # Delete the analysis
        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.id == analysis.id)
            analysis_obj = session.scalar(stmt)
            session.delete(analysis_obj)
            session.commit()

        # Verify strings are also deleted
        with Session(store.engine) as session:
            stmt = select(String).where(String.analysis_id == analysis.id)
            strings = list(session.scalars(stmt))

        assert len(strings) == 0


class TestAnalysisRelationships:
    """Test ORM relationship access."""

    def test_analysis_findings_relationship(self, db_path):
        """Access findings through analysis relationship."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        base_time = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)
        store.add_finding(
            analysis_id=analysis.id,
            technique_id="T1055.001",
            technique_name="DLL Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.9,
            evidence_count=5,
            first_seen=base_time,
            last_seen=base_time,
        )

        # Access through relationship
        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == "test-session")
            retrieved = session.scalar(stmt)
            # Refresh to load relationship
            session.refresh(retrieved)

            assert len(retrieved.findings) == 1
            assert retrieved.findings[0].technique_id == "T1055.001"

    def test_analysis_api_calls_relationship(self, db_path):
        """Access api_calls through analysis relationship."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        timestamp = datetime(2026, 4, 20, 18, 45, 0, tzinfo=timezone.utc)
        store.add_api_call(
            analysis_id=analysis.id,
            timestamp=timestamp,
            api_name="CreateProcessA",
            syscall_name=None,
            address="0x12345678",
            params_json=None,
            return_value="True",
        )

        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == "test-session")
            retrieved = session.scalar(stmt)
            session.refresh(retrieved)

            assert len(retrieved.api_calls) == 1
            assert retrieved.api_calls[0].api_name == "CreateProcessA"

    def test_analysis_strings_relationship(self, db_path):
        """Access strings through analysis relationship."""
        store = DatabaseStore(db_path)
        init_database(db_path)

        analysis = store.create_analysis(
            session_id="test-session",
            sample_sha256="a" * 64,
            sample_path="/samples/test.exe",
            sample_size=1000,
            platform="windows",
            architecture="x86",
        )

        store.add_string(
            analysis_id=analysis.id,
            value="malicious_string",
            address="0x00401234",
        )

        with Session(store.engine) as session:
            stmt = select(Analysis).where(Analysis.session_id == "test-session")
            retrieved = session.scalar(stmt)
            session.refresh(retrieved)

            assert len(retrieved.strings) == 1
            assert retrieved.strings[0].value == "malicious_string"
