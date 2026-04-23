"""CLI tests for Detonate."""

import json
import subprocess
import sys
import os
from pathlib import Path

import pytest

from detonate.db.init_db import init_database
from detonate.db.store import DatabaseStore
from detonate.db.models import Analysis


@pytest.fixture
def cli_runner():
    """Create a CLI test runner using subprocess."""
    import shutil
    
    detonate_bin = shutil.which("detonate", path="/home/ubuntu/detonate/.venv/bin")
    if not detonate_bin:
        detonate_bin = "/home/ubuntu/detonate/.venv/bin/detonate"
    
    def run_cli(args, env=None, cwd=None):
        """Run CLI command and return result."""
        import os
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        
        result = subprocess.run(
            [detonate_bin] + args,
            capture_output=True,
            text=True,
            env=full_env,
            cwd=cwd,
        )
        return type('Result', (), {
            'exit_code': result.returncode,
            'output': result.stdout + result.stderr,
            'stdout': result.stdout,
            'stderr': result.stderr,
        })()
    
    return run_cli


@pytest.fixture
def populated_db(temp_dir):
    """Create a database with sample analysis data."""
    db_path = str(temp_dir / "test.db")
    init_database(db_path)
    
    db = DatabaseStore(db_path)
    
    # Create an analysis
    analysis = db.create_analysis(
        session_id="550e8400-e29b-41d4-a716-446655440000",
        sample_sha256="4a8c3d2e1f0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c",
        sample_md5="d41d8cd98f00b204e9800998ecf8427e",
        sample_path="/samples/test.exe",
        sample_size=12345,
        file_type="PE32 executable",
        platform="windows",
        architecture="x86",
    )
    
    # Add a finding
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="execution",
        confidence="high",
        confidence_score=0.9,
        evidence_count=3,
        first_seen=now,
        last_seen=now,
    )
    
    # Add an API call
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name="CreateProcessA",
        syscall_name=None,
        address="0x12345678",
        params_json={"lpCommandLine": "powershell -enc SGVsbG8gV29ybGQ="},
        return_value="True",
        technique_id="T1059.001",
        confidence="high",
    )
    
    return db_path


@pytest.fixture
def edge_case_db(temp_dir):
    """Create a database with edge-case analysis data for testing robustness.
    
    Includes:
    - None optional fields (sample_md5, duration_seconds, file_type)
    - API calls with non-string params (int, bool)
    - Long parameter values for truncation testing
    - A finding to test detailed findings section
    """
    db_path = str(temp_dir / "edge_case.db")
    init_database(db_path)
    
    db = DatabaseStore(db_path)
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    # Create an analysis with None optional fields
    analysis = db.create_analysis(
        session_id="660e8400-e29b-41d4-a716-446655440001",
        sample_sha256="5b9d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d",
        sample_md5=None,  # Edge case: None optional field
        sample_path="/samples/edge_case.exe",
        sample_size=54321,
        file_type=None,  # Edge case: None optional field
        platform="linux",
        architecture="x86_64",
    )
    
    # Manually set duration_seconds to None (it's computed, but test needs it None)
    from sqlalchemy import update
    with db.engine.connect() as conn:
        from sqlalchemy.orm import Session as SQLASession
        with SQLASession(conn) as session:
            session.execute(
                update(Analysis)
                .where(Analysis.id == analysis.id)
                .values(duration_seconds=None)
            )
            session.commit()
    
    # Add API call with non-string params (int, bool, nested dict)
    # Use CreateProcessA so it appears in Process Activity section
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name="CreateProcessA",
        syscall_name=None,
        address="0x87654321",
        params_json={
            "lpCommandLine": "C:\\very\\long\\path\\to\\executable\\that\\exceeds\\thirty\\characters\\program.exe",  # Long string for truncation
            "count": 5,  # int
            "recursive": True,  # bool
        },
        return_value="True",
        technique_id=None,
        confidence="medium",
    )
    
    # Add another API call with very long string parameter for file system section
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name="CreateFileA",
        syscall_name=None,
        address="0x11111111",
        params_json={
            "lpFileName": "/home/user/very_long_path/to/some/file/that/is/quite/deep/in/the/directory/structure/file.txt",  # Long path
        },
        return_value="0x123",
        technique_id=None,
        confidence="low",
    )
    
    # Add network API call to test _summarize_params truncation in Network Activity section
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name="InternetOpenA",
        syscall_name=None,
        address="0x22222222",
        params_json={
            "lpszAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 with very long user agent string",  # >30 chars
        },
        return_value="0x456",
        technique_id=None,
        confidence="medium",
    )
    
    # Add a finding with evidence to test detailed findings section
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1102",
        technique_name="Web Service",
        tactic="command_and_control",
        confidence="medium",
        confidence_score=0.6,
        evidence_count=1,
        first_seen=now,
        last_seen=now,
    )
    
    return db_path


@pytest.fixture
def empty_findings_db(temp_dir):
    """Create a database with analysis that has no findings (empty findings list)."""
    db_path = str(temp_dir / "empty_findings.db")
    init_database(db_path)
    
    db = DatabaseStore(db_path)
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    # Create an analysis with no findings
    analysis = db.create_analysis(
        session_id="770e8400-e29b-41d4-a716-446655440002",
        sample_sha256="6c0e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e",
        sample_md5="abc123",
        sample_path="/samples/clean.exe",
        sample_size=1000,
        file_type="ELF",
        platform="linux",
        architecture="x86_64",
    )
    
    # No findings added - tests empty findings list
    
    return db_path


@pytest.fixture
def malformed_findings_db(temp_dir):
    """Create a database with edge-case findings for robustness testing.
    
    Tests boundary conditions and None handling:
    - Findings at confidence_score boundaries (0.0 and 1.0)
    - Finding with evidence_count=0 (boundary condition)
    - API call with api_name but NULL syscall_name (valid per schema)
    - API call with syscall_name but NULL api_name (valid per schema)
    """
    db_path = str(temp_dir / "malformed_findings.db")
    init_database(db_path)
    
    db = DatabaseStore(db_path)
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    # Create an analysis
    analysis = db.create_analysis(
        session_id="880e8400-e29b-41d4-a716-446655440003",
        sample_sha256="7d1e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e",
        sample_md5="malformed123",
        sample_path="/samples/malformed.exe",
        sample_size=2000,
        file_type="PE32",
        platform="windows",
        architecture="x86",
    )
    
    # Valid finding for baseline
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="execution",
        confidence="high",
        confidence_score=0.9,
        evidence_count=3,
        first_seen=now,
        last_seen=now,
    )
    
    # Finding at confidence_score boundary (1.0 - max valid)
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1055.001",
        technique_name="DLL Injection",
        tactic="defense_evasion",
        confidence="high",
        confidence_score=1.0,  # Boundary: max valid
        evidence_count=2,
        first_seen=now,
        last_seen=now,
    )
    
    # Finding at confidence_score boundary (0.0 - min valid)
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic="defense_evasion",
        confidence="low",
        confidence_score=0.0,  # Boundary: min valid
        evidence_count=1,
        first_seen=now,
        last_seen=now,
    )
    
    # Finding with evidence_count=0 (boundary condition)
    db.add_finding(
        analysis_id=analysis.id,
        technique_id="T1070",
        technique_name="Indicator Removal",
        tactic="defense_evasion",
        confidence="medium",
        confidence_score=0.5,
        evidence_count=0,  # Boundary: zero evidence
        first_seen=now,
        last_seen=now,
    )
    
    # API call with api_name but NULL syscall_name (valid)
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name="CreateProcessA",
        syscall_name=None,  # NULL syscall_name is valid
        address="0x12345678",
        params_json={"lpCommandLine": "cmd.exe"},
        return_value="True",
        technique_id="T1059.001",
        confidence="high",
    )
    
    # API call with syscall_name but NULL api_name (valid)
    db.add_api_call(
        analysis_id=analysis.id,
        timestamp=now,
        api_name=None,  # NULL api_name is valid
        syscall_name="sys_open",
        address="0x87654321",
        params_json={"filename": "/etc/passwd"},
        return_value="0x3",
        technique_id="T1027",
        confidence="low",
    )
    
    return db_path


class TestDbCommands:
    """Test database CLI commands."""
    
    def test_db_init_creates_database(self, cli_runner, temp_dir):
        """Test db init command creates database."""
        db_path = str(temp_dir / "new.db")
        
        result = cli_runner(["db", "init"], env={"DETONATE_DATABASE": db_path})
        
        assert result.exit_code == 0
        assert "Database initialized" in result.output
        assert Path(db_path).exists()
    
    def test_db_migrate_applies_migrations(self, cli_runner, temp_dir):
        """Test db migrate command applies migrations."""
        db_path = str(temp_dir / "migrate.db")
        
        result = cli_runner(["db", "migrate"], env={"DETONATE_DATABASE": db_path})
        
        assert result.exit_code == 0
        assert "Database migrations applied" in result.output
        assert Path(db_path).exists()


class TestExportCommand:
    """Test export command."""
    
    def test_export_report_format(self, cli_runner, populated_db):
        """Test export with report format."""
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "-f", "report",
        ], env={"DETONATE_DATABASE": populated_db})
        
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout: {result.stdout[:1000]}")
        print(f"Stderr: {result.stderr[:1000]}")
        
        assert result.exit_code == 0
        assert "Detonate Analysis Report" in result.output
        assert "T1059.001" in result.output
        assert "PowerShell" in result.output
    
    def test_export_report_edge_cases(self, cli_runner, edge_case_db):
        """Test export with edge-case data: None fields, non-string params, long params."""
        result = cli_runner([
            "export",
            "660e8400-e29b-41d4-a716-446655440001",
            "-f", "report",
        ], env={"DETONATE_DATABASE": edge_case_db})
        
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout: {result.stdout[:2000]}")
        print(f"Stderr: {result.stderr[:1000]}")
        
        # Should not raise TypeError or KeyError
        assert result.exit_code == 0
        
        # Report should render without error
        assert "Detonate Analysis Report" in result.output
        
        # Should handle None fields gracefully (no "None" string in output for missing fields)
        # MD5 field should not appear since it's None
        assert "MD5" not in result.output
        
        # Duration should not appear since it's None
        assert "Duration" not in result.output
        
        # File type should show "Unknown" for None
        assert "Unknown" in result.output
        
        # Long file paths should appear
        assert "very_long_path" in result.output
        
        # Truncation should occur for long network params (30 char limit + "...")
        assert "Mozilla/5.0 (Windows NT 10...." in result.output
    
    def test_export_report_empty_findings(self, cli_runner, empty_findings_db):
        """Test export with empty findings list shows 'No techniques detected'."""
        result = cli_runner([
            "export",
            "770e8400-e29b-41d4-a716-446655440002",
            "-f", "report",
        ], env={"DETONATE_DATABASE": empty_findings_db})
        
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout: {result.stdout[:1500]}")
        print(f"Stderr: {result.stderr[:500]}")
        
        # Should not raise error
        assert result.exit_code == 0
        
        # Report should render without error
        assert "Detonate Analysis Report" in result.output
        
        # Empty findings should show "No techniques detected"
        assert "No techniques detected" in result.output
    
    def test_export_navigator_format(self, cli_runner, populated_db):
        """Test export with navigator format."""
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "--format", "navigator",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "4.5"
        assert "techniques" in data
        assert len(data["techniques"]) > 0
        assert data["techniques"][0]["techniqueID"] == "T1059.001"
    
    def test_export_navigator_edge_cases(self, cli_runner, malformed_findings_db):
        """Test export with navigator format handles edge cases gracefully.
        
        Edge cases tested:
        (1) Findings at confidence_score boundaries (0.0 and 1.0)
        (2) Finding with evidence_count=0 (boundary condition)
        (3) API calls with NULL api_name or NULL syscall_name (valid per schema)
        (4) Score calculation handles boundary values correctly
        """
        result = cli_runner([
            "export",
            "880e8400-e29b-41d4-a716-446655440003",
            "--format", "navigator",
        ], env={"DETONATE_DATABASE": malformed_findings_db})
        
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout: {result.stdout[:2000]}")
        print(f"Stderr: {result.stderr[:1000]}")
        
        # Should not crash - should handle edge cases gracefully
        assert result.exit_code == 0
        
        data = json.loads(result.output)
        assert data["version"] == "4.5"
        assert "techniques" in data
        
        # Should have multiple findings including boundary cases
        technique_ids = [t["techniqueID"] for t in data["techniques"]]
        
        # All valid findings should be present
        assert "T1059.001" in technique_ids, "Valid finding should be included"
        assert "T1055.001" in technique_ids, "confidence_score=1.0 finding should be included"
        assert "T1027" in technique_ids, "confidence_score=0.0 finding should be included"
        assert "T1070" in technique_ids, "evidence_count=0 finding should be included"
        
        # Check that techniques have valid structure
        for technique in data["techniques"]:
            assert "techniqueID" in technique
            assert "tactic" in technique
            assert "score" in technique
            assert isinstance(technique["score"], int)
            assert 0 <= technique["score"] <= 10, f"Score should be clamped to [0, 10], got {technique['score']}"
            
            # Check comment field is always a string
            if "comment" in technique:
                assert isinstance(technique["comment"], str), "Comment should always be a string"
        
        # Verify score calculation for boundary cases
        technique_by_id = {t["techniqueID"]: t for t in data["techniques"]}
        
        # confidence_score=1.0, evidence_count=2 -> score should be high (but capped at 10)
        # formula: 1.0 * 10 * log(2+1) = 10 * 1.099 = 10.99 -> capped to 10
        assert technique_by_id["T1055.001"]["score"] == 10, "Max confidence should yield max score"
        
        # confidence_score=0.0, evidence_count=1 -> score should be 0
        # formula: 0.0 * 10 * log(1+1) = 0
        assert technique_by_id["T1027"]["score"] == 0, "Zero confidence should yield zero score"
        
        # confidence_score=0.5, evidence_count=0 -> score should be 0
        # formula: 0.5 * 10 * log(0+1) = 0.5 * 10 * 0 = 0
        assert technique_by_id["T1070"]["score"] == 0, "Zero evidence should yield zero score"
    
    def test_export_stix_format(self, cli_runner, populated_db):
        """Test export with STIX format."""
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "-f", "stix",
        ], env={"DETONATE_DATABASE": populated_db})
        
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout: {result.stdout[:1000]}")
        print(f"Stderr: {result.stderr[:1000]}")
        
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "objects" in data
        # Should have malware, attack-pattern, relationship objects
        object_types = {obj["type"] for obj in data["objects"]}
        assert "malware" in object_types
    
    def test_export_log_format(self, cli_runner, populated_db):
        """Test export with JSON log format."""
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "--format", "log",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        # Should be JSON lines format
        lines = result.output.strip().split("\n")
        assert len(lines) > 0
        entry = json.loads(lines[0])
        assert "api" in entry or "syscall" in entry
    
    def test_export_not_found(self, cli_runner, populated_db):
        """Test export with nonexistent session ID."""
        result = cli_runner([
            "export",
            "00000000-0000-0000-0000-000000000000",
            "--format", "report",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 1
        assert "Analysis not found" in result.output
    
    def test_export_invalid_format(self, cli_runner, populated_db):
        """Test export with invalid format."""
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "--format", "invalid",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 1
        assert "Invalid format" in result.output
    
    def test_export_to_file(self, cli_runner, populated_db, temp_dir):
        """Test export to file."""
        output_path = str(temp_dir / "exported_report.md")
        
        result = cli_runner([
            "export",
            "550e8400-e29b-41d4-a716-446655440000",
            "--format", "report",
            "--output", output_path,
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        assert "Exported report to" in result.output
        assert Path(output_path).exists()
        content = Path(output_path).read_text()
        assert "Detonate Analysis Report" in content


class TestListAnalysesCommand:
    """Test list-analyses command."""
    
    def test_list_analyses_empty(self, cli_runner, temp_dir):
        """Test list-analyses with empty database."""
        db_path = str(temp_dir / "empty.db")
        init_database(db_path)
        
        result = cli_runner(["list-analyses"], env={"DETONATE_DATABASE": db_path})
        
        assert result.exit_code == 0
        assert "No analyses found" in result.output
    
    def test_list_analyses_with_data(self, cli_runner, populated_db):
        """Test list-analyses with data."""
        result = cli_runner(["list-analyses"], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        assert "550e8400" in result.output
        assert "windows" in result.output
    
    def test_list_analyses_json_format(self, cli_runner, populated_db):
        """Test list-analyses with JSON format."""
        result = cli_runner(["list-analyses", "--format", "json"], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["session_id"] == "550e8400-e29b-41d4-a716-446655440000"


class TestShowCommand:
    """Test show command."""
    
    def test_show_analysis(self, cli_runner, populated_db):
        """Test show command with valid session."""
        result = cli_runner([
            "show",
            "550e8400-e29b-41d4-a716-446655440000",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 0
        assert "Session ID:" in result.output
        assert "windows" in result.output
    
    def test_show_not_found(self, cli_runner, populated_db):
        """Test show command with nonexistent session."""
        result = cli_runner([
            "show",
            "00000000-0000-0000-0000-000000000000",
        ], env={"DETONATE_DATABASE": populated_db})
        
        assert result.exit_code == 1
        assert "Analysis not found" in result.output


class TestServeCommand:
    """Test serve command."""
    
    def test_serve_help(self, cli_runner):
        """Test serve command help."""
        result = cli_runner(["serve", "--help"])
        
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output
