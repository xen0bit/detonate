"""CLI tests for Detonate."""

import json
import subprocess
import sys
import os
from pathlib import Path

import pytest

from detonate.db.init_db import init_database
from detonate.db.store import DatabaseStore


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
        # TODO: Prior test only covers happy-path with complete data. Missing edge cases:
        # (1) Analysis with None optional fields (sample_md5=None, duration_seconds=None,
        #     file_type=None) — report generator must handle gracefully
        # (2) API calls with non-string params (int, bool, nested dict/list) —
        #     _summarize_params() must serialize correctly without TypeError
        # (3) Empty findings list — report should show "No techniques detected"
        # (4) Very long parameter values (>30 chars) — truncation with "..." suffix
        # Add fixture for edge-case analysis and assert report renders without error.
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
    
    def test_export_navigator_format(self, cli_runner, populated_db):
        """Test export with navigator format."""
        # TODO: Prior test lacks edge cases for navigator generation:
        # (1) Findings with invalid confidence_score (<0 or >1) should be skipped
        # (2) Findings with missing required fields (technique_id=None) should be skipped
        # (3) Evidence records with None api_name and None syscall_name — should use "unknown"
        # (4) Negative evidence_count should be rejected or handled
        # Add test with malformed findings fixture and verify they're filtered out.
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
