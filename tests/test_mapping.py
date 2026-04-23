"""Tests for ATT&CK mapping engine."""

from detonate.mapping.engine import ATTCKMapper, TechniqueMatch


class TestATTCKMapper:
    """Test ATT&CK mapping engine."""

    def test_map_windows_api(self):
        """Test Windows API mapping."""
        mapper = ATTCKMapper()

        # Test CreateProcessA with PowerShell
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "powershell -enc base64"},
            platform="windows",
        )

        assert result is not None
        assert result.technique_id == "T1059.001"
        assert result.technique_name == "PowerShell"
        assert result.tactic == "execution"
        assert result.confidence == "high"

    def test_map_windows_api_generic(self):
        """Test generic Windows API mapping."""
        mapper = ATTCKMapper()

        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )

        assert result is not None
        assert result.technique_id == "T1106"
        assert result.confidence == "medium"

    def test_map_linux_syscall(self):
        """Test Linux syscall mapping."""
        mapper = ATTCKMapper()

        result = mapper.map_api_call(
            "execve",
            {"filename": "/bin/bash", "argv": ["/bin/bash", "-c", "id"]},
            platform="linux",
        )

        assert result is not None
        assert result.technique_id == "T1059.004"
        assert result.technique_name == "Unix Shell"
        assert result.tactic == "execution"

    def test_map_credential_access(self):
        """Test credential access detection."""
        mapper = ATTCKMapper()

        result = mapper.map_api_call(
            "open",
            {"filename": "/etc/shadow"},
            platform="linux",
        )

        assert result is not None
        assert result.technique_id == "T1003.008"
        assert "Credential" in result.technique_name

    def test_evidence_accumulation(self):
        """Test evidence count increases confidence."""
        mapper = ATTCKMapper()

        # First call - use generic API match (not param-refined)
        result1 = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )
        initial_score = result1.confidence_score

        # Second call (same technique)
        result2 = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "calc.exe"},
            platform="windows",
        )

        # Evidence count should increase
        assert result2.evidence_count == 2
        # Confidence should not decrease
        assert result2.confidence_score >= initial_score

    def test_unknown_api(self):
        """Test mapping for unknown API."""
        mapper = ATTCKMapper()

        result = mapper.map_api_call(
            "UnknownAPI",
            {},
            platform="windows",
        )

        assert result is None

    def test_get_all_findings(self):
        """Test retrieving all findings."""
        mapper = ATTCKMapper()

        mapper.map_api_call("CreateProcessA", {"lpCommandLine": "powershell"}, platform="windows")
        mapper.map_api_call("RegSetValueExA", {"lpValueName": "Run"}, platform="windows")

        findings = mapper.get_all_findings()

        assert len(findings) == 2
        technique_ids = [f.technique_id for f in findings]
        assert "T1059.001" in technique_ids
