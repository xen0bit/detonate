"""Tests for STIX Indicator generation."""

import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from src.detonate.core.session import APICallRecord
from src.detonate.output.indicators import (
    should_generate_indicators,
    generate_indicator_from_api_call,
    generate_indicators_for_session,
    _calculate_confidence,
)


class TestShouldGenerateIndicators:
    """Test environment variable control."""

    def test_disabled_by_default(self):
        """Indicator generation should be disabled by default."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove the variable if it exists
            os.environ.pop("DETONATE_GENERATE_INDICATORS", None)
            assert should_generate_indicators() is False

    def test_enabled_with_true(self):
        """Indicator generation enabled with 'true'."""
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            assert should_generate_indicators() is True

    def test_enabled_with_True(self):
        """Indicator generation enabled with 'True' (case insensitive)."""
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "True"}):
            assert should_generate_indicators() is True

    def test_enabled_with_1(self):
        """Indicator generation enabled with '1'."""
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "1"}):
            # Should be false since we check for "true" specifically
            assert should_generate_indicators() is False

    def test_disabled_with_false(self):
        """Indicator generation disabled with 'false'."""
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "false"}):
            assert should_generate_indicators() is False


class TestPowerShellExecutionIndicators:
    """Test PowerShell execution detection."""

    def test_powershell_via_createprocess(self):
        """Detect PowerShell execution via CreateProcessA."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={"lpCommandLine": "powershell.exe -EncodedCommand JAB"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "PowerShell" in indicator.name
        assert "powershell" in indicator.pattern.lower()

    def test_pwsh_via_createprocess(self):
        """Detect pwsh (PowerShell Core) execution."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessW",
            syscall_name=None,
            params={"lpCommandLine": "pwsh -Command Get-Process"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "PowerShell" in indicator.name

    def test_cmd_execution(self):
        """Detect cmd.exe execution."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={"lpCommandLine": "cmd.exe /c whoami"},
            return_value=0,
            address="0x401000",
            confidence="medium",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Command Shell" in indicator.name
        assert "cmd" in indicator.pattern.lower()

    def test_bash_execution(self):
        """Detect bash execution."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={"lpCommandLine": "bash -c 'cat /etc/passwd'"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Bash" in indicator.name


class TestRegistryPersistenceIndicators:
    """Test registry persistence detection."""

    def test_run_key_persistence(self):
        """Detect Run key persistence."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="RegSetValueExA",
            syscall_name=None,
            params={
                "lpSubKey": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "lpValueName": "malware",
            },
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Registry" in indicator.name
        assert "Run" in indicator.name

    def test_runonce_key_persistence(self):
        """Detect RunOnce key persistence."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="RegCreateKeyExW",
            syscall_name=None,
            params={"lpSubKey": "CurrentVersion\\RunOnce"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None

    def test_service_registry_persistence(self):
        """Detect service registry modification."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="RegSetValueExW",
            syscall_name=None,
            params={"lpSubKey": "SYSTEM\\CurrentControlSet\\Services\\MalService"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Service" in indicator.name


class TestNetworkC2Indicators:
    """Test C2 communication detection."""

    def test_http_c2_connection(self):
        """Detect HTTP C2 connection."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="InternetConnectA",
            syscall_name=None,
            params={"lpszServerName": "evil-c2.example.com"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "C2" in indicator.name
        assert "evil-c2.example.com" in indicator.name

    def test_ip_c2_connection(self):
        """Detect IP-based C2 connection."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="HttpOpenRequestA",
            syscall_name=None,
            params={"server": "192.168.1.100"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "192.168.1.100" in indicator.name

    def test_localhost_excluded(self):
        """Localhost connections should not generate indicators."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="InternetConnectA",
            syscall_name=None,
            params={"lpszServerName": "127.0.0.1"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is None

    def test_linux_socket_connection(self):
        """Detect Linux socket connection."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="socket",
            syscall_name="socket",
            params={"server": "attacker.com", "domain": "2"},
            return_value=3,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None


class TestSuspiciousFileAccessIndicators:
    """Test suspicious file access detection."""

    def test_shadow_file_access(self):
        """Detect /etc/shadow access."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="openat",
            syscall_name="openat",
            params={"pathname": "/etc/shadow"},
            return_value=3,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "shadow" in indicator.name.lower()

    def test_ssh_key_access(self):
        """Detect SSH key access."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="open",
            syscall_name="open",
            params={"filename": "/home/user/.ssh/id_rsa"},
            return_value=3,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "ssh" in indicator.name.lower()

    def test_lsass_access(self):
        """Detect LSASS access."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateFileA",
            syscall_name=None,
            params={"lpFileName": "\\\\LSASS"},
            return_value=0xFFFFFFFF,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "LSASS" in indicator.name


class TestContainerEscapeIndicators:
    """Test container escape detection."""

    def test_mount_syscall(self):
        """Detect mount syscall (container escape)."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="mount",
            syscall_name="mount",
            params={"source": "/dev/sda1", "target": "/host"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Container Escape" in indicator.name

    def test_unshare_syscall(self):
        """Detect unshare syscall."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="unshare",
            syscall_name="unshare",
            params={"unshare_flags": "CLONE_NEWNS"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None


class TestCloudMetadataIndicators:
    """Test cloud metadata access detection."""

    def test_aws_metadata_access(self):
        """Detect AWS metadata endpoint access."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="connect",
            syscall_name="connect",
            params={"server": "169.254.169.254", "port": 80},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Cloud Metadata" in indicator.name

    def test_gcp_metadata_access(self):
        """Detect GCP metadata endpoint access."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="socket",
            syscall_name="socket",
            params={"server": "metadata.google.internal"},
            return_value=3,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None


class TestConfidenceCalculation:
    """Test confidence score calculation."""

    def test_high_confidence_base(self):
        """High confidence API call gets appropriate score."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        score = _calculate_confidence(api_call)
        assert score >= 80

    def test_medium_confidence_base(self):
        """Medium confidence API call gets appropriate score."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="medium",
        )
        
        score = _calculate_confidence(api_call)
        assert score >= 65

    def test_technique_id_bonus(self):
        """Technique ID adds bonus confidence."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="medium",
            technique_id="T1059.001",
        )
        
        score_with_id = _calculate_confidence(api_call)
        
        api_call_no_id = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="medium",
        )
        
        score_without_id = _calculate_confidence(api_call_no_id)
        assert score_with_id > score_without_id

    def test_subtechnique_bonus(self):
        """Sub-technique ID adds extra bonus."""
        api_call_sub = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="medium",
            technique_id="T1059.001",
        )
        
        api_call_parent = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="medium",
            technique_id="T1059",
        )
        
        score_sub = _calculate_confidence(api_call_sub)
        score_parent = _calculate_confidence(api_call_parent)
        assert score_sub > score_parent

    def test_capped_at_100(self):
        """Confidence score capped at 100."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
            confidence="high",
            technique_id="T1059.001",
        )
        
        score = _calculate_confidence(api_call)
        assert score <= 100


class TestGenerateIndicatorsForSession:
    """Test batch indicator generation."""

    def test_generates_multiple_indicators(self):
        """Generate multiple indicators from session."""
        api_calls = [
            APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="CreateProcessA",
                syscall_name=None,
                params={"lpCommandLine": "powershell.exe -EncodedCommand JAB"},
                return_value=0,
                address="0x401000",
                confidence="high",
            ),
            APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="InternetConnectA",
                syscall_name=None,
                params={"lpszServerName": "evil-c2.com"},
                return_value=0,
                address="0x401000",
            ),
        ]
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicators = generate_indicators_for_session(api_calls)
        
        assert len(indicators) >= 2

    def test_deduplicates_patterns(self):
        """Deduplicate indicators with same pattern."""
        api_calls = [
            APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="CreateProcessA",
                syscall_name=None,
                params={"lpCommandLine": "powershell.exe -Command A"},
                return_value=0,
                address="0x401000",
            ),
            APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="CreateProcessW",
                syscall_name=None,
                params={"lpCommandLine": "powershell.exe -Command B"},
                return_value=0,
                address="0x401000",
            ),
        ]
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicators = generate_indicators_for_session(api_calls)
        
        # Should deduplicate PowerShell indicators
        powershell_indicators = [
            i for i in indicators if "PowerShell" in i.name
        ]
        assert len(powershell_indicators) == 1

    def test_returns_empty_when_disabled(self):
        """Return empty list when indicator generation disabled."""
        api_calls = [
            APICallRecord(
                timestamp=datetime.now(timezone.utc),
                api_name="CreateProcessA",
                syscall_name=None,
                params={"lpCommandLine": "powershell.exe"},
                return_value=0,
                address="0x401000",
            ),
        ]
        
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DETONATE_GENERATE_INDICATORS", None)
            indicators = generate_indicators_for_session(api_calls)
        
        assert len(indicators) == 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_no_api_name(self):
        """Handle API call with no name."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name=None,
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is None

    def test_empty_params(self):
        """Handle API call with empty params."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        # Should return None since no command line to analyze
        assert indicator is None

    def test_script_execution_detection(self):
        """Detect script execution via ShellExecuteEx."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="ShellExecuteExW",
            syscall_name=None,
            params={"lpFile": "malicious.ps1"},
            return_value=0,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Script" in indicator.name

    def test_rwx_memory_detection(self):
        """Detect RWX memory allocation."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="VirtualAllocEx",
            syscall_name=None,
            params={"flProtect": "PAGE_EXECUTE_READWRITE"},
            return_value=0x1000,
            address="0x401000",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "RWX" in indicator.name or "Memory" in indicator.name

    def test_credential_access_detection(self):
        """Detect credential access via CredEnumerate."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CredEnumerateA",
            syscall_name=None,
            params={"Target": "Vault"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        with patch.dict(os.environ, {"DETONATE_GENERATE_INDICATORS": "true"}):
            indicator = generate_indicator_from_api_call(api_call)
        
        assert indicator is not None
        assert "Credential" in indicator.name
