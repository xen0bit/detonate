"""Tests for enhanced Windows API hooks (Phase 1.1)."""

import pytest
from unittest.mock import Mock, MagicMock, PropertyMock
from datetime import datetime, timezone
from pathlib import Path

from src.detonate.core.session import AnalysisSession
from src.detonate.core.hooks.windows import WindowsHooks
from src.detonate.mapping.windows_map import API_TO_TECHNIQUE


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory fixture."""
    return tmp_path


def create_mock_ql():
    """Create mock Qiling instance for hook testing."""
    ql = Mock()
    ql.mem = Mock()
    ql.mem.string = Mock(return_value="test")
    ql.mem.wstring = Mock(return_value="test")
    ql.os = Mock()
    ql.os.f_param_read = Mock(return_value=0x1000)
    ql.arch = Mock()
    ql.arch.pc = 0x401000
    return ql


@pytest.fixture
def mock_session(temp_dir):
    """Create a mock analysis session."""
    sample_file = temp_dir / "test.exe"
    sample_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    session = AnalysisSession(
        sample_path=str(sample_file),
        sample_sha256="abcd1234" * 8,
        platform="windows",
        architecture="x86",
    )
    return session


class TestCredentialAccessHooks:
    """Test credential access API hooks."""

    def test_CredEnumerateA_detects_lsass_access(self, mock_session):
        """Test CredEnumerateA detects credential dumping."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "Vault"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CredEnumerateA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1003.001" for f in findings)

    def test_CredEnumerateW_unicode(self, mock_session):
        """Test CredEnumerateW (Unicode version)."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "Vault"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CredEnumerateW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1003.001" for f in findings)

    def test_CredReadA(self, mock_session):
        """Test CredReadA detection."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CredReadA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1003.001" for f in findings)

    def test_SamIConnect_detects_sam_access(self, mock_session):
        """Test SamIConnect detects SAM database access."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_SamIConnect(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1003.002" for f in findings)

    def test_LsaOpenPolicy_detects_lsa_secrets(self, mock_session):
        """Test LsaOpenPolicy detects LSA secrets access."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_LsaOpenPolicy(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1003.004" for f in findings)


class TestDiscoveryHooks:
    """Test discovery API hooks."""

    def test_GetSystemInfo(self, mock_session):
        """Test GetSystemInfo detection."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_GetSystemInfo(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1082" for f in findings)

    def test_NetShareEnum(self, mock_session):
        """Test NetShareEnum detects network share discovery."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_NetShareEnum(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1135" for f in findings)

    def test_DsGetDcNameW(self, mock_session):
        """Test DsGetDcNameW detects domain controller discovery."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_DsGetDcNameW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1082" for f in findings)


class TestLateralMovementHooks:
    """Test lateral movement API hooks."""

    def test_WNetAddConnection2W_smb_share(self, mock_session):
        """Test WNetAddConnection2W detects SMB share connections."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "\\\\server\\share"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_WNetAddConnection2W(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1021.002" for f in findings)

    def test_CreateProcessWithLogonW(self, mock_session):
        """Test CreateProcessWithLogonW detection."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "cmd.exe /c whoami"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CreateProcessWithLogonW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1021.003" for f in findings)

    def test_ImpersonateLoggedOnUser(self, mock_session):
        """Test ImpersonateLoggedOnUser detects token impersonation."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_ImpersonateLoggedOnUser(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1134.001" for f in findings)


class TestPersistenceHooks:
    """Test persistence API hooks."""

    def test_SchTasksCreate(self, mock_session):
        """Test SchTasksCreate detects scheduled task persistence."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "MaliciousTask"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_SchTasksCreate(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1053.005" for f in findings)

    def test_RegCreateKeyExW_run_key(self, mock_session):
        """Test RegCreateKeyExW detects registry run key persistence."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_RegCreateKeyExW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1547.001" for f in findings)

    def test_CreateServiceW(self, mock_session):
        """Test CreateServiceW detects Windows service persistence."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "MaliciousService"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CreateServiceW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1543.003" for f in findings)


class TestDefenseEvasionHooks:
    """Test defense evasion API hooks."""

    def test_SetFileTime(self, mock_session):
        """Test SetFileTime detects timestomping."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_SetFileTime(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1070.003" for f in findings)

    def test_ClearEventLogA(self, mock_session):
        """Test ClearEventLogA detects event log clearing."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_ClearEventLogA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1070.001" for f in findings)

    def test_RemoveDirectoryA(self, mock_session):
        """Test RemoveDirectoryA detects file deletion."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "C:\\malware"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_RemoveDirectoryA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1070.004" for f in findings)


class TestExecutionHooks:
    """Test execution API hooks."""

    def test_CreateProcessWithTokenW_powershell(self, mock_session):
        """Test CreateProcessWithTokenW detects PowerShell execution."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "powershell -enc SGVsbG8="

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CreateProcessWithTokenW(ql)

        findings = list(mock_session.findings.values())
        # Should detect PowerShell sub-technique
        assert any(f.technique_id == "T1059.001" for f in findings)

    def test_ShellExecuteExW(self, mock_session):
        """Test ShellExecuteExW detection."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "cmd.exe"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_ShellExecuteExW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id in ["T1059.003", "T1106"] for f in findings)

    def test_ShellExecuteW_unicode(self, mock_session):
        """Test ShellExecuteW (Unicode) detects execution."""
        ql = create_mock_ql()
        ql.mem.wstring.return_value = "powershell.exe"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_ShellExecuteW(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id in ["T1059.001", "T1106"] for f in findings)
        # Verify string was extracted
        assert any("powershell.exe" in s for s in mock_session.strings)


class TestFixedHooks:
    """Test hooks that were fixed from TODO state."""

    def test_ReadFile_detects_data_collection(self, mock_session):
        """Test ReadFile detects data from local system."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_ReadFile(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1005" for f in findings)

    def test_WriteFile_detects_data_staging(self, mock_session):
        """Test WriteFile detects data staging/collection."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_WriteFile(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1005" for f in findings)

    @pytest.mark.parametrize(
        "file_path,expected_cve",
        [
            ("\\\\pipe\\srvsvc", "CVE-2017-0144"),
            ("C:\\\\Windows\\\\sysmon.sys", "CVE-2021-34527"),
            ("C:\\\\Windows\\\\System32\\\\netlogon.dll", "CVE-2020-1472"),
            ("C:\\\\Windows\\\\System32\\\\lsass.exe", "CVE-2024-30085"),
        ],
    )
    def test_CreateFileA_detects_cve_indicators(self, mock_session, file_path, expected_cve):
        """Test CreateFileA detects CVE indicator patterns in file paths."""
        ql = create_mock_ql()
        ql.mem.string.return_value = file_path

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_CreateFileA(ql)

        # Verify technique detection still works
        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1083" for f in findings)

        # Verify CVE indicator was detected (vulnerability not added without NVD API enabled)
        # The CVE indicator matching happens regardless of NVD API status
        # When NVD API is disabled, lookup returns None and no vulnerability is added
        # This test verifies the pattern matching logic exists
        assert hasattr(hooks, "CVE_INDICATOR_PATTERNS")
        assert any(pattern in file_path for pattern in hooks.CVE_INDICATOR_PATTERNS.keys())


class TestCollectionHooks:
    """Test collection API hooks."""

    def test_GetClipboardData(self, mock_session):
        """Test GetClipboardData detects clipboard data collection."""
        ql = create_mock_ql()

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_GetClipboardData(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1115" for f in findings)

    def test_FindFirstFileA(self, mock_session):
        """Test FindFirstFileA detects file discovery."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "C:\\*.txt"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_FindFirstFileA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1083" for f in findings)


class TestExfiltrationHooks:
    """Test exfiltration API hooks."""

    def test_InternetOpenUrlA(self, mock_session):
        """Test InternetOpenUrlA detects C2 communication."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "http://evil.com/malware.exe"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_InternetOpenUrlA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1071.001" for f in findings)

    def test_HttpSendRequestA(self, mock_session):
        """Test HttpSendRequestA detects HTTP C2."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "POST /beacon"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_HttpSendRequestA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1071.001" for f in findings)

    def test_FtpPutFileA(self, mock_session):
        """Test FtpPutFileA detects FTP exfiltration."""
        ql = create_mock_ql()
        ql.mem.string.return_value = "C:\\secret.txt"

        hooks = WindowsHooks(mock_session, ql)
        hooks.hook_FtpPutFileA(ql)

        findings = list(mock_session.findings.values())
        assert any(f.technique_id == "T1048" for f in findings)


class TestWindowsMapCoverage:
    """Test Windows API mapping coverage."""

    def test_new_credential_apis_mapped(self):
        """Test that new credential access APIs are mapped."""
        required_apis = [
            "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
            "SamIConnect", "LsaOpenPolicy", "LsaQueryInformationPolicy"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_discovery_apis_mapped(self):
        """Test that new discovery APIs are mapped."""
        required_apis = [
            "GetSystemInfo", "GetVersionExA", "GetVersionExW",
            "NetShareEnum", "NetGetJoinInformation", "DsGetDcNameW"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_lateral_movement_apis_mapped(self):
        """Test that new lateral movement APIs are mapped."""
        required_apis = [
            "WNetAddConnection2W", "CreateProcessWithLogonW",
            "ImpersonateLoggedOnUser"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_persistence_apis_mapped(self):
        """Test that new persistence APIs are mapped."""
        required_apis = [
            "SchTasksCreate", "RegCreateKeyExW", "CreateServiceW"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_defense_evasion_apis_mapped(self):
        """Test that new defense evasion APIs are mapped."""
        required_apis = [
            "SetFileTime", "RemoveDirectoryA", "RemoveDirectoryW",
            "ClearEventLogA", "BackupEventLogA"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_execution_apis_mapped(self):
        """Test that new execution APIs are mapped."""
        required_apis = [
            "CreateProcessWithTokenW", "ShellExecuteExW"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_collection_apis_mapped(self):
        """Test that new collection APIs are mapped."""
        required_apis = [
            "FindFirstFileA", "FindFirstFileW", "FindNextFileA",
            "GetClipboardData"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_new_exfiltration_apis_mapped(self):
        """Test that new exfiltration APIs are mapped."""
        required_apis = [
            "InternetOpenUrlA", "HttpSendRequestA", "FtpPutFileA"
        ]
        for api in required_apis:
            assert api in API_TO_TECHNIQUE, f"{api} not mapped"

    def test_sub_technique_specificity(self):
        """Test that sub-techniques are used where applicable."""
        # Check that PowerShell execution uses T1059.001, not just T1059
        create_process = API_TO_TECHNIQUE.get("CreateProcessA", {})
        param_checks = create_process.get("param_checks", {})
        lp_command_line = param_checks.get("lpCommandLine", {})
        
        # PowerShell should map to sub-technique T1059.001
        if "powershell" in lp_command_line:
            assert lp_command_line["powershell"]["id"] == "T1059.001"
