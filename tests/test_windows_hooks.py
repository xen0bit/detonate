"""Tests for Windows API hooks."""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.detonate.core.hooks.windows import WindowsHooks
from src.detonate.core.session import AnalysisSession, APICallRecord


@pytest.fixture
def mock_session(temp_dir):
    """Create a mock analysis session."""
    # Create a fake sample file
    sample_file = temp_dir / "test.exe"
    sample_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    session = AnalysisSession(
        sample_path=str(sample_file),
        sample_sha256="abcd1234" * 8,
        platform="windows",
        architecture="x86",
    )
    return session


@pytest.fixture
def mock_ql():
    """Create a mock Qiling instance."""
    ql = MagicMock()
    ql.arch.pc = 0x00401000
    ql.os.f_param_read = MagicMock(side_effect=lambda x: 0x1000 + x * 4)
    ql.mem.string = MagicMock(return_value="test_string")
    ql.mem.read = MagicMock(return_value=b"\x00\x00\x00\x00")
    return ql


class TestRecordApiCall:
    """Tests for _record_api_call method."""

    def test_records_api_call_with_timezone_aware_timestamp(self, mock_session, mock_ql):
        """Test that API calls are recorded with timezone-aware timestamps."""
        hooks = WindowsHooks(mock_session, mock_ql)
        
        record = hooks._record_api_call(
            api_name="TestAPI",
            params={"param1": "value1"},
            return_value=42,
            address="0x00401000",
        )
        
        assert record.api_name == "TestAPI"
        assert record.params == {"param1": "value1"}
        assert record.return_value == 42
        assert record.address == "0x00401000"
        # Check timestamp is timezone-aware
        assert record.timestamp.tzinfo is not None
        assert record.timestamp.tzinfo == timezone.utc
        
    def test_extracts_address_from_pc_when_not_provided(self, mock_session, mock_ql):
        """Test that address is extracted from PC when not provided."""
        hooks = WindowsHooks(mock_session, mock_ql)
        
        record = hooks._record_api_call(
            api_name="TestAPI",
            params={},
        )
        
        assert record.address == "0x401000"
        
    def test_increments_sequence_number(self, mock_session, mock_ql):
        """Test that sequence numbers are incremented for each call."""
        hooks = WindowsHooks(mock_session, mock_ql)
        
        record1 = hooks._record_api_call("API1", {})
        record2 = hooks._record_api_call("API2", {})
        record3 = hooks._record_api_call("API3", {})
        
        assert record1.sequence_number == 1
        assert record2.sequence_number == 2
        assert record3.sequence_number == 3
        
    def test_adds_record_to_session(self, mock_session, mock_ql):
        """Test that records are added to session."""
        hooks = WindowsHooks(mock_session, mock_ql)
        
        record = hooks._record_api_call("TestAPI", {})
        
        assert len(mock_session.api_calls) == 1
        assert mock_session.api_calls[0] == record


class TestHookCreateProcessA:
    """Tests for hook_CreateProcessA."""

    def test_reads_command_line_successfully(self, mock_session, mock_ql):
        """Test successful command line reading."""
        mock_ql.os.f_param_read.side_effect = lambda x: 0x1000 if x == 1 else 0x2000
        mock_ql.mem.string.side_effect = lambda x: "notepad.exe" if x == 0x2000 else "notepad.exe"
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_CreateProcessA(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert record.api_name == "CreateProcessA"
        assert "lpCommandLine" in record.params
        assert record.params["lpCommandLine"] == "notepad.exe"
        
    def test_handles_invalid_pointer_gracefully(self, mock_session, mock_ql):
        """Test graceful handling of invalid pointers."""
        # Return a non-zero pointer that will cause exception when read
        mock_ql.os.f_param_read.side_effect = lambda x: 0xDEADBEEF
        mock_ql.mem.string.side_effect = Exception("Invalid memory access")
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_CreateProcessA(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        # Should not crash, should have fallback values
        assert record.params["lpCommandLine"] == "<invalid_pointer>"
        
    def test_extracts_strings(self, mock_session, mock_ql):
        """Test that strings are extracted from command line."""
        mock_ql.os.f_param_read.side_effect = lambda x: 0x1000 if x == 1 else 0x2000
        mock_ql.mem.string.side_effect = lambda x: "malware.exe -silent" if x == 0x2000 else "malware.exe"
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_CreateProcessA(mock_ql)
        
        assert "malware.exe" in mock_session.strings
        assert "malware.exe -silent" in mock_session.strings


class TestHookVirtualAllocEx:
    """Tests for hook_VirtualAllocEx."""

    def test_decodes_protection_flags(self, mock_session, mock_ql):
        """Test that protection flags are decoded correctly."""
        PAGE_EXECUTE_READWRITE = 0x40
        mock_ql.os.f_param_read.side_effect = lambda x: {
            0: 0x100,  # hProcess
            1: 0x5000,  # lpAddress
            2: 0x1000,  # dwSize
            3: 0x1000,  # flAllocationType (MEM_COMMIT)
            4: PAGE_EXECUTE_READWRITE,  # flProtect
        }.get(x, 0)
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_VirtualAllocEx(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert "PAGE_EXECUTE_READWRITE" in record.params["flProtect"]
        assert record.params["suspicious_rwx"] is True
        
    def test_flags_rwx_as_suspicious(self, mock_session, mock_ql):
        """Test that RWX allocations are flagged as suspicious."""
        PAGE_EXECUTE_READWRITE = 0x40
        mock_ql.os.f_param_read.side_effect = lambda x: {
            4: PAGE_EXECUTE_READWRITE,
        }.get(x, 0x1000)
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_VirtualAllocEx(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.params["suspicious_rwx"] is True
        
    def test_normal_protection_not_flagged(self, mock_session, mock_ql):
        """Test that normal protection flags are not flagged."""
        PAGE_READWRITE = 0x04
        mock_ql.os.f_param_read.side_effect = lambda x: {
            4: PAGE_READWRITE,
        }.get(x, 0x1000)
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_VirtualAllocEx(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.params["suspicious_rwx"] is False
        assert "PAGE_READWRITE" in record.params["flProtect"]
        
    def test_decodes_allocation_type(self, mock_session, mock_ql):
        """Test that allocation type is decoded."""
        MEM_COMMIT = 0x1000
        mock_ql.os.f_param_read.side_effect = lambda x: {
            3: MEM_COMMIT,
            4: 0x04,  # PAGE_READWRITE
        }.get(x, 0x1000)
        
        hooks = WindowsHooks(mock_session, mock_ql)
        hooks.hook_VirtualAllocEx(mock_ql)
        
        record = mock_session.api_calls[0]
        assert "MEM_COMMIT" in record.params["flAllocationType"]


class TestScoreToLabel:
    """Tests for _score_to_label helper."""

    def test_high_confidence(self):
        """Test high confidence labeling."""
        assert WindowsHooks._score_to_label(0.8) == "high"
        assert WindowsHooks._score_to_label(0.95) == "high"
        assert WindowsHooks._score_to_label(1.0) == "high"
        
    def test_medium_confidence(self):
        """Test medium confidence labeling."""
        assert WindowsHooks._score_to_label(0.5) == "medium"
        assert WindowsHooks._score_to_label(0.7) == "medium"
        assert WindowsHooks._score_to_label(0.79) == "medium"
        
    def test_low_confidence(self):
        """Test low confidence labeling."""
        assert WindowsHooks._score_to_label(0.0) == "low"
        assert WindowsHooks._score_to_label(0.2) == "low"
        assert WindowsHooks._score_to_label(0.49) == "low"
