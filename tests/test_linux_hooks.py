"""Tests for Linux syscall hooks."""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.detonate.core.hooks.linux import LinuxHooks
from src.detonate.core.session import AnalysisSession


@pytest.fixture
def mock_session(temp_dir):
    """Create a mock analysis session."""
    sample_file = temp_dir / "test.elf"
    sample_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    
    session = AnalysisSession(
        sample_path=str(sample_file),
        sample_sha256="deadbeef" * 8,
        platform="linux",
        architecture="x86_64",
    )
    return session


@pytest.fixture
def mock_ql():
    """Create a mock Qiling instance for x86_64."""
    ql = MagicMock()
    ql.arch.regs.rip = 0x00401000
    ql.arch.regs.pc = 0x00401000
    ql.mem.string = MagicMock(return_value="test_string")
    ql.mem.read = MagicMock(return_value=b"\x00\x00\x00\x00\x00\x00\x00\x00")
    return ql


class TestRecordSyscall:
    """Tests for _record_syscall method."""

    def test_records_syscall_with_timezone_aware_timestamp(self, mock_session, mock_ql):
        """Test that syscalls are recorded with timezone-aware timestamps."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        record = hooks._record_syscall(
            syscall_name="execve",
            params={"filename": "/bin/sh"},
        )
        
        assert record.syscall_name == "execve"
        assert record.params == {"filename": "/bin/sh"}
        assert record.address == "0x401000"
        assert record.timestamp.tzinfo is not None
        assert record.timestamp.tzinfo == timezone.utc
        
    def test_increments_sequence_number(self, mock_session, mock_ql):
        """Test that sequence numbers are incremented for each call."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        record1 = hooks._record_syscall("execve", {})
        record2 = hooks._record_syscall("open", {})
        record3 = hooks._record_syscall("socket", {})
        
        assert record1.sequence_number == 1
        assert record2.sequence_number == 2
        assert record3.sequence_number == 3
        
    def test_adds_record_to_session(self, mock_session, mock_ql):
        """Test that records are added to session."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        record = hooks._record_syscall("execve", {})
        
        assert len(mock_session.api_calls) == 1
        assert mock_session.api_calls[0] == record


class TestDecodeProtFlags:
    """Tests for memory protection flag decoding."""

    def test_decode_prot_read(self, mock_session, mock_ql):
        """Test decoding PROT_READ."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_prot_flags(0x1) == ["PROT_READ"]
        
    def test_decode_prot_write(self, mock_session, mock_ql):
        """Test decoding PROT_WRITE."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_prot_flags(0x2) == ["PROT_WRITE"]
        
    def test_decode_prot_exec(self, mock_session, mock_ql):
        """Test decoding PROT_EXEC."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_prot_flags(0x4) == ["PROT_EXEC"]
        
    def test_decode_rwx(self, mock_session, mock_ql):
        """Test decoding RWX (suspicious)."""
        hooks = LinuxHooks(mock_session, mock_ql)
        flags = hooks._decode_prot_flags(0x7)  # PROT_READ | PROT_WRITE | PROT_EXEC
        assert "PROT_READ" in flags
        assert "PROT_WRITE" in flags
        assert "PROT_EXEC" in flags
        
    def test_decode_prot_none(self, mock_session, mock_ql):
        """Test decoding PROT_NONE."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_prot_flags(0x0) == ["PROT_NONE"]


class TestDecodeCloneFlags:
    """Tests for clone flag decoding."""

    def test_decode_clone_vm(self, mock_session, mock_ql):
        """Test decoding CLONE_VM."""
        hooks = LinuxHooks(mock_session, mock_ql)
        flags = hooks._decode_clone_flags(0x00000100)
        assert "CLONE_VM" in flags
        
    def test_decode_clone_thread(self, mock_session, mock_ql):
        """Test decoding CLONE_THREAD."""
        hooks = LinuxHooks(mock_session, mock_ql)
        flags = hooks._decode_clone_flags(0x00010000)
        assert "CLONE_THREAD" in flags
        
    def test_decode_clone_multiple(self, mock_session, mock_ql):
        """Test decoding multiple clone flags."""
        hooks = LinuxHooks(mock_session, mock_ql)
        flags = hooks._decode_clone_flags(0x00010100)  # CLONE_VM | CLONE_THREAD
        assert "CLONE_VM" in flags
        assert "CLONE_THREAD" in flags


class TestDecodeSocketDomain:
    """Tests for socket domain decoding."""

    def test_decode_af_inet(self, mock_session, mock_ql):
        """Test decoding AF_INET."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_socket_domain(2) == "AF_INET"
        
    def test_decode_af_unix(self, mock_session, mock_ql):
        """Test decoding AF_UNIX."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_socket_domain(1) == "AF_UNIX"
        
    def test_decode_unknown_domain(self, mock_session, mock_ql):
        """Test decoding unknown domain."""
        hooks = LinuxHooks(mock_session, mock_ql)
        result = hooks._decode_socket_domain(99)
        assert "AF_99" in result


class TestDecodeSocketType:
    """Tests for socket type decoding."""

    def test_decode_sock_stream(self, mock_session, mock_ql):
        """Test decoding SOCK_STREAM."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_socket_type(1) == "SOCK_STREAM"
        
    def test_decode_sock_dgram(self, mock_session, mock_ql):
        """Test decoding SOCK_DGRAM."""
        hooks = LinuxHooks(mock_session, mock_ql)
        assert hooks._decode_socket_type(2) == "SOCK_DGRAM"
        
    def test_decode_sock_nonblock(self, mock_session, mock_ql):
        """Test decoding SOCK_STREAM | SOCK_NONBLOCK."""
        hooks = LinuxHooks(mock_session, mock_ql)
        result = hooks._decode_socket_type(1 | 0o4000)
        assert "SOCK_STREAM" in result
        assert "SOCK_NONBLOCK" in result


class TestHookSysExecve:
    """Tests for hook_sys_execve."""

    def test_reads_filename_and_argv(self, mock_session, mock_ql):
        """Test successful reading of filename and argv."""
        mock_ql.arch.regs.rdi = 0x1000  # filename
        mock_ql.arch.regs.rsi = 0x2000  # argv
        
        def mock_string(addr):
            if addr == 0x1000:
                return "/bin/bash"
            return ""
        
        mock_ql.mem.string = MagicMock(side_effect=mock_string)
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_execve(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert record.syscall_name == "execve"
        assert record.params["filename"] == "/bin/bash"
        
    def test_extracts_shell_strings(self, mock_session, mock_ql):
        """Test that shell paths are extracted as strings."""
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.arch.regs.rsi = 0x2000
        mock_ql.mem.string = MagicMock(return_value="/bin/sh")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_execve(mock_ql)
        
        assert "/bin/sh" in mock_session.strings


class TestHookSysMmap:
    """Tests for hook_sys_mmap."""

    def test_detects_rwx_memory(self, mock_session, mock_ql):
        """Test that RWX memory mappings are detected."""
        mock_ql.arch.regs.rdi = 0x0  # addr
        mock_ql.arch.regs.rsi = 0x1000  # length
        mock_ql.arch.regs.rdx = 0x7  # prot (PROT_READ | PROT_WRITE | PROT_EXEC)
        mock_ql.arch.regs.r10 = 0x22  # flags
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_mmap(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert record.syscall_name == "mmap"
        assert record.params["prot"] == 0x7
        assert "PROT_READ" in record.params["prot_decoded"]
        assert "PROT_WRITE" in record.params["prot_decoded"]
        assert "PROT_EXEC" in record.params["prot_decoded"]
        
    def test_normal_protection_not_flagged(self, mock_session, mock_ql):
        """Test that normal protection is not flagged."""
        mock_ql.arch.regs.rdx = 0x3  # PROT_READ | PROT_WRITE (no exec)
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_mmap(mock_ql)
        
        record = mock_session.api_calls[0]
        assert "PROT_EXEC" not in record.params["prot_decoded"]


class TestHookSysMprotect:
    """Tests for hook_sys_mprotect."""

    def test_detects_rwx_mprotect(self, mock_session, mock_ql):
        """Test that RWX mprotect is detected."""
        mock_ql.arch.regs.rdi = 0x5000  # addr
        mock_ql.arch.regs.rsi = 0x1000  # length
        mock_ql.arch.regs.rdx = 0x7  # prot (RWX)
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_mprotect(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "mprotect"
        assert record.params["prot"] == 0x7


class TestHookSysPtrace:
    """Tests for hook_sys_ptrace."""

    def test_records_ptrace_as_injection(self, mock_session, mock_ql):
        """Test that ptrace is recorded as process injection."""
        mock_ql.arch.regs.rdi = 0  # PTRACE_TRACEME
        mock_ql.arch.regs.rsi = 1234  # pid
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_ptrace(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert record.syscall_name == "ptrace"
        assert record.params["pid"] == 1234
        
        # Should have technique evidence added (findings is a dict keyed by technique_id)
        assert "T1055.008" in mock_session.findings
        finding = mock_session.findings["T1055.008"]
        assert finding.technique_id == "T1055.008"
        assert finding.confidence == "high"


class TestHookSysSetuid:
    """Tests for hook_sys_setuid."""

    def test_records_setuid_as_privilege_escalation(self, mock_session, mock_ql):
        """Test that setuid is recorded as privilege escalation."""
        mock_ql.arch.regs.rdi = 0  # uid 0 (root)
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_setuid(mock_ql)
        
        assert len(mock_session.api_calls) == 1
        assert "T1548.001" in mock_session.findings
        finding = mock_session.findings["T1548.001"]
        assert finding.technique_id == "T1548.001"
        assert finding.confidence == "high"


class TestHookSysUnlink:
    """Tests for hook_sys_unlink."""

    def test_records_file_deletion(self, mock_session, mock_ql):
        """Test that unlink is recorded as file deletion."""
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.mem.string = MagicMock(return_value="/tmp/malware")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_unlink(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "unlink"
        assert record.params["pathname"] == "/tmp/malware"
        # Note: unlink hook doesn't add strings (only execve does)
        assert len(mock_session.api_calls) == 1


class TestHookSysSocket:
    """Tests for hook_sys_socket."""

    def test_records_socket_syscall(self, mock_session, mock_ql):
        """Test that socket syscall is recorded."""
        mock_ql.arch.regs.rdi = 2  # AF_INET
        mock_ql.arch.regs.rsi = 1  # SOCK_STREAM
        mock_ql.arch.regs.rdx = 0  # IPPROTO_IP
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_socket(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "socket"
        assert record.params["domain"] == 2
        assert record.params["type"] == 1
        assert record.params["protocol"] == 0


class TestScoreToLabel:
    """Tests for _score_to_label helper."""

    def test_high_confidence(self):
        """Test high confidence labeling."""
        assert LinuxHooks._score_to_label(0.8) == "high"
        assert LinuxHooks._score_to_label(0.95) == "high"
        assert LinuxHooks._score_to_label(1.0) == "high"
        
    def test_medium_confidence(self):
        """Test medium confidence labeling."""
        assert LinuxHooks._score_to_label(0.5) == "medium"
        assert LinuxHooks._score_to_label(0.7) == "medium"
        assert LinuxHooks._score_to_label(0.79) == "medium"
        
    def test_low_confidence(self):
        """Test low confidence labeling."""
        assert LinuxHooks._score_to_label(0.0) == "low"
        assert LinuxHooks._score_to_label(0.2) == "low"
        assert LinuxHooks._score_to_label(0.49) == "low"


class TestCaptureReturnValue:
    """Tests for _capture_return_value method."""

    def test_updates_pending_syscall_return(self, mock_session, mock_ql):
        """Test that return values are captured for pending syscalls."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        # First record a syscall without return value
        hooks._record_syscall("open", {"filename": "/etc/passwd"})
        
        # Verify return value is None initially
        assert mock_session.api_calls[0].return_value is None
        
        # Capture return value - the method looks for records with None return_value
        hooks._capture_return_value(mock_ql, LinuxHooks.SYS_OPEN, 42)
        
        # Verify return value was updated (the _capture_return_value method
        # searches for the most recent record with None return_value)
        assert mock_session.api_calls[0].return_value == 42
        
    def test_handles_unknown_syscall_gracefully(self, mock_session, mock_ql):
        """Test graceful handling of unknown syscalls."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        # Should not raise exception for unknown syscall number
        hooks._capture_return_value(mock_ql, 9999, 0)
        
        # Session should be unchanged
        assert len(mock_session.api_calls) == 0
