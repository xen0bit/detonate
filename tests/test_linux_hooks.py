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


class TestExitHandler:
    """Tests for EXIT handler which captures return values."""

    def test_exit_handler_captures_return_value_from_rax(self, mock_session, mock_ql):
        """Test that EXIT handler captures return values from RAX register."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        # Mock the RAX register to return a value
        mock_ql.arch.regs.rax = 42
        
        # Call the ENTER handler for open (this creates a pending record)
        mock_ql.arch.regs.rdi = 0x1000  # filename address
        mock_ql.mem.string = MagicMock(return_value="/etc/passwd")
        hooks.hook_sys_open(mock_ql)
        
        # Verify return value is None initially (pending)
        assert len(mock_session.api_calls) == 1
        record = mock_session.api_calls[0]
        assert record.return_value is None
        
        # Simulate EXIT handler - this should capture the return value
        exit_handler = hooks._create_exit_handler("open")
        exit_handler(mock_ql)
        
        # Verify return value was updated from RAX
        assert record.return_value == 42
        
    def test_exit_handler_handles_exception_gracefully(self, mock_session, mock_ql):
        """Test graceful handling when RAX read fails."""
        hooks = LinuxHooks(mock_session, mock_ql)
        
        # Make RAX access raise an exception
        type(mock_ql.arch.regs).rax = property(lambda self: (_ for _ in ()).throw(Exception("Register access failed")))
        
        # Call the ENTER handler for open
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.mem.string = MagicMock(return_value="/etc/passwd")
        hooks.hook_sys_open(mock_ql)
        
        # Should not raise exception
        exit_handler = hooks._create_exit_handler("open")
        exit_handler(mock_ql)
        
        # Return value should be -1 (default on failure)
        record = mock_session.api_calls[0]
        assert record.return_value == -1


class TestExpandedCredentialAccess:
    """Tests for expanded credential access syscall coverage."""

    def test_getuid_records_syscall(self, mock_session, mock_ql):
        """Test getuid syscall is recorded."""
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_getuid(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "getuid"
        
    def test_geteuid_records_syscall(self, mock_session, mock_ql):
        """Test geteuid syscall is recorded."""
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_geteuid(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "geteuid"
        
    def test_setresuid_privilege_escalation(self, mock_session, mock_ql):
        """Test setresuid is detected as privilege escalation."""
        mock_ql.arch.regs.rdi = 0  # ruid
        mock_ql.arch.regs.rsi = 0  # euid
        mock_ql.arch.regs.rdx = 0  # suid
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_setresuid(mock_ql)
        
        assert "T1548.001" in mock_session.findings
        finding = mock_session.findings["T1548.001"]
        assert finding.technique_id == "T1548.001"
        assert finding.confidence == "high"
        
    def test_setresgid_privilege_escalation(self, mock_session, mock_ql):
        """Test setresgid is detected as privilege escalation."""
        mock_ql.arch.regs.rdi = 0  # rgid
        mock_ql.arch.regs.rsi = 0  # egid
        mock_ql.arch.regs.rdx = 0  # sgid
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_setresgid(mock_ql)
        
        assert "T1548.001" in mock_session.findings
        finding = mock_session.findings["T1548.001"]
        assert finding.technique_id == "T1548.001"


class TestExpandedDiscovery:
    """Tests for expanded discovery syscall coverage."""

    def test_uname_records_syscall(self, mock_session, mock_ql):
        """Test uname syscall is recorded."""
        mock_ql.arch.regs.rdi = 0x1000  # buf
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_uname(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "uname"
        
    def test_getcwd_records_syscall(self, mock_session, mock_ql):
        """Test getcwd syscall is recorded."""
        mock_ql.arch.regs.rdi = 0x1000  # buf
        mock_ql.arch.regs.rsi = 256  # size
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_getcwd(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "getcwd"
        
    def test_readlink_extracts_pathname(self, mock_session, mock_ql):
        """Test readlink extracts and stores pathname."""
        mock_ql.arch.regs.rdi = 0x1000  # pathname
        mock_ql.mem.string = MagicMock(return_value="/etc/passwd")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_readlink(mock_ql)
        
        assert "/etc/passwd" in mock_session.strings
        
    def test_gethostname_records_syscall(self, mock_session, mock_ql):
        """Test gethostname syscall is recorded."""
        mock_ql.arch.regs.rdi = 0x1000  # name
        mock_ql.arch.regs.rsi = 64  # length
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_gethostname(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "gethostname"
        
    def test_sysinfo_records_syscall(self, mock_session, mock_ql):
        """Test sysinfo syscall is recorded."""
        mock_ql.arch.regs.rdi = 0x1000  # info struct
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_sysinfo(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "sysinfo"


class TestContainerEscape:
    """Tests for container escape detection."""

    def test_mount_proc_detects_escape(self, mock_session, mock_ql):
        """Test mount of /proc detects container escape."""
        mock_ql.arch.regs.rdi = 0x1000  # source
        mock_ql.arch.regs.rsi = 0x2000  # target
        mock_ql.arch.regs.rdx = 0x3000  # fstype
        
        def mock_string(addr):
            if addr == 0x1000:
                return "/proc"
            elif addr == 0x2000:
                return "/mnt/proc"
            return ""
        
        mock_ql.mem.string = MagicMock(side_effect=mock_string)
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_mount(mock_ql)
        
        assert "T1611" in mock_session.findings
        finding = mock_session.findings["T1611"]
        assert finding.confidence == "high"
        assert finding.confidence_score == 0.95
        
    def test_mount_sys_detects_escape(self, mock_session, mock_ql):
        """Test mount of /sys detects container escape."""
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.arch.regs.rsi = 0x2000
        mock_ql.mem.string = MagicMock(side_effect=lambda addr: "/sys" if addr == 0x1000 else "/mnt/sys")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_mount(mock_ql)
        
        assert "T1611" in mock_session.findings
        
    def test_pivot_root_detects_escape(self, mock_session, mock_ql):
        """Test pivot_root detects container escape."""
        mock_ql.arch.regs.rdi = 0x1000  # new_root
        mock_ql.arch.regs.rsi = 0x2000  # put_old
        mock_ql.mem.string = MagicMock(return_value="/newroot")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_pivot_root(mock_ql)
        
        assert "T1611" in mock_session.findings
        finding = mock_session.findings["T1611"]
        assert finding.confidence == "high"
        assert finding.confidence_score == 0.9
        
    def test_unshare_detects_escape(self, mock_session, mock_ql):
        """Test unshare detects container escape."""
        mock_ql.arch.regs.rdi = 0x00020000  # CLONE_NEWNS
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_unshare(mock_ql)
        
        assert "T1611" in mock_session.findings
        finding = mock_session.findings["T1611"]
        assert finding.confidence == "medium"


class TestDefenseEvasion:
    """Tests for defense evasion detection."""

    def test_rename_history_clearing(self, mock_session, mock_ql):
        """Test rename of .bash_history detects history clearing."""
        mock_ql.arch.regs.rdi = 0x1000  # oldpath
        mock_ql.arch.regs.rsi = 0x2000  # newpath
        mock_ql.mem.string = MagicMock(side_effect=lambda addr: ".bash_history" if addr == 0x1000 else ".bash_history.bak")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_rename(mock_ql)
        
        assert "T1070.003" in mock_session.findings
        finding = mock_session.findings["T1070.003"]
        assert finding.confidence == "high"
        assert finding.confidence_score == 0.9
        
    def test_renameat2_history_clearing(self, mock_session, mock_ql):
        """Test renameat2 of .bash_history detects history clearing."""
        mock_ql.arch.regs.rdi = 0  # olddirfd
        mock_ql.arch.regs.rsi = 0x1000  # oldpath
        mock_ql.arch.regs.rdx = 0  # newdirfd
        mock_ql.arch.regs.r10 = 0x2000  # newpath
        mock_ql.arch.regs.r8 = 0  # flags
        mock_ql.mem.string = MagicMock(side_effect=lambda addr: ".zsh_history" if addr == 0x1000 else ".zsh_history.bak")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_renameat2(mock_ql)
        
        assert "T1070.003" in mock_session.findings


class TestPersistenceDetection:
    """Tests for persistence mechanism detection."""

    def test_access_cron_detection(self, mock_session, mock_ql):
        """Test access to /etc/cron detects persistence."""
        mock_ql.arch.regs.rdi = 0x1000  # pathname
        mock_ql.arch.regs.rsi = 0  # mode
        mock_ql.mem.string = MagicMock(return_value="/etc/cron.d/malicious")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_access(mock_ql)
        
        # Should store the string
        assert "/etc/cron.d/malicious" in mock_session.strings
        
    def test_access_systemd_detection(self, mock_session, mock_ql):
        """Test access to systemd directory detects persistence."""
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.mem.string = MagicMock(return_value="/etc/systemd/system/malware.service")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_access(mock_ql)
        
        assert "/etc/systemd/system/malware.service" in mock_session.strings
        
    def test_access_bashrc_detection(self, mock_session, mock_ql):
        """Test access to .bashrc detects shell persistence."""
        mock_ql.arch.regs.rdi = 0x1000
        mock_ql.mem.string = MagicMock(return_value="/home/user/.bashrc")
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_access(mock_ql)
        
        assert "/home/user/.bashrc" in mock_session.strings


class TestCollectionExfiltration:
    """Tests for collection and exfiltration detection."""

    def test_pread64_records_syscall(self, mock_session, mock_ql):
        """Test pread64 syscall is recorded."""
        mock_ql.arch.regs.rdi = 3  # fd
        mock_ql.arch.regs.rsi = 0x1000  # buf
        mock_ql.arch.regs.rdx = 1024  # count
        mock_ql.arch.regs.r10 = 0  # offset
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_pread64(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "pread64"
        
    def test_sendmsg_records_syscall(self, mock_session, mock_ql):
        """Test sendmsg syscall is recorded for exfiltration detection."""
        mock_ql.arch.regs.rdi = 5  # sockfd
        mock_ql.arch.regs.rdx = 256  # length
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_sendmsg(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "sendmsg"
        
    def test_recvmsg_records_syscall(self, mock_session, mock_ql):
        """Test recvmsg syscall is recorded."""
        mock_ql.arch.regs.rdi = 5  # sockfd
        mock_ql.arch.regs.rdx = 256  # length
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_recvmsg(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "recvmsg"
        
    def test_accept_records_syscall(self, mock_session, mock_ql):
        """Test accept syscall is recorded for lateral movement."""
        mock_ql.arch.regs.rdi = 4  # sockfd
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_accept(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "accept"
        
    def test_accept4_records_syscall(self, mock_session, mock_ql):
        """Test accept4 syscall is recorded."""
        mock_ql.arch.regs.rdi = 4  # sockfd
        mock_ql.arch.regs.rsi = 0  # flags
        
        hooks = LinuxHooks(mock_session, mock_ql)
        hooks.hook_sys_accept4(mock_ql)
        
        record = mock_session.api_calls[0]
        assert record.syscall_name == "accept4"


class TestLinuxMapCoverage:
    """Tests for linux_map.py coverage verification."""

    def test_credential_access_syscalls_mapped(self):
        """Test credential access syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        credential_syscalls = ["getuid", "geteuid", "setresuid", "setresgid", "setreuid", "setregid"]
        for syscall in credential_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_discovery_syscalls_mapped(self):
        """Test discovery syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        discovery_syscalls = ["uname", "getcwd", "readlink", "readlinkat", "gethostname", "sysinfo"]
        for syscall in discovery_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_container_escape_syscalls_mapped(self):
        """Test container escape syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        escape_syscalls = ["mount", "umount", "umount2", "pivot_root", "unshare"]
        for syscall in escape_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_persistence_syscalls_mapped(self):
        """Test persistence/defense evasion syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        persistence_syscalls = ["rename", "renameat2", "fadvise64"]
        for syscall in persistence_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_collection_syscalls_mapped(self):
        """Test collection syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        collection_syscalls = ["pread64", "pwrite64", "splice", "vmsplice", "tee"]
        for syscall in collection_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_exfiltration_syscalls_mapped(self):
        """Test exfiltration syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        exfil_syscalls = ["sendmsg", "recvmsg"]
        for syscall in exfil_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_lateral_movement_syscalls_mapped(self):
        """Test lateral movement syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        latmov_syscalls = ["accept", "accept4"]
        for syscall in latmov_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_file_discovery_syscalls_mapped(self):
        """Test file discovery syscalls have mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        file_disc_syscalls = ["access", "faccessat", "stat", "fstat", "lstat", "statx"]
        for syscall in file_disc_syscalls:
            assert syscall in SYSCALL_TO_TECHNIQUE, f"{syscall} not mapped"
            
    def test_openat_has_container_paths(self):
        """Test openat has container escape path mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        openat_mapping = SYSCALL_TO_TECHNIQUE["openat"]
        assert "param_checks" in openat_mapping
        assert "pathname" in openat_mapping["param_checks"]
        
        pathname_checks = openat_mapping["param_checks"]["pathname"]
        assert "/var/run/docker.sock" in pathname_checks
        assert "/.dockerenv" in pathname_checks
        
    def test_openat_has_persistence_paths(self):
        """Test openat has persistence path mappings."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        openat_mapping = SYSCALL_TO_TECHNIQUE["openat"]
        pathname_checks = openat_mapping["param_checks"]["pathname"]
        
        assert "/etc/cron.d/" in pathname_checks
        assert "/etc/systemd/system/" in pathname_checks
        
    def test_connect_has_cloud_metadata(self):
        """Test connect has cloud metadata endpoint detection."""
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        connect_mapping = SYSCALL_TO_TECHNIQUE["connect"]
        assert "param_checks" in connect_mapping
        assert "address" in connect_mapping["param_checks"]
        
        address_checks = connect_mapping["param_checks"]["address"]
        assert "169.254.169.254" in address_checks  # AWS
        assert "metadata.google.internal" in address_checks  # GCP
