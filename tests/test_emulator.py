"""Tests for core emulator."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.detonate.core.emulator import DetonateEmulator
from src.detonate.core.timeout import TimeoutError


def create_mock_qiling():
    """Create a mock Qiling instance."""
    mock_ql = MagicMock()
    mock_ql.arch.pc = 0x00401000
    mock_ql.os.set_api = MagicMock()
    mock_ql.hook_intno = MagicMock()
    mock_ql.run = MagicMock()
    return mock_ql


def setup_qiling_mock(monkeypatch, mock_ql=None):
    """Set up Qiling module mock."""
    if mock_ql is None:
        mock_ql = create_mock_qiling()
    
    mock_qiling_class = MagicMock(return_value=mock_ql)
    
    # Create mock qiling module
    mock_module = MagicMock()
    mock_module.Qiling = mock_qiling_class
    
    monkeypatch.setitem(sys.modules, "qiling", mock_module)
    return mock_qiling_class, mock_ql


class TestDetonateEmulatorInit:
    """Test emulator initialization."""

    def test_init_with_explicit_platform_arch(self, temp_dir):
        """Test initialization with explicit platform and architecture."""
        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="windows",
            arch="x86",
            timeout=30,
        )

        assert emulator.platform == "windows"
        assert emulator.architecture == "x86"
        assert emulator.timeout == 30
        assert emulator.session is None

    def test_init_with_auto_detection_pe_x86(self, temp_dir):
        """Test auto-detection for PE x86 binary."""
        # Create proper minimal PE header
        pe_data = bytearray(128)  # Enough space for headers
        pe_data[0:2] = b"MZ"  # MZ header
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")  # PE offset
        pe_data[64:68] = b"PE\x00\x00"  # PE signature
        pe_data[68:70] = (0x014C).to_bytes(2, "little")  # Machine: x86

        sample = temp_dir / "test_x86.exe"
        sample.write_bytes(bytes(pe_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="auto",
            arch="auto",
        )

        assert emulator.platform == "windows"
        assert emulator.architecture == "x86"

    def test_init_with_auto_detection_pe_x64(self, temp_dir):
        """Test auto-detection for PE x64 binary."""
        pe_data = bytearray(128)
        pe_data[0:2] = b"MZ"
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        pe_data[64:68] = b"PE\x00\x00"
        pe_data[68:70] = (0x8664).to_bytes(2, "little")  # Machine: x64

        sample = temp_dir / "test_x64.exe"
        sample.write_bytes(bytes(pe_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="auto",
            arch="auto",
        )

        assert emulator.platform == "windows"
        assert emulator.architecture == "x86_64"

    def test_init_with_auto_detection_elf_x64(self, temp_dir):
        """Test auto-detection for ELF x64 binary."""
        elf_data = bytearray(64)
        elf_data[0:4] = b"\x7fELF"  # ELF magic
        elf_data[4] = 0x02  # 64-bit
        elf_data[5] = 0x01  # Little endian
        elf_data[0x12:0x14] = (0x3E).to_bytes(2, "little")  # e_machine: x86_64

        sample = temp_dir / "test_x64.elf"
        sample.write_bytes(bytes(elf_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="auto",
            arch="auto",
        )

        assert emulator.platform == "linux"
        assert emulator.architecture == "x86_64"

    def test_init_raises_for_missing_sample(self, temp_dir):
        """Test that missing sample raises FileNotFoundError."""
        nonexistent = temp_dir / "does_not_exist.exe"

        emulator = DetonateEmulator(
            sample_path=str(nonexistent),
            platform="windows",
            arch="x86",
        )

        with pytest.raises(FileNotFoundError, match="Sample not found"):
            asyncio.run(emulator.run())

    def test_init_raises_for_missing_rootfs(self, temp_dir):
        """Test that missing rootfs raises FileNotFoundError."""
        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(temp_dir / "nonexistent_rootfs"),
            platform="windows",
            arch="x86",
        )

        with pytest.raises(FileNotFoundError, match="Rootfs not found"):
            asyncio.run(emulator.run())


class TestDetectFileType:
    """Test file type detection."""

    def test_detect_pe32_x86(self, temp_dir):
        """Test PE32 x86 detection."""
        pe_data = bytearray(b"MZ" + b"\x00" * 0x3C)
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        pe_data.extend(b"\x00" * (pe_offset - len(pe_data)))
        pe_data.extend(b"PE\x00\x00")
        pe_data.extend((0x014C).to_bytes(2, "little"))

        sample = temp_dir / "test.exe"
        sample.write_bytes(bytes(pe_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="windows",
            arch="x86",
        )

        file_type = emulator._detect_file_type()
        assert file_type == "PE32 executable"

    def test_detect_pe32_plus_x64(self, temp_dir):
        """Test PE32+ x64 detection."""
        pe_data = bytearray(b"MZ" + b"\x00" * 0x3C)
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        pe_data.extend(b"\x00" * (pe_offset - len(pe_data)))
        pe_data.extend(b"PE\x00\x00")
        pe_data.extend((0x8664).to_bytes(2, "little"))

        sample = temp_dir / "test.exe"
        sample.write_bytes(bytes(pe_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="windows",
            arch="x86_64",
        )

        file_type = emulator._detect_file_type()
        assert file_type == "PE32+ executable"

    def test_detect_elf_32bit(self, temp_dir):
        """Test ELF 32-bit detection."""
        elf_data = bytearray(b"\x7fELF")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x00" * 9)
        elf_data.extend((0x03).to_bytes(2, "little"))

        sample = temp_dir / "test.elf"
        sample.write_bytes(bytes(elf_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="linux",
            arch="x86",
        )

        file_type = emulator._detect_file_type()
        assert file_type == "ELF 32-bit executable"

    def test_detect_elf_64bit(self, temp_dir):
        """Test ELF 64-bit detection."""
        elf_data = bytearray(b"\x7fELF")
        elf_data.extend(b"\x02")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x00" * 9)
        elf_data.extend((0x3E).to_bytes(2, "little"))

        sample = temp_dir / "test.elf"
        sample.write_bytes(bytes(elf_data))

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="linux",
            arch="x86_64",
        )

        file_type = emulator._detect_file_type()
        assert file_type == "ELF 64-bit executable"

    def test_detect_unknown_binary(self, temp_dir):
        """Test unknown binary type."""
        sample = temp_dir / "test.bin"
        sample.write_bytes(b"random garbage data")

        emulator = DetonateEmulator(
            sample_path=str(sample),
            platform="linux",
            arch="x86_64",
        )

        file_type = emulator._detect_file_type()
        assert file_type == "Unknown binary"


class TestEmulatorRun:
    """Test emulator run method."""

    def test_run_creates_session(self, temp_dir, monkeypatch):
        """Test that run creates an analysis session."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
            timeout=60,
        )

        result = asyncio.run(emulator.run())

        assert emulator.session is not None
        assert result.session_id == emulator.session.session_id
        assert result.status == "completed"
        assert result.sample_sha256 is not None
        assert len(result.sample_sha256) == 64

    def test_run_records_session_metadata(self, temp_dir, monkeypatch):
        """Test that session metadata is recorded correctly."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        result = asyncio.run(emulator.run())

        assert result.platform == "windows"
        assert result.architecture == "x86"
        assert result.file_type == "PE32 executable"
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0

    def test_run_handles_qiling_not_installed(self, temp_dir, monkeypatch):
        """Test graceful handling when Qiling is not installed."""
        # Mock the import inside _run_emulation to raise ImportError
        import builtins
        original_import = builtins.__import__
        
        def mock_import(name, *args, **kwargs):
            if name == "qiling":
                raise ImportError("No module named 'qiling'")
            return original_import(name, *args, **kwargs)
        
        monkeypatch.setattr(builtins, "__import__", mock_import)
        
        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        with pytest.raises(RuntimeError, match="Qiling not installed"):
            asyncio.run(emulator.run())


class TestTimeoutEnforcement:
    """Test timeout enforcement."""

    def test_timeout_marks_session_as_failed(self, temp_dir, monkeypatch):
        """Test that timeout marks session as failed."""
        import time
        
        mock_ql = create_mock_qiling()
        def blocking_run():
            time.sleep(10)
        
        mock_ql.run = blocking_run
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
            timeout=1,
        )

        # Timeout is handled gracefully - session marked as failed, no exception raised
        result = asyncio.run(emulator.run())

        assert emulator.session is not None
        assert emulator.session.status == "failed"
        assert "timeout" in emulator.session.error_message.lower()
        assert result.status == "failed"


class TestExceptionHandling:
    """Test exception handling and partial result preservation."""

    def test_emulation_crash_preserves_partial_results(self, temp_dir, monkeypatch):
        """Test that crashes preserve partial results."""
        mock_ql = create_mock_qiling()
        mock_ql.run = MagicMock(side_effect=Exception("Emulation crashed"))
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        with pytest.raises(Exception, match="Emulation crashed"):
            asyncio.run(emulator.run())

        assert emulator.session is not None
        assert emulator.session.status == "failed"
        assert emulator.session.error_message == "Emulation crashed"
        assert emulator.session.sample_sha256 is not None

    def test_session_started_before_emulation(self, temp_dir, monkeypatch):
        """Test that session is started before emulation begins."""
        mock_ql = create_mock_qiling()
        mock_ql.run = MagicMock(side_effect=Exception("Immediate crash"))
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        try:
            asyncio.run(emulator.run())
        except Exception:
            pass

        assert emulator.session is not None
        assert emulator.session.started_at is not None
        assert emulator.session.status == "failed"


class TestHookInstallation:
    """Test hook installation."""

    def test_windows_hooks_installed(self, temp_dir, monkeypatch):
        """Test that Windows hooks are installed for Windows platform."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        asyncio.run(emulator.run())

        assert mock_ql.os.set_api.called

    def test_linux_hooks_installed(self, temp_dir, monkeypatch):
        """Test that Linux hooks are installed for Linux platform."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        elf_data = bytearray(b"\x7fELF")
        elf_data.extend(b"\x02")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x01")
        elf_data.extend(b"\x00" * 9)
        elf_data.extend((0x3E).to_bytes(2, "little"))

        sample = temp_dir / "test.elf"
        sample.write_bytes(bytes(elf_data))
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="linux",
            arch="x86_64",
        )

        asyncio.run(emulator.run())

        # Verify that set_syscall was called (new API using ql.os.set_syscall)
        assert mock_ql.os.set_syscall.called


class TestAnalysisResult:
    """Test analysis result structure."""

    def test_result_contains_api_calls(self, temp_dir, monkeypatch):
        """Test that result contains API call records."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        result = asyncio.run(emulator.run())

        assert hasattr(result, "api_calls")
        assert isinstance(result.api_calls, list)

    def test_result_contains_findings(self, temp_dir, monkeypatch):
        """Test that result contains technique findings."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        result = asyncio.run(emulator.run())

        assert hasattr(result, "findings")
        assert isinstance(result.findings, list)

    def test_result_contains_strings(self, temp_dir, monkeypatch):
        """Test that result contains extracted strings."""
        mock_ql = create_mock_qiling()
        mock_qiling_class, _ = setup_qiling_mock(monkeypatch, mock_ql)

        sample = temp_dir / "test.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 100)
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir()

        emulator = DetonateEmulator(
            sample_path=str(sample),
            rootfs_path=str(rootfs),
            platform="windows",
            arch="x86",
        )

        result = asyncio.run(emulator.run())

        assert hasattr(result, "strings")
        assert isinstance(result.strings, list)
