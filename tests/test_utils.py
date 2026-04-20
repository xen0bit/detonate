"""Tests for utility functions."""

from pathlib import Path

from detonate.utils.hashing import hash_file, get_file_hashes
from detonate.utils.binary import is_pe, is_elf, detect_platform_arch


class TestHashing:
    """Test file hashing utilities."""

    def test_hash_file_sha256(self, temp_dir):
        """Test SHA256 hashing."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("hello world")

        hash_result = hash_file(test_file, "sha256")

        # Known SHA256 of "hello world"
        assert hash_result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_hash_file_md5(self, temp_dir):
        """Test MD5 hashing."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("hello world")

        hash_result = hash_file(test_file, "md5")

        # Known MD5 of "hello world"
        assert hash_result == "5eb63bbbe01eeed093cb22bb8f5acdc3"

    def test_get_file_hashes(self, temp_dir):
        """Test getting multiple hashes."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")

        hashes = get_file_hashes(test_file)

        assert "sha256" in hashes
        assert "md5" in hashes
        assert "sha1" in hashes
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32


class TestBinaryDetection:
    """Test binary type detection."""

    def test_is_pe(self, temp_dir):
        """Test PE file detection."""
        # Create fake PE file (MZ header)
        pe_file = temp_dir / "fake.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)

        assert is_pe(pe_file) is True

        # Non-PE file
        elf_file = temp_dir / "fake.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        assert is_pe(elf_file) is False

    def test_is_elf(self, temp_dir):
        """Test ELF file detection."""
        # Create fake ELF file
        elf_file = temp_dir / "fake.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        assert is_elf(elf_file) is True

        # Non-ELF file
        pe_file = temp_dir / "fake.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)

        assert is_elf(pe_file) is False

    def test_detect_platform_arch_pe_x86(self, temp_dir):
        """Test PE x86 detection."""
        # Minimal PE x86 header
        pe_data = bytearray(128)
        pe_data[0:2] = b"MZ"
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        pe_data[64:68] = b"PE\x00\x00"
        pe_data[68:70] = (0x014C).to_bytes(2, "little")

        pe_file = temp_dir / "test_x86.exe"
        pe_file.write_bytes(bytes(pe_data))

        platform, arch = detect_platform_arch(pe_file)

        assert platform == "windows"
        assert arch == "x86"

    def test_detect_platform_arch_pe_x64(self, temp_dir):
        """Test PE x64 detection."""
        pe_data = bytearray(128)
        pe_data[0:2] = b"MZ"
        pe_offset = 64
        pe_data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        pe_data[64:68] = b"PE\x00\x00"
        pe_data[68:70] = (0x8664).to_bytes(2, "little")

        pe_file = temp_dir / "test_x64.exe"
        pe_file.write_bytes(bytes(pe_data))

        platform, arch = detect_platform_arch(pe_file)

        assert platform == "windows"
        assert arch == "x86_64"

    def test_detect_platform_arch_elf_x64(self, temp_dir):
        """Test ELF x64 detection."""
        # ELF header with x86_64 machine type (0x3E)
        elf_data = bytearray(64)
        elf_data[0:4] = b"\x7fELF"
        elf_data[4] = 0x02  # 64-bit
        elf_data[5] = 0x01  # Little endian
        elf_data[0x12:0x14] = (0x3E).to_bytes(2, "little")  # e_machine: x86_64

        elf_file = temp_dir / "test_x64.elf"
        elf_file.write_bytes(bytes(elf_data))

        platform, arch = detect_platform_arch(elf_file)

        assert platform == "linux"
        assert arch == "x86_64"

    def test_detect_nonexistent_file(self, temp_dir):
        """Test detection for nonexistent file."""
        nonexistent = temp_dir / "does_not_exist"

        platform, arch = detect_platform_arch(nonexistent)

        assert platform == "unknown"
        assert arch == "unknown"
