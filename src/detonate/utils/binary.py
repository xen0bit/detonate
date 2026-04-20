"""Binary file detection utilities."""

from pathlib import Path


def is_pe(file_path: str | Path) -> bool:
    """
    Check if file is a PE (Portable Executable) file.

    Args:
        file_path: Path to file

    Returns:
        True if PE file, False otherwise
    """
    path = Path(file_path)
    if not path.exists():
        return False

    with path.open("rb") as f:
        # PE files start with MZ header
        magic = f.read(2)
        return magic == b"MZ"


def is_elf(file_path: str | Path) -> bool:
    """
    Check if file is an ELF (Executable and Linkable Format) file.

    Args:
        file_path: Path to file

    Returns:
        True if ELF file, False otherwise
    """
    path = Path(file_path)
    if not path.exists():
        return False

    with path.open("rb") as f:
        # ELF files start with 0x7f ELF
        magic = f.read(4)
        return magic == b"\x7fELF"


def detect_platform_arch(file_path: str | Path) -> tuple[str, str]:
    """
    Auto-detect platform and architecture from binary.

    Args:
        file_path: Path to binary file

    Returns:
        Tuple of (platform, architecture) where:
        - platform: "windows" or "linux"
        - architecture: "x86", "x86_64", "arm", "arm64", or "unknown"
    """
    path = Path(file_path)

    if not path.exists():
        return ("unknown", "unknown")

    with path.open("rb") as f:
        magic = f.read(4)

        # PE file (Windows) - starts with MZ (may have extra bytes)
        if magic[:2] == b"MZ":
            return _detect_pe_arch(path)

        # ELF file (Linux)
        if magic == b"\x7fELF":
            return _detect_elf_arch(path)

    return ("unknown", "unknown")


def _detect_pe_arch(path: Path) -> tuple[str, str]:
    """Detect architecture from PE file."""
    with path.open("rb") as f:
        # Skip to PE header offset (at 0x3C)
        f.seek(0x3C)
        pe_offset_bytes = f.read(4)
        if len(pe_offset_bytes) < 4:
            return ("windows", "unknown")

        import struct
        pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

        # Seek to PE signature
        f.seek(pe_offset)
        pe_sig = f.read(4)
        if pe_sig != b"PE\x00\x00":
            return ("windows", "unknown")

        # Read COFF header
        coff_header = f.read(20)
        if len(coff_header) < 20:
            return ("windows", "unknown")

        import struct
        machine = struct.unpack("<H", coff_header[0:2])[0]

        # Machine types
        machine_map = {
            0x014C: "x86",      # IMAGE_FILE_MACHINE_I386
            0x8664: "x86_64",   # IMAGE_FILE_MACHINE_AMD64
            0x01C0: "arm",      # IMAGE_FILE_MACHINE_ARM
            0xAA64: "arm64",    # IMAGE_FILE_MACHINE_ARM64
        }

        arch = machine_map.get(machine, "unknown")
        return ("windows", arch)


def _detect_elf_arch(path: Path) -> tuple[str, str]:
    """Detect architecture from ELF file."""
    with path.open("rb") as f:
        # Read ELF header
        f.seek(0x12)  # e_machine offset
        machine_bytes = f.read(2)

        if len(machine_bytes) < 2:
            return ("linux", "unknown")

        import struct
        machine = struct.unpack("<H", machine_bytes)[0]

        # Machine types
        machine_map = {
            0x03: "x86",       # EM_386
            0x3E: "x86_64",    # EM_X86_64
            0x28: "arm",       # EM_ARM
            0xB7: "arm64",     # EM_AARCH64
        }

        arch = machine_map.get(machine, "unknown")
        return ("linux", arch)
