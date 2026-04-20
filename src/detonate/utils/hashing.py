"""File hashing utilities."""

import hashlib
from pathlib import Path


def hash_file(file_path: str | Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, md5, sha1)

    Returns:
        Hex-encoded hash string
    """
    hash_func = getattr(hashlib, algorithm)()
    path = Path(file_path)

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def get_file_hashes(file_path: str | Path) -> dict[str, str]:
    """
    Calculate multiple hashes for a file.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with sha256, md5, sha1 hashes
    """
    path = Path(file_path)
    return {
        "sha256": hash_file(path, "sha256"),
        "md5": hash_file(path, "md5"),
        "sha1": hash_file(path, "sha1"),
    }


def compute_file_hash(content: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of file content.

    Args:
        content: File content as bytes
        algorithm: Hash algorithm (sha256, md5, sha1)

    Returns:
        Hex-encoded hash string
    """
    hash_func = getattr(hashlib, algorithm)()
    hash_func.update(content)
    return hash_func.hexdigest()


def detect_file_type(content: bytes) -> str:
    """
    Detect file type from content.

    Args:
        content: File content as bytes

    Returns:
        File type description (e.g., "PE32 executable", "ELF 64-bit executable")
    """
    if len(content) < 4:
        return "Unknown (too small)"

    # Check for PE header
    if content[:2] == b"MZ":
        return "PE32 executable"

    # Check for ELF header
    if content[:4] == b"\x7fELF":
        # Check class (32-bit or 64-bit)
        if content[4] == 1:
            return "ELF 32-bit executable"
        elif content[4] == 2:
            return "ELF 64-bit executable"
        return "ELF executable"

    return "Unknown binary"
