"""Utility functions."""

from .hashing import hash_file, get_file_hashes
from .binary import detect_platform_arch, is_pe, is_elf

__all__ = [
    "hash_file",
    "get_file_hashes",
    "detect_platform_arch",
    "is_pe",
    "is_elf",
]
