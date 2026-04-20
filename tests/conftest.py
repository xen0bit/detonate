"""Pytest fixtures."""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_elf_path():
    """Return path to a test ELF binary if available."""
    # Try common locations for test binaries
    test_paths = [
        "/bin/true",
        "/bin/false",
        "/usr/bin/true",
    ]
    for path in test_paths:
        if Path(path).exists():
            return path
    return None


@pytest.fixture
def db_path(temp_dir):
    """Create a temporary database path."""
    return str(temp_dir / "test.db")
