"""Configuration management using pydantic-settings.

This module provides centralized configuration for the Detonate malware analysis platform.

**Local vs Docker Usage:**
- **Local development**: Uses default `./data/detonate.db` — no environment variables needed.
  The database directory is created automatically if it doesn't exist.
- **Docker deployment**: Set `DETONATE_DATABASE=/var/lib/detonate/detonate.db` via
  docker-compose.yml environment. The container runs as root, so `/var/lib/detonate/`
  must exist and be writable (handled by Dockerfile).

The database path validation ensures the parent directory is writable before the
application starts, preventing cryptic permission errors during analysis.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides.

    Settings can be overridden via environment variables prefixed with `DETONATE_`.
    For example, `DETONATE_DATABASE=/path/to/db.sqlite` overrides the database path.
    """

    model_config = SettingsConfigDict(
        env_prefix="DETONATE_",
        env_file=".env",
        extra="ignore",
    )

    # Database
    # Default: ./data/detonate.db for local development
    # Docker override: DETONATE_DATABASE=/var/lib/detonate/detonate.db
    database: str = "./data/detonate.db"

    @model_validator(mode="after")
    def validate_database_writable(self) -> "Settings":
        """Validate that the database directory is writable.

        This check runs after model initialization to catch permission issues early,
        before any database operations are attempted. For relative paths, the directory
        is resolved relative to the current working directory.

        Raises:
            ValueError: If the database parent directory cannot be created or is not writable.
        """
        db_path = Path(self.database)
        # Handle both relative and absolute paths - resolve relative to cwd
        if not db_path.is_absolute():
            db_path = Path.cwd() / db_path

        db_dir = db_path.parent

        # Try to create the directory if it doesn't exist
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            raise ValueError(
                f"Database directory '{db_dir}' cannot be created: {e}. "
                "For Docker deployments, set DETONATE_DATABASE to a writable path "
                "(e.g., /var/lib/detonate/detonate.db). For local development, "
                "ensure the current directory is writable."
            ) from e

        # Check writability by attempting to touch a test file
        test_file = db_dir / ".detonate_write_test"
        try:
            test_file.touch(exist_ok=True)
            test_file.unlink(missing_ok=True)
        except (OSError, PermissionError) as e:
            raise ValueError(
                f"Database directory '{db_dir}' is not writable: {e}. "
                "For Docker deployments, set DETONATE_DATABASE to a writable path "
                "(e.g., /var/lib/detonate/detonate.db). For local development, "
                "ensure the current directory is writable."
            ) from e

        return self

    # Rootfs paths
    rootfs: str = "./data/qiling_rootfs"

    # Windows DLL paths (user-provided)
    dlls_x86: str = "./data/rootfs/x86_windows/dlls"
    dlls_x64: str = "./data/rootfs/x8664_windows/dlls"

    # Analysis defaults
    default_timeout: int = 60
    max_timeout: int = 300

    # API settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_workers: int = 1

    # Output
    # Default to local path for development/testing, override via DETONATE_OUTPUT_DIR for Docker
    output_dir: Path = Path("./data/output")

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    @property
    def db_path(self) -> Path:
        """Return database directory path."""
        return Path(self.database).parent

    def get_rootfs_path(self, platform: str, arch: str) -> Path:
        """Get rootfs path for given platform and architecture.
        
        Supported architectures (priority order):
        - High: x86_64, x86, arm64
        - Medium: arm, mips, mipsel
        - Low: riscv64
        
        Architecture aliases supported:
        - x86_64: x64, amd64
        - x86: i386, i686
        - arm64: aarch64
        
        Args:
            platform: Target platform (linux, windows)
            arch: Architecture name (auto-detected or user-specified)
        
        Returns:
            Path to rootfs directory for given platform/arch
        
        Raises:
            ValueError: If architecture unsupported
        """
        # Normalize architecture names with aliases
        arch_aliases = {
            # x86_64 aliases
            "x86_64": "x8664",
            "x64": "x8664",
            "amd64": "x8664",
            # x86 aliases
            "x86": "x86",
            "i386": "x86",
            "i686": "x86",
            # ARM64 aliases
            "arm64": "arm64",
            "aarch64": "arm64",
            # ARM aliases
            "arm": "arm",
            "armv7": "arm",
            # MIPS aliases
            "mips": "mips32",
            "mips32": "mips32",
            "mipsel": "mips32el",
            # RISC-V
            "riscv64": "riscv64",
        }
        
        normalized_arch = arch_aliases.get(arch.lower(), arch.lower())
        
        if platform == "windows":
            # Windows uses separate rootfs (user-provided DLLs)
            path_name = f"{normalized_arch}_windows"
            # Point to user-provided Windows DLLs in data/rootfs/
            return Path("./data/rootfs") / path_name
        else:  # linux
            path_name = f"{normalized_arch}_linux"
            path = Path(self.rootfs) / path_name
            
            # Validate rootfs has required files
            if not _is_valid_rootfs(path):
                # Fall back to system rootfs for Linux
                return Path("/")
            
            return path


def _is_valid_rootfs(path: Path) -> bool:
    """Check if the rootfs path contains minimum required files.
    
    Validates presence of architecture-specific dynamic linker.
    
    Args:
        path: Path to rootfs directory
    
    Returns:
        True if rootfs is valid, False otherwise
    """
    if not path.exists():
        return False
    
    # Architecture-specific dynamic linker paths
    # Note: Some architectures use lib/ instead of lib64/
    ld_paths = [
        # x86_64
        path / "lib64" / "ld-linux-x86-64.so.2",
        # x86
        path / "lib" / "ld-linux.so.2",
        # ARM64 (can be in lib/ or lib64/)
        path / "lib" / "ld-linux-aarch64.so.1",
        path / "lib64" / "ld-linux-aarch64.so.1",
        # ARM
        path / "lib" / "ld-linux-armhf.so.3",
        # MIPS
        path / "lib" / "ld.so.1",
        # RISC-V 64
        path / "lib64" / "ld-linux-riscv64-lp64d.so.1",
    ]
    
    return any(p.exists() for p in ld_paths)


def validate_windows_dlls(arch: str) -> tuple[bool, str | None]:
    """Validate that required Windows DLLs are present.
    
    Args:
        arch: Architecture (x86 or x86_64)
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if DLLs present
        - error_message: None if valid, helpful message if missing
    """
    dll_dir = Path("./data/rootfs") / f"{arch}_windows" / "dlls"
    
    if not dll_dir.exists():
        return False, (
            f"Windows DLLs not found at {dll_dir}\n"
            f"Please copy required DLLs from a Windows installation:\n"
            f"  mkdir -p {dll_dir}\n"
            f"  cp kernel32.dll ntdll.dll user32.dll advapi32.dll {dll_dir}/\n"
            f"\n"
            f"See WINDOWS_DLL_SETUP.md for detailed instructions."
        )
    
    # Check for essential DLLs
    required_dlls = ["kernel32.dll", "ntdll.dll"]
    missing = [dll for dll in required_dlls if not (dll_dir / dll).exists()]
    
    if missing:
        return False, (
            f"Missing required Windows DLLs: {', '.join(missing)}\n"
            f"Please copy these DLLs to: {dll_dir}\n"
            f"\n"
            f"See WINDOWS_DLL_SETUP.md for detailed instructions."
        )
    
    return True, None


def get_dlls_path(arch: str) -> Path:
    """Get DLLs path for given architecture."""
    if arch == "x86":
        return Path("/opt/rootfs/x86_windows/dlls")
    return Path("/opt/rootfs/x8664_windows/dlls")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
