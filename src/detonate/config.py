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
    rootfs: str = "/app/data/rootfs"

    # Windows DLL paths (user-provided)
    dlls_x86: str = "/opt/rootfs/x86_windows/dlls"
    dlls_x64: str = "/opt/rootfs/x8664_windows/dlls"

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
        """Get rootfs path for given platform and architecture."""
        platform_map = {
            "windows": "x86_windows" if arch == "x86" else "x8664_windows",
            "linux": "x86_linux" if arch == "x86" else "x8664_linux",
        }
        path = Path(self.rootfs) / platform_map.get(platform, "x86_linux")
        # For Linux, fall back to system rootfs if custom rootfs is empty/missing
        if platform == "linux" and not _is_valid_rootfs(path):
            return Path("/")  # Use host filesystem as rootfs
        return path


def _is_valid_rootfs(path: Path) -> bool:
    """Check if the rootfs path contains the minimum required files."""
    if not path.exists():
        return False
    # Check for dynamic linker presence
    ld_paths = [
        path / "lib64" / "ld-linux-x86-64.so.2",
        path / "lib" / "ld-linux.so.2",
    ]
    return any(p.exists() for p in ld_paths)


def get_dlls_path(arch: str) -> Path:
    """Get DLLs path for given architecture."""
    if arch == "x86":
        return Path("/opt/rootfs/x86_windows/dlls")
    return Path("/opt/rootfs/x8664_windows/dlls")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
