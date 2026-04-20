"""Configuration management using pydantic-settings."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides."""

    model_config = SettingsConfigDict(
        env_prefix="DETONATE_",
        env_file=".env",
        extra="ignore",
    )

    # Database
    database: str = "/var/lib/detonate/detonate.db"

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
    output_dir: Path = Path("/output")

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
        return Path(self.rootfs) / platform_map.get(platform, "x86_linux")

    def get_dlls_path(self, arch: str) -> Path:
        """Get DLLs path for given architecture."""
        if arch == "x86":
            return Path(self.dlls_x86)
        return Path(self.dlls_x64)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
