"""Core emulation logic using Qiling."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from ..config import Settings, get_settings
from ..utils.binary import detect_platform_arch, is_elf, is_pe
from ..utils.hashing import get_file_hashes
from .hooks import LinuxHooks, WindowsHooks
from .session import AnalysisSession, APICallRecord
from .timeout import TimeoutError, timeout_context

log = structlog.get_logger()


class DetonateEmulator:
    """
    Qiling-based malware emulator.

    Handles setup, execution, and hook configuration for both
    Windows PE and Linux ELF binaries.
    """

    def __init__(
        self,
        sample_path: str,
        rootfs_path: str | None = None,
        platform: str = "auto",
        arch: str = "auto",
        timeout: int = 60,
        settings: Settings | None = None,
    ):
        """
        Initialize emulator.

        Args:
            sample_path: Path to sample binary
            rootfs_path: Path to Qiling rootfs (auto-detected if None)
            platform: Target platform (auto, windows, linux)
            arch: Target architecture (auto, x86, x86_64, arm, arm64)
            timeout: Execution timeout in seconds
            settings: Application settings (uses defaults if None)
        """
        self.sample_path = Path(sample_path)
        self.timeout = timeout
        self.settings = settings or get_settings()

        # Detect platform and architecture
        if platform == "auto" or arch == "auto":
            detected_platform, detected_arch = detect_platform_arch(self.sample_path)

            if platform == "auto":
                platform = detected_platform
            if arch == "auto":
                arch = detected_arch

        self.platform = platform
        self.architecture = arch

        # Determine rootfs
        if rootfs_path:
            self.rootfs_path = Path(rootfs_path)
        else:
            self.rootfs_path = self.settings.get_rootfs_path(platform, arch)

        # Session tracking
        self.session: AnalysisSession | None = None

    async def run(self) -> Any:
        """
        Run emulation and return results.

        Returns:
            AnalysisResult with all captured data

        Raises:
            TimeoutError: If execution exceeds timeout
            ValueError: If platform/architecture unsupported
            FileNotFoundError: If sample or rootfs not found
        """
        if not self.sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {self.sample_path}")

        if not self.rootfs_path.exists():
            raise FileNotFoundError(f"Rootfs not found: {self.rootfs_path}")

        # Initialize session
        hashes = get_file_hashes(self.sample_path)
        file_type = self._detect_file_type()

        self.session = AnalysisSession(
            sample_path=str(self.sample_path),
            sample_sha256=hashes["sha256"],
            sample_md5=hashes["md5"],
            platform=self.platform,
            architecture=self.architecture,
            file_type=file_type,
        )

        self.session.start()

        log.info(
            "analysis_started",
            session_id=self.session.session_id,
            sample_sha256=self.session.sample_sha256,
            platform=self.platform,
            architecture=self.architecture,
            timeout=self.timeout,
        )

        try:
            async with timeout_context(self.timeout):
                await self._run_emulation()

            self.session.complete()
        except TimeoutError as e:
            log.warning("analysis_timeout", session_id=self.session.session_id)
            self.session.fail(str(e))
        except Exception as e:
            log.error("analysis_failed", session_id=self.session.session_id, error=str(e))
            self.session.fail(str(e))
            raise

        log.info(
            "analysis_completed",
            session_id=self.session.session_id,
            status=self.session.status,
            api_calls=len(self.session.api_calls),
            findings=len(self.session.findings),
        )

        return self.session.to_result()

    def _detect_file_type(self) -> str:
        """Detect file type description."""
        if is_pe(self.sample_path):
            if self.architecture == "x86":
                return "PE32 executable"
            elif self.architecture == "x86_64":
                return "PE32+ executable"
            return "PE executable"
        elif is_elf(self.sample_path):
            if self.architecture == "x86":
                return "ELF 32-bit executable"
            elif self.architecture == "x86_64":
                return "ELF 64-bit executable"
            return "ELF executable"
        return "Unknown binary"

    async def _run_emulation(self) -> None:
        """Run Qiling emulation with hooks."""
        # Import qiling here to avoid import errors if not installed
        try:
            from qiling import Qiling
        except ImportError:
            raise RuntimeError("Qiling not installed. Run: pip install qiling")

        # Determine Qiling arch string
        arch_map = {
            "x86": "x86",
            "x86_64": "x8664",
            "arm": "arm",
            "arm64": "arm64",
        }
        ql_arch = arch_map.get(self.architecture, "x86")

        # Determine OS profile
        if self.platform == "windows":
            profile = "windows"
        else:
            profile = "linux"

        # Initialize Qiling
        ql = Qiling(
            argv=[str(self.sample_path)],
            rootfs=str(self.rootfs_path),
            archname=ql_arch,
            ostype=profile,
            console=False,
        )

        # Set up hooks based on platform
        self._setup_hooks(ql)

        # Run emulation (blocking, so run in executor)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, ql.run)

    def _setup_hooks(self, ql: Any) -> None:
        """Configure Qiling hooks based on platform."""
        if self.session is None:
            return

        if self.platform == "windows":
            hooks = WindowsHooks(self.session, ql)
            hooks.install()
        else:
            hooks = LinuxHooks(self.session, ql)
            hooks.install()

        log.debug("hooks_installed", platform=self.platform)
