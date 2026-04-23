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
            from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS
        except ImportError:
            raise RuntimeError("Qiling not installed. Run: pip install qiling")

        # Map platform/arch to Qiling enums
        arch_map = {
            # x86 family
            "x86": QL_ARCH.X86,
            "i386": QL_ARCH.X86,
            "i686": QL_ARCH.X86,
            "x86_64": QL_ARCH.X8664,
            "x64": QL_ARCH.X8664,
            "amd64": QL_ARCH.X8664,
            # ARM family
            "arm": QL_ARCH.ARM,
            "armv7": QL_ARCH.ARM,
            "arm64": QL_ARCH.ARM64,
            "aarch64": QL_ARCH.ARM64,
            # MIPS family (endianness handled separately via endian param)
            "mips": QL_ARCH.MIPS,
            "mips32": QL_ARCH.MIPS,
            "mipsel": QL_ARCH.MIPS,
            "mips32el": QL_ARCH.MIPS,
            # RISC-V
            "riscv64": QL_ARCH.RISCV64,
        }
        os_map = {
            "windows": QL_OS.WINDOWS,
            "linux": QL_OS.LINUX,
        }
        # MIPS endianness mapping
        endian_map = {
            "mips": QL_ENDIAN.EB,      # Big-endian
            "mips32": QL_ENDIAN.EB,    # Big-endian
            "mipsel": QL_ENDIAN.EL,    # Little-endian
            "mips32el": QL_ENDIAN.EL,  # Little-endian
        }

        ql_arch = arch_map.get(self.architecture)
        ql_os = os_map.get(self.platform)
        ql_endian = endian_map.get(self.architecture)  # None for non-MIPS

        if ql_arch is None:
            raise ValueError(f"Unsupported architecture: {self.architecture}")
        if ql_os is None:
            raise ValueError(f"Unsupported platform: {self.platform}")

        # Validate Windows DLLs if analyzing Windows binary
        if self.platform == "windows":
            from ..config import validate_windows_dlls
            
            is_valid, error_msg = validate_windows_dlls(self.architecture)
            if not is_valid:
                raise FileNotFoundError(error_msg)

        # Validate that the sample binary matches the detected architecture
        # Mismatched architecture causes silent emulation failures in Qiling
        self._validate_binary_architecture()

        # Log configuration for debugging
        log.debug(
            "qiling_config",
            archtype=str(ql_arch),
            ostype=str(ql_os),
            rootfs=str(self.rootfs_path),
            sample=str(self.sample_path),
        )

        # Initialize Qiling with proper error handling
        try:
            # Build kwargs dynamically - endian only for MIPS architectures
            ql_kwargs = {
                "argv": [str(self.sample_path)],
                "rootfs": str(self.rootfs_path),
                "archtype": ql_arch,
                "ostype": ql_os,
                "console": False,
            }
            # Add endian parameter for MIPS (required for correct byte order)
            if ql_endian is not None:
                ql_kwargs["endian"] = ql_endian
            
            ql = Qiling(**ql_kwargs)
        except FileNotFoundError as e:
            # Missing rootfs files (e.g., ld-linux, libc)
            raise RuntimeError(
                f"Qiling initialization failed: missing rootfs files. "
                f"Ensure {self.rootfs_path} contains required libraries. "
                f"Original error: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"Qiling initialization failed for {self.sample_path} "
                f"(arch={self.architecture}, platform={self.platform}): {e}"
            ) from e

        # Setup hooks before running
        self._setup_hooks(ql)

        # Run emulation in a thread to allow async timeout to work
        # ql.run() is blocking, so we must run it in a thread pool
        try:
            await asyncio.to_thread(ql.run)
        except Exception as e:
            log.error(
                "emulation_runtime_error",
                session_id=self.session.session_id if self.session else None,
                error=str(e),
            )
            raise

    def _validate_binary_architecture(self) -> None:
        """
        Validate that the sample binary matches the detected architecture.

        Mismatched architecture causes silent emulation failures in Qiling.
        """
        if not self.sample_path.exists():
            return

        detected_platform, detected_arch = detect_platform_arch(self.sample_path)

        # Check architecture match
        if detected_arch != "unknown" and detected_arch != self.architecture:
            raise ValueError(
                f"Architecture mismatch: sample is {detected_arch} but "
                f"emulation configured for {self.architecture}. "
                f"Sample: {self.sample_path}"
            )

        # Check platform match
        if detected_platform != "unknown" and detected_platform != self.platform:
            raise ValueError(
                f"Platform mismatch: sample is {detected_platform} but "
                f"emulation configured for {self.platform}. "
                f"Sample: {self.sample_path}"
            )

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
