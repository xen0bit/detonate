"""API and syscall hook definitions."""

from .windows import WindowsHooks
from .linux import LinuxHooks

__all__ = ["WindowsHooks", "LinuxHooks"]
