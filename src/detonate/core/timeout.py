"""Execution timeout enforcement."""

import asyncio
import signal
import threading
import sys
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator


class TimeoutError(Exception):
    """Raised when execution exceeds timeout."""

    pass


@asynccontextmanager
async def timeout_context(seconds: int) -> AsyncGenerator[None, None]:
    """
    Async context manager for timeout enforcement.

    Args:
        seconds: Timeout in seconds

    Raises:
        TimeoutError: If timeout is exceeded
    """

    async def _timeout():
        await asyncio.sleep(seconds)
        raise TimeoutError(f"Execution timeout after {seconds} seconds")

    try:
        timeout_task = asyncio.create_task(_timeout())
        yield
        timeout_task.cancel()
        try:
            await timeout_task
        except asyncio.CancelledError:
            pass
    except TimeoutError:
        timeout_task.cancel()
        try:
            await timeout_task
        except asyncio.CancelledError:
            pass
        raise


@contextmanager
def enforce_timeout_sync(seconds: int) -> Generator[None, None, None]:
    """
    Synchronous context manager for timeout enforcement.

    On Unix-like systems, uses signal.SIGALRM for precise timeout.
    On Windows, falls back to threading.Timer (less precise, cannot
    forcibly terminate, only raises TimeoutError after the fact).

    Args:
        seconds: Timeout in seconds

    Raises:
        TimeoutError: If timeout is exceeded

    Example:
        ```python
        with enforce_timeout_sync(60):
            dangerous_operation()
        ```
    """
    if sys.platform == "win32":
        # Windows fallback: threading.Timer cannot forcibly terminate,
        # but will raise TimeoutError when timer fires
        timer_fired = threading.Event()
        original_thread = threading.current_thread()

        def _on_timeout():
            timer_fired.set()
            # Note: Cannot forcibly terminate thread on Windows
            # The protected code must check for timeout or complete naturally

        timer = threading.Timer(seconds, _on_timeout)
        timer.daemon = True
        timer.start()
        try:
            yield
            # Check if timeout occurred after completion
            if timer_fired.is_set():
                raise TimeoutError(f"Execution timeout after {seconds} seconds")
        finally:
            timer.cancel()
    else:
        # Unix: use SIGALRM for precise timeout enforcement
        def _timeout_handler(signum, frame):
            raise TimeoutError(f"Execution timeout after {seconds} seconds")

        # Save existing handler
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        # signal.alarm requires integer seconds, round up to ensure timeout
        signal.alarm(max(1, int(seconds)))
        try:
            yield
        finally:
            signal.alarm(0)  # Cancel alarm
            signal.signal(signal.SIGALRM, old_handler)  # Restore handler
