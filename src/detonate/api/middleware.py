"""Request logging and error handling middleware."""

import time
from datetime import datetime
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log incoming requests with timing information."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log timing."""
        start_time = time.time()

        response = await call_next(request)

        process_time = time.time() - start_time

        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)

        # Log request details (would use structlog in production)
        log_entry = {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "process_time_ms": round(process_time * 1000, 2),
            "client_host": request.client.host if request.client else "unknown",
        }

        # In production, this would use structlog
        # log.info("request_completed", **log_entry)

        return response


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Global error handler for consistent error responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and handle errors."""
        try:
            return await call_next(request)
        except Exception as exc:
            # Log the exception with traceback to file
            import traceback
            with open('/tmp/error.log', 'a') as f:
                f.write(f"\n=== ERROR at {datetime.now()} ===\n")
                f.write(f"Path: {request.url.path}\n")
                f.write(f"Exception: {type(exc).__name__}: {exc}\n")
                f.write(traceback.format_exc())
                f.write("\n")

            # Return consistent error response
            return JSONResponse(
                status_code=500,
                content={
                    "detail": f"Internal server error: {type(exc).__name__}: {exc}",
                    "type": type(exc).__name__,
                },
            )


def setup_middleware(app: FastAPI) -> None:
    """
    Configure middleware for FastAPI application.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(ErrorHandlerMiddleware)
