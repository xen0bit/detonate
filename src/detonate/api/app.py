"""FastAPI application factory."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI

from ..db.init_db import init_database
from ..db.store import DatabaseStore
from .middleware import setup_middleware
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    # Startup
    db_path = app.state.db_path
    init_database(db_path)
    app.state.db = DatabaseStore(str(db_path))
    app.state.start_time = datetime.now(timezone.utc)

    yield

    # Shutdown
    pass


def create_app(db_path: str | Path | None = None) -> FastAPI:
    """
    Create FastAPI application.

    Args:
        db_path: Path to SQLite database

    Returns:
        Configured FastAPI application
    """
    from ..config import get_settings

    settings = get_settings()
    database = db_path or settings.database

    app = FastAPI(
        title="Detonate API",
        description="Malware analysis platform with ATT&CK mapping",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.db_path = Path(database)

    # Setup middleware
    setup_middleware(app)

    # Include routes
    app.include_router(router, prefix="/api/v1")

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "version": "0.1.0",
            "uptime_seconds": (datetime.now(timezone.utc) - app.state.start_time).total_seconds()
            if hasattr(app.state, "start_time")
            else 0,
        }

    return app
