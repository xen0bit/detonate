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

    # Mount static files for web UI
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse
    import logging

    logger = logging.getLogger(__name__)

    # Check environment variable first (for Docker deployments), then fall back to relative path
    import os
    web_dir_env = os.environ.get("DETONATE_WEB_DIR")
    if web_dir_env:
        web_dir = Path(web_dir_env)
    else:
        # Correct path: api/ → detonate/ → src/ → project root (3 levels up)
        # This file is at: src/detonate/api/app.py
        # Project root is 3 parent directories up
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        web_dir = project_root / "web"

    # Log warning if web directory doesn't exist (aids debugging)
    if not web_dir.exists():
        logger.warning(f"Web directory not found at {web_dir}. Static files will not be served.")
    else:
        # Mount static files - use explicit str() conversion for compatibility
        app.mount("/web", StaticFiles(directory=str(web_dir)), name="web")
        logger.info(f"Mounted static files from {web_dir}")

    # Root redirect to web UI
    @app.get("/")
    async def root_redirect():
        index_html = web_dir / "index.html"
        if index_html.exists():
            return FileResponse(str(index_html))
        return {"message": "Detonate API", "web_ui": "/web/index.html"}

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """
        Health check endpoint with dependency validation.
        
        Returns 200 if all dependencies are healthy, 503 if any are unhealthy.
        Response body contains detailed component status for debugging.
        """
        import os
        import shutil
        
        from fastapi.responses import JSONResponse
        
        health_status = {
            "status": "healthy",
            "version": "0.1.0",
            "components": {},
            "uptime_seconds": None,
        }
        
        # Check database connectivity
        try:
            db = getattr(app.state, "db", None)
            if db is None:
                health_status["components"]["database"] = {
                    "status": "unhealthy",
                    "error": "Database not initialized",
                }
                health_status["status"] = "unhealthy"
            else:
                # Test database connectivity with a simple query
                db.get_analysis("nonexistent-session-id-for-health-check")
                health_status["components"]["database"] = {
                    "status": "healthy",
                    "path": str(app.state.db_path),
                }
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"
        
        # Check disk space for output directory
        try:
            output_dir = settings.output_dir
            if output_dir.exists():
                total, used, free = shutil.disk_usage(str(output_dir))
                # Mark unhealthy if less than 100MB free
                min_free_bytes = 100 * 1024 * 1024
                if free < min_free_bytes:
                    health_status["components"]["disk_space"] = {
                        "status": "unhealthy",
                        "error": f"Less than 100MB free ({free / (1024*1024):.1f}MB available)",
                        "free_bytes": free,
                    }
                    health_status["status"] = "unhealthy"
                else:
                    health_status["components"]["disk_space"] = {
                        "status": "healthy",
                        "path": str(output_dir),
                        "free_bytes": free,
                        "free_mb": free / (1024 * 1024),
                    }
            else:
                # Output dir doesn't exist yet - try to create it
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                    health_status["components"]["disk_space"] = {
                        "status": "healthy",
                        "path": str(output_dir),
                        "note": "Directory created",
                    }
                except Exception as e:
                    health_status["components"]["disk_space"] = {
                        "status": "unhealthy",
                        "error": f"Cannot create output directory: {str(e)}",
                    }
                    health_status["status"] = "unhealthy"
        except Exception as e:
            health_status["components"]["disk_space"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"
        
        # Calculate uptime
        start_time = getattr(app.state, "start_time", None)
        if start_time:
            health_status["uptime_seconds"] = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Return appropriate status code
        if health_status["status"] == "healthy":
            return JSONResponse(content=health_status, status_code=200)
        else:
            return JSONResponse(content=health_status, status_code=503)

    return app
