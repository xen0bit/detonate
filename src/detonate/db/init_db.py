"""Database initialization."""

from pathlib import Path

from sqlalchemy import create_engine

from .models import Base


def init_database(db_path: str | Path) -> None:
    """
    Initialize the SQLite database.

    Creates all tables if they don't exist.

    Args:
        db_path: Path to SQLite database file
    """
    path = Path(db_path)

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
