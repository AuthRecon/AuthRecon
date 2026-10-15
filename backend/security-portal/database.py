"""Database helpers for the Security Portal."""
from __future__ import annotations

from typing import Callable

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy models."""


_ENGINE = None
_ENGINE_URL: str | None = None
SessionLocal: Callable | None = None


def init_engine(database_url: str):
    """Initialize the global SQLAlchemy engine/session."""
    global _ENGINE, _ENGINE_URL, SessionLocal
    if _ENGINE is not None and _ENGINE_URL == database_url:
        return _ENGINE
    if _ENGINE is not None and _ENGINE_URL != database_url:
        _ENGINE.dispose()

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _ENGINE = create_engine(database_url, future=True, connect_args=connect_args)
    SessionLocal = sessionmaker(
        bind=_ENGINE,
        autocommit=False,
        autoflush=False,
        future=True,
        expire_on_commit=False,
    )
    _ENGINE_URL = database_url
    return _ENGINE


def get_session():
    """Return a new SQLAlchemy session."""
    if SessionLocal is None:
        raise RuntimeError("Database engine not initialized")
    return SessionLocal()
