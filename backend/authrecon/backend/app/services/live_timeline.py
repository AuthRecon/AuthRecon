"""Write run timeline events as they happen.

Login handlers collect their step messages in a plain list that the worker
used to turn into timeline rows only after the whole attempt returned, and the
rows were saved when the run finished. Every step got the same timestamp and
the live timeline showed nothing until the end, which hid where time went.

``live_timeline(run_id)`` (set by the worker around a run) makes two things
write immediately, each in its own short session with its real timestamp:

- ``LiveEvents``: the list type handlers use for their messages. ``append``
  writes the row, then stores the message as before.
- ``write()``: for the worker's own messages.

Everything is best-effort: a failed write is logged and the run carries on.
Outside ``live_timeline`` both behave exactly like before (nothing written).
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Callable, Iterator

logger = logging.getLogger(__name__)

_writer: ContextVar["LiveTimeline | None"] = ContextVar("live_timeline_writer", default=None)
_prefix: ContextVar[str] = ContextVar("live_timeline_prefix", default="")


class LiveTimeline:
    def __init__(self, run_id: str, session_factory: Callable | None = None) -> None:
        self.run_id = run_id
        if session_factory is None:
            from app.db.session import SessionLocal

            session_factory = SessionLocal
        self._session_factory = session_factory

    def write(self, message: str, occurred_at: datetime | None = None) -> bool:
        from app.models import TimelineEvent

        try:
            session = self._session_factory()
            try:
                session.add(TimelineEvent(
                    run_id=self.run_id,
                    occurred_at=occurred_at or datetime.now(timezone.utc),
                    message=message,
                ))
                session.commit()
            finally:
                session.close()
            return True
        except Exception:
            logger.warning("Could not write live timeline event for run %s", self.run_id, exc_info=True)
            return False


@contextmanager
def live_timeline(run_id: str, session_factory: Callable | None = None) -> Iterator[LiveTimeline]:
    token = _writer.set(LiveTimeline(run_id, session_factory))
    try:
        yield _writer.get()
    finally:
        _writer.reset(token)


@contextmanager
def event_prefix(prefix: str) -> Iterator[None]:
    """Prefix for handler messages, e.g. "[admin] " on multi-role runs."""
    token = _prefix.set(prefix)
    try:
        yield
    finally:
        _prefix.reset(token)


def current() -> LiveTimeline | None:
    return _writer.get()


def write(message: str) -> bool:
    """Write one event now if a live timeline is active. True if written."""
    writer = _writer.get()
    return bool(writer and writer.write(message))


class LiveEvents(list):
    """A handler's message list that also writes each message as it's appended."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.written_live = False

    def append(self, message) -> None:  # type: ignore[override]
        super().append(message)
        writer = _writer.get()
        if writer is not None and writer.write(f"{_prefix.get()}{message}"):
            self.written_live = True


def live_events() -> LiveEvents:
    return LiveEvents()


def not_yet_written(messages) -> list:
    """Messages still to record afterwards: none if they were written live."""
    return [] if getattr(messages, "written_live", False) else list(messages or [])
