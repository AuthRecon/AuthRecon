from collections.abc import Callable

from fastapi import APIRouter
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import SessionLocal
from app.services.queue import get_redis_connection

router = APIRouter()


def _check_database() -> str:
    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return "error"
    finally:
        session.close()
    return "ok"


def _check_queue() -> str:
    try:
        get_redis_connection().ping()
    except RedisError:
        return "error"
    return "ok"


def _check_storage() -> str:
    # Placeholder until real object storage client is wired.
    return "skipped"


_READINESS_CHECKS: dict[str, Callable[[], str]] = {
    "database": _check_database,
    "queue": _check_queue,
    "storage": _check_storage,
}


@router.get("/live", summary="Liveness probe")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", summary="Readiness probe")
async def ready() -> dict[str, object]:
    components: dict[str, str] = {}

    status = "ok"
    for name, check in _READINESS_CHECKS.items():
        result = check()
        components[name] = result
        if result == "error" and status == "ok":
            status = "degraded"

    return {"status": status, "components": components}
