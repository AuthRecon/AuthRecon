from rq import Queue
from redis import Redis

from app.core.config import get_settings

_redis_connection: Redis | None = None
_queues: dict[str, Queue] = {}


def get_redis_connection() -> Redis:
    global _redis_connection
    if _redis_connection is None:
        settings = get_settings()
        _redis_connection = Redis.from_url(str(settings.redis_url))
    return _redis_connection


def get_queue(name: str = "runs") -> Queue:
    # One cached Queue per name (a single cached instance would hand back
    # whichever queue was requested first, regardless of ``name``).
    queue = _queues.get(name)
    if queue is None:
        queue = _queues[name] = Queue(name, connection=get_redis_connection())
    return queue
