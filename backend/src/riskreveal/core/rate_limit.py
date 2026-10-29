"""Rate limiting for authentication endpoints (slowapi).

Usage in a route module::

    @router.post("/login")
    @limiter.limit(auth_limit)
    def login(request: Request, ...): ...

The route function MUST take a parameter named ``request: Request`` —
slowapi finds the client address through it.

``auth_limit`` is passed as a *callable* so the limit string is read from
settings on every request rather than frozen at import time.

Counters are in-process memory (``memory://``): correct for a single
development server, but each worker process counts separately. Switch
``storage_uri`` to ``settings.redis_url`` before running more than one
worker. Also note ``get_remote_address`` sees the proxy's IP behind a
reverse proxy; configure trusted forwarded headers at that point.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from riskreveal.config import get_settings

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def auth_limit() -> str:
    return get_settings().auth_rate_limit
