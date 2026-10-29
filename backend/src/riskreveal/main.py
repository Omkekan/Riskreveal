"""FastAPI application factory and entrypoint.

Run with (from backend/, with .venv active via `uv run`):
    uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from riskreveal.api.v1.router import api_router
from riskreveal.config import get_settings
from riskreveal.core.rate_limit import limiter
from riskreveal.db.session import check_database_connection, get_engine

logger = logging.getLogger("riskreveal")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hooks.

    On shutdown, disposes the SQLAlchemy engine's connection pool, so a
    `--reload` restart or a graceful container stop doesn't leave open
    connections dangling against Postgres.
    """
    settings = get_settings()
    logger.info("Starting %s (environment=%s)", settings.app_name, settings.environment.value)
    yield
    get_engine().dispose()
    logger.info("Shutdown complete.")


def create_app() -> FastAPI:
    """Application factory.

    A factory function — rather than a bare module-level `FastAPI()` — so
    tests can build independent app instances (with overridden
    dependencies, different settings) instead of every test sharing one
    process-wide app and its state.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        # Always False — NOT settings.debug. Starlette's own debug mode
        # returns its own HTML traceback page for unhandled exceptions
        # *before* any custom exception handler runs (confirmed by
        # reading starlette/middleware/errors.py: `if self.debug:` is
        # checked ahead of `self.handler`), which would bypass
        # _unhandled_exception_handler below entirely and leak full
        # tracebacks to the browser even just in local dev. Our handler
        # decides how much detail to reveal, driven by settings.debug
        # itself, instead of delegating that decision to this flag.
        debug=False,
        lifespan=lifespan,
        # Interactive docs enumerate every route and request/response
        # schema in the app — genuinely useful in development, free
        # reconnaissance for an attacker in production. Hide all three in
        # production rather than relying on "nobody will find the URL."
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # slowapi looks the limiter up on app.state when a @limiter.limit route runs.
    app.state.limiter = limiter

    _register_exception_handlers(app)
    _register_routes(app)

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Baseline error handling.

    Deliberately minimal for now — `core/exceptions.py` (a later batch)
    replaces this with full RFC 9457 Problem Details responses across
    every route, including domain-specific error types. The one rule
    already enforced here is not negotiable, though: an unhandled
    exception must never leak its message or traceback to the client.
    That's a direct disclosure path for internals — stack frames, file
    paths, fragments of a failed query — to anyone who can trigger a 500.
    """

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"error": "validation_error", "detail": exc.errors()},
        )

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        # Deliberately generic: don't echo the configured limit to the client.
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": "rate_limited", "detail": "Too many requests. Try again later."},
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Full detail always goes to the server log, where only operators
        # can see it, regardless of environment.
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)

        settings = get_settings()
        # settings.debug being True in production is already impossible —
        # config.py's production-safety check rejects that combination at
        # startup — so this is only ever more verbose on a developer's own
        # machine, never on a shared or deployed environment.
        detail = str(exc) if settings.debug else "An unexpected error occurred."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_server_error", "detail": detail},
        )


def _register_routes(app: FastAPI) -> None:
    @app.get("/healthz", tags=["system"])
    async def healthz() -> JSONResponse:
        """Liveness/readiness probe that also verifies the database.

        Returns 503 (not 200) when the database is unreachable, so a load
        balancer or orchestrator correctly takes this instance out of
        rotation. "The API process is running" is not the same thing as
        "the API is healthy" when every real route needs the database.
        """
        settings = get_settings()
        db_ok = check_database_connection()
        payload = {
            "status": "ok" if db_ok else "degraded",
            "service": settings.app_name,
            "environment": settings.environment.value,
            "database": "reachable" if db_ok else "unreachable",
        }
        return JSONResponse(
            status_code=status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload,
        )

    app.include_router(api_router, prefix=get_settings().api_v1_prefix)


app = create_app()
