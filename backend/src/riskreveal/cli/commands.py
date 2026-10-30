"""Command-line maintenance tools.

Run from the ``backend`` folder (so ``.env`` is found)::

    uv run python -m riskreveal.cli --help
    uv run python -m riskreveal.cli load-kev
    uv run python -m riskreveal.cli load-epss
    uv run python -m riskreveal.cli feed-status

``load-kev`` and ``load-epss`` download the official feeds. Pass ``--file`` to
load a file you already have (useful offline and for testing).

Deliberately NOT using ``from __future__ import annotations``: Typer reads the
real annotations at runtime.
"""

from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy.exc import SQLAlchemyError

from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.intelligence import repository, service
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.sources import fetch, payload
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.first_epss import (
    EPSS_MAX_BYTES,
    EPSS_URL,
    EpssReader,
)

app = typer.Typer(
    help="RiskReveal maintenance commands.",
    no_args_is_help=True,
    add_completion=False,
    # Typer's pretty tracebacks print local variables; some frames hold the
    # settings object (JWT / Fernet secrets). Never show them.
    pretty_exceptions_show_locals=False,
)

FileOption = Annotated[
    Path | None,
    typer.Option("--file", dir_okay=False, help="Read this local file instead of downloading."),
]


def _fail(message: str) -> typer.Exit:
    typer.echo(f"Error: {message}", err=True)
    return typer.Exit(code=1)


def _db_error(exc: SQLAlchemyError) -> typer.Exit:
    return _fail(
        f"the database operation failed ({type(exc).__name__}). Is Docker running and "
        "'alembic upgrade head' applied?"
    )


@app.command("load-kev")
def load_kev(file: FileOption = None) -> None:
    """Import the CISA Known Exploited Vulnerabilities catalog."""
    try:
        if file is not None:
            raw = payload.read_local(file, KEV_MAX_BYTES)
        else:
            raw = fetch.download(KEV_URL, max_bytes=KEV_MAX_BYTES)
        catalog = parse_kev(raw)
        with get_sessionmaker()() as db:
            result = service.import_kev(db, catalog)
    except FeedError as exc:
        raise _fail(str(exc)) from exc
    except SQLAlchemyError as exc:
        raise _db_error(exc) from exc
    typer.echo(
        f"KEV: stored {result.imported} entries (catalog {result.version or 'unknown'}); "
        f"skipped {result.skipped} invalid."
    )


@app.command("load-epss")
def load_epss(file: FileOption = None) -> None:
    """Import the daily FIRST EPSS scores (about 300,000 rows; takes a minute)."""
    try:
        if file is not None:
            raw = payload.read_local(file, EPSS_MAX_BYTES)
        else:
            raw = fetch.download(EPSS_URL, max_bytes=EPSS_MAX_BYTES)
        reader = EpssReader.from_bytes(raw)
        with get_sessionmaker()() as db:
            result = service.import_epss(db, reader)
    except FeedError as exc:
        raise _fail(str(exc)) from exc
    except SQLAlchemyError as exc:
        raise _db_error(exc) from exc
    typer.echo(
        f"EPSS: stored {result.imported} scores (model/date {result.version}); "
        f"skipped {result.skipped} invalid rows."
    )


@app.command("feed-status")
def feed_status() -> None:
    """Show when each intelligence feed was last imported."""
    try:
        with get_sessionmaker()() as db:
            syncs = repository.list_syncs(db)
    except SQLAlchemyError as exc:
        raise _db_error(exc) from exc
    if not syncs:
        typer.echo("No feeds have been imported yet.")
        return
    for sync in syncs:
        typer.echo(
            f"{sync.source:<12} last success {sync.last_success_at.isoformat()}  "
            f"version {sync.version or '-'}  records {sync.record_count}"
        )
