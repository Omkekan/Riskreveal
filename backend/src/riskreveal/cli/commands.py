"""Command-line maintenance tools.

Run from the ``backend`` folder (so ``.env`` is found)::

    uv run python -m riskreveal.cli --help
    uv run python -m riskreveal.cli load-kev
    uv run python -m riskreveal.cli load-epss
    uv run python -m riskreveal.cli feed-status
    uv run python -m riskreveal.cli sync-cves "cpe:/a:apache:http_server:2.4.7"
    uv run python -m riskreveal.cli match-scan <scan-id>

``sync-cves`` asks the NVD about one CPE and stores the answer (without an
``NVD_API_KEY`` the NVD allows 5 requests per 30 s, so it may take a minute).
``match-scan`` compares a completed scan with the stored CVE data and creates
``version_match`` findings; ``--offline`` uses only what is already stored.

``load-kev`` and ``load-epss`` download the official feeds. Pass ``--file`` to
load a file you already have (useful offline and for testing).

Deliberately NOT using ``from __future__ import annotations``: Typer reads the
real annotations at runtime.
"""

import uuid
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy.exc import SQLAlchemyError

from riskreveal.config import get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.intelligence import cve_service, matching_service, repository, service
from riskreveal.domain.intelligence.cpe import full_version, parse_cpe
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.sources import fetch, payload
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.first_epss import (
    EPSS_MAX_BYTES,
    EPSS_URL,
    EpssReader,
)
from riskreveal.domain.intelligence.sources.nvd_client import NvdClient

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


def _nvd_client() -> NvdClient:
    key = get_settings().nvd_api_key
    return NvdClient(api_key=key.get_secret_value() if key else None)


@app.command("sync-cves")
def sync_cves(
    cpe: Annotated[str, typer.Argument(help="A CPE, e.g. cpe:/a:apache:http_server:2.4.7")],
) -> None:
    """Download and store the NVD's CVEs for one CPE."""
    parsed = parse_cpe(cpe)
    if parsed is None or full_version(parsed) is None:
        raise _fail("that is not a CPE with a version (e.g. cpe:/a:apache:http_server:2.4.7)")
    try:
        with get_sessionmaker()() as db:
            status = cve_service.ensure_cpe_data(
                db, parsed, _nvd_client(), max_age=timedelta(0), ignore_negative_cache=True
            )
    except FeedError as exc:
        raise _fail(str(exc)) from exc
    except SQLAlchemyError as exc:
        raise _db_error(exc) from exc
    messages = {
        cve_service.DataStatus.FETCHED: "Stored the NVD's CVEs for that CPE.",
        cve_service.DataStatus.UNKNOWN_CPE: (
            "The NVD does not know that CPE name. That means NO DATA, not 'no vulnerabilities'."
        ),
        cve_service.DataStatus.NO_NAME: "That CPE cannot be turned into an NVD name.",
    }
    typer.echo(messages.get(status, f"Result: {status.value}."))


@app.command("match-scan")
def match_scan(
    scan_id: Annotated[str, typer.Argument(help="The id of a completed scan")],
    offline: Annotated[
        bool, typer.Option("--offline", help="Use only CVE data already stored; no NVD calls.")
    ] = False,
) -> None:
    """Create version_match findings for a completed scan."""
    try:
        parsed = uuid.UUID(scan_id)
    except ValueError as exc:
        raise _fail("the scan id must be a UUID") from exc
    settings = get_settings()
    try:
        with get_sessionmaker()() as db:
            summary = matching_service.match_scan(
                db,
                parsed,
                client=None if offline else _nvd_client(),
                cache_max_age=timedelta(hours=settings.nvd_cache_hours),
            )
    except FeedError as exc:
        raise _fail(str(exc)) from exc
    except SQLAlchemyError as exc:
        raise _db_error(exc) from exc
    typer.echo(
        f"Created {summary.findings_created} version_match findings from "
        f"{summary.services_checked} service(s); {summary.services_skipped} skipped for lack "
        f"of a usable CPE/version; {summary.weak_matches} weak match(es) left for review."
    )
    if summary.sync_errors:
        typer.echo(f"The NVD could not be read for {summary.sync_errors} CPE(s); try again later.")
    if summary.no_data:
        typer.echo(
            "No CVE data for: " + ", ".join(summary.no_data) + ". That does NOT mean they are safe."
        )
    if summary.truncated:
        typer.echo("Result truncated: more matches than the per-scan limit.")
