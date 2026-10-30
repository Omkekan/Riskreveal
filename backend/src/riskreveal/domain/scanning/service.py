"""Scan lifecycle: create, run, cancel, and clean up stuck scans.

Two halves, running in different processes:

* **API side** -- :func:`create_scan` validates the target (scope policy +
  operator allowlist), enforces a per-user cap on active scans, stores a
  ``queued`` row and commits. The route then hands the scan id to the task
  queue.
* **Worker side** -- :func:`run_scan` atomically claims the queued scan,
  re-validates the target with fresh DNS, runs the **real** Nmap binary, and
  writes assets and findings in ONE transaction together with the final
  status. If anything fails, that transaction is rolled back (no partial
  results) and the scan is marked ``failed`` with a short, safe message.

Rules enforced here (see the handoff, section 6):

* Raw subprocess output, stderr and tracebacks go to the server log only,
  never into ``Scan.error`` or an API response.
* Scan data is attacker-controlled: every string from Nmap is clipped to its
  column size (an oversized banner must not crash persistence) and stripped
  of NUL bytes.
* No database transaction is held open while Nmap runs.
* A scan is processed at most once: the claim is a conditional UPDATE, so a
  duplicate or redelivered task is a harmless no-op.
"""

from __future__ import annotations

import logging
import subprocess
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskreveal.config import Settings, get_settings
from riskreveal.domain.assets import repository as asset_repository
from riskreveal.domain.findings.enums import FindingSource, FindingStatus
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.scanning import repository as scan_repository
from riskreveal.domain.scanning.authorization import check_authorized, parse_allowlist
from riskreveal.domain.scanning.enums import ScanStatus
from riskreveal.domain.scanning.models import Scan
from riskreveal.domain.scanning.profiles import PROFILES, UnknownProfileError, get_profile
from riskreveal.domain.scanning.scope_policy import (
    Resolver,
    ScopeError,
    ValidatedTarget,
    system_resolver,
    validate_target,
)
from riskreveal.domain.users.models import User
from riskreveal.engines.base import (
    EngineError,
    EngineNotFoundError,
    EngineTimeoutError,
    NmapParseError,
    ParsedHost,
    ScanResult,
)
from riskreveal.engines.nmap_engine import Runner, run_nmap
from riskreveal.engines.normalizer import FindingDraft, normalize_host

logger = logging.getLogger("riskreveal.scanning")

# Column sizes from the models. Anything longer than this from a scanned host
# would make PostgreSQL reject the INSERT and fail the whole scan.
_MAX_ADDRESS = 45
_MAX_HOSTNAME = 253
_MAX_OS_NAME = 255
_MAX_TITLE = 255
_MAX_PROTOCOL = 8
_MAX_SERVICE = 64
_MAX_PRODUCT = 128
_MAX_VERSION = 128
_MAX_CPE = 255

# A running scan older than (longest profile timeout x 2) is certainly stuck.
STALE_RUNNING_AFTER = timedelta(seconds=2 * max(p.timeout_seconds for p in PROFILES.values()))
# A queued scan that nobody picked up for this long was lost (e.g. Redis wiped).
STALE_QUEUED_AFTER = timedelta(hours=6)


class ScanRejectedError(Exception):
    """The scan cannot be created. The message is safe to show the user."""


class TooManyActiveScansError(ScanRejectedError):
    """The user already has the maximum number of queued/running scans."""


class ScanNotCancellableError(Exception):
    """The scan already finished, so it cannot be cancelled."""


# ---------------------------------------------------------------------------
# API side
# ---------------------------------------------------------------------------


def create_scan(
    db: Session,
    *,
    owner_id: uuid.UUID,
    raw_target: str,
    profile_name: str,
    settings: Settings | None = None,
    resolver: Resolver = system_resolver,
) -> Scan:
    """Validate and store a new ``queued`` scan. Raises ``ScopeError`` for a
    refused target, :class:`ScanRejectedError` for a refused request."""
    cfg = settings if settings is not None else get_settings()
    profile = get_profile(profile_name)  # raises UnknownProfileError
    target = _validate_and_authorize(raw_target, cfg, resolver)

    # Lock the user's row so two simultaneous requests cannot both pass the
    # "active scans" cap. The lock is released by the commit/rollback below.
    locked = db.scalar(select(User.id).where(User.id == owner_id).with_for_update())
    if locked is None:
        db.rollback()
        raise ScanRejectedError("This account is not available.")
    if scan_repository.count_active(db, owner_id) >= cfg.scan_max_active_per_user:
        db.rollback()
        raise TooManyActiveScansError(
            f"You already have {cfg.scan_max_active_per_user} scans queued or running. "
            "Wait for one to finish or cancel it."
        )

    scan = Scan(
        owner_id=owner_id,
        target=target.original,
        profile=profile.name,
        status=ScanStatus.QUEUED.value,
        scanned_addresses=list(target.scan_args),
    )
    db.add(scan)
    db.flush()
    db.commit()
    db.refresh(scan)
    return scan


def mark_queue_failed(db: Session, scan_id: uuid.UUID) -> None:
    """The task queue refused the scan: do not leave it ``queued`` forever."""
    db.rollback()
    scan_repository.transition(
        db,
        scan_id,
        expected=[ScanStatus.QUEUED],
        new=ScanStatus.FAILED,
        error="The scan could not be queued. Please try again later.",
    )
    db.commit()


def cancel_scan(db: Session, *, scan_id: uuid.UUID, owner_id: uuid.UUID) -> Scan | None:
    """Cancel a queued or running scan. ``None`` if it does not exist for this
    owner. A *running* scan is marked cancelled at once; its Nmap process runs
    to its own time limit, but its results are discarded."""
    scan = scan_repository.get_for_owner(db, scan_id, owner_id)
    if scan is None:
        db.rollback()
        return None
    changed = scan_repository.transition(
        db,
        scan_id,
        expected=scan_repository.ACTIVE_STATUSES,
        new=ScanStatus.CANCELLED,
    )
    db.commit()
    if not changed:
        raise ScanNotCancellableError("This scan has already finished.")
    return scan_repository.get_for_owner(db, scan_id, owner_id)


# ---------------------------------------------------------------------------
# Worker side
# ---------------------------------------------------------------------------


def run_scan(
    db: Session,
    scan_id: uuid.UUID,
    *,
    settings: Settings | None = None,
    resolver: Resolver = system_resolver,
    runner: Runner = subprocess.run,
) -> ScanStatus | None:
    """Run one queued scan to completion. Returns the final status, or ``None``
    if the scan was not queued (cancelled, duplicate delivery, unknown id).

    ``resolver`` and ``runner`` default to real DNS and the real
    ``subprocess.run``; they are parameters only so tests can inject failures.
    """
    cfg = settings if settings is not None else get_settings()

    if not scan_repository.claim_queued(db, scan_id):
        db.rollback()
        return None
    db.commit()

    scan = scan_repository.get(db, scan_id)
    if scan is None:  # cannot happen after a successful claim; be defensive
        db.rollback()
        return None
    owner_id, target_text, profile_name = scan.owner_id, scan.target, scan.profile
    db.commit()  # end the read transaction: don't hold a connection during Nmap

    try:
        profile = get_profile(profile_name)
        # Re-validate with fresh DNS: time has passed since the request, and
        # what is scanned must be what is allowed *now*.
        target = _validate_and_authorize(target_text, cfg, resolver)
        scan_repository.set_scanned_addresses(db, scan_id, list(target.scan_args))
        db.commit()

        logger.info("scan %s started (profile=%s kind=%s)", scan_id, profile.name, target.kind)
        result = run_nmap(target, profile, nmap_path=cfg.nmap_path, runner=runner)

        if _persist_result(db, scan_id=scan_id, owner_id=owner_id, target=target, result=result):
            logger.info("scan %s completed (%d host(s))", scan_id, len(result.hosts))
            return ScanStatus.COMPLETED
        logger.info("scan %s was cancelled while running; results discarded", scan_id)
        return ScanStatus.CANCELLED
    except (ScopeError, UnknownProfileError) as exc:
        return _fail(db, scan_id, str(exc))  # both messages are written to be user-safe
    except EngineError as exc:
        # The raw message can contain Nmap's stderr: log it, never store it.
        logger.warning("scan %s engine failure: %s", scan_id, exc)
        return _fail(db, scan_id, _engine_message(exc))
    except Exception:
        logger.exception("scan %s failed unexpectedly", scan_id)
        return _fail(db, scan_id, "The scan failed because of an internal error.")


def fail_stale_scans(db: Session, *, now: datetime | None = None) -> int:
    """Fail scans stuck in ``running`` (worker died) or ``queued`` (lost)."""
    current = now if now is not None else datetime.now(UTC)
    count = scan_repository.fail_stale(
        db,
        running_before=current - STALE_RUNNING_AFTER,
        queued_before=current - STALE_QUEUED_AFTER,
        running_message="The scan stopped unexpectedly and was marked as failed.",
        queued_message="The scan was never started and was marked as failed.",
    )
    db.commit()
    if count:
        logger.warning("marked %d stale scan(s) as failed", count)
    return count


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _validate_and_authorize(raw: str, cfg: Settings, resolver: Resolver) -> ValidatedTarget:
    target = validate_target(
        raw, allow_private=cfg.scan_private_ranges_allowed, resolver=resolver
    )
    check_authorized(target, allowlist=parse_allowlist(cfg.scan_public_allowlist))
    return target


def _fail(db: Session, scan_id: uuid.UUID, message: str) -> ScanStatus:
    """Discard any partial work and record a safe failure message."""
    db.rollback()
    changed = scan_repository.transition(
        db,
        scan_id,
        expected=[ScanStatus.RUNNING],
        new=ScanStatus.FAILED,
        error=_clip(message, 500),
    )
    db.commit()
    return ScanStatus.FAILED if changed else ScanStatus.CANCELLED


def _engine_message(exc: EngineError) -> str:
    if isinstance(exc, EngineNotFoundError):
        return "Nmap is not available on the scan worker."
    if isinstance(exc, EngineTimeoutError):
        return "The scan exceeded its time limit and was stopped."
    if isinstance(exc, NmapParseError):
        return "The scanner returned output that could not be read."
    return "The scanner failed to run."


def _persist_result(
    db: Session,
    *,
    scan_id: uuid.UUID,
    owner_id: uuid.UUID,
    target: ValidatedTarget,
    result: ScanResult,
) -> bool:
    """Write assets, findings and the final status in one transaction.

    Returns False (and writes nothing) if the scan was cancelled meanwhile.
    """
    # The conditional UPDATE also takes the row lock, so a concurrent cancel
    # either lands before this (we discard) or waits until we commit.
    if not scan_repository.transition(
        db, scan_id, expected=[ScanStatus.RUNNING], new=ScanStatus.COMPLETED
    ):
        db.rollback()
        return False

    for host in result.hosts:
        if host.status != "up":
            continue
        asset_id = asset_repository.upsert(
            db,
            owner_id=owner_id,
            address=_clip(host.address, _MAX_ADDRESS),
            hostname=_hostname_for(host, target),
            os_name=_clip_opt(host.os_name, _MAX_OS_NAME),
        )
        db.add_all(
            [_finding_from_draft(scan_id, asset_id, draft) for draft in normalize_host(host)]
        )
    db.commit()
    return True


def _hostname_for(host: ParsedHost, target: ValidatedTarget) -> str | None:
    if target.kind == "hostname" and host.address in target.addresses:
        return _clip_opt(target.hostname, _MAX_HOSTNAME)
    return None


def _finding_from_draft(scan_id: uuid.UUID, asset_id: uuid.UUID, draft: FindingDraft) -> Finding:
    return Finding(
        scan_id=scan_id,
        asset_id=asset_id,
        source=FindingSource.NMAP.value,
        confidence=draft.confidence,
        severity=draft.severity,
        status=FindingStatus.OPEN.value,
        title=_clip(draft.title, _MAX_TITLE),
        description=_clean(draft.description),
        port=draft.port,
        protocol=_clip(draft.protocol, _MAX_PROTOCOL),
        service=_clip_opt(draft.service, _MAX_SERVICE),
        product=_clip_opt(draft.product, _MAX_PRODUCT),
        version=_clip_opt(draft.version, _MAX_VERSION),
        cpe=_clip_opt(draft.cpe, _MAX_CPE),
        raw_evidence=None if draft.raw_evidence is None else _clean(draft.raw_evidence),
    )


def _clean(value: str) -> str:
    """PostgreSQL text cannot hold NUL bytes."""
    return value.replace("\x00", "")


def _clip(value: str, limit: int) -> str:
    return _clean(value)[:limit]


def _clip_opt(value: str | None, limit: int) -> str | None:
    return None if value is None else _clip(value, limit)
