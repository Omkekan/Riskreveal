# RiskReveal v2 — Handoff (v6)

Supersedes v5 for "what's next". Everything in v5 still holds (Windows-only, PowerShell,
uv, small verified steps, never paste `.env`, no destructive Docker commands).

## What this session added: threat-intelligence foundation (CISA KEV + FIRST EPSS)

| Piece | Files |
|---|---|
| Tables `kev_entries`, `epss_scores`, `feed_syncs` | `domain/intelligence/models.py` |
| CVE-id validation (strict ASCII) | `domain/intelligence/cve_id.py` |
| Errors | `domain/intelligence/errors.py` |
| Pure parsers | `sources/cisa_kev.py`, `sources/first_epss.py`, `sources/textutil.py` |
| Size limits, gzip-bomb guard, local files | `sources/payload.py` |
| HTTPS downloader (size/time caps) | `sources/fetch.py` |
| Upserts + `get_threat_signals()` | `repository.py` |
| Atomic imports (one transaction each) | `service.py` |
| CLI | `cli/commands.py`, `cli/__main__.py` |
| Tests | `tests/unit/test_kev_parser.py`, `test_epss_parser.py`, `test_feed_fetch.py`; `tests/integration/test_intelligence_import.py`; fixtures (SYNTHETIC, CVE-2099-xxxx) |
| Patched | `db/migrations/env.py`, `tests/conftest.py`, `tests/integration/test_migrations.py` (register/expect the new tables) |

Design rules: bad records are skipped individually, but a file with too many bad
records (KEV 2 %, EPSS 1 %) or none valid is refused and the import rolls back; an older EPSS
file never overwrites newer scores; feed content is untrusted (size-capped, NUL-stripped,
clipped); Typer's local-variable tracebacks are disabled (they could print secrets).

## Verification status (be honest about this)

Run in the author's sandbox (stdlib only; no ruff/mypy/SQLAlchemy/httpx/typer there):
- 71 parser/gzip tests pass; 3 deliberate code mutations were each caught by a test.
- DB-layer modules and the CLI were imported and executed against stub libraries; CLI error
  paths exit 1 with a clean message; service transaction logic (3 batches, single commit,
  rollback, no sync row on failure) verified with a recording fake DB.

NOT run by anyone yet: `ruff`, `mypy --strict`, the real SQL (`repository.py`), the new
migration (not generated yet), `test_feed_fetch.py`, `test_intelligence_import.py`, real
downloads from CISA/FIRST. KEV URL and EPSS URL (`epss.empiricalsecurity.com`) were
confirmed by web search, not by downloading.

## Next steps
1. Apply, generate migration (`alembic revision --autogenerate`), review it contains ONLY the
   3 new tables, `alembic upgrade head`.
2. ruff / mypy / `pytest tests/unit` / `pytest tests/integration`; fix anything they report.
3. `load-kev`, `load-epss`, `feed-status` against the real feeds.
4. Then: CVE records (CVE list v5 / NVD) + CPE/version matcher -> vulnerability findings,
   consuming `get_threat_signals()`; risk scorer after that.
5. Still open from v5: per-user target-ownership verification before others use the API.

## Known gaps / notes
- `feed_syncs.last_success_at` also updates when a *stale* EPSS file was replayed (scores are
  protected, the timestamp is not).
- Nothing schedules the imports yet (Celery beat task is a later step).
- KEV/EPSS are enrichment only: they add value once findings carry CVE ids.
