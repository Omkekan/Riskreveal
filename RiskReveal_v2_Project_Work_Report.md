# RiskReveal v2 — Project Work Report

> **Written:** 30 October 2026
> **Covers:** the whole rebuild to date (concept, architecture, everything built and verified), with a detailed account of the most recent work — the **threat-intelligence foundation (CISA KEV + FIRST EPSS)**.
> **Reads best after:** `RiskReveal_v2_Handoff_v5.md` (project state before this session) and `RiskReveal_v2_Handoff_v6.md` (short handoff for this session).
>
> **Status words used throughout**
> - **Verified** — the owner pasted real command output, or the result was shown in chat.
> - **Verified in sandbox only** — executed in the assistant's limited sandbox (no SQLAlchemy, Docker, network, ruff, mypy). Useful evidence, not final proof.
> - **Delivered, not run** — code was written but nobody has executed it yet.
> - **Pending** — a step that still has to be done.

---

## Table of contents

1. [What RiskReveal is](#1-what-riskreveal-is)
2. [How the project got here](#2-how-the-project-got-here)
3. [Environment](#3-environment)
4. [Architecture and standing rules](#4-architecture-and-standing-rules)
5. [What is built: the foundation (before this session)](#5-what-is-built-the-foundation-before-this-session)
6. [This session's work: threat-intelligence foundation](#6-this-sessions-work-threat-intelligence-foundation)
7. [How the code behaves — detailed design](#7-how-the-code-behaves--detailed-design)
8. [Security considerations](#8-security-considerations)
9. [Testing and verification record](#9-testing-and-verification-record)
10. [Real-data results](#10-real-data-results)
11. [Problems found and how they were resolved](#11-problems-found-and-how-they-were-resolved)
12. [Corrections to earlier statements](#12-corrections-to-earlier-statements)
13. [Command cheat-sheet (PowerShell)](#13-command-cheat-sheet-powershell)
14. [Known gaps](#14-known-gaps)
15. [What comes next](#15-what-comes-next)
16. [Complete file inventory of this session's delivery](#16-complete-file-inventory-of-this-sessions-delivery)

---

## 1. What RiskReveal is

RiskReveal is a **vulnerability management platform**. The goal is Nessus / InsightVM-style results, achieved by **orchestrating proven open-source tools** (Nmap, Nuclei, public threat-intelligence feeds) instead of re-implementing a scanner.

The ideas that distinguish it (from the planning documents `01`–`05`):

- **Accuracy over noise.** Every finding carries a *confidence* level — `inferred → detected → confirmed` — and evidence. A service banner alone can only produce an `inferred` vulnerability; it never claims to be proof.
- **Risk-based prioritisation.** The risk score is meant to combine CVSS severity, EPSS (probability of exploitation), CISA KEV (known to be exploited), exploit maturity and the asset's context — not raw CVSS alone.
- **Five AI agents** (Verifier, Related-findings, Chain analyzer, Evidence, Mitigation). The agents *reason*; only deterministic, scope-checked tools *act*. Scan data is treated as attacker-controlled and is never handed to an agent as instructions.
- **Authorized scanning only**, enforced in code (scope policy + allowlist today; verified ownership planned).

The project replaces an earlier **Flask prototype**. A review of that prototype (25 numbered problems in `01_Conversation_Summary.md`) drives many design rules here. The prototype's `dev` branch contains a live SQL-injection / XSS attack engine with WAF evasion; **none of that is to be ported** (`04_Dev_Branch_Review.md`).

---

## 2. How the project got here

| Stage | What happened | Evidence |
|---|---|---|
| Planning | Seven documents (concept, master plan, frontend review, dev-branch review, rebuild file plan, tech-stack list, dual-OS guide) and a skeleton script that created ~170 stub files, each containing only a `TODO` docstring | `Riskreveal-documentation.zip` |
| Infrastructure | Docker Compose for PostgreSQL (host port `5433`) and Redis (host port `6380`), project name `riskreveal-v2`, bound to loopback only so v1 services are not disturbed | Handoffs v1–v2, verified healthy |
| App shell | Pydantic Settings that fail closed when secrets are missing; FastAPI app with `/healthz` doing a real DB check; CORS; exception handling that closes a Starlette debug-traceback leak | Handoffs v2–v3 |
| Auth slice | `User` model, Argon2id password hashing, JWT access/refresh tokens (type claim, pinned algorithm), register/login/refresh/me routes, rate limiting | Handoffs v2–v4 |
| Build-order change | Full multi-tenant organizations/RBAC was **deliberately deferred** in favour of one working end-to-end path first | Handoff v2 §3 |
| Scanning foundation | Asset / scan / finding models and migration, scan-scope policy, scan profiles, Nmap runner and XML parser, normalizer | Handoff v4 |
| Scan pipeline | Scan service, repositories, Celery app and tasks, scan/finding/asset routes, operator allowlist | Handoff v5 |
| **First milestone** | Register → log in → scan `scanme.nmap.org` with real Nmap through API + Celery → 2 findings (22/tcp OpenSSH 6.6.1p1, 80/tcp Apache 2.4.7) stored in the database | **Verified** (Handoff v5 §0) |
| **This session** | Threat-intelligence foundation: KEV + EPSS importers, tables, CLI, tests | §6–§10 below |

---

## 3. Environment

| Item | Value |
|---|---|
| OS / shell | **Windows 11, PowerShell** (development is entirely Windows-native; no WSL, no Fedora — the dual-OS guide `07` is ignored) |
| Repo root | `D:\WORK\VS Code\riskreveal` |
| Backend | `...\riskreveal\backend`, `src` layout (`src\riskreveal\`) |
| Python | 3.12.16 via `uv`, virtual environment `backend\.venv` |
| Database / cache | Docker Desktop; PostgreSQL on `127.0.0.1:5433`, Redis on `127.0.0.1:6380`; Compose project `riskreveal-v2` |
| Scanner | Nmap 7.97 with Npcap 1.72 on `PATH` |
| Queue | Celery 5.6.3 with `--pool=solo` (the default pool needs `fork`, which Windows lacks) |
| Git | Remote `https://github.com/Omkekan/Riskreveal`, working branch `dev`. The owner reports the project (up to the previous zip) is committed to GitHub. **This session's changes are not yet confirmed committed.** |

Two repositories exist and must not be confused: **`Riskreveal-Vulnerability-scanner`** (the old Flask prototype — never port its `dev` branch) and **`Riskreveal`** (this rebuild, where all new work happens).

---

## 4. Architecture and standing rules

### 4.1 Technology

FastAPI · synchronous SQLAlchemy 2 + psycopg 3 · Alembic · PostgreSQL 17 · Redis · Celery · Pydantic v2 · `uv` for dependencies · Typer for the CLI · httpx for downloads · pytest + testcontainers (each integration run starts its own throwaway PostgreSQL) · ruff (rules E, F, I, UP, B, S, C4, SIM, RUF; line length 100) · mypy `--strict`.

### 4.2 Layout (relevant parts)

```
backend/src/riskreveal/
├── main.py, config.py, dependencies.py
├── core/            security.py, rate_limit.py, pagination.py
├── db/              base.py, session.py, migrations/
├── api/v1/routes/   auth, scans, findings, assets (others are stubs)
├── domain/
│   ├── users/ assets/ scanning/ findings/        (built)
│   ├── intelligence/                             (built this session: KEV + EPSS)
│   └── organizations/ credentials/ risk/ agents/ reports/ remediation/ ...   (stubs)
├── engines/         nmap_engine.py, normalizer.py (built); nuclei, script_classifier (stubs)
├── tasks/           celery_app.py, scan_tasks.py (built)
└── cli/             commands.py, __main__.py (built this session)
```

### 4.3 Rules to preserve (carried forward from earlier handoffs)

1. Windows-native only; exact PowerShell commands; one small verified step at a time.
2. Services commit; `get_db` never auto-commits. A failed operation leaves nothing half-saved.
3. Secrets fail closed (`JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL` have no defaults). Never paste `.env` contents in chat.
4. `FastAPI(debug=...)` stays `False`. Never return `exc.errors()` from an exception handler (it can echo submitted passwords).
5. Route modules do **not** use `from __future__ import annotations`.
6. Any test needing tables goes through `conftest.py`'s `api_app` fixture, which imports **every** model module; a new model module must also be added to `db/migrations/env.py`.
7. Scan data and feed data are **untrusted**: never render as HTML, never use in file paths, never feed to an AI agent as instructions.
8. No destructive Docker commands (`down -v`, `volume rm`, `system prune`) without explicit approval. Always `docker compose -p riskreveal-v2`.
9. Tests may inject failures, but production code never fakes results.
10. Always say plainly what was and wasn't actually run.

---

## 5. What is built: the foundation (before this session)

All items below were **verified** by the owner's own runs (Handoff v5).

### 5.1 Authentication
`POST /api/v1/auth/register`, `/login`, `/refresh`, `GET /auth/me`. Argon2id hashing; login always performs a hash check even for unknown emails (prevents timing-based email enumeration); JWTs carry a `type` claim so a refresh token cannot be replayed as an access token; the algorithm is pinned (an `alg=none` token is rejected); rate limiting on auth endpoints.

### 5.2 Scan safety gates (two layers in front of Nmap)
1. **Scope policy** (`scope_policy.py`): one target per scan (IP, CIDR or hostname). Rejects shell-ish and option-like strings, URLs, zone ids, non-ASCII hostnames, and look-alike numeric hosts (`127.1`) **before any DNS lookup**. Never allows unspecified, multicast, link-local (includes cloud metadata `169.254.169.254`), reserved, or IPv6 transition ranges that embed IPv4 (NAT64, 6to4, Teredo). Private/loopback ranges only with an explicit opt-in. Hostnames are resolved, **every** resolved IP must pass, and the **resolved IPs — not the name — are scanned**.
2. **Operator allowlist** (`authorization.py`): public targets are scannable only if listed in `SCAN_PUBLIC_ALLOWLIST` (exact hostnames, single IPs, or small CIDRs). Empty by default = no public scanning at all. This is an interim control; per-user ownership verification is planned.

Both gates run at request time **and again** when the worker starts the scan.

### 5.3 Scan lifecycle
- **API side:** validate → lock the user's row to enforce the active-scan cap (default 3) → insert a `queued` scan and commit → enqueue; if enqueueing fails the scan is marked `failed` and the API answers 503.
- **Worker side:** atomic claim (`UPDATE ... WHERE status='queued'`) so duplicate/redelivered tasks are harmless → re-validate → run real Nmap with **no database transaction open** → in one transaction: mark completed, upsert assets, insert findings, commit → any error rolls everything back and records a fixed, safe failure message (raw stderr/tracebacks go only to the server log).
- Nmap command shape: `nmap -oX - --no-stylesheet -n --open <profile args> ...`, never `shell=True`, no user-supplied flags, no `-O`, no `--script`.

### 5.4 Data model (before this session)
`users`, `assets` (unique per owner+address), `scans` (status, profile, `scanned_addresses` audit trail), `findings` (severity, confidence, status, source, port/protocol/service/product/version/CPE, `raw_evidence`). Findings are currently **informational**: "this port is open and looks like X".

### 5.5 The main product gap
There is **no CVE matching and no risk scoring yet**. A finding says "OpenSSH 6.6.1p1 on port 22" but does not say which vulnerabilities that implies. This session started closing that gap from the data side.

---

## 6. This session's work: threat-intelligence foundation

### 6.1 Why this was chosen
The owner asked the assistant to choose the next work. Vulnerability matching was the recommended next product step (Handoff v5, Step D), and it needs threat data to exist first. **CISA KEV** (CVEs known to be exploited in the wild) and **FIRST EPSS** (probability a CVE will be exploited in the next 30 days) are the smallest, highest-value feeds, have stable public formats, and can be tested thoroughly. They are *enrichment*: they become fully useful once findings carry CVE ids (next step).

### 6.2 What was delivered

**Database tables** (`domain/intelligence/models.py`):

| Table | Primary key | Contents |
|---|---|---|
| `kev_entries` | `cve_id` | vendor/project, product, vulnerability name, date added, short description, required action, due date, known-ransomware-use flag, notes, CWE list (JSONB), timestamps |
| `epss_scores` | `cve_id` | score (0–1), percentile (0–1), `score_date` (the date the score was *computed*, from the file header), model version, timestamps |
| `feed_syncs` | `source` | when each feed last imported successfully, its version, and record count — the basis for a future "feed health" page |

`cve_id` is deliberately **plain text, not a foreign key**: a feed may list CVEs not yet ingested, and they must still be stored. CHECK constraints enforce the CVE-id format and the 0–1 ranges at the database level.

**Importer pipeline:**

```
 official URL / local --file
        │
        ▼
   fetch.py  (HTTPS only, size cap, time cap, redirect check)   payload.py (gzip-bomb guard)
        │
        ▼
   parser (cisa_kev.py / first_epss.py)   ← pure functions, no network, no database
        │   skips bad records individually, refuses mostly-bad files
        ▼
   service.py  (one transaction per import; commit once; rollback on any error)
        │
        ▼
   repository.py  (batched PostgreSQL upserts)  →  kev_entries / epss_scores / feed_syncs
```

**Lookup for later steps:** `repository.get_threat_signals(db, cve_ids)` returns, per CVE, whether it is in KEV (plus date added and ransomware flag) and its EPSS score/percentile/date. A CVE with no information is simply absent from the result — "unknown" is not the same as "EPSS of zero". The future risk scorer will consume this.

**Command-line tool** (`python -m riskreveal.cli`):

| Command | Purpose |
|---|---|
| `load-kev [--file PATH]` | Download (or read) the KEV catalog and store it |
| `load-epss [--file PATH]` | Download (or read) the daily EPSS file and store it |
| `feed-status` | Show when each feed was last imported |

### 6.3 Sources and formats (confirmed by web search, then by a real download)

- **KEV:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` — a JSON object with `catalogVersion`, `dateReleased`, `count` and a `vulnerabilities` list (`cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`).
- **EPSS:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` — gzip CSV. First line is a comment (`#model_version:...,score_date:...`), second line is the header `cve,epss,percentile`. The `score_date` appears in more than one format over time (`...+0000` and `...Z`), so only its leading `YYYY-MM-DD` is used. (The older `epss.cyentia.com` host is superseded.)

---

## 7. How the code behaves — detailed design

### 7.1 CVE id validation (`cve_id.py`)
A valid id is `CVE-` + 4-digit year + `-` + 4 to 10 digits, upper-cased and stripped. Matching is **ASCII-only and uses `[0-9]`, not `\d`**, because Python's `\d` also matches non-ASCII digits (for example full-width digits), which would let look-alike strings into the database. The same rule is repeated as a PostgreSQL CHECK constraint (defence in depth).

### 7.2 KEV parser (`sources/cisa_kev.py`)
- Entry without a valid CVE id or a valid `dateAdded` → skipped and counted.
- Unreadable or missing `dueDate` → stored as null (a known-exploited CVE must not be lost over a bad due date).
- Duplicate CVE id in one catalog → the later entry wins; not counted as skipped.
- Every string is cleaned (NUL bytes removed — PostgreSQL rejects them) and **clipped to its column size**, so one oversized field cannot break an import.
- Missing vendor/product → `"Unknown"`; missing name → the CVE id.
- **Catalog-level refusal:** invalid JSON, wrong shape, no valid entries, or more than **2 %** invalid entries → `FeedParseError`, nothing saved. Extremely deep JSON nesting is refused, not allowed to crash the process.
- `catalogVersion` is kept as the feed version (falls back to `dateReleased`).

### 7.3 EPSS reader (`sources/first_epss.py`)
~400,000 rows, so rows are **streamed** through `EpssReader`: the header is validated immediately (comment line with `model_version` and `score_date`, then exactly `cve,epss,percentile`), then rows are yielded one by one while counting `rows_read` and `skipped`. A row is skipped if it has the wrong number of columns, an invalid CVE id, or a score/percentile that is not a finite number in [0, 1] (NaN, infinity and non-ASCII digits are rejected — Python's `float()` would otherwise accept some of them). The reader can be iterated only once. `EpssReader.from_bytes` handles gzip or plain input, a UTF-8 byte-order mark and Windows line endings.

### 7.4 Downloading and decompression (`sources/fetch.py`, `sources/payload.py`)
- Only `https://` URLs; at most 3 redirects, and a redirect that lands on non-HTTPS is refused.
- Body streamed with a **hard size cap** (KEV 20 MiB, EPSS 64 MiB) and an **overall time limit** (120 s).
- Error messages contain only the exception class name — no server-supplied text.
- `gunzip_limited` decompresses with a hard output limit (a tiny gzip file can expand to gigabytes — a "decompression bomb"), detects truncated and corrupt files, and accepts output exactly at the limit. A test **measures peak memory** to prove the limit stops the expansion itself rather than merely rejecting the finished result.

### 7.5 Import service (`service.py`) — atomic imports
- **One import = one transaction**, committed once at the very end. Any failure — database error, empty file, too many invalid rows — rolls back everything from that import; the previous good data stays in place.
- EPSS is written in batches of **5,000 rows** (5,000 × 5 columns = 25,000 bound parameters, safely under PostgreSQL's 65,535 per-statement limit); KEV in batches of **500**.
- A CVE repeated within one EPSS batch is collapsed (later wins), because PostgreSQL refuses to update the same row twice in one statement.
- After streaming, an EPSS file with more than **1 %** invalid rows (or none valid) is refused and the whole transaction rolled back.
- Only after everything succeeds is `feed_syncs` updated.

### 7.6 Upsert behaviour (`repository.py`)
All writes are `INSERT ... ON CONFLICT (cve_id) DO UPDATE`, so re-running an import is safe (idempotent). EPSS adds `WHERE epss_scores.score_date <= excluded.score_date`: **an older file can never overwrite a newer score**; a same-day re-import is allowed.

### 7.7 CLI behaviour (`cli/commands.py`)
Feed errors and database errors print a single clean line and exit with code 1. Typer's "pretty exceptions show locals" is **turned off**, because some stack frames hold the settings object (JWT and Fernet secrets) and the default error page would print them to the terminal.

---

## 8. Security considerations

| Risk | Mitigation |
|---|---|
| Hostile or corrupted feed content | Treated as untrusted data: size caps, NUL stripping, clipping, strict field validation, per-record skipping |
| Decompression bomb | Hard output limit during decompression; peak-memory test |
| Slow or never-ending download | Per-read timeouts plus an overall deadline |
| Downgrade via redirect | Final URL must be HTTPS |
| Look-alike CVE ids (Unicode digits) | ASCII-only strict regex in code **and** a database CHECK constraint |
| NaN / infinity / out-of-range scores | Rejected by the parser; also constrained in the database |
| Half-imported data | Single transaction per import, rollback on any failure |
| Stale data replacing fresh data | `score_date` guard on EPSS upserts |
| Secrets leaking in tracebacks | Typer locals disabled; error messages never include raw feed content, URLs with credentials, or database URLs |
| Information in logs | Skip counts only; no record contents |

---

## 9. Testing and verification record

### 9.1 Owner's runs (30 Oct 2026) — **verified**

| Check | Result |
|---|---|
| Unit tests (`uv run pytest tests/unit`) | **241 passed** (was 158 → **+83 new**: EPSS parser/gzip 35, downloader 12, KEV parser 36) |
| Integration tests (`uv run pytest tests/integration`) | **58 passed** (was 45 → **+13 new** database import tests) |
| Migration test (upgrade → `alembic check` → downgrade → upgrade) | **Passed** — the generated migration matches the models exactly |
| `ruff check .` | **1 error**: SIM300 (backwards comparison) at `tests\integration\test_migrations.py:69` — a style fix, see §11 |
| `mypy` | **Not actually run** — the bare `uv run mypy` printed its usage text. The correct command is `uv run mypy src`. **Pending.** |

### 9.2 Assistant's sandbox checks — **verified in sandbox only**

The sandbox has no ruff, mypy, SQLAlchemy, httpx, typer, Docker or network, so only the standard-library parts could be executed for real.

- **71 parser/gzip tests passed** under a stand-in test runner (identical to the 36 + 35 that later passed under real pytest).
- **Mutation checks** — the code was deliberately broken in three places to prove the tests have teeth:
  1. allowing non-ASCII digits in CVE ids → a test failed ✔
  2. dropping the NaN/infinity check → five tests failed ✔
  3. removing the decompression limit → **no test failed** ✘ (a real gap: the old test only checked the final result, which still triggered, but only *after* the whole bomb had been expanded in memory). A peak-memory test was added; the mutation then failed as it should ✔
- **Import and flow harness:** the database-layer modules and the CLI were imported and executed against stub libraries; CLI error paths exit with code 1 and a one-line message.
- **Transaction-logic harness** with a recording fake database confirmed: 3 batches for 10,017 rows (5,000 / 5,000 / 17), a single commit as the last event, duplicates collapsed, rollback with no `feed_syncs` row on invalid/empty files, rollback re-raising the *original* exception on a database error, and the same commit-once/rollback behaviour for KEV.
- Static checks: byte-compile clean, no line over 100 characters, no tabs or trailing whitespace.

### 9.3 What the real runs proved that the sandbox could not
The real SQL (upserts, `ON CONFLICT`, the `WHERE` guard, JSONB, CHECK constraints), the migration, the downloader tests with a fake network, and the live feeds all passed on the owner's machine.

### 9.4 Coverage note
Unit-only coverage is 46 % overall (database and API code is exercised by the integration suite); integration coverage is 84 %. The downloader (`fetch.py`) shows 0 % in the integration run because it is covered by the unit suite.

---

## 10. Real-data results

Loaded from the live official feeds on the owner's machine, then read back with `feed-status`:

| Feed | Stored | Version | Last success (UTC) |
|---|---|---|---|
| CISA KEV | **1,764 entries** | catalog `2026.10.29` | 2026-10-30 14:06 |
| FIRST EPSS | **398,142 scores**, 0 skipped | model `v2026.06.15`, score date `2026-10-30` | 2026-10-30 14:08 |

The EPSS import was 79 batches of 5,000 rows plus a final batch of 3,142 (79 × 5,000 + 3,142 = 398,142), all in one transaction, committed once. The verbose SQL in the owner's log is caused by `DEBUG=true` in `backend\.env` (it switches on SQL echo, which the code only allows in development); setting `DEBUG=false` quiets it.

---

## 11. Problems found and how they were resolved

| # | Symptom | Cause | Resolution | Status |
|---|---|---|---|---|
| 19 | `ruff`: SIM300 "Yoda condition" at `test_migrations.py:69` | The assistant wrote `_EXPECTED_TABLES <= _tables(...)` (constant on the left) | Rewrite as `assert _tables(migration_db_url) >= _EXPECTED_TABLES` (or `uv run ruff check . --fix`) | **Pending** (one-line fix) |
| 20 | `uv run mypy` printed usage instead of checking | The assistant gave the bare command; earlier handoffs use `uv run mypy src` | Run `uv run mypy src` | **Pending** — the only static check still outstanding |
| 21 | Python `SyntaxWarning: invalid escape sequence` in `cli/commands.py` | A Windows path (`backend\`) inside a docstring | Reworded; found by the assistant's own compile check | Resolved before delivery |
| 22 | A decompression-limit mutation survived the test-suite | Test inspected only the result, not memory use | Added a peak-memory test; mutation now caught | Resolved before delivery |
| 23 | Convoluted parametrized test case (a whitespace-padded CVE id, which is actually *valid*) | Poorly structured test | Split into a dedicated, clearer test | Resolved before delivery |
| 24 | Noisy SQL logs in CLI output | `DEBUG=true` in `.env` | Set `DEBUG=false` (cosmetic) | Open — owner action |

---

## 12. Corrections to earlier statements

In my previous message I said the EPSS import ran "in batches of roughly 3,100 rows". **That was wrong.** Re-reading your log against the code: the batch size is **5,000**, and the 3,142-row figure is only the *final* batch. The numbers in §7.5 and §10 above are the correct ones. This does not change any behaviour or result — only my description of it.

Also, my first message after delivery asked you to run `uv run mypy`; the correct command is `uv run mypy src` (§11 #20).

---

## 13. Command cheat-sheet (PowerShell)

```powershell
# Infrastructure — always name the project; never add -v without approval
Set-Location "D:\WORK\VS Code\riskreveal\infra"
docker compose -p riskreveal-v2 up -d
docker compose -p riskreveal-v2 ps

# Backend — always from backend\ so .env and alembic.ini are found
Set-Location "D:\WORK\VS Code\riskreveal\backend"
uv sync --extra dev

# Database migrations
uv run alembic revision --autogenerate -m "message"   # then READ the generated file
uv run alembic upgrade head
uv run alembic current

# Quality gates (all four should be green before committing)
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration                        # needs Docker Desktop running

# Threat-intelligence feeds (this session)
uv run python -m riskreveal.cli load-kev
uv run python -m riskreveal.cli load-epss
uv run python -m riskreveal.cli feed-status
uv run python -m riskreveal.cli load-kev --file C:\path\to\known_exploited_vulnerabilities.json

# Run the API and the worker (two windows)
uv run uvicorn riskreveal.main:app --host 127.0.0.1 --port 8000
uv run celery -A riskreveal.tasks.celery_app:celery_app worker --pool=solo --loglevel=INFO

# Git (no pager)
Set-Location "D:\WORK\VS Code\riskreveal"
git --no-pager status --short
```

Before committing: `git --no-pager status --short` should show no `.env`, no `.venv`, and nothing under `frontend\node_modules`.

---

## 14. Known gaps

**Specific to this session's work**
- `ruff` fix and `mypy src` are still pending (§11 #19–20). The slice is **not yet committed**.
- `feed_syncs.last_success_at` also updates when a *stale* EPSS file is re-imported (the scores are protected from being overwritten; the timestamp is not).
- Nothing schedules the feed imports yet — they run only when the CLI is run (a Celery beat task is a later step).
- KEV/EPSS are enrichment only: they add value once findings carry CVE ids.
- No CVE record store, no CPE/version matching, no distro-advisory handling yet.

**Carried forward from earlier work (Handoff v5 §9)**
- **No per-user target-ownership verification** — the allowlist is operator-wide. Must be done before anyone but the owner uses the API.
- Findings are informational only; no cross-scan de-duplication (`first_seen` / `last_seen`).
- Cancelling a running scan discards results but does not kill the Nmap process.
- DNS resolution has no timeout (took ~11 s for `scanme.nmap.org`) and happens while a DB transaction is open.
- The Postgres password in `infra/docker-compose.yml` has a hardcoded fallback.
- `register` reveals whether an email exists (409); no refresh-token revocation; the rate limiter is in-process memory (move to Redis before multiple workers); error-body shapes are inconsistent until `core/exceptions.py` exists.
- Unit tests for the Nmap parser use a synthetic fixture; a real captured Nmap XML should be added.
- The whole frontend is still stubs (not a runnable Next.js app; Tailwind not installed; toolchain versions too new).
- The `.env` currently has `DEBUG=true`.

---

## 15. What comes next

1. **Finish this slice:** fix SIM300, run `uv run mypy src`, run the four gates once more, then commit (`git add backend`, review `git status`, commit).
2. **Step D — vulnerability matching (recommended):**
   - Ingest **CVE records** (CVE list v5 and/or NVD API 2.0): descriptions, CVSS, affected products and version ranges, CPE data.
   - Build a **conservative version matcher** that compares detected product/version/CPE against affected ranges and stores matches as findings with `confidence = inferred` and a new source such as `version_match` (requires relaxing the `ck_findings_source_valid` CHECK constraint, which currently allows only `nmap`).
   - Handle **distro-patched versions** (for example `6.6.1p1 Ubuntu 2ubuntu2.13`) so upstream CVE data does not over-report — the plan calls for the Ubuntu, Debian and Red Hat advisory feeds.
   - Consume `get_threat_signals()` so each match carries KEV / EPSS context.
   - Needs a migration: CVE tables; finding columns for `cve_id`, CVSS, EPSS, KEV, `first_seen`, `last_seen`.
3. **Risk scorer** combining CVSS, EPSS, KEV, exploit maturity and asset context.
4. **Step E — per-user target ownership** (DNS TXT record or well-known file; verification fetches must pin the validated IP and apply the same scope policy), **before** any other user touches the API.
5. Hardening (DNS timeout, Compose password variable, scheduled stale-scan reaper, scheduled feed refresh).
6. Then organizations/RBAC, `script_classifier` (before ever enabling Nmap scripts), Nuclei, the five agents, reports, and the frontend.

---

## 16. Complete file inventory of this session's delivery

Delivered as `riskreveal_intel_slice.zip` (22 files, extracted at the repository root; paths below are under `backend\`). **Applied and exercised by the owner's runs.**

### New source files (14)
| File | Purpose |
|---|---|
| `src/riskreveal/domain/intelligence/errors.py` | `FeedError`, `FeedFetchError`, `FeedParseError` — messages safe to log, never contain raw feed content |
| `src/riskreveal/domain/intelligence/cve_id.py` | Strict ASCII CVE-id validation, shared by every source; the SQL regex for CHECK constraints |
| `src/riskreveal/domain/intelligence/sources/textutil.py` | `clean_text`: strip NUL bytes, trim, clip to column size |
| `src/riskreveal/domain/intelligence/sources/payload.py` | `gunzip_limited`, `maybe_gunzip`, `read_local` — size limits and the decompression-bomb guard |
| `src/riskreveal/domain/intelligence/sources/cisa_kev.py` | KEV parser (`parse_kev`, `KevRecord`, `KevCatalog`), source URL and limits |
| `src/riskreveal/domain/intelligence/sources/first_epss.py` | EPSS streaming reader (`EpssReader`, `EpssRecord`), source URL and limits |
| `src/riskreveal/domain/intelligence/sources/fetch.py` | HTTPS downloader with size/time caps and redirect check |
| `src/riskreveal/domain/intelligence/models.py` | `KevEntry`, `EpssScore`, `FeedSync` tables (replaced a `TODO` stub) |
| `src/riskreveal/domain/intelligence/repository.py` | Batched upserts, `record_sync`, `list_syncs`, `get_threat_signals`, `ThreatSignal` |
| `src/riskreveal/domain/intelligence/service.py` | Atomic `import_kev` and `import_epss`, `ImportResult` |
| `src/riskreveal/domain/intelligence/sources/__init__.py` | Package docstring (replaced a `TODO` stub) |
| `src/riskreveal/cli/commands.py` | Typer commands `load-kev`, `load-epss`, `feed-status` (replaced a `TODO` stub) |
| `src/riskreveal/cli/__main__.py` | Enables `python -m riskreveal.cli` |
| *(migration)* | Generated by the owner with `alembic revision --autogenerate`; creates only `kev_entries`, `epss_scores`, `feed_syncs` |

### Tests and fixtures (6)
| File | Contents |
|---|---|
| `tests/unit/test_kev_parser.py` | 36 tests: sample catalog, bad ids (incl. full-width digits and SQL-injection-looking text), bad dates, non-object entries, duplicates, clipping and NUL stripping, defaults, refusal thresholds, deeply nested JSON |
| `tests/unit/test_epss_parser.py` | 35 tests: header formats, BOM and CRLF, bad rows (NaN, inf, out of range, wrong columns, Arabic-Indic digits), bad headers, single-pass guard, gzip round trip, bomb refusal, **bounded-memory test**, truncated/corrupt gzip, local file limits |
| `tests/unit/test_feed_fetch.py` | 12 tests with a fake network: success, HTTP-only refusal, non-200 statuses, oversize, exact-limit, error messages without leaked detail, redirect-to-HTTP refusal, deadline |
| `tests/integration/test_intelligence_import.py` | 13 tests against a real throwaway PostgreSQL: KEV import and idempotence, CHECK constraint enforced by the database, EPSS import, newer-wins/older-never-rolls-back, same-day re-import, duplicates in a file, mostly-invalid file fully rolled back, empty file, failed import keeps previous data, multi-batch import (10,017 rows), `get_threat_signals` combinations |
| `tests/fixtures/kev_sample.json` | **Synthetic** catalog (made-up `CVE-2099-xxxx` ids) shaped like CISA's feed |
| `tests/fixtures/epss_sample.csv` | **Synthetic** scores for made-up ids |

### Existing files modified (3 — one-line or small changes)
| File | Change |
|---|---|
| `src/riskreveal/db/migrations/env.py` | Added `import riskreveal.domain.intelligence.models` so Alembic sees the new tables |
| `tests/conftest.py` | Same import, so `create_all` builds the new tables in tests |
| `tests/integration/test_migrations.py` | Expects the three new tables (`_EXPECTED_TABLES`). **Line 69 needs the SIM300 fix (§11 #19)** |

### Documents
`RiskReveal_v2_Handoff_v6.md` (short handoff for this session) and this report.

---

*End of report. Anything not marked **verified** above should be treated as unconfirmed until its result has been shown.*
