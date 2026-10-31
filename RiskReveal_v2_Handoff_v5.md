# RiskReveal v2 — Handoff (v5)

> **Supersedes** `RiskReveal_v2_Handoff_v4.md` (and everything v4 superseded).
> Written 30 Oct 2026.
>
> **Status words used in this file**
> - **Verified** — a command output or API response was shown in chat, or the file was read from the owner's zip.
> - **Delivered, not run** — code was written, but the assistant's sandbox could not execute it (no SQLAlchemy, Docker, network or Nmap there). Only the owner's own runs count as proof.
> - **Not confirmed** — nobody has shown the result either way. Do not treat it as done.

---

## 0. TL;DR

- **The first full milestone is reached and verified.** A registered user logged in, `POST /api/v1/scans` queued a scan of `scanme.nmap.org`, a Celery worker ran the **real Nmap binary**, and `GET /api/v1/findings` returned 2 findings (22/tcp OpenSSH 6.6.1p1, 80/tcp Apache 2.4.7). Worker log: `succeeded in 9.5s`.
- The same scan also ran through `scripts/smoke_scan_e2e.py` (no API, no Celery) against the real dev database. Both paths **verified**.
- The scan pipeline (service, repositories, Celery app/tasks, scan/finding/asset routes, operator allowlist) came from `riskreveal_scan_pipeline.zip` and is applied in the working tree. After applying: `mypy` clean (133 files), **158 unit tests pass**, **44 of 45 integration tests passed** — the one failure was a pre-existing bug in `main.py`'s 422 handler (§9, incident 14). The fix was applied (the API's 422 body is now clean JSON, verified in the login attempt), but **the four quality gates were not re-run in a pasted output after the fix** — Step A below.
- The findings are still **informational only** ("this port is open and looks like X"). There is **no CVE matching and no scoring yet**. That is the main product gap.
- **Next action:** re-run the gates, commit (§8). Then choose between vulnerability matching and per-user target-ownership verification (§8 Step D/E). The recommendation is matching first, ownership verification before anyone besides the owner uses the API.

---

## 1. Environment

| Item | Value | Status |
|---|---|---|
| Repo root | `D:\WORK\VS Code\riskreveal` | verified |
| Backend | `...\riskreveal\backend` (src layout: `src\riskreveal\`) | verified |
| OS / shell | Windows 11, PowerShell in VS Code. No WSL. | verified |
| Python | 3.12.16 via `uv`; venv `backend\.venv` | verified |
| Git remote | `https://github.com/Omkekan/Riskreveal` | from v3; **not confirmed** |
| Branch | `dev` (last hash shown to any session: `88fd16d`, before the scanning foundation) | see below |
| Docker | Docker Desktop; Compose project `riskreveal-v2`; Postgres on `127.0.0.1:5433`, Redis on `127.0.0.1:6380` | verified (worker connected to `redis://localhost:6380/0`) |
| Nmap | 7.97 with Npcap 1.72, on `PATH` | verified |
| Celery | 5.6.3, pool `solo` | verified |
| Dev API | `uvicorn riskreveal.main:app --host 127.0.0.1 --port 8000` | verified |

**Git state is not fully known.** When the pipeline files were applied, `git status` showed the scanning-foundation files (`scope_policy.py`, `nmap_engine.py` etc.) as *tracked*, so the foundation was committed locally. The pipeline files themselves showed as modified/untracked. **No commit of the pipeline and no push has been confirmed.**

`backend\.env` currently has `DEBUG=true`, which switches on SQL echo (very noisy logs, every worker line printed twice). Harmless; set `DEBUG=false`. `SCAN_PUBLIC_ALLOWLIST` must contain `scanme.nmap.org` for the live checks to work (it evidently does, since they ran).

Not confirmed installed: Node/nvm, Go, Nuclei, naabu, Trivy, gitleaks, MSYS2/GTK for WeasyPrint.

### Two repositories, two `dev` branches — don't confuse them

| Repo | What it is | `dev` means |
|---|---|---|
| `Riskreveal-Vulnerability-scanner` | The **old Flask prototype** that docs 01–05 review | A half-finished rewrite containing a **live SQLi/XSS attack engine with WAF evasion**. **Never port it.** See `04_Dev_Branch_Review.md`. |
| `Riskreveal` (this rebuild) | FastAPI rebuild | The **rebuild's working branch**. All new work happens here. Do not merge or push to `main` without asking. |

---

## 2. Documentation set (`Riskreveal-documentation.zip`)

| File | Use it for |
|---|---|
| `01_Conversation_Summary.md` | Original goal, the five-agent concept, the **25-item review of the old backend**. The "why" behind most design rules. |
| `02_RiskReveal_Master_Plan.md` | Vision, roadmap Phases 0–8, **data model (§4)**, finding lifecycle (Appendix A), agent I/O (Appendix C). |
| `03_Frontend_and_Full_Review.md` | Frontend review and recommended stack. |
| `04_Dev_Branch_Review.md` | Why the old repo's `dev` must not be ported. |
| `05_Rebuild_Structure_and_File_Plan.md` | **Target layout and keep/rewrite/delete table per file.** Check it before creating any file. |
| `06_Tech_Stack_Installation_List.md` | Package list only. |
| `07_Dual_OS_Dev_Environment_Setup.md` | Fedora/WSL guide. **Ignore** — development is Windows-native. |

Deliberate deviation from the plan: organizations/RBAC are deferred until the scan → findings loop works (it now does). Revisit when the owner decides (§8).

---

## 3. Repository state

### 3.1 Real code (verified from the owner's `Riskreveal-dev.zip` and later outputs)

Auth slice (unchanged since v4): `config.py`, `main.py`, `dependencies.py`, `core/security.py`, `core/rate_limit.py`, `db/{base,session}.py`, migrations `1d2459ffc65b` (users) and **`19317048b280` (assets, scans, findings — applied, verified)**, `domain/users/*`, `api/v1/routes/auth.py`.

Scanning foundation (v4 §3.3, now verified by the owner's runs): `domain/{assets,scanning,findings}/models.py`, enums, `scope_policy.py`, `profiles.py`, `engines/{base,nmap_engine,normalizer}.py`, `scripts/smoke_nmap.py`, unit tests and the synthetic fixture `tests/fixtures/nmap_sample.xml`.

### 3.2 New in this session — from `riskreveal_scan_pipeline.zip` (applied)

Paths relative to the repo root.

| File | Purpose |
|---|---|
| `backend/src/riskreveal/domain/scanning/authorization.py` | **Operator allowlist for public targets.** `parse_allowlist`, `check_authorized`. See §4. Pure stdlib. |
| `backend/src/riskreveal/domain/scanning/scope_policy.py` (modified) | Also refuses IPv6 transition ranges that embed an IPv4 address: NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`. Never allowed, flag or not. |
| `backend/src/riskreveal/domain/scanning/service.py` | **The scan lifecycle.** `create_scan`, `run_scan`, `cancel_scan`, `mark_queue_failed`, `fail_stale_scans`. See §5. |
| `backend/src/riskreveal/domain/scanning/repository.py` | Queries plus atomic conditional-UPDATE state changes (`claim_queued`, `transition`, `fail_stale`). |
| `backend/src/riskreveal/domain/scanning/schemas.py` | `ScanCreate` (extra fields forbidden, profile must be a known *name*), `ScanRead`, `ScanPage`. |
| `backend/src/riskreveal/domain/assets/{repository,schemas}.py` | Asset upsert (`INSERT ... ON CONFLICT ON CONSTRAINT uq_assets_owner_id_address DO UPDATE`), owner-scoped reads. |
| `backend/src/riskreveal/domain/findings/{repository,schemas}.py` | Owner-scoped finding queries (ownership comes from joining `scans.owner_id`); list schema omits `raw_evidence`, detail schema includes it. |
| `backend/src/riskreveal/core/pagination.py` | `Pagination` dependency: `limit` 1–100 (default 50), `offset` 0–1,000,000. |
| `backend/src/riskreveal/core/rate_limit.py` (modified) | Added `scan_limit()`. |
| `backend/src/riskreveal/config.py` (modified) | New settings: `scan_public_allowlist`, `scan_rate_limit` (`10/minute`), `scan_max_active_per_user` (3), `nmap_path`. |
| `backend/src/riskreveal/tasks/celery_app.py` | Celery app: JSON only, no result backend, `acks_late`, prefetch 1, `visibility_timeout` 3600. |
| `backend/src/riskreveal/tasks/scan_tasks.py` | Tasks `riskreveal.scan.run` and `riskreveal.scan.reap_stale`; `dispatch_scan()`; reaper also runs on `worker_ready`. |
| `backend/src/riskreveal/api/v1/routes/{scans,findings,assets}.py`, `router.py` | `POST/GET /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /findings`, `GET /findings/{id}`, `GET /assets`, `GET /assets/{id}`. All owner-scoped. |
| `backend/scripts/smoke_scan_e2e.py` | Real DB + real Nmap, no API/Celery: `uv run python scripts/smoke_scan_e2e.py you@example.com [target]`. |
| `backend/tests/conftest.py` (modified) | Imports **all** model modules before `create_all`; pins scan env vars (`SCAN_PRIVATE_RANGES_ALLOWED=false`, empty allowlist, etc.) so a developer's `.env` cannot change test outcomes. |
| `backend/tests/unit/test_{authorization,scope_transition,scan_schemas}.py` | New unit tests (pass: 158 total). |
| `backend/tests/integration/test_migrations.py` | Runs real Alembic (upgrade, `alembic check`, downgrade, upgrade) against its own throwaway Postgres, in a subprocess. |
| `backend/tests/integration/test_scan_pipeline.py` | Includes `test_real_nmap_finds_the_open_port_and_stores_it` (marker `live_nmap`): opens a TCP listener on 127.0.0.1, scans it with **real Nmap**, checks the DB. Other tests use a fake subprocess runner **only** to force timeouts, garbage output, oversized banners and cancellation. |
| `backend/tests/integration/test_scans_api.py` | HTTP routes with the queue replaced by a recorder (dependency override `get_scan_dispatcher`) and settings replaced via `dependency_overrides[get_settings]`. |
| `backend/pyproject.toml` (modified) | mypy overrides for `celery`/`kombu` (untyped) and `riskreveal.tasks.*` (untyped decorators); pytest marker `live_nmap`; `S603` ignored under `tests/**`. |
| `backend/.env.example` | Replaced with a real template (empty secret placeholders). |

### 3.3 Still `# TODO` stubs

`domain/{organizations,audit,credentials,intelligence,risk,agents,reports,remediation}`, `domain/findings/{service,lifecycle,dedupe}.py`, `domain/assets/{service,identity_resolution}.py`, `engines/{discovery,nuclei,script_classifier,auth_collectors}`, `tasks/{agent,beat_schedule,feed,report}_tasks.py`, `cli/*`, `core/exceptions.py`, `logging.py`, all other routes, `Dockerfile.scanner`, `Dockerfile.worker`, root `README.md`/`SECURITY.md`, and the whole frontend (not a runnable Next.js app; see §11).

### 3.4 Test counts

| Suite | Result | Status |
|---|---|---|
| Unit | 158 passed | verified (after applying the zip) |
| Integration | 44 passed, 1 failed (`test_bad_profile_and_extra_fields_are_422`, fixed in `main.py`) | verified |
| ruff / mypy after the `main.py` fix | | **not confirmed** |

---

## 4. Scope policy and authorization — rules to preserve

`validate_target` (scope policy) **then** `check_authorized` (allowlist) are the only gates in front of Nmap. Only `ValidatedTarget.scan_args` may ever reach the scanner. The service runs both at request time **and again** when the worker starts the scan (fresh DNS; a target removed from the allowlist while queued fails the scan).

1. One target per scan: single IP, CIDR, or hostname. Whitespace, commas, `;`, URLs, zone ids (`%`), option-like strings (`-sV`), non-ASCII hostnames and all-digit final labels (`127.1`, `2130706433`) are rejected **before any DNS lookup**.
2. **Never allowed, flag or not:** unspecified, multicast, link-local (includes cloud metadata `169.254.169.254`), reserved, and the IPv6 transition ranges listed in §3.2.
3. **Opt-in only** (`SCAN_PRIVATE_RANGES_ALLOWED=true`): loopback, RFC 1918, CGNAT and other non-global ranges.
4. IPv4-mapped IPv6 is unwrapped and judged as the IPv4 address.
5. Hostnames are resolved by the policy, **every resolved IP must pass**, and **the resolved IPs — not the name — are scanned**. A name with both A and AAAA records scans IPv4.
6. Ranges larger than 256 addresses are rejected; names resolving to more than 16 addresses are rejected.
7. Error messages never echo resolved IPs.
8. **Public targets need the operator's allowlist (new).** `SCAN_PUBLIC_ALLOWLIST` is comma separated: exact hostnames (no subdomain matching), single IPs, or CIDR ranges no wider than /16 (IPv4) or /48 (IPv6). Empty (default) means **no public scanning at all**. Targets whose addresses are all non-public pass this check because the scope policy already required the private-range opt-in. A hostname resolving to a mix of public and private addresses needs the allowlist.
9. The policy still cannot prove **authorization**. The allowlist is an interim operator control, **not** per-user ownership verification (§9). Scan only systems you own or have written permission to test.

Nmap command shape (`build_command`): `nmap -oX - --no-stylesheet -n --open <profile args> [-6] [-Pn] <validated targets>`. `-Pn` for single hosts only. No `-O`, no `-sC`/`--script`. Profiles: `quick` (top 100, 300 s limit) and `standard` (top 1000, 900 s limit).

---

## 5. Scan lifecycle — how it works (preserve these properties)

**API side** (`create_scan`): validate + authorize target → lock the user's row (`SELECT ... FOR UPDATE`) so the active-scan cap (`SCAN_MAX_ACTIVE_PER_USER`, default 3) cannot be raced → insert `queued` row, **commit** → the route then enqueues. If enqueueing fails the scan is marked `failed` ("could not be queued") and the API answers 503.

**Worker side** (`run_scan`), in order:
1. `UPDATE ... SET status='running' WHERE id=? AND status='queued' RETURNING id` — the atomic claim. If no row: return `None`. A duplicate or redelivered task, or a cancelled scan, is a harmless no-op.
2. Re-validate the target; store the exact `scan_args` in `scanned_addresses` (audit: what did this scan touch?) and commit.
3. Run the real Nmap **with no database transaction open**.
4. In **one transaction**: conditional `UPDATE ... status='completed' WHERE status='running'` (this also takes the row lock; if a cancel landed first, nothing matches and results are discarded) → upsert assets → insert findings → commit.
5. Any exception → rollback (no partial results) → conditional UPDATE to `failed` with a **fixed, safe message**. Raw stderr and tracebacks go to the server log only.

Other properties: every string from Nmap is clipped to its column size and stripped of NUL bytes (an oversized banner must not crash persistence); down hosts create no asset; a re-scan updates the same asset (`last_scanned_at`, hostname/OS filled in but never blanked) and adds new findings; `fail_stale_scans` fails `running` scans older than 2× the longest profile timeout and `queued` scans older than 6 hours.

---

## 6. Decisions and rules (carry forward)

1. Windows-native only. No WSL, no Fedora/Linux instructions, no bash-only commands.
2. FastAPI + **synchronous** SQLAlchemy 2 + psycopg3. Services commit; `get_db` never auto-commits.
3. Secrets fail closed: `JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL` have no defaults.
4. `FastAPI(debug=...)` stays `False` always.
5. Build order: users → security → migration → auth routes → assets/scanning/findings → Nmap engine → Celery → scan/findings routes → **milestone (done)** → *next:* vulnerability matching / ownership verification → organizations/RBAC → Nuclei, agents, reports, frontend.
6. Celery on Windows: `--pool=solo` (one scan at a time). Celery soft/hard time limits do not work there; the real limit is the Nmap subprocess timeout from the profile.
7. WeasyPrint needs GTK on Windows; don't import it at app start-up.
8. **Findings semantics:** an Nmap open port is an informational / `detected` finding. It claims no vulnerability. Script output is evidence only until `engines/script_classifier.py` exists.
9. **Findings attach to an asset (an IP)**, parsed from each `<host>` element.
10. **Scan data is attacker-controlled.** Never render as HTML, never use in file paths, never feed to an AI agent as instructions.
11. Scans store `scanned_addresses`.
12. Raw subprocess output and tracebacks never go into `Scan.error` or API responses.
13. **Ownership is by scan.** A scan, finding or asset belonging to another user answers **404**, identical to "does not exist".
14. **Route modules have no `from __future__ import annotations`** (slowapi wraps endpoints and FastAPI must resolve plain annotations). Applies to `auth.py`, `scans.py`, `findings.py`, `assets.py`, and `core/pagination.py`.
15. Tests: any test that needs tables must go through `conftest.py`'s `api_app` fixture, which imports **every** model module. A new model module must be added there and in `db/migrations/env.py`.
16. Tests must use the real Nmap where the point is "does scanning work"; a fake subprocess runner is allowed **only** to force failure modes that cannot be produced on demand. Production code never contains simulated output.
17. **The owner's standing requirement:** generated code must be bug-free, secure, reusable, runnable, and must execute real tools and report real results. Say plainly when something was not run.

---

## 7. Command cheat-sheet (PowerShell)

```powershell
# Infra — ALWAYS name the project; NEVER add -v without asking.
Set-Location "D:\WORK\VS Code\riskreveal\infra"
docker compose -p riskreveal-v2 up -d
docker compose -p riskreveal-v2 ps

# Backend — always from backend\ so .env and alembic.ini are found
Set-Location "D:\WORK\VS Code\riskreveal\backend"
$env:UV_LINK_MODE = "copy"
uv sync --extra dev

# Window 1: API
uv run uvicorn riskreveal.main:app --host 127.0.0.1 --port 8000
# Window 2: worker (Windows needs --pool=solo)
uv run celery -A riskreveal.tasks.celery_app:celery_app worker --pool=solo --loglevel=INFO

# Quality gates
uv run ruff check . --fix
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration        # needs Docker Desktop running

# Real end-to-end scan without API/Celery (needs SCAN_PUBLIC_ALLOWLIST=scanme.nmap.org in .env)
uv run python scripts/smoke_scan_e2e.py you@example.com

# Real scan through the API + worker (Window 3). Do NOT put the password in the prompt text.
$base = "http://127.0.0.1:8000/api/v1"
$pw = Read-Host "Enter password"
$login = @{ email = "you@example.com"; password = $pw } | ConvertTo-Json
$tok = (Invoke-RestMethod -Method Post "$base/auth/login" -ContentType "application/json" -Body $login).access_token
$h = @{ Authorization = "Bearer $tok" }
$scan = Invoke-RestMethod -Method Post "$base/scans" -Headers $h -ContentType "application/json" -Body (@{ target = "scanme.nmap.org" } | ConvertTo-Json)
Start-Sleep -Seconds 30
(Invoke-RestMethod "$base/scans/$($scan.id)" -Headers $h).status
Invoke-RestMethod "$base/findings?scan_id=$($scan.id)" -Headers $h | ConvertTo-Json -Depth 4

# Alembic
uv run alembic revision --autogenerate -m "message"
uv run alembic upgrade head
uv run alembic current

# Git: avoid the pager
git --no-pager status --short
```

Login is rate limited (`AUTH_RATE_LIMIT`, default 5/minute): a 429 means wait a minute.

---

## 8. Next steps, in order

**Step A — gates and commit.** (Required before anything else.)
```powershell
Set-Location "D:\WORK\VS Code\riskreveal\backend"
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration
Set-Location "D:\WORK\VS Code\riskreveal"
git --no-pager status --short       # no .env, no .venv, nothing under frontend\
git add backend
git commit -m "Add scan service, Celery worker, scan/finding/asset routes and allowlist gate"
```
Don't push until the gates are green. Also set `DEBUG=false` in `backend\.env`.

**Step B — failure drills with the real worker (optional, small).** Not yet done against real infrastructure: cancel a scan while real Nmap runs (`POST /scans/{id}/cancel` — the Nmap process keeps running to its own time limit, but results are discarded); kill the worker mid-scan and restart it (the startup reaper should fail the stuck scan — only after the stale threshold, 30 min for `quick`/`standard`); stop Redis and `POST /scans` (expect 503 and a `failed` scan row).

**Step C — small hardening.**
- DNS resolution has no timeout (`getaddrinfo`), took ~11 s for `scanme.nmap.org` on the owner's network, and happens while the request's DB transaction is open. Resolve with a timeout (e.g. in a thread with a deadline) and/or before the DB session is used.
- Make the Postgres password in `infra/docker-compose.yml` a required variable (`${POSTGRES_PASSWORD:?...}`), not a hardcoded fallback.
- Schedule `reap_stale_scans_task` via `beat_schedule.py` (currently only runs at worker start).

**Step D — vulnerability matching (recommended next product work).** First slice: pull CISA KEV, NVD (API 2.0) and EPSS from their official sources (the machine needs internet); match detected product/version/CPE to CVEs; store as findings with `confidence=inferred` (a banner cannot prove a vulnerability) and a `source` such as `version_match` (needs a CHECK-constraint change: `ck_findings_source_valid` currently allows only `nmap`); recognise distro-patched versions (e.g. `6.6.1p1 Ubuntu 2ubuntu2.13`) so upstream CVE data does not over-report — plan calls for the Ubuntu/Debian/Red Hat feeds. Requires a migration (CVE table, finding columns for `cve_id`, CVSS, EPSS, KEV, `first_seen`/`last_seen` for cross-scan de-duplication). Stubs already exist under `domain/intelligence/`.

**Step E — per-user target ownership verification.** Replace the operator allowlist with verified ownership: user registers a target, proves control via a DNS TXT record or a file at a well-known URL; verification fetches must pin the validated IP and apply the same scope policy (no SSRF); scans of public targets require a verified, unexpired record. Needs an `authorized_targets` table. **Do this before anyone but the owner uses the API.**

**Step F — then:** organizations/RBAC, `script_classifier.py` (and only then `--script`), Nuclei, agents, reports, frontend (§11).

**Step G — repo hygiene:** real root `README.md` and `SECURITY.md`; keep `backend\README.md` (the build needs it); decide about `frontend/components.json.bak`.

---

## 9. Known gaps and accepted shortcomings

From the auth slice (unchanged): `register` returns 409 for an existing email (account enumeration; needs email verification); no refresh-token revocation (`jti` not stored); tokens returned in the JSON body; error bodies mix `{"detail"}` with `{"error","detail"}` until `core/exceptions.py` (RFC 9457) exists; no per-account lockout; **rate limiter is in-process memory** (switch to `settings.redis_url` before more than one worker).

From the scanning work:
- **No ownership verification** (Step E). The allowlist is operator-wide, not per-user.
- **Only informational findings**; no CVE matching, no scoring (Step D).
- **No cross-scan de-duplication**: every scan inserts new findings, so re-scanning the same host produces duplicate-looking findings across scans (the asset is shared). `first_seen`/`last_seen`/`service` table are not built.
- **Cancelling a running scan** marks it cancelled and discards results but does not kill the Nmap process (it ends at its own timeout).
- **One scan at a time** per worker (`--pool=solo`); active scans per user capped at 3.
- A scan whose Nmap run exceeds the profile timeout fails as a whole; **there are no partial results** (by design, but a large range at `standard` may hit it).
- DNS may change between validation and scan for ranges (hostnames are pinned to the resolved IPs and re-validated at run time).
- `-O` (OS detection) is not used; `os_name` is usually empty. Nmap is found via `PATH` or `NMAP_PATH`.
- Banner data is attacker-controlled; the API returns `raw_evidence` only on the finding detail endpoint and clients must show it as plain text.
- Unit tests for the parser use a **synthetic** fixture; add a real captured Nmap XML as a second fixture (the live scan output is a good source — a separate step, not yet done).
- The assistant's sandbox cannot run SQLAlchemy/Docker/Nmap: the database, Celery and route code was proven only by the owner's runs. Pure-Python modules (scope policy, allowlist, parser, normalizer, engine command builder) were additionally exercised in the sandbox with a stand-in test runner (135 cases).

---

## 10. Incident log (new entries; v4's #1–13 stand, with #12 and #13 now resolved)

| # | Symptom | Resolution | Status |
|---|---|---|---|
| 12 | Committed `backend/.env.example` was a stub | Real template shipped in the pipeline zip | Resolved (applied) |
| 13 | `TRUNCATE TABLE users` fails once other tables reference `users` | `TRUNCATE ... CASCADE` in `conftest.py` | Resolved (integration tests pass) |
| 14 | `test_bad_profile_and_extra_fields_are_422` failed: `TypeError: Object of type ValueError is not JSON serializable`. The 422 handler in `main.py` returned `exc.errors()`, which holds exception objects (`ctx`) and the submitted values (`input`, e.g. passwords). Would have 500'd on **any** field-validator error and echoed inputs. | Handler now returns only `type`, `loc`, `msg`. | Fix applied (the API answered with the clean shape); gates **not re-run in a pasted output** |
| 15 | `Expand-Archive "<where you saved>\..."` failed | The literal placeholder was left in the command; the files had already been copied in manually | Harmless |
| 16 | `Read-Host "Testuser@123"` — the password was typed as the prompt text, so the real input was empty → 422 "password too short" | Use a neutral prompt: `Read-Host "Enter password"` | Resolved. **The `test@test.com` password was shown in chat — treat it as burned.** It is a local dev account only. |
| 17 | Worker and script logs flooded with SQL, every worker line twice | `DEBUG=true` in `.env` enables SQL echo | Open (cosmetic): set `DEBUG=false` |
| 18 | `scanme.nmap.org` lookup took ~11 s | `getaddrinfo` has no timeout | Open (Step C) |

---

## 11. Frontend notes (unchanged; work comes after the backend is further along)

Installed (per v3 pnpm output): `next 16.4.3`, `react`/`react-dom 19.3.1`, `@tanstack/react-query`, `react-table`, `react-virtual`, `recharts`, `@xyflow/react`, `zod`, `react-hook-form`, `nuqs`, `openapi-fetch`, `sonner`, `geist`, `next-themes`, `lucide-react`, `@sentry/nextjs`; dev: `typescript 7.0.2`, `eslint 10.13.0`, `vitest`, `msw`, `@playwright/test`, `openapi-typescript`, `knip`, `prettier`, `husky`, `lint-staged`.

Problems: TypeScript 7 / ESLint 10 are too new for parts of the toolchain (recommended `eslint@^9`, `typescript@~5.9`; **not confirmed applied**); **Tailwind is not installed**; skeleton files are stubs (`next.config.mjs` may contain `# TODO`, invalid JavaScript — verify); `shadcn init` failed (`components.json.bak`). Suggested approach: scaffold a real Next app in a temp folder with `create-next-app` (TypeScript, App Router, Tailwind, ESLint, pnpm), move the generated config into `frontend\`, reconcile with the skeleton's `app/` layout, then `pnpm dlx shadcn@latest init`. The new API gives the frontend its first real endpoints (`/scans`, `/findings`, `/assets`); finding text fields must be rendered as plain text.

---

## 12. Do-not-reintroduce list

- `case_sensitive=True` in `Settings`; dropping `NoDecode` from `cors_origins` / `scan_public_allowlist`; `FastAPI(debug=settings.debug)`; the deprecated `HTTP_422_UNPROCESSABLE_ENTITY` (use `HTTP_422_UNPROCESSABLE_CONTENT`).
- Hardcoded fallback secrets; `AutoAddPolicy()` for SSH host keys; `server_cert_validation='ignore'` for WinRM.
- Skipping the password hash when a login email doesn't exist.
- `from __future__ import annotations` in any route module (§6 rule 14).
- `docker compose` without `-p riskreveal-v2`; `docker compose down -v` without approval.
- `uv sync --active` / activating the parent folder's venv.
- **Returning `exc.errors()` (or any `ctx`/`input`) from an exception handler.**
- **Scanning:** `shell=True` or string-built commands; user-supplied Nmap flags; passing a hostname (rather than validated IPs) to Nmap; turning every script output into a finding; any port of the old repo's `dev` `WebScanner`/`WAFEvasionToolkit`; scanning without the scope policy **and** the allowlist; storing raw tool output, stderr or tracebacks in user-visible fields; holding a DB transaction open while Nmap runs; committing partial scan results; a plain `TRUNCATE` without `CASCADE` in `conftest.py`; saving unclipped scanner strings into length-limited columns.
- Celery: pickle serializer; `task_acks_late` without an atomic claim; blocking prefork on Windows.
- Importing `models` from the new `domain/*/__init__.py` files.
- Putting a password in a `Read-Host` prompt string, or asking anyone to paste `.env` contents.

---

## 13. Operating rules for whoever continues

1. Windows/PowerShell only. Never suggest WSL, Fedora, or bash-only commands.
2. Start with a **read-only audit** of what is actually on disk. Files shown in chat may be stale.
3. **Never ask the user to paste `.env` contents.** Mask passwords in any output (`-replace '(://[^:]+:)[^@]+@', '$1****@'`).
4. No destructive Docker commands (`down -v`, `volume rm`, `system prune`) without explicit approval and a listing first.
5. Small steps, each with a verification command; say plainly when something was not run.
6. Run backend commands from `backend\` with `uv run`. Use `git --no-pager`.
7. Distinguish **verified**, **delivered, not run**, and **not confirmed** in every status update.
8. The owner is a beginner: exact commands, one step at a time, plain explanations. Deliver code as a zip whose folder layout matches the repo (extract at the repo root), and list which files are new, which replace stubs and which overwrite working files.
9. Scan only systems the owner owns or is authorized to test. `scanme.nmap.org` is Nmap's public test host: one quick scan at a time, no loops.
10. Generated code must be secure, bug-free as far as can be shown, and must run the real tools; tests may inject failures but production code never fakes results.
