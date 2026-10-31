# RiskReveal v2 — Handoff (v4)

> **Supersedes** `RiskReveal_v2_Handoff_v3.md` (and everything v3 superseded).
> Written 29 Oct 2026.
>
> **Status words used in this file**
> - **Verified** — a command output was shown in chat, or the file was read in a repo snapshot.
> - **Delivered, not run** — code was written and compile-checked, but never executed in the owner's environment.
> - **Not confirmed** — nobody has shown the result either way. Do not treat it as done.

---

## 0. TL;DR

- The **auth slice is committed and pushed**. Local `dev` = `origin/dev` = `88fd16d`, working tree clean (**verified**, `git log` / `git status --short`).
- Per the previous session's closing summary: migration `1d2459ffc65b` applied, 12 integration tests passed, `ruff` clean (**reported, raw output not seen by this session**).
- **Nmap 7.97 with Npcap 1.72 is installed** (**verified**, `nmap --version`).
- This session delivered the **scanning foundation** as `riskreveal_scanning_foundation.zip` (24 files): asset/scan/finding models, scan-scope policy, scan profiles, Nmap runner + XML parser, a normalizer, tests, and a smoke script. **Delivered, not run** in the owner's environment. The pure-Python parts (scope policy, parser, command builder, normalizer — 97 test cases) were executed in a sandbox with a stand-in test runner and passed. **Models, migration, `ruff`, `mypy` and real `pytest` have not been run.**
- **Next action:** apply the zip, run the quality gates, autogenerate the second migration, read it, apply it, commit (§8).

---

## 1. Environment

| Item | Value | Status |
|---|---|---|
| Repo root | `D:\WORK\VS Code\riskreveal` | verified |
| Backend | `...\riskreveal\backend` (src layout: `src\riskreveal\`) | verified |
| OS / shell | Windows, PowerShell in VS Code. No WSL. | verified |
| Python | 3.12.16 via `uv python install 3.12`; venv `backend\.venv` managed by `uv` | verified |
| Git remote | `https://github.com/Omkekan/Riskreveal` | from v3; `git remote -v` output **not confirmed** |
| Branch | **`dev`**, tracking `origin/dev`, at `88fd16d` | verified |
| Docker | Docker Desktop; Compose project `riskreveal-v2` | verified in v3 |
| Nmap | 7.97, Npcap 1.72, on `PATH` | verified |
| pnpm | 12.15.0, store `D:\.pnpm-store\v11` | from v3 install logs |

Not confirmed installed (no output ever shown): Node/nvm, Go, Nuclei, naabu, Trivy, gitleaks, MSYS2/GTK for WeasyPrint.

### Two repositories, two `dev` branches — don't confuse them

| Repo | What it is | `dev` means |
|---|---|---|
| `Riskreveal-Vulnerability-scanner` | The **old Flask prototype** that docs 01–05 review | A half-finished rewrite containing a **live SQLi/XSS attack engine with WAF evasion**. **Never port it.** See `04_Dev_Branch_Review.md`. |
| `Riskreveal` (this rebuild) | FastAPI rebuild, structure from `05_Rebuild_Structure_and_File_Plan.md` | The **rebuild's working branch**. This is where all new work happens. |

Docs 01–05 say "base the rebuild on `main`, not `dev`" — that sentence is about the *old* repo's branches. In the new repo the owner works on `dev`. Whether the new repo's `main` should be fast-forwarded later is an open owner decision; don't merge or push to `main` without asking.

---

## 2. Documentation set (`Riskreveal-documentation.zip`, all read this session)

| File | Use it for |
|---|---|
| `01_Conversation_Summary.md` | The original goal, the five-agent concept, and the **25-item review of the old backend** (security, accuracy, reliability). The "why" behind most design rules. |
| `02_RiskReveal_Master_Plan.md` | Vision, roadmap Phases 0–8, **data model (§4)**, finding lifecycle (Appendix A), agent I/O (Appendix C). |
| `03_Frontend_and_Full_Review.md` | Frontend review and recommended frontend stack. |
| `04_Dev_Branch_Review.md` | Why the old repo's `dev` must not be ported (D-01…D-04). |
| `05_Rebuild_Structure_and_File_Plan.md` | **Target layout and keep/rewrite/delete table per file.** Check it before creating any file. |
| `06_Tech_Stack_Installation_List.md` | Package list only. |
| `07_Dual_OS_Dev_Environment_Setup.md` | Fedora/WSL guide. **Ignore entirely** — development is Windows-native. |
| `create_riskreveal_skeleton.sh` | Generated the stub tree. Safe to ignore. |

`RiskReveal_v2_Handoff_Updated.md` (the document before v2) was never available to the last two sessions.

**Known deliberate deviation from the plan:** doc 05 §6 puts organizations/RBAC early; the revised build order (v2 §3, v3 §4) defers them until one real scan → findings loop works. Keep following the revised order unless the owner changes it.

---

## 3. Repository state

### 3.1 Real code in the repo at `88fd16d` (verified from the GitHub snapshot)

`config.py`, `main.py`, `dependencies.py`, `core/security.py`, `core/rate_limit.py`, `db/base.py`, `db/session.py`, `db/migrations/{env.py, script.py.mako}`, migration `20261029_1510_1d2459ffc65b_create_users_table.py`, `domain/users/{models,repository,schemas,service}.py`, `api/v1/router.py`, `api/v1/routes/auth.py`, `alembic.ini`, `pyproject.toml` (+ `email-validator`, ruff `extend-exclude` for migrations), `uv.lock`, `tests/conftest.py` (with the `riskreveal_test` safety assert), `tests/unit/test_user_schemas.py`, `tests/integration/test_auth_flow.py`, `infra/docker-compose.yml` (`name: riskreveal-v2`, ports 5433/6380), `.gitignore`, `backend/README.md`.

### 3.2 Still `# TODO` stubs in the repo (verified)

- `backend/.env.example` is a **one-line stub** (the proper file lives in chat uploads; see §3.3).
- Root `README.md`, `SECURITY.md` and similar root files.
- Everything under `domain/{organizations,audit,credentials,intelligence,risk,agents,reports,remediation}`, `engines/{discovery,nuclei,script_classifier,auth_collectors}`, `tasks/*`, `cli/*`, and all routes except `auth.py`.
- Frontend: stub pages; `components.json.bak`; packages installed but **not a runnable Next.js app** (see §11). Frontend files were listed, not opened, this session.

### 3.3 Delivered this session — `riskreveal_scanning_foundation.zip` (**delivered, not run**)

Paths are relative to the repo root.

| File | Purpose |
|---|---|
| `domain/assets/models.py` | `Asset`: `owner_id` (FK users, cascade), `address` (IP text, ≤45), `hostname`, `os_name`, `last_scanned_at`; unique `(owner_id, address)`. |
| `domain/scanning/models.py` | `Scan`: `owner_id`, `target` (as typed), `profile`, `status` (string + CHECK constraint, not a PG enum), `scanned_addresses` (JSONB — what was *actually* scanned), `started_at`, `finished_at`, `error`. |
| `domain/findings/models.py` | `Finding`: `scan_id`, `asset_id` (both FK, cascade, indexed), `source`, `confidence`, `severity`, `status`, `title`, `description`, `port`, `protocol`, `service`, `product`, `version`, `cpe`, `raw_evidence`; CHECK constraints on the four enum columns. |
| `domain/scanning/enums.py`, `domain/findings/enums.py` | `ScanStatus`, `Severity`, `Confidence`, `FindingStatus`, `FindingSource`. Stdlib-only so tests need no ORM. |
| `domain/*/__init__.py` (assets, scanning, findings) | Docstring only. **They deliberately do not import `models`** — import models explicitly (`from riskreveal.domain.assets.models import Asset`). |
| `domain/scanning/scope_policy.py` | `validate_target(raw, allow_private=..., max_hosts=256, resolver=...)` → `ValidatedTarget` or `ScopeError`. See §4. |
| `domain/scanning/profiles.py` | Fixed profiles `quick` (top 100) and `standard` (top 1000). Users pick a *name*; they never supply Nmap flags. |
| `engines/base.py` | Frozen dataclasses `ParsedScript/Port/Host`, `ScanResult`; `EngineError`, `EngineNotFoundError`, `EngineTimeoutError`, `NmapParseError`. |
| `engines/nmap_engine.py` | `find_nmap`, `build_command`, `run_nmap` (list args, `shell=False`, hard timeout), `parse_nmap_xml` (defusedxml; per-host attribution; parses `hostscript`). |
| `engines/normalizer.py` | One **informational** `FindingDraft` per *open* port on each *up* host. Script output becomes evidence, **never** a finding by itself. |
| `db/migrations/env.py` | Now imports the three new model modules so autogenerate sees them. |
| `tests/conftest.py` | `TRUNCATE TABLE users` → `TRUNCATE TABLE users CASCADE` (new tables reference `users`; a plain TRUNCATE would fail). The `riskreveal_test` assert is kept. |
| `tests/unit/test_scope_policy.py`, `test_nmap_parser.py`, `test_nmap_engine.py`, `test_normalizer.py`, `test_scan_models.py`; `tests/fixtures/nmap_sample.xml` | Tests. The fixture is **synthetic** (shaped like Nmap 7.9x output), not a real scan. `test_scan_models.py` needs SQLAlchemy and was **not run**. |
| `scripts/smoke_nmap.py` | Manual end-to-end check: validate → real Nmap → parse → normalize → print. Saves nothing. |
| `backend/.env.example`, `infra/.env.example` | Corrected examples: ports **5433/6380**, empty secret placeholders. Contain no real secrets. |

**What was executed in the sandbox (no SQLAlchemy/pytest/network available):** 97 test cases across the scope policy, parser, command builder (with a fake subprocess runner) and normalizer, using a stand-in `pytest.raises`/`parametrize`. One real bug was found and fixed this way (Python classes IPv6 `::1` as "reserved", which blocked loopback even with private ranges enabled).

**Never executed:** the models, the migration, `ruff`, `mypy`, real `pytest`, a real Nmap run.

---

## 4. Scope policy — rules to preserve

`validate_target` is the only gate in front of Nmap. Only `ValidatedTarget.scan_args` may ever reach the scanner.

1. One target per scan: single IP, CIDR, or hostname. Whitespace, commas, `;`, URLs, zone ids (`%`), option-like strings (`-sV`), non-ASCII hostnames and all-digit final labels (`127.1`, `2130706433`) are rejected **before any DNS lookup**.
2. **Never allowed, flag or not:** unspecified, multicast, link-local (includes cloud metadata `169.254.169.254`), reserved (`240.0.0.0/4`, broadcast).
3. **Opt-in only** (`SCAN_PRIVATE_RANGES_ALLOWED=true`): loopback, RFC 1918, CGNAT and any other non-global range.
4. IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is unwrapped and judged as the IPv4 address.
5. Hostnames are **resolved by the policy, every resolved IP must pass**, and **the resolved IPs — not the name — are scanned** (pins the answer; stops Nmap re-resolving to something else). If a name has both A and AAAA records, IPv4 is scanned.
6. Ranges larger than 256 addresses are rejected; hostnames resolving to more than 16 addresses are rejected.
7. Error messages never echo resolved IPs (no probing of internal DNS through error text).
8. The policy cannot prove **authorization**. Scan only systems you own or have written permission to test. `scanme.nmap.org` is Nmap's public test host — one quick scan, no loops.

Nmap command shape (`build_command`): `nmap -oX - --no-stylesheet -n --open <profile args> [-6] [-Pn] <validated targets>`. `-Pn` is added for single hosts only; ranges keep host discovery. No `-O` (needs admin/raw sockets on Windows), no `-sC`/`--script` yet (see `profiles.py` docstring).

---

## 5. Infrastructure (Docker)

Verified in v3; the committed compose file now has `name: riskreveal-v2` (verified in the snapshot), which removes the duplicate-`infra`-stack incident.

| Container | Ports | Notes |
|---|---|---|
| `riskreveal-v2-postgres-1` (postgres:17-alpine) | `127.0.0.1:5433 -> 5432` | volume `riskreveal-v2_riskreveal_pgdata` |
| `riskreveal-v2-redis-1` (redis:7-alpine) | `127.0.0.1:6380 -> 6379` | volume `riskreveal-v2_riskreveal_redisdata` |

`backend\.env`: `DATABASE_URL=postgresql+psycopg://riskreveal:****@localhost:5433/riskreveal`, `REDIS_URL=redis://localhost:6380/0`. Integration tests start their **own** throwaway Postgres (`riskreveal_test`) via testcontainers and never touch this database.

Unrelated leftovers — **do not touch without asking:** containers `redis-test`, `redis-server`, `redis`; four exited containers referencing `asia-south1-docker.pkg.dev/riskreveal-474614/...`; three anonymous hash-named volumes.

Not confirmed: `select count(*) from users` on the dev database after the integration run (expected 0).

---

## 6. Decisions and rules (carry forward)

1. Windows-native only. No WSL, no Fedora/Linux instructions, no bash-only commands.
2. FastAPI + **synchronous** SQLAlchemy 2 + psycopg3. Services commit; `get_db` never auto-commits.
3. Secrets fail closed: `JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL` have no defaults.
4. `FastAPI(debug=...)` stays `False` always.
5. Build order (revised): users → security → migration → auth routes → **assets/scanning/findings (minimal) — models delivered** → Nmap engine — **delivered** → Celery → scan/findings routes → milestone (scan `scanme.nmap.org`, see findings in the DB) → *then* organizations/RBAC, intel feeds, scorer, Nuclei, agents, reports, frontend.
6. Celery on Windows must use `--pool=solo` (or `threads`).
7. WeasyPrint needs GTK on Windows; don't import it at app start-up.
8. **Findings semantics (new):** an Nmap open port is an **informational / detected** finding — it states what was observed and claims no vulnerability. Script output is evidence only until `engines/script_classifier.py` exists (old bug: every script output became a "finding", 01 #7).
9. **Findings attach to an asset (an IP)**, parsed from each `<host>` element — never "port N of whatever host" (old bug 01 #8).
10. **Scan data is attacker-controlled.** Banners, product strings and script output may contain anything: never render as HTML, never use in file paths, never feed to an AI agent as instructions.
11. Scans store `scanned_addresses` so there is always an audit answer to "what did this scan touch?".
12. Raw subprocess output and tracebacks never go into `Scan.error` or API responses.

---

## 7. Command cheat-sheet (PowerShell)

```powershell
# Infra — ALWAYS name the project; NEVER add -v without asking.
Set-Location "D:\WORK\VS Code\riskreveal\infra"
docker compose -p riskreveal-v2 up -d
docker compose -p riskreveal-v2 ps
docker compose -p riskreveal-v2 down            # stops, keeps data

# Backend — always from backend\ so .env and alembic.ini are found
Set-Location "D:\WORK\VS Code\riskreveal\backend"
$env:UV_LINK_MODE = "copy"
uv sync --extra dev
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
Invoke-RestMethod http://127.0.0.1:8000/healthz   # from a second terminal

# Alembic
uv run alembic revision --autogenerate -m "add assets scans findings"
uv run alembic upgrade head
uv run alembic current
docker exec riskreveal-v2-postgres-1 psql -U riskreveal -d riskreveal -c "\dt"

# Quality gates
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration        # needs Docker Desktop running

# Real-Nmap smoke test (after the gates pass; scans scanme.nmap.org once)
uv run python scripts/smoke_nmap.py

# Git: avoid the pager that froze a script earlier
git config --global core.pager cat
git --no-pager status --short
```

---

## 8. Next steps, in order

**Step A — apply and check the zip.** (`git status` must be clean first.)

```powershell
Set-Location "D:\WORK\VS Code\riskreveal"
git --no-pager status --short          # expect no output
Expand-Archive "<where you saved>\riskreveal_scanning_foundation.zip" -DestinationPath . -Force
git --no-pager status --short          # review: only the files listed in §3.3
Set-Location backend
uv add --dev types-defusedxml          # type stubs, so mypy --strict accepts defusedxml
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
```

Likely first failures, most probable first:
- `ruff`: the `S405`/`S314` family on `xml.etree` imports (type-only import in `nmap_engine.py` under `TYPE_CHECKING`) → add a targeted `# noqa` or a per-file ignore; or `RUF100` if a `noqa` is reported unused. Import-sort nits → `ruff check --fix`.
- `mypy --strict`: `defusedxml` stub details, or `slowapi` untyped (carried over from v3) → `[[tool.mypy.overrides]]`.
- `test_scan_models.py`: a constraint/index name differing from the naming convention → adjust the test or the model; the *model* names matter more because they end up in the migration.

**Step B — second migration.**

```powershell
uv run alembic revision --autogenerate -m "add assets scans findings"
```

**Read the generated file before applying.** Expect `create_table` for `assets`, `scans`, `findings`; unique `uq_assets_owner_id_address`; indexes `ix_assets_owner_id`, `ix_scans_owner_id`, `ix_findings_scan_id`, `ix_findings_asset_id`; foreign keys named `fk_<table>_<col>_<referred>`; check constraints `ck_scans_status_valid` and the four `ck_findings_*_valid`. The migration must **not** touch `users`. Then `uv run alembic upgrade head`, `\dt`, `uv run alembic current`.

**Step C — integration tests, then commit locally.**

```powershell
uv run pytest tests/integration         # confirms the TRUNCATE ... CASCADE change
Set-Location "D:\WORK\VS Code\riskreveal"
git --no-pager status --short           # no .env, no .venv, nothing under frontend\
git add backend infra
git commit -m "Add assets/scans/findings models, scope policy and Nmap engine"
```

Don't push until the gates are green. Keep frontend changes out of this commit.

**Step D — optional live check.** `uv run python scripts/smoke_nmap.py` scans `scanme.nmap.org` once and prints finding drafts. Expect open ports such as 22 (ssh), 80 (http), 9929 and 31337, but trust the real output over this list.

**Step E — next increment (not started):**
1. `domain/scanning/service.py` + `repository.py`: create a `Scan` (validate target, store `scanned_addresses`), run it, upsert `Asset` per host IP, insert `Finding`s, set status/timestamps — **one commit at the end; on any failure roll back and mark the scan `failed` with a safe message** (old bug: `finally: commit()` saved partial results, 01 #18).
2. `tasks/celery_app.py` + `tasks/scan_tasks.py` (`--pool=solo`): honour `cancelled`, set time limits, never leave a scan stuck in `running`.
3. `api/v1/routes/scans.py` and `findings.py`: owner-scoped (a user sees only their own scans/assets/findings), pagination, rate limiting. Add `SCAN_PRIVATE_RANGES_ALLOWED` and an Nmap path setting to `config.py`/`.env.example` if needed.
4. Milestone: register → log in → scan `scanme.nmap.org` → see findings via the API.
5. Then revisit RBAC/organizations, `script_classifier.py`, intelligence feeds.

**Step F — repo hygiene (small):** write the real root `README.md` and `SECURITY.md`; make sure `backend\README.md` stays (the build needs it); remove or archive `frontend/components.json.bak` decision (see §11).

---

## 9. Known gaps and accepted shortcomings

From the auth slice (unchanged): `register` returns 409 for an existing email (account enumeration; needs email verification); no refresh-token revocation/rotation (`jti` is not stored); tokens are returned in the JSON body; error bodies mix `{"detail"}` with `{"error","detail"}` until `core/exceptions.py` (RFC 9457) exists; no per-account lockout; rate limiter is in-process memory (switch to `settings.redis_url` before more than one worker).

New with the scanning foundation:
- Nothing enforces **authorization**: any logged-in user could scan any *public* target once the routes exist. An authorized-targets / scope table (`scan_scope` in 02 §4.3) is needed before this is exposed beyond the owner.
- The scope policy resolves DNS itself; a very short-TTL name could in principle change between validation and scan. Mitigated (the resolved IP is what's scanned), not eliminated for ranges.
- Only informational findings exist; no CVE matching, no scoring.
- `Finding` has no cross-scan de-duplication (`first_seen`/`last_seen`) and no `service` table yet.
- `-O` (OS detection) is not used; `os_name` will usually be empty.
- Nmap is found via `PATH` only; there is no configurable path.
- Unit tests cover the parser against a **synthetic** fixture; a real captured Nmap XML should be added as a second fixture after the first real scan.

---

## 10. Incident log (condensed from v3; status updated)

| # | Symptom | Resolution | Status |
|---|---|---|---|
| 1 | `VIRTUAL_ENV` pointed at the parent folder's venv; Pylance unresolved imports | `deactivate`; `uv sync --extra dev` (no `--active`); select `backend\.venv\Scripts\python.exe`; open `riskreveal` as the workspace | `uv run` works (verified). VS Code interpreter **not confirmed**. |
| 2 | `Readme file does not exist: README.md` | `backend\README.md` exists | Resolved (in snapshot) |
| 3 | `uv init`/`uv add` vs the `# TODO` pyproject | Real `pyproject.toml` in place | Resolved |
| 4 | "Failed to hardlink files" (cache on `C:`, project on `D:`) | `$env:UV_LINK_MODE="copy"` | Harmless |
| 5 | `ERR_PNPM_IGNORED_BUILDS: unrs-resolver` | `pnpm approve-builds` pressed with nothing selected | Fine unless ESLint errors mention it |
| 6 | pnpm peers: `eslint` 10, `typescript` 7 too new | Recommended `eslint@^9`, `typescript@~5.9` | **Not confirmed applied** |
| 7 | `shadcn init` invalid `components.json` | Rename to `.bak`, install Tailwind, scaffold Next properly | **Unresolved** (`.bak` exists) |
| 8 | Duplicate `infra` compose stack, port 5433 clash | `docker compose -p infra down`; `name: riskreveal-v2` added | Resolved |
| 9 | Compose file in chat ≠ on disk | Disk is the truth | Noted |
| 10 | `git diff` opened a pager and froze a script | `git config --global core.pager cat`; use `git --no-pager` | Resolved |
| 11 | `Expand-Archive` failed: zip not in Downloads | Zip was not needed; files were already in place | Resolved |
| 12 | Committed `backend/.env.example` is a stub; chat copy had wrong ports | Corrected files are in the zip (§3.3) | Fix delivered, **not applied** |
| 13 | `TRUNCATE TABLE users` fails once other tables reference `users` | `TRUNCATE ... CASCADE` in `conftest.py` | Fix delivered, **not run** |

---

## 11. Frontend notes (unchanged; work is after the backend milestone)

Installed (per v3 pnpm output): `next 16.4.3`, `react`/`react-dom 19.3.1`, `@tanstack/react-query 5.105.0`, `react-table 9.3.1`, `react-virtual 3.14.23`, `recharts 3.10.1`, `@xyflow/react 12.12.0`, `zod 4.6.7`, `react-hook-form 7.91.0`, `nuqs 2.10.2`, `openapi-fetch 0.17.0`, `sonner`, `geist`, `next-themes`, `lucide-react 1.62.0`, `@sentry/nextjs 11.9.0`; dev: `typescript 7.0.2`, `eslint 10.13.0`, `vitest 5.0.5`, `msw 3.0.3`, `@playwright/test 1.64.1`, `openapi-typescript 7.13.0`, `knip`, `prettier`, `husky`, `lint-staged`.

Problems: TypeScript 7 / ESLint 10 are too new for parts of the toolchain (§10 #6); **Tailwind is not installed**; skeleton files are stubs (`next.config.mjs` may contain `# TODO`, which is invalid JavaScript — verify); `openapi-typescript` wants TypeScript 5.x. Suggested approach: scaffold a real Next app in a temp folder with `create-next-app` (TypeScript, App Router, Tailwind, ESLint, pnpm), move the generated config into `frontend\`, reconcile with the skeleton's `app/` layout, then run `pnpm dlx shadcn@latest init`.

---

## 12. Do-not-reintroduce list

- `case_sensitive=True` in `Settings`; dropping `NoDecode` from `cors_origins`; `FastAPI(debug=settings.debug)`; the deprecated `HTTP_422_UNPROCESSABLE_ENTITY`.
- Hardcoded fallback secrets; `AutoAddPolicy()` for SSH host keys; `server_cert_validation='ignore'` for WinRM.
- Skipping the password hash when a login email doesn't exist.
- `from __future__ import annotations` in `routes/auth.py`.
- `docker compose` without `-p riskreveal-v2`; `docker compose down -v` without approval.
- `uv sync --active` / activating the parent folder's venv.
- **Scanning:** `shell=True` or string-built commands; user-supplied Nmap flags; passing a hostname (rather than validated IPs) to Nmap; turning every script output into a finding; any port of the old repo's `dev` `WebScanner`/`WAFEvasionToolkit`; scanning without the scope policy; storing raw tool output or tracebacks in user-visible fields; a plain `TRUNCATE` without `CASCADE` in `conftest.py`.
- Importing `models` from the new `domain/*/__init__.py` files (keeps the pure modules importable without the ORM and avoids import cycles).

---

## 13. Operating rules for whoever continues

1. Windows/PowerShell only. Never suggest WSL, Fedora, or bash-only commands.
2. Start with a **read-only audit** of what is actually on disk. Files shown in chat may be stale.
3. **Never ask the user to paste `.env` contents.** Mask passwords in any output (`-replace '(://[^:]+:)[^@]+@', '$1****@'`).
4. No destructive Docker commands (`down -v`, `volume rm`, `system prune`) without explicit approval and a listing first.
5. Small steps, each with a verification command; say plainly when something was not run.
6. Run backend commands from `backend\` with `uv run`. Use `git --no-pager`.
7. Distinguish **verified**, **delivered, not run**, and **not confirmed** in every status update.
8. The owner is a beginner: exact commands, one step at a time, plain explanations.
9. Scan only systems the owner owns or is authorized to test.
