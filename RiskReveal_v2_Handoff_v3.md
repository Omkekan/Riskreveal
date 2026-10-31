# RiskReveal v2 — Handoff (v3)

> **Supersedes** `RiskReveal_v2_Handoff_v2.md` and
> `RiskReveal_v2_venv_Setup_and_Troubleshooting.md`.
>
> **How to read the status words in this file.** *Verified* = a command
> output was pasted into the chat and showed it. *Delivered, not run* = code
> was written and compile-checked but never executed. *Not confirmed* = nobody
> has shown the result either way. Do not treat "not confirmed" as done.
>
> `RiskReveal_v2_Handoff_Updated.md` (the document before v2) was **not
> available** in the session that wrote this file. Where this file doesn't
> contradict it, it still applies.

---

## 0. TL;DR

- Development is **native Windows, PowerShell, no WSL, no Fedora**. Files 06
  and 07 in the repo describe Ubuntu/Fedora/WSL setups; **ignore 07
  entirely** and treat 06 as a package list only.
- Backend runs: `uv run uvicorn riskreveal.main:app --reload` starts cleanly,
  and `GET /healthz` returned `status: ok, database: reachable` against the
  Docker Postgres on port **5433** (verified).
- **Next action: the first Alembic migration** (`users` table). The Alembic
  files were written this session but it is *not confirmed* they were placed
  or that the migration was generated/applied.
- An **auth slice** (register / login / refresh / me) was delivered this
  session as `riskreveal_auth_slice.zip`. It is *delivered, not run* — see §9.
- Frontend: packages installed, but it is **not a runnable Next.js app yet**,
  and `shadcn init` failed (§11).

---

## 1. Environment

| Item | Value |
|---|---|
| Repo root | `D:\WORK\VS Code\riskreveal` |
| Backend | `D:\WORK\VS Code\riskreveal\backend` (src layout: `src\riskreveal\`) |
| OS / shell | Windows, PowerShell inside VS Code |
| Python | 3.12.16, installed by `uv python install 3.12` (verified) |
| Backend venv | `backend\.venv`, managed by `uv` |
| pnpm | 12.15.0; store at `D:\.pnpm-store\v11` (from install logs) |
| Docker | Docker Desktop, working (verified) |
| Git remote | `https://github.com/Omkekan/Riskreveal` (branch `main`) |

Tools **not confirmed** installed (they were in the install guide but no
output was ever shown): Node version/nvm, Go, Nmap (+ Npcap), Nuclei, naabu,
Trivy, gitleaks, MSYS2/GTK for WeasyPrint.

---

## 2. Repository state

### 2.1 Docs in the repo (from the GitHub listing)

`01_Conversation_Summary.md`, `02_RiskReveal_Master_Plan.md`,
`03_Frontend_and_Full_Review.md`, `04_Dev_Branch_Review.md`,
`05_Rebuild_Structure_and_File_Plan.md`, `06_Tech_Stack_Installation_List.md`,
`07_Dual_OS_Dev_Environment_Setup.md`, `create_riskreveal_skeleton.sh`.
Only 06, 07 and the skeleton script were read in the session that wrote this
file; 01–05 were not.

### 2.2 Backend — written and previously verified (per the v2 handoff)

`config.py`, `db/base.py`, `db/session.py`, `main.py`,
`domain/users/models.py`, `domain/users/__init__.py`, `core/security.py`,
`pyproject.toml`, `.env.example`. The v2 handoff reports these as `ruff` and
`mypy --strict` clean with behavioural tests for models/security.

**Files on disk may differ from the copies uploaded to chat.** This already
happened once (§5, item 9). When in doubt, read the file on disk.

### 2.3 Backend — written this session

| File | Status |
|---|---|
| `backend/alembic.ini` | Provided (replaces the one-line skeleton stub). **Not confirmed placed.** |
| `backend/src/riskreveal/db/migrations/env.py` | Provided. Reads `DATABASE_URL` via `riskreveal.config`; imports `riskreveal.domain.users.models`. **Not confirmed placed.** |
| `backend/src/riskreveal/db/migrations/script.py.mako` | Provided (new file). **Not confirmed placed.** |
| Auth slice (11 files, §9) | **Delivered, not run.** |

`uv run alembic heads` printed nothing and no error when run against the
*placeholder* `env.py`/`alembic.ini`; that only proves Alembic starts.

### 2.4 Still skeleton stubs

Everything else from `create_riskreveal_skeleton.sh`: it writes a one-line
`# TODO` (or `"""TODO"""` / `{}`) into every file. Notably this means
`frontend/next.config.mjs` contains `# TODO: ...`, which is **invalid
JavaScript** (`#` is a syntax error), and `frontend/tsconfig.json` and
`frontend/components.json` are `{}`.

---

## 3. Infrastructure state (Docker) — verified

Running, healthy:

| Container | Ports | Compose project |
|---|---|---|
| `riskreveal-v2-postgres-1` (postgres:17-alpine) | `127.0.0.1:5433 -> 5432` | `riskreveal-v2` |
| `riskreveal-v2-redis-1` (redis:7-alpine) | `127.0.0.1:6380 -> 6379` | `riskreveal-v2` |

Volumes holding the real data: `riskreveal-v2_riskreveal_pgdata`,
`riskreveal-v2_riskreveal_redisdata`.

`backend\.env` (verified, password masked):
`DATABASE_URL=postgresql+psycopg://riskreveal:****@localhost:5433/riskreveal`,
`REDIS_URL=redis://localhost:6380/0`.

The compose file **on disk** maps `5433` and `6380` and has **no `name:`
line** (verified by `Select-String`). The copy uploaded to chat used
`5432`/`6379`; the disk copy is the truth. `.env.example` in the repo says
`5432`/`6379` and is therefore wrong for this setup.

Unrelated leftovers — **do not touch without asking**: containers
`redis-test`, `redis-server`, `redis`, and four exited containers from 12
months ago that reference a GCP Artifact Registry
(`asia-south1-docker.pkg.dev/riskreveal-474614/...`); plus three anonymous
volumes with hash names of unknown origin.

---

## 4. Decisions and rules (carry forward)

1. Windows-native only. No WSL, no Fedora/Linux instructions.
2. FastAPI + synchronous SQLAlchemy 2 + psycopg3; services commit, `get_db`
   never auto-commits.
3. Secrets fail closed: `JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL` have no
   defaults; Fernet key is validated at startup.
4. `FastAPI(debug=...)` stays `False` always (Starlette's debug page bypasses
   custom handlers and leaks tracebacks).
5. Build order (revised): users → security → **Alembic migration** → auth
   routes → assets/scanning/findings (minimal) → Nmap engine → Celery →
   scan/findings routes → milestone (scan `scanme.nmap.org`, see findings)
   → *then* organizations/RBAC, intel feeds, scorer, Nuclei, agents, reports,
   frontend.
6. Celery on Windows must use `--pool=solo` (or `threads`); `prefork` needs
   `os.fork()`.
7. WeasyPrint needs GTK on Windows (MSYS2 `pango` +
   `WEASYPRINT_DLL_DIRECTORIES=C:\msys64\mingw64\bin`). It is in
   `pyproject.toml`, so it installs, but **importing it fails** until GTK is
   set up. Don't import it at app start-up.
8. Scan only systems you own or are authorized to test
   (`scanme.nmap.org` for the milestone).

---

## 5. Incident log — what went wrong and how it was resolved

| # | Symptom | Cause | Resolution | Status |
|---|---|---|---|---|
| 1 | `VIRTUAL_ENV=D:\WORK\VS Code\.venv` mismatch warning; Pylance unresolved imports | Shell/VS Code were using a venv in the **parent** folder | `deactivate`; clear `VIRTUAL_ENV`; `uv sync --extra dev` (no `--active`); select `backend\.venv\Scripts\python.exe`; open `riskreveal` (not its parent) as the workspace | `uv run uvicorn` now works (verified). VS Code interpreter choice **not confirmed**. |
| 2 | `OSError: Readme file does not exist: README.md` | `pyproject.toml` has `readme = "README.md"`; no `backend\README.md` | Create `backend\README.md` | Not confirmed; sync evidently succeeded afterwards |
| 3 | `uv init`/`uv add` errors: `pyproject.toml already exists`, "missing `[project]` table" | Skeleton had written a `# TODO` pyproject; real one was written later | Use the real `pyproject.toml`; `uv sync --extra dev` | Resolved |
| 4 | "Failed to hardlink files" | uv cache on `C:`, project on `D:` | `$env:UV_LINK_MODE="copy"` (or `setx UV_LINK_MODE copy`) | Harmless |
| 5 | `ERR_PNPM_IGNORED_BUILDS: unrs-resolver` | pnpm blocks dependency build scripts | `pnpm approve-builds` — Enter was pressed with **nothing selected**, so it is denied | Fine unless ESLint errors mention `unrs-resolver` |
| 6 | `pnpm peers check`: `eslint` 10 and `typescript` 7 unmet | Unpinned install pulled majors newer than the plugins support | Recommended: `pnpm add -D eslint@^9 typescript@~5.9` and `pnpm remove @typescript-eslint/parser @typescript-eslint/eslint-plugin` | **Not confirmed applied** |
| 7 | `shadcn init`: "Invalid configuration found in components.json" | Skeleton wrote `{}`; Tailwind never installed; frontend isn't a real Next app | Rename `components.json`; install Tailwind; scaffold Next properly (§11) | **Unresolved** |
| 8 | `docker compose up -d` in `infra\` failed: `Bind for 127.0.0.1:5433 failed: port is already allocated` | Compose named the project after the folder (`infra`), creating a duplicate stack that clashed with running `riskreveal-v2` | `docker compose -p infra down` (no `-v`); removed the two empty `infra_*` volumes | Resolved (verified). **Prevention not confirmed:** add `name: riskreveal-v2` to the compose file |
| 9 | Compose file in chat ≠ compose file on disk | Disk copy is the older 5433/6380 version | Trust disk | Noted |
| 10 | Blank output from `Invoke-RestMethod .../healthz` | Request made before/against a stale terminal | Re-ran; got `ok / reachable` | Resolved |

---

## 6. Command cheat-sheet (PowerShell)

```powershell
# Infra (from infra\). ALWAYS name the project; NEVER add -v without asking.
Set-Location "D:\WORK\VS Code\riskreveal\infra"
docker compose -p riskreveal-v2 up -d
docker compose -p riskreveal-v2 ps
docker compose -p riskreveal-v2 down            # stops, keeps data

# Backend (always from backend\ so .env and alembic.ini are found)
Set-Location "D:\WORK\VS Code\riskreveal\backend"
$env:UV_LINK_MODE = "copy"
uv sync --extra dev
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
Invoke-RestMethod http://127.0.0.1:8000/healthz   # from a second terminal

# Alembic
uv run alembic revision --autogenerate -m "create users table"
uv run alembic upgrade head
uv run alembic current
docker exec riskreveal-v2-postgres-1 psql -U riskreveal -d riskreveal -c "\dt"

# Quality gates
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration        # needs Docker Desktop running
```

---

## 7. Verified vs. not confirmed

**Verified (output was shown):** Python 3.12.16 via uv; dev dependencies
installed; API starts and shuts down cleanly; `/healthz` ok/reachable;
Docker state in §3; duplicate `infra` stack removed; `.env` ports; Alembic
placeholder starts; frontend packages installed (list in §11); Playwright
browsers downloaded; `shadcn init` fails.

**Not confirmed:** any Alembic file placed or migration generated/applied;
`backend\README.md` created; frontend version pins applied; `name:` added to
compose; `git check-ignore -v backend/.env` run; VS Code interpreter set;
anything in the auth slice; the optional system tools in §1.

---

## 8. Next steps, in order

1. **Place the Alembic files** (`alembic.ini`, `env.py`, `script.py.mako` —
   contents were given in chat), then:
   `uv run alembic revision --autogenerate -m "create users table"`.
   **Read the generated file before applying**: `upgrade()` must contain
   `op.create_table('users', ...)` and `op.create_index('ix_users_email', 'users', ['email'], unique=True)`.
   If it only says `pass`, autogenerate can't see `User` — check the model
   import in `env.py`.
2. `uv run alembic upgrade head`, then `\dt` / `\d users` via `docker exec`
   (expect `users` and `alembic_version`; `pk_users`, `ix_users_email`).
3. Add `name: riskreveal-v2` as the first line of `infra\docker-compose.yml`.
4. `git check-ignore -v backend/.env` must print a rule. Then commit
   (migration file included, `.env` excluded).
5. Install and verify the auth slice (§9).
6. Pivot step from the build order: minimal `assets`, `scanning`, `findings`
   models + migration; then `engines/nmap_engine.py` (install Nmap + Npcap
   first), Celery with `--pool=solo`, scan/findings routes, milestone.
7. Frontend scaffold (§11) — later, after the milestone.

---

## 9. Auth slice (delivered, not run)

Delivered as `riskreveal_auth_slice.zip`, paths relative to the repo root.
Compile-checked in a sandbox that had **no FastAPI/slowapi/network**, so it
has **never been executed, linted, or type-checked**.

| File | Purpose |
|---|---|
| `domain/users/schemas.py` | `UserCreate`, `LoginRequest`, `RefreshRequest`, `UserRead`, `TokenPair`. Emails trimmed/lower-cased and capped at 254; password 12–128 chars; unknown fields rejected. |
| `domain/users/repository.py` | `get_by_id`, `get_by_email`, `add` (flush only; never commits). |
| `domain/users/service.py` | `register_user`, `authenticate`, `issue_token_pair`, `refresh_session`. |
| `core/rate_limit.py` | slowapi limiter (in-memory), `auth_limit()` reads `AUTH_RATE_LIMIT` per request. |
| `dependencies.py` | `get_current_user` / `CurrentUser` (Bearer token → active `User`, else one generic 401). |
| `api/v1/routes/auth.py` | `POST /register` (201/409/422), `POST /login`, `POST /refresh`, `GET /me`. |
| `api/v1/router.py` | Aggregates v1 routes. |
| `main.py` | **Patched copy of the uploaded `main.py`**: adds the router (under `settings.api_v1_prefix` = `/api/v1`), `app.state.limiter`, and a 429 handler. Diff it against the on-disk file (`git diff`) before trusting it. |
| `tests/conftest.py`, `tests/unit/test_user_schemas.py`, `tests/integration/test_auth_flow.py` | Unit tests need nothing; integration tests start their own Postgres container (Docker Desktop required) and never touch the dev database. |

**Needs one new dependency:** `uv add email-validator` (for `EmailStr`; it was
not in `pyproject.toml`).

**Design decisions to preserve**

- **No timing oracle on login:** `authenticate` always runs exactly one
  `verify_password`, against a random dummy hash computed at import when the
  email doesn't exist. An integration test spies on `verify_password` to
  guard this. Same generic 401 for unknown email, wrong password, disabled
  account.
- **Access vs refresh tokens are not interchangeable** (checked by the `type`
  claim; covered by tests in both directions).
- **Routes file has no `from __future__ import annotations`** on purpose
  (slowapi wraps endpoints; see the module docstring). Every
  `@limiter.limit`-decorated route must take `request: Request`.
- Rate limiter storage is in-process memory. Switch to `settings.redis_url`
  before running more than one worker; behind a proxy, configure trusted
  forwarded headers.

**Accepted shortcomings (revisit later, deliberately not built yet)**

- `register` returns 409 for an existing email (account enumeration). A real
  fix needs email verification.
- No refresh-token revocation or rotation; tokens have a `jti` but nothing
  stores it. Old refresh tokens stay valid until expiry.
- Tokens are returned in the JSON body. When the frontend exists, consider
  an httpOnly-cookie refresh token.
- Error bodies mix FastAPI's `{"detail"}` with the app's `{"error","detail"}`
  until `core/exceptions.py` (RFC 9457) is written.
- No per-account (as opposed to per-IP) lockout.

**First-run checks for the slice**

```powershell
Set-Location "D:\WORK\VS Code\riskreveal"
git status                                   # commit or stash first
Expand-Archive "$env:USERPROFILE\Downloads\riskreveal_auth_slice.zip" -DestinationPath . -Force
git diff backend/src/riskreveal/main.py      # review what changed
Set-Location backend
uv add email-validator
uv run ruff check . ; uv run mypy src ; uv run pytest tests/unit
uv run pytest tests/integration
```

Likely first failures, in order of probability: a `mypy` complaint about
slowapi being untyped (add a `[[tool.mypy.overrides]]` for `slowapi.*`);
`ruff` import-sorting nits (`ruff check --fix`); the testcontainers
`driver="psycopg"` argument differing in the installed version; the
rate-limit test if slowapi caches parsed limits (it should re-read a callable
limit per request).

---

## 10. Do-not-reintroduce list

- `case_sensitive=True` in `Settings` (env vars are UPPERCASE, fields lower).
- Dropping `NoDecode` from `cors_origins` (comma-separated env value breaks).
- `FastAPI(debug=settings.debug)`.
- The deprecated `HTTP_422_UNPROCESSABLE_ENTITY` constant (the code uses
  `HTTP_422_UNPROCESSABLE_CONTENT`).
- Hardcoded fallback secrets; `AutoAddPolicy()` for SSH host keys;
  `server_cert_validation='ignore'` for WinRM.
- Skipping the password hash when a login email doesn't exist.
- `from __future__ import annotations` in `routes/auth.py`.
- Running `docker compose` without `-p riskreveal-v2` (or the `name:` line).
- `uv sync --active` / activating the parent folder's venv.

---

## 11. Frontend notes

Installed (verified from pnpm output): `next 16.4.3`, `react`/`react-dom 19.3.1`,
`@tanstack/react-query 5.105.0`, `react-table 9.3.1`, `react-virtual 3.14.23`,
`recharts 3.10.1`, `@xyflow/react 12.12.0`, `zod 4.6.7`, `react-hook-form 7.91.0`,
`nuqs 2.10.2`, `openapi-fetch 0.17.0`, `sonner`, `geist`, `next-themes`,
`lucide-react 1.62.0`, `@sentry/nextjs 11.9.0`; dev: `typescript 7.0.2`,
`eslint 10.13.0`, `vitest 5.0.5`, `msw 3.0.3`, `@playwright/test 1.64.1`,
`openapi-typescript 7.13.0`, `knip`, `prettier`, `husky`, `lint-staged`.

Problems:

- `typescript 7` / `eslint 10` are too new for parts of the toolchain (§5
  item 6). `openapi-typescript` wants TypeScript 5.x and is needed to
  generate API types from FastAPI's OpenAPI.
- **Tailwind is not installed** (`tailwindcss`, `@tailwindcss/postcss`,
  `postcss`); shadcn needs it.
- The skeleton's frontend files are stubs (§2.4). `next.config.mjs` is
  invalid JS right now. A practical approach: scaffold a real Next app in a
  temporary folder with `create-next-app` (TypeScript, App Router, Tailwind,
  ESLint, pnpm), then move the generated config files into `frontend\` and
  reconcile with the skeleton's `app/` layout before running
  `pnpm dlx shadcn@latest init`.
- Frontend work is intentionally after the backend milestone (§4.5).

---

## 12. Operating rules for whoever continues

1. Windows/PowerShell only. Never suggest WSL, Fedora, bash-only commands.
2. Start with a **read-only audit** of what is actually on disk; files shown
   in chat may be stale (§5 item 9).
3. **Never ask the user to paste `.env` contents**; mask passwords in any
   output (`-replace '(://[^:]+:)[^@]+@', '$1****@'`).
4. No destructive Docker commands (`down -v`, `volume rm`, `system prune`)
   without explicit approval and a listing first.
5. Small steps, each with a verification command; say plainly when something
   was not run.
6. Run backend commands from `backend\`, with `uv run`.
7. Distinguish "verified", "delivered, not run", and "not confirmed" in every
   status update.
