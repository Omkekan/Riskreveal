# RiskReveal v2 --- Docker & Project Handoff for the Coding Agent

> **Purpose:** This document is a handoff note for the agent that will
> continue coding RiskReveal v2. It records the setup decisions, the
> Docker work completed so far, the local environment, the current
> backend scaffold status, and the intended architecture/build
> direction.
>
> **Important:** This is a working handoff based on the conversation and
> the rebuild plan. It is not a substitute for inspecting the actual
> repository. Verify the current files and git diff before changing
> anything.

## 1. Project and local environment

-   Project: **RiskReveal v2 rebuild**
-   Local repository root: `D:\WORK\VS Code\riskreveal`
-   OS / shell: Windows, PowerShell
-   Python: `3.12.16`
-   Backend uses a `src` layout: `backend\src\riskreveal`
-   Backend virtual environment exists at `backend\.venv`
-   Docker Desktop is installed and was running successfully.
-   User is a beginner; provide exact PowerShell commands, explain what
    each step does, and prefer small verified steps.
-   Keep v2 local services isolated from the existing v1 PostgreSQL and
    Redis services.

## 2. Architecture decisions inherited from the rebuild plan

These are the intended product/rebuild decisions; preserve them unless
the owner explicitly changes direction:

1.  Rebuild from the **`main` branch** as the baseline, not `dev`.
2.  Move the backend from Flask to **FastAPI**.
3.  Use a clean `backend/` and `frontend/` repository structure, with
    shared `infra/` and `docs/`.
4.  Start a **fresh Alembic baseline** for the new schema. The old
    branch migrations describe the old schema and should not be blindly
    carried forward.
5.  Use the planned `backend/src/riskreveal` package layout.
6.  Security matters: fail startup when required secrets/configuration
    are missing; do not hardcode production secrets; do not log DB URLs,
    tokens, credentials, or secret values.
7.  Do not carry forward the `dev` branch's live SQL-injection/XSS
    attack engine or WAF-evasion functionality. Deliberately evaluate
    salvageable parts such as the risk scorer, authenticated SSH/WinRM
    collector, and dashboard-widget concept with their fixes.
8.  Suggested overall build order:
    -   Skeleton and local infrastructure / CI
    -   Users, organizations, authentication, RBAC
    -   Assets, credentials, scanning engines,
        normalization/classification
    -   Threat-intelligence sources (CVE list v5, KEV, EPSS first; then
        OSV and distro advisories)
    -   Risk scorer
    -   Findings UI and API
    -   Reports
    -   Agents
    -   Remediation, dashboard widgets, attack-path visualization

The detailed source plan was uploaded as
`05_Rebuild_Structure_and_File_Plan.md`. It contains the target layout
and file-by-file keep/rewrite/delete decisions. Refer to that document
in the repository/project materials if available.

## 3. Docker work completed

### Docker Compose location and project identity

-   Compose file: `infra\docker-compose.yml`
-   Compose project name used: `riskreveal-v2`
-   The current Compose setup is intentionally limited to local
    **PostgreSQL and Redis** services as the infrastructure foundation.
-   Do not assume API, worker, scanner, frontend, MinIO, or
    reverse-proxy services are already implemented in Compose. The
    full-stack Compose design is a future target in the rebuild plan.

### Host/container ports

  Service        Host bind / port   Container port Purpose
  ------------ ------------------ ---------------- -------------------------
  PostgreSQL     `127.0.0.1:5433`           `5432` v2 application database
  Redis          `127.0.0.1:6380`           `6379` v2 cache / broker

The host ports differ from typical defaults specifically to avoid
colliding with v1/local services. Keep the host binds loopback-only for
local development.

### Containers and verified state

Compose-created container names observed:

-   `riskreveal-v2-postgres-1`
-   `riskreveal-v2-redis-1`

The services were reported healthy / running. The following checks
succeeded in the prior setup conversation:

-   PostgreSQL `pg_isready` reported that it was accepting connections.
-   Redis `PING` returned `PONG`.

Treat these as the **last known successful state**, not a guarantee that
containers are still running. Re-check when starting work.

### PostgreSQL development connection

The backend `.env` was confirmed to use:

``` dotenv
DATABASE_URL=postgresql+psycopg://riskreveal:riskreveal@localhost:5433/riskreveal
```

This is a local development credential only as represented in the
conversation. Do not expose or reuse it in production. The agent should
inspect `.env` privately but must not ask the user to paste secret
values.

### Redis development connection

The backend `.env` was confirmed to use:

``` dotenv
REDIS_URL=redis://localhost:6380/0
```

Note: `config.py`'s default Redis URL was previously described as port
`6379`, while `.env` overrides it to host port `6380`. Ensure
configuration is loaded correctly so the app does not silently connect
to the wrong Redis instance.

## 4. Environment/configuration status

-   `backend\.env` exists.
-   `backend\.env.example` exists but was originally a tiny placeholder
    and should be checked/updated to document all required variable
    names without real secrets.
-   `backend\src\riskreveal\config.py` has been implemented with
    Pydantic Settings.
-   Required settings described in the conversation include:
    -   `DATABASE_URL`
    -   `JWT_SECRET_KEY` (minimum 32 characters)
    -   `FERNET_KEY` (valid Fernet key)
-   Other settings include environment, debug mode, API prefix (default
    `/api/v1`), CORS, and Redis URL.
-   Do **not** request the user's JWT secret, Fernet key, or other
    private `.env` values in chat. Ask only for redacted error output.

### Potential `.env` loading gotcha

The `.env` file is in `backend\.env`, not at repository root. Pydantic's
`env_file=".env"` is relative to the process working directory. If
Uvicorn is launched from the repository root, settings may not load from
`backend\.env`.

For initial local testing, the safest working-directory approach is:

``` powershell
Set-Location "D:\WORK\VS Code\riskreveal\backend"
.\.venv\Scripts\Activate.ps1
uvicorn riskreveal.main:app --app-dir .\src --reload
```

Alternatively, fix `SettingsConfigDict(env_file=...)` so the path is
anchored to the backend/project location and works regardless of current
directory. Do not assume the root-level launch command works until
tested.

## 5. Backend files and current scaffold status

The following files were inspected and existed in the repo's
`backend\src\riskreveal` package:

-   `config.py`
-   `dependencies.py`
-   `logging.py`
-   `main.py`
-   `__init__.py`
-   `api\__init__.py`
-   `api\v1\router.py`
-   `api\v1\__init__.py`
-   multiple route placeholders under `api\v1\routes\` (auth, users,
    organizations, assets, credentials, scans, findings, reports,
    remediation, dashboard, widgets, agents, admin feeds, etc.)
-   `core\` modules (security, exceptions, pagination, rate limiting)
-   `db\` modules
-   `cli\commands.py`

`backend\pyproject.toml` already includes a set of backend dependencies
including FastAPI, Uvicorn, SQLAlchemy, Alembic, psycopg, Redis, Celery,
and others. Inspect the actual file before changing dependencies.

### Recently discussed starter implementation

The prior assistant proposed (but the user has **not yet confirmed that
they applied or tested**) these minimal implementations:

-   `db/base.py`: SQLAlchemy `DeclarativeBase` with naming conventions
    for indexes, unique constraints, checks, foreign keys, and primary
    keys.
-   `db/session.py`: SQLAlchemy engine created from
    `settings.database_url` with `pool_pre_ping=True`; `SessionLocal` /
    `sessionmaker`; `get_db()` yields a session and closes it.
-   `api/v1/router.py`: an `APIRouter` with `GET /health` returning
    `{"status": "ok"}`.
-   `main.py`: `create_app()` creates FastAPI using app name/debug
    settings, includes the v1 router with `settings.api_v1_prefix`, and
    exposes module-level `app = create_app()`.

**Agent must inspect these files and git diff to determine whether the
proposal was actually applied.** Do not assume the health endpoint is
working yet.

### Proposed smoke test (not yet confirmed)

From the backend directory with the virtual environment active:

``` powershell
uvicorn riskreveal.main:app --app-dir .\src --reload
```

Then check:

-   `http://127.0.0.1:8000/api/v1/health`
-   `http://127.0.0.1:8000/docs`

Expected health response if the scaffold was applied:

``` json
{"status":"ok"}
```

This is an app-level health check only. It does not yet prove PostgreSQL
or Redis connectivity unless explicitly extended to test those
dependencies.

## 6. PowerShell commands for Docker verification

From the repository root:

``` powershell
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml ps
```

Start services:

``` powershell
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml up -d
```

Inspect logs:

``` powershell
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml logs --tail 100
```

Stop services without deleting persisted data:

``` powershell
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml down
```

**Caution:** `docker compose down -v` removes Compose-managed volumes
and can delete the local v2 database data. Do not run it unless the user
explicitly approves data removal.

For container-specific logs:

``` powershell
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml logs --tail 100 postgres
docker compose -p riskreveal-v2 -f .\infra\docker-compose.yml logs --tail 100 redis
```

The service keys may differ; inspect the actual Compose file before
relying on the service names.

## 7. Intended repository target (high-level)

``` text
riskreveal/
├── backend/
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── alembic.ini
│   ├── Dockerfile
│   ├── Dockerfile.worker
│   ├── Dockerfile.scanner
│   ├── .env.example
│   └── src/riskreveal/
│       ├── main.py
│       ├── config.py
│       ├── dependencies.py
│       ├── logging.py
│       ├── core/
│       ├── db/
│       ├── domain/
│       ├── api/v1/
│       ├── tasks/
│       └── cli/
├── frontend/
├── infra/
│   └── docker-compose.yml
├── docs/
└── .github/workflows/
```

The final intended local full-stack Compose may include API, worker(s),
scheduler/beat, PostgreSQL, Redis, MinIO, frontend, and a proxy. Those
are planned components, not confirmed as currently configured.

## 8. Agent operating instructions

1.  **Begin with a read-only audit**: inspect `git status`, the Compose
    file, `.env.example`, `pyproject.toml`, `config.py`, `main.py`,
    `api/v1/router.py`, `db/base.py`, and `db/session.py`.
2.  Never print or expose `backend\.env`. If inspecting it is necessary,
    check variable names or redact values.
3.  Confirm Docker container health and port mappings before diagnosing
    backend connectivity.
4.  Confirm the backend's `.env` loading behavior and working directory
    before interpreting missing-settings errors.
5.  Make changes in small, coherent steps. After each meaningful change,
    run the relevant checks and report exact results.
6.  Do not destructively reset volumes, delete data, or overwrite v1
    services.
7.  Do not claim a command or test passed unless it was actually run and
    its output observed.
8.  Keep the owner informed in beginner-friendly language; provide exact
    PowerShell commands rather than assuming Bash.
9.  Prefer safe defaults: loopback host bindings for local-only
    services, non-root containers when Dockerfiles are implemented,
    healthchecks, pinned/managed dependencies, and no secrets in images
    or git.
10. Before adding more services to Compose, first make the current
    PostgreSQL/Redis foundation and minimal FastAPI health route
    reliable.

## 9. What is known vs. still unverified

### Known from the prior conversation

-   Windows PowerShell environment and project path.
-   Python 3.12.16.
-   Docker Desktop was running.
-   v2 PostgreSQL and Redis Compose services were started and reported
    healthy.
-   Host ports are PostgreSQL `5433` and Redis `6380`, loopback-bound.
-   Backend `.env` connection URLs use those host ports.
-   Pydantic Settings config was implemented.
-   Main/router and DB files were previously TODO placeholders when
    inspected.
-   Minimal app/database/health scaffold code was then proposed.

### Must be checked by the coding agent

-   Whether the proposed scaffold code was actually pasted into the
    files.
-   Current `git status` / exact changes.
-   Whether the health endpoint starts and responds.
-   Whether Pydantic finds `backend\.env` from the chosen working
    directory.
-   Whether API can establish DB/Redis connections (not just whether
    containers are healthy).
-   Exact Compose service names, volume names, and healthcheck
    definitions.
-   Whether `.env.example` and `.gitignore` are adequate.
-   Whether the current local DB contains data that must be preserved.

------------------------------------------------------------------------

**Handoff principle:** Treat this document as a concise record of the
work and decisions already discussed. Inspect the live repository before
acting, preserve v1 isolation, and verify each claim with actual command
output.
