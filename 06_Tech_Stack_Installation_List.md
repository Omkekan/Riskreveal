# RiskReveal – Tech Stack & Installation List

*Companion to `02_RiskReveal_Master_Plan.md` and `05_Rebuild_Structure_and_File_Plan.md`. This file is the shopping list: every system tool and library the rebuild structure needs, with install commands, organized by what the skeleton's folders actually require. "Now" items support Phases 0–2; "Later" items are flagged so you don't install things you don't need yet.*

---

## 0. How to read this file

- Commands assume **Ubuntu/Debian** for system packages and **macOS (Homebrew)** as the alternative; swap for your distro's package manager if different.
- Python packages are grouped to match `backend/pyproject.toml`'s dependency groups — paste each block as a group, don't just dump everything into one unsorted list.
- Frontend packages use `pnpm` (per the rebuild plan's decision to standardize on it).
- Where I'm not confident a package name or version is current, I say so rather than guess.

---

## 1. System-level tools (install once, outside any project folder)

| Tool | Why | Install |
|---|---|---|
| **Python 3.12 or 3.13** | Backend runtime | `sudo apt install python3.12 python3.12-venv` · macOS: `brew install [email protected]` |
| **uv** | Python package/dependency manager, replaces pip + Poetry | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Node.js 24.x (Active LTS)** | Frontend runtime | Use `nvm`/`fnm`, not the OS package manager, so you can pin per-project: `nvm install 24 && nvm use 24`. **Note:** Node 20 reached end-of-life on April 30, 2026 — if you have it installed, upgrade. Node 22 is still Maintenance LTS (safe but aging); Node 26 just entered Active LTS today (Oct 28, 2026) and is also a reasonable choice. |
| **pnpm** | Frontend package manager (already your lockfile choice) | `corepack enable && corepack prepare pnpm@latest --activate` |
| **PostgreSQL 16+** | Primary database (drop SQLite entirely, per the master plan) | `sudo apt install postgresql postgresql-contrib` · macOS: `brew install postgresql@16` — or run it only via Docker Compose and skip a local install |
| **Redis 7+ (or Valkey)** | Celery broker/result backend, caching | `sudo apt install redis-server` · macOS: `brew install redis` — or via Docker Compose |
| **Docker + Docker Compose v2** | Runs the whole stack locally and in CI | https://docs.docker.com/engine/install/ |
| **Git** | You have this already | — |
| **Nmap** | Core scan engine. **License note from our stack discussion:** free for end-use, but its license restricts bundling it inside a proprietary product you distribute — fine to run on your own servers, get a lawyer's confirmation before shipping it inside any image or appliance you distribute | `sudo apt install nmap` · macOS: `brew install nmap` |
| **Nuclei** | Template-based web/CVE scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`, or download a release binary from the ProjectDiscovery GitHub releases page; then `nuclei -update-templates` |
| **naabu** (optional, Phase 1) | Fast port discovery before `-sV` | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **Trivy** | Scans your own Docker images and dependencies in CI | `sudo apt install trivy` (needs the Aqua Security apt repo) or the install script at https://aquasecurity.github.io/trivy/ |
| **gitleaks** | Secret scanning in CI (catches another leaked Fernet key before it ships) | `brew install gitleaks` or download a release binary |
| **Go** (only if building `nuclei`/`naabu` from source instead of using release binaries) | — | `sudo apt install golang-go` · macOS: `brew install go` |

---

## 2. Python backend — grouped by `pyproject.toml` dependency group

Run these from `backend/` after `uv init` (or add them directly to `pyproject.toml` and run `uv sync`).

### 2.1 Core web framework

```bash
uv add fastapi "uvicorn[standard]" pydantic pydantic-settings python-multipart
```

### 2.2 Database and migrations

```bash
uv add "sqlalchemy>=2.0" alembic "psycopg[binary,pool]" redis
```

> `psycopg[binary,pool]` is psycopg3 — the current recommended PostgreSQL driver. If you want a fully async DB layer (`asyncpg`) instead, add `asyncpg` and use SQLAlchemy's async engine; either works with the rebuild structure.

### 2.3 Task queue

```bash
uv add celery
uv add --optional flower   # Celery monitoring UI, nice to have, not required
```

### 2.4 Security and auth

```bash
uv add pyjwt argon2-cffi cryptography slowapi
```

- `pyjwt` — JWT issue/verify (simpler than `python-jose`; either is fine).
- `argon2-cffi` — password hashing, replaces Bcrypt per the stack recommendation.
- `cryptography` — Fernet/envelope encryption for stored credentials. **This was in `main`'s code but missing from `Requirement.txt`, which is why the original app couldn't start from a clean install — don't repeat that.**
- `slowapi` — rate limiting for FastAPI routes (auth endpoints especially).

### 2.5 Scanning engines, parsing, and collectors

```bash
uv add defusedxml httpx paramiko pywinrm
```

- `defusedxml` — parse Nmap's XML output safely; target-controlled content shouldn't go through the stdlib `xml` parser.
- `httpx` — async HTTP client for web checks and calling Nuclei's JSON output / any HTTP-based verification.
- `paramiko` — SSH collector (Linux authenticated scanning). **Reminder from the dev-branch review: never set `AutoAddPolicy()` for host keys — verify or pin them.**
- `pywinrm` — WinRM collector (Windows authenticated scanning). **Same reminder: never set `server_cert_validation='ignore'`.**

### 2.6 Intelligence and version matching

```bash
uv add packaging univers cpe
```

- `packaging` — PEP 440 version comparison (Python ecosystem; also useful as a general semver-ish fallback).
- `univers` — verified as an actively maintained package (by nexB/AboutCode, the team behind VulnerableCode) that parses and compares version **ranges** across multiple ecosystems (PyPI, npm, Debian, RPM, etc.) through a unified model. This is the library that makes real CPE/version-range matching possible, closing the accuracy gap flagged repeatedly in the code review.
- `cpe` — parses and compares CPE 2.2/2.3 strings.

### 2.7 Risk scoring and chain analysis

```bash
uv add networkx
```

- Used by the Chain Analyzer agent to build and validate attack-path graphs (per `01_…`'s design: the LLM proposes edges, code validates them against this graph).

### 2.8 AI agents

```bash
uv add anthropic tenacity
```

- `anthropic` — official SDK for calling Claude.
- `tenacity` — retry/backoff wrapper for agent and feed-sync calls.
- Add `langfuse` later if you want dedicated LLM tracing/evals beyond OpenTelemetry (§2.10).

### 2.9 Reports

```bash
uv add weasyprint python-docx matplotlib
```

- These were imported by the original code but **missing from its requirements file** — the exact bug that broke a clean install. Make sure they're declared this time.
- WeasyPrint also needs system libraries (Pango, Cairo, GDK-Pixbuf): `sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0` (or use the official WeasyPrint Docker base/instructions for your distro).

### 2.10 Observability

```bash
uv add structlog sentry-sdk "opentelemetry-sdk" "opentelemetry-instrumentation-fastapi"
```

### 2.11 CLI

```bash
uv add typer
```

- Replaces the old Flask-CLI `load-cves`/`load-cwes`/`load-exploits` commands with a Typer app (`backend/src/riskreveal/cli/commands.py`). Typer also makes it trivial to avoid the `dev` branch's duplicate-function bug, since each command is its own decorated function.

### 2.12 Dev/test dependencies

```bash
uv add --dev pytest pytest-asyncio pytest-cov hypothesis testcontainers ruff mypy pre-commit
```

- `hypothesis` — property-based testing, good for fuzzing the Nmap/Nuclei parsers and the version matcher.
- `testcontainers` — spins up real Postgres/Redis in CI for integration tests instead of mocking the database.
- `ruff` — lint + format in one tool.
- `mypy` — type checking (pairs with Pydantic's typed schemas).

### 2.13 All at once (if you'd rather paste one block)

```bash
cd backend
uv add fastapi "uvicorn[standard]" pydantic pydantic-settings python-multipart \
  "sqlalchemy>=2.0" alembic "psycopg[binary,pool]" redis \
  celery \
  pyjwt argon2-cffi cryptography slowapi \
  defusedxml httpx paramiko pywinrm \
  packaging univers cpe \
  networkx \
  anthropic tenacity \
  weasyprint python-docx matplotlib \
  structlog sentry-sdk opentelemetry-sdk opentelemetry-instrumentation-fastapi \
  typer

uv add --dev pytest pytest-asyncio pytest-cov hypothesis testcontainers ruff mypy pre-commit
```

---

## 3. Frontend — grouped by what each package is for

Run these from `frontend/` (after `pnpm create next-app` or equivalent has set up the base project).

### 3.1 Core (usually already present from `create-next-app`)

```bash
pnpm add next react react-dom
pnpm add -D typescript @types/react @types/react-dom @types/node
```

### 3.2 UI system

```bash
pnpm dlx shadcn@latest init
pnpm add lucide-react next-themes sonner geist class-variance-authority clsx tailwind-merge
```

- shadcn/ui components aren't one npm package — the CLI copies each component's source into `components/ui/` on demand (`pnpm dlx shadcn@latest add button table dialog ...`), pulling in the Radix UI primitive each one needs automatically. **Add components as you use them** — the review flagged ~40 of 50 previously-generated components as dead code.
- `geist` replaces `next/font/google`, so builds don't depend on internet access (closes a specific issue from the frontend review).

### 3.3 Data layer

```bash
pnpm add @tanstack/react-query @tanstack/react-table @tanstack/react-virtual
pnpm add openapi-fetch nuqs
pnpm add -D openapi-typescript
```

- `openapi-typescript` (dev) generates TypeScript types from your FastAPI app's OpenAPI document; `openapi-fetch` is the typed client that consumes them. Together they replace the hand-written, drift-prone `lib/api.ts`.
- `nuqs` — type-safe URL query-string state, so filters/sort/page are shareable links, not component state.

### 3.4 Forms

```bash
pnpm add react-hook-form zod @hookform/resolvers
```

### 3.5 Charts and graphs

```bash
pnpm add recharts
pnpm add @xyflow/react
```

- **Package-name note:** the attack-path graph library is published as **`@xyflow/react`**. The older `reactflow` package name was retired at v12 and should not be installed for new code.
- Add `echarts` + `echarts-for-react` later, only once dashboards get dense enough that Recharts feels limiting (per the stack discussion — don't front-load this).

### 3.6 Testing

```bash
pnpm add -D vitest @testing-library/react @testing-library/jest-dom @testing-library/user-event
pnpm add -D msw
pnpm add -D @playwright/test
pnpm add -D @axe-core/playwright
```

- `msw` mocks your API in component/unit tests.
- `@axe-core/playwright` runs accessibility checks inside your end-to-end tests — directly closes the "zero `aria-label`s, no WCAG testing" finding from the frontend review.

### 3.7 Lint, format, and dead-code detection

```bash
pnpm add -D eslint eslint-config-next
pnpm add -D @typescript-eslint/parser @typescript-eslint/eslint-plugin
pnpm add -D eslint-plugin-jsx-a11y
pnpm add -D prettier
pnpm add -D husky lint-staged
pnpm add -D knip
```

- `knip` finds unused files, exports, and dependencies — the tool that would have caught the duplicate CSS files and 40 unused shadcn components automatically.

### 3.8 Monitoring

```bash
pnpm add @sentry/nextjs
```

### 3.9 All at once

```bash
cd frontend
pnpm add next react react-dom \
  lucide-react next-themes sonner geist class-variance-authority clsx tailwind-merge \
  @tanstack/react-query @tanstack/react-table @tanstack/react-virtual \
  openapi-fetch nuqs \
  react-hook-form zod @hookform/resolvers \
  recharts @xyflow/react \
  @sentry/nextjs

pnpm add -D typescript @types/react @types/react-dom @types/node \
  openapi-typescript \
  vitest @testing-library/react @testing-library/jest-dom @testing-library/user-event \
  msw @playwright/test @axe-core/playwright \
  eslint eslint-config-next @typescript-eslint/parser @typescript-eslint/eslint-plugin eslint-plugin-jsx-a11y \
  prettier husky lint-staged knip
```

---

## 4. CI / supply-chain tooling (not installed into either project — used by GitHub Actions)

These don't go in `pyproject.toml` or `package.json`; reference them in `.github/workflows/ci.yml` instead.

| Tool | Purpose |
|---|---|
| `pip-audit` | Python dependency vulnerability scan — run via `uvx pip-audit` in CI, no need to add it as a project dependency |
| Dependabot or Renovate | Automated dependency-update PRs for both `pyproject.toml` and `package.json` |
| Semgrep | SAST — GitHub Action `returntocorp/semgrep-action` |
| CodeQL | GitHub's built-in SAST, enable under repo Security settings |
| cosign | Sign the images you publish |
| syft | Generate an SBOM (CycloneDX) for your own releases |

---

## 5. Explicitly NOT needed yet (Tier 2 / later phases)

Don't install these until you've actually hit the limit they solve — installing them now is the over-engineering trap the earlier stack discussion warned about.

| Tool | Wait for |
|---|---|
| Keycloak / Authentik (SSO/MFA identity provider) | Phase 8, once you have real multi-tenant customers asking for SSO |
| OpenFGA / Casbin (fine-grained authz) | Phase 8, once RBAC alone isn't enough |
| ClickHouse | Tier 2 scale — millions of finding rows, trend queries too slow on Postgres |
| Temporal | Only if Celery's chain/chord orchestration genuinely becomes hard to reason about (cancellation, long retries, human-approval steps) |
| Kubernetes / Helm / Argo CD | Once a single VM + Docker Compose genuinely can't keep up |
| Langfuse (dedicated LLM observability) | Once OpenTelemetry tracing on the agent pipeline isn't detailed enough |
| vLLM (self-hosted model serving) | Only if a customer requires it for data-residency reasons |
| PgBouncer | Once you're running enough API/worker replicas that Postgres connection count becomes a real problem |

---

## 6. Order of operations

1. Install everything in **§1** once, on your dev machine (or bake into Docker images per `infra/docker-compose.yml`).
2. `cd backend && uv init` (if not already done by the skeleton script), then run **§2.13**.
3. `cd frontend`, confirm `create-next-app` scaffolding, then run **§3.9**.
4. `uv lock` in `backend/`, `pnpm install` in `frontend/` — this generates the lockfiles the skeleton script deliberately left out.
5. `nuclei -update-templates` once, and set up a scheduled job to re-run it (template freshness matters for detection quality).
6. Wire the **§4** tools into `.github/workflows/ci.yml` before writing much application code, so every PR from here on is checked automatically.
