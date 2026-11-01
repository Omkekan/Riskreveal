# RiskReveal

RiskReveal is a vulnerability scanning and management platform being rebuilt
from scratch toward the kind of accuracy, prioritization, and remediation
guidance you'd expect from tools like Nessus, Rapid7 InsightVM, or Qualys
VMDR — with an AI agent pipeline (verification, related-finding discovery,
attack-chain analysis, evidence collection, and remediation) layered on top
as a differentiator rather than a replacement for careful detection
engineering.

> **Status: early, active rebuild. Not production-ready, not open for
> general use.** The backend has a working auth flow, a real Nmap-based scan
> pipeline, a threat-intelligence layer (CISA KEV, FIRST EPSS, NVD CVE
> matching), and an owner-scoped data model — but no frontend yet, no
> multi-tenant authorization in front of the API beyond the scan owner
> check, and no stable release. Expect breaking changes on `main`.

## ⚠️ Authorized scanning only

RiskReveal is a network and vulnerability scanner. **Only scan assets you
own or have explicit, documented authorization to scan.** The scanning
engine enforces a scope policy (target validation, private-range blocking by
default) as a technical safeguard, but that is not a substitute for actual
authorization. Scanning systems without permission may be illegal where you
are. See [`SECURITY.md`](SECURITY.md) for how this interacts with
vulnerability reporting.

## What's actually built so far

| Area | Status |
|---|---|
| Backend framework | FastAPI, PostgreSQL, SQLAlchemy 2.0, Alembic — fail-closed config (the app refuses to start with missing/weak secrets) |
| Auth | Argon2id password hashing, JWT access/refresh tokens with type-checked decode |
| Scanning | Nmap engine with a scope policy gate (target validation, argument-injection hardening, private-range blocking), result normalizer, Celery task pipeline |
| Threat intelligence | CISA KEV and FIRST EPSS feed ingestion; NVD CVE matching core (CPE parsing, version comparison, exact/range/all-versions matching with a `needs_review` flag for weak matches) |
| Frontend | Not started |
| AI agent pipeline | Not started |

See [`docs/`](docs/) for the full architecture and build plan, and the
project's handoff documents for the detailed history of what's been built,
tested, and verified so far.

## Quickstart (Windows-native, no WSL)

```powershell
# 1. Infrastructure (Docker Desktop must be running)
cd infra
copy .env.example .env
docker compose -p riskreveal-v2 up -d

# 2. Backend
cd ..\backend
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # -> JWT_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # -> FERNET_KEY
uv sync
uv run alembic upgrade head
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
```

Then check `http://127.0.0.1:8000/healthz` and `http://127.0.0.1:8000/docs`.

## Tech stack

**Backend:** Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, PostgreSQL,
Celery + Redis, Argon2id + PyJWT, Nmap (subprocess, `defusedxml` parsing).
**Dependency management:** `uv`. **Quality gates:** `ruff`, `mypy --strict`,
`pytest`. **Frontend (planned):** Next.js, TypeScript, Tailwind, shadcn/ui.

## Repository layout

```
riskreveal/
├── backend/        FastAPI app, domain modules, scanning/intelligence engines
├── frontend/        (not started)
├── infra/           docker-compose.yml for local Postgres + Redis
├── docs/             architecture notes, the rebuild plan, decision history
└── .github/          CI workflows, issue/PR templates
```

## Documentation

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow, the engineering gates every change must pass, Git/GitHub practices
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability, scope, responsible use
- [`CHANGELOG.md`](CHANGELOG.md) — what's shipped, in [Keep a Changelog](https://keepachangelog.com/) format
- [`docs/`](docs/) — architecture, the full rebuild/build-order plan, threat model

## License

MIT — see [`LICENSE`](LICENSE). **One caveat:** this project uses Nmap,
whose own license (NPSL) restricts bundling Nmap inside a proprietary
product you distribute (an OEM license is required for that). Running Nmap
on your own servers, as RiskReveal does, is unaffected — this only matters
if you ever ship a packaged RiskReveal image or installer. Not legal advice;
get a real license review before distributing anything that bundles Nmap.
