<div align="center">

# 🛡️ RiskReveal

**Next-Generation Vulnerability Scanning, Threat Intelligence & Risk Prioritization Platform**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PostgreSQL 17](https://img.shields.io/badge/PostgreSQL-17-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis 7](https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
[![Celery](https://img.shields.io/badge/Celery-37814A?style=for-the-badge&logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![Mypy Strict](https://img.shields.io/badge/mypy-strict-2A6DB2?style=for-the-badge)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/badge/ruff-checked-D7FF64?style=for-the-badge&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)

*Engineered for high-precision detection, real-world exploitability context (CISA KEV + FIRST EPSS + NVD), and strict scope safety.*

[Architecture](docs/architecture.md) · [API Reference](docs/api.md) · [Threat Model](docs/threat-model.md) · [Contributing](CONTRIBUTING.md) · [Security Policy](SECURITY.md)

</div>

---

> [!CAUTION]
> ### ⚠️ STRICTLY FOR AUTHORIZED USE ONLY — LIABILITY DISCLAIMER
> **RiskReveal is a defensive network and vulnerability assessment platform. Using this software to scan, probe, or assess any host, network, or system without explicit, prior written permission from the system owner is strictly prohibited and may violate local, national, and international laws.**
>
> **The repository owner (`@Omkekan`) assumes ZERO responsibility or liability for any misuse, unauthorized scanning, network disruption, data loss, or legal consequences resulting from the use of this software.** By cloning, running, or interacting with this repository, you agree to the terms in [`LICENSE`](LICENSE).

---

## ✨ Why RiskReveal?

RiskReveal is a clean-slate architectural rebuild designed toward the accuracy, evidence rigor, and risk prioritization of enterprise platforms like **Nessus**, **Rapid7 InsightVM**, and **Qualys VMDR**—built by orchestrating proven security engines (**Nmap**, **Nuclei**) and authoritative threat feeds rather than relying on noisy banner guesses.

* 🎯 **Accuracy Over Noise**: Every finding tracks an explicit confidence level (`inferred` $\rightarrow$ `detected` $\rightarrow$ `confirmed`). Open ports are recorded as `detected` observations; version-based CVE matches are marked `inferred` and gated for platform and distro backport review.
* 🔒 **Two-Layer Pre-Scan Safety Gate**: No target ever reaches Nmap without passing both the **Scope Policy** (blocking cloud metadata `169.254.169.254`, link-local, multicast, reserved ranges, shell metacharacters, and DNS rebinding) and the **Operator Allowlist**.
* 🧠 **Real Threat Intelligence Built In**: Native ingestion of **CISA Known Exploited Vulnerabilities (KEV)** and **FIRST EPSS** (~400,000 exploitation probability scores), paired with a conservative **NVD CVE API 2.0** range and platform matcher.
* 🛡️ **Untrusted Input Hardening**: All scanner banners, XML outputs (`defusedxml`), and external threat feeds are treated as hostile—enforcing HTTPS downgrade protection, bounded-memory gzip bomb guards, NUL-byte stripping, and column clipping.

---

## 🏗️ System Architecture at a Glance

```text
  [ Client / CLI ]
         │
         ▼  Bearer JWT (Argon2id + PyJWT, Rate-Limited)
┌─────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Application                             │
│  ┌──────────────────────┐   ┌───────────────────────┐   ┌────────────┐  │
│  │ 1. Target Scope Gate │──▶│ 2. Operator Allowlist │──▶│ Row-Locked │  │
│  │ (5s DNS + IP Pinning)│   │ (Public Target Gate)  │   │ Quota Cap  │  │
│  └──────────────────────┘   └───────────────────────┘   └─────┬──────┘  │
└───────────────────────────────────────────────────────────────┼─────────┘
                                                                │ Enqueue
                                                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   Celery Solo Worker + Redis Broker                     │
│  1. Atomic Claim (queued ──▶ running)                                   │
│  2. Re-validate Target & Record Audit Trail (scanned_addresses)         │
│  3. Run Real Nmap Binary (shell=False, defusedxml, no open DB tx)       │
│  4. Single-Transaction Upsert: Assets + Informational Findings          │
└───────────────────────────────────────────────────────────────┬─────────┘
                                                                │
                                                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             PostgreSQL 17 + Threat Intelligence & Matcher               │
│  • Core Tables: users, assets, scans, findings                          │
│  • Threat Feeds: kev_entries (CISA KEV), epss_scores (FIRST EPSS)       │
│  • Matching Core: CPE 2.2/2.3 + Version Ordering + Platform Filtering   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Build Status & Verified Metrics

| Component | Status | Verification Highlights |
| :--- | :---: | :--- |
| **Core App & Fail-Closed Config** | ✅ Built | Refuses startup without secrets; `FastAPI(debug=False)`; sanitized 422 responses |
| **Authentication (`Argon2id` + `PyJWT`)** | ✅ Built | Timing-oracle login protection; pinned JWT algorithms; token `type` isolation |
| **Scope Policy & Nmap Pipeline** | ✅ Built | 5s DNS timeout; DNS IP pinning; real Nmap verified against `scanme.nmap.org` |
| **Celery Worker & Scan API** | ✅ Built | Atomic state transitions; startup stale-scan reaper; owner-scoped pagination |
| **CISA KEV & FIRST EPSS Importers** | ✅ Built | **1,766 KEV entries** & **398,142 EPSS scores** imported live in single transactions |
| **NVD CVE Matcher Core** | ✅ Built | **121/121** Apache & **53/53** OpenSSH CVEs matched on live NVD data; `needs_review` gating |
| **Automated Test Suites** | ✅ Passing | **422+ Unit Tests**, **58 Testcontainers Integration Tests**, `mypy --strict` & `ruff` clean |
| **NVD DB Persistence & Risk Scorer** | 🚧 Next | Post-scan CVE persistence, multi-factor risk scoring, per-user target verification |
| **AI Agent Pipeline & Next.js UI** | 🗓️ Planned | 5-agent verification/remediation pipeline & Next.js/Tailwind dashboard |

---

## 🚀 Quickstart (Windows-Native PowerShell)

### 1. Start PostgreSQL 17 & Redis 7

Make sure **Docker Desktop** is running:

```powershell
Set-Location "infra"
Copy-Item .env.example .env
docker compose -p riskreveal up -d
docker compose -p riskreveal-v2 ps
```

### 2. Configure & Launch the Backend API

```powershell
Set-Location "..\backend"
Copy-Item .env.example .env

# Generate required secrets and paste them into backend\.env:
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('FERNET_KEY=' + Fernet.generate_key().decode())"

uv sync --extra dev
uv run alembic upgrade head
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
```

* **Health Check**: `http://127.0.0.1:8000/healthz`
* **Interactive OpenAPI Docs**: `http://127.0.0.1:8000/docs`

### 3. Start the Celery Scan Worker (Second Terminal)

```powershell
Set-Location "backend"
uv run celery -A riskreveal.tasks.celery_app:celery_app worker --pool=solo --loglevel=INFO
```

### 4. Sync Live Threat-Intelligence Feeds (CISA KEV & FIRST EPSS)

```powershell
Set-Location "backend"
uv run python -m riskreveal.cli load-kev
uv run python -m riskreveal.cli load-epss
uv run python -m riskreveal.cli feed-status
```

### 5. Run the Quality Gates

```powershell
Set-Location "backend"
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration
```

---

## 📂 Repository Structure

```text
riskreveal/
├── backend/
│   ├── scripts/                  # Live smoke tests & NVD matcher comparison tools
│   ├── src/riskreveal/
│   │   ├── api/v1/routes/        # Owner-scoped REST routes (auth, scans, findings, assets)
│   │   ├── cli/                  # Typer CLI (load-kev, load-epss, feed-status)
│   │   ├── core/                 # Argon2id/JWT security, rate limiting, pagination
│   │   ├── db/                   # SQLAlchemy 2 session management & Alembic migrations
│   │   ├── domain/               # Modular domain slices (users, assets, scanning, findings, intelligence)
│   │   ├── engines/              # Hardened Nmap runner, defusedxml parser, finding normalizer
│   │   └── tasks/                # Celery app & scan execution/reaper tasks
│   └── tests/                    # 420+ unit tests & 58 Testcontainers integration tests
├── docs/                         # Architecture, API reference, Threat Model, & GitHub guide
├── frontend/                     # Next.js App Router scaffold (planned after backend milestone)
└── infra/                        # Docker Compose for PostgreSQL 17 (port 5433) & Redis 7 (port 6380)
```

---

## 📚 Documentation

* 🏛️ **[Architecture Guide (`docs/architecture.md`)](docs/architecture.md)** — Domain layout, database schema, scan state machine, and intelligence pipeline.
* 🔌 **[API Reference (`docs/api.md`)](docs/api.md)** — Full REST endpoint documentation, request/response schemas, status codes, and CLI reference.
* 🛡️ **[Threat Model (`docs/threat-model.md`)](docs/threat-model.md)** — Trust boundaries, STRIDE mitigations, scope policy rules, and residual risks.
* 🧭 **[GitHub Workflow Guide (`docs/github-guide.md`)](docs/github-guide.md)** — How Issues, Pull Requests, Agents, Actions, Projects, Wiki, Security, and Insights are organized.
* 🤝 **[Contributing Policy (`CONTRIBUTING.md`)](CONTRIBUTING.md)** — **Owner permission requirement**, quality gates, and development workflow.
* 🔐 **[Security Policy (`SECURITY.md`)](SECURITY.md)** — Responsible vulnerability disclosure and authorized scanning rules.

---

## 🤝 Contributing (Owner Permission Required)

RiskReveal is an actively architected security platform maintained by **`@Omkekan`**.
**Prior written permission from the repository owner is strictly required before submitting any code or pull request.** Unsolicited pull requests will be closed without review. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for instructions on how to request permission and the quality gates every approved change must pass.

---

## 📜 License & Legal Notice

This project is licensed under the **MIT License with Strict Authorized-Use Conditions and Liability Disclaimers** — see [`LICENSE`](LICENSE) for full details.

* **No Unauthorized Use**: You may only scan systems you own or have explicit written authorization to test.
* **No Liability**: The author and owner (`@Omkekan`) shall not be held liable for any claims, damages, illegal use, or consequences of any kind arising from the use or misuse of this software.
* **Third-Party Tools**: RiskReveal invokes an external installation of [Nmap](https://nmap.org/) (licensed under the NPSL). Review Nmap's OEM licensing terms before distributing any packaged binary or container image that bundles Nmap.
