# RiskReveal - Architecture

## 1. Design Philosophy & Core Principles

RiskReveal v2 is a ground-up rebuild of the RiskReveal vulnerability management platform on **FastAPI**, **synchronous SQLAlchemy 2 (`psycopg` v3)**, **PostgreSQL 17**, **Redis 7**, and **Celery**. Every architectural decision traces back to lessons from a 25-point security and reliability audit of the v1 prototype (`01_Conversation_Summary.md` and `04_Dev_Branch_Review.md`):

1. **Orchestrate Proven Scanners, Never Write Exploit Engines**: RiskReveal orchestrates battle-tested security tools (**Nmap** today, **Nuclei** planned) and public threat-intelligence feeds (**CISA KEV**, **FIRST EPSS**, **NVD CVE API 2.0**). It contains zero custom SQLi/XSS attack payloads or WAF-evasion scripts.
2. **Confidence Hierarchy Over False Positives**: Every finding carries a confidence level (`inferred` $\rightarrow$ `detected` $\rightarrow$ `confirmed`).
   * An open port reported by Nmap is an `informational` finding with `confidence="detected"`.
   * Raw Nmap script output is attached as supporting `raw_evidence` on the port finding-never blindly promoted into standalone vulnerability claims.
   * Version-based CVE matches are always `confidence="inferred"`, and matches requiring specific OS platforms (`conditional`) or lacking version bounds (`all_versions`) are flagged with `needs_review=True`.
3. **Explicit Transaction Boundaries**: Database sessions (`get_db`) never auto-commit. Domain services (`domain/*/service.py`) own transaction boundaries and commit once at the end of a unit of work. On any error, the entire transaction rolls back so partial scan results or half-imported threat feeds can never persist.
4. **Fail-Closed Startup & Untrusted Data Boundaries**: Application startup fails immediately if `DATABASE_URL`, `JWT_SECRET_KEY`, or `FERNET_KEY` is missing or invalid. All scanner outputs and threat-intelligence feeds are treated as attacker-controlled data.

---

## 2. Repository & Package Layout

The backend uses Python's `src/` layout (`backend/src/riskreveal/`) managed by `uv`:

```text
backend/src/riskreveal/
├── main.py                     # FastAPI app factory, /healthz, CORS, 422/429/500 handlers
├── config.py                   # Fail-closed Pydantic Settings
├── dependencies.py             # get_CurrentUser Bearer token dependency
├── core/
│   ├── security.py             # Argon2id password hashing & PyJWT issue/decode
│   ├── rate_limit.py           # slowapi rate limiters (auth_limit, scan_limit)
│   └── pagination.py           # Bounded limit/offset Pagination dependency
├── db/
│   ├── base.py                 # DeclarativeBase with PostgreSQL constraint naming convention
│   ├── session.py              # Engine, SessionLocal, and get_db generator
│   └── migrations/             # Alembic environment and versioned migration scripts
├── domain/
│   ├── users/                  # User model, Argon2id/JWT auth service, repository, schemas
│   ├── assets/                 # Asset model, ON CONFLICT upsert repository, schemas
│   ├── scanning/               # Scan model, scope_policy, authorization allowlist, profiles, service
│   ├── findings/               # Finding model, enums, owner-scoped repository, schemas
│   ├── intelligence/           # KEV/EPSS models & importers, CPE/Version/NVD matcher core, distro/platform detectors
│   └── [organizations, audit, credentials, risk, agents, reports, remediation]  # Planned slices
├── engines/
│   ├── base.py                 # Frozen dataclasses (ParsedHost, ParsedPort, ScanResult) & engine errors
│   ├── nmap_engine.py          # Safe subprocess runner (shell=False) & defusedxml parser
│   └── normalizer.py           # Converts ScanResult into informational FindingDraft records
├── tasks/
│   ├── celery_app.py           # Celery configuration (JSON-only, acks_late, prefetch=1)
│   └── scan_tasks.py           # riskreveal.scan.run & riskreveal.scan.reap_stale tasks
├── api/v1/
│   ├── router.py               # Aggregates v1 routers
│   └── routes/                 # auth.py, scans.py, findings.py, assets.py
└── cli/
    ├── __main__.py             # Enables `python -m riskreveal.cli`
    └── commands.py             # Typer CLI: load-kev, load-epss, feed-status
```

> **Important Annotation Rule**: Domain, engine, and utility modules use `from __future__ import annotations`. **FastAPI route modules (`api/v1/routes/*.py`) and `core/pagination.py` deliberately omit `from __future__ import annotations`** so `slowapi` and FastAPI dependency injection can evaluate runtime type annotations directly.

---

## 3. Database Schema & Migrations

All tables inherit from `Base` (`db/base.py`), which enforces deterministic PostgreSQL naming conventions (`pk_`, `uq_`, `ix_`, `ck_`, `fk_`). Three Alembic migrations are currently in place:

### Migration 1: `1d2459ffc65b_create_users_table`
* **`users`**: `id` (UUID PK, generated in Python via `uuid.uuid4`), `email` (unique index `ix_users_email`), `hashed_password`, `full_name`, `is_active`, `created_at`, `updated_at`.

### Migration 2: `19317048b280_add_assets_scans_findings`
* **`assets`**: `id` (UUID PK), `owner_id` (FK $\rightarrow$ `users.id` ON DELETE CASCADE), `address` ($\le 45$ chars), `hostname`, `os_name`, `last_scanned_at`, `created_at`, `updated_at`. Unique constraint `uq_assets_owner_id_address` on `(owner_id, address)`.
* **`scans`**: `id` (UUID PK), `owner_id` (FK $\rightarrow$ `users.id` ON DELETE CASCADE), `target`, `profile`, `status` (`CHECK` constraint `ck_scans_status_valid`: `queued`, `running`, `completed`, `failed`, `cancelled`), `scanned_addresses` (JSONB audit log of exact IPs passed to Nmap), `started_at`, `finished_at`, `error`, `created_at`, `updated_at`.
* **`findings`**: `id` (UUID PK), `scan_id` (FK $\rightarrow$ `scans.id` ON DELETE CASCADE), `asset_id` (FK $\rightarrow$ `assets.id` ON DELETE CASCADE), `source`, `confidence`, `severity`, `status` (each protected by a PostgreSQL `CHECK` constraint), `title`, `description`, `port`, `protocol`, `service`, `product`, `version`, `cpe`, `raw_evidence`, `created_at`, `updated_at`.

### Migration 3: `9c4e7e871afa_add_threat_intel_tables`
* **`kev_entries`**: `cve_id` (PK, `CHECK` constraint enforcing `^CVE-[0-9]{4}-[0-9]{4,10}$`), `vendor_project`, `product`, `vulnerability_name`, `date_added`, `short_description`, `required_action`, `due_date`, `known_ransomware_campaign_use`, `notes`, `cwes` (JSONB), `created_at`, `updated_at`.
* **`epss_scores`**: `cve_id` (PK, ASCII CVE-ID `CHECK` constraint), `score` (`CHECK` $0 \le \text{score} \le 1$), `percentile` (`CHECK` $0 \le \text{percentile} \le 1$), `score_date`, `model_version`, `created_at`, `updated_at`.
* **`feed_syncs`**: `source` (PK: `"cisa_kev"`, `"first_epss"`), `last_success_at`, `version`, `record_count`, `created_at`, `updated_at`.

---

## 4. Scan Execution Lifecycle & State Machine

```text
           POST /api/v1/scans
                   │
                   ▼
               [ queued ] ──────(POST /cancel)──────▶ [ cancelled ]
                   │                                        ▲
     (Worker atomic claim_queued)                           │
                   ▼                                        │
              [ running ] ──────(POST /cancel)──────────────┘
               │       │
   (Success)   │       │ (Timeout / EngineError / ParseError)
               ▼       ▼
        [ completed ] [ failed ]
```

1. **Request Gate (`create_scan`)**:
   * Validates the target string with `validate_target` (5-second DNS timeout) and checks `check_authorized` against `SCAN_PUBLIC_ALLOWLIST`.
   * Locks the user's row in `users` (`SELECT ... FOR UPDATE`) and counts active (`queued` + `running`) scans to enforce `SCAN_MAX_ACTIVE_PER_USER` without race conditions.
   * Inserts the `queued` scan row, commits, and dispatches `riskreveal.scan.run` to Celery. If broker enqueueing fails, marks the scan `failed` and returns `503`.
2. **Worker Execution (`run_scan`)**:
   * **Step 1 (Atomic Claim)**: Executes `UPDATE scans SET status='running', started_at=NOW() WHERE id=:id AND status='queued' RETURNING id`. If 0 rows match (already claimed or cancelled), exits cleanly.
   * **Step 2 (Re-validation & Audit Trail)**: Re-runs `validate_target` and `check_authorized` with fresh DNS resolution, stores the exact pinned IPs (`ValidatedTarget.scan_args`) into `Scan.scanned_addresses`, and commits.
   * **Step 3 (Transaction-Free Subprocess)**: Runs the real Nmap binary (`nmap -oX - --no-stylesheet -n --open ...`) with **no database transaction held open**.
   * **Step 4 (Atomic Persistence)**: Opens a single transaction, conditionally updates `status='completed' WHERE id=:id AND status='running'` (discarding results if a user cancelled the scan while Nmap was running), upserts each `up` host into `assets`, inserts normalized `findings` (with NUL bytes stripped and strings clipped to column limits), and commits once.

---

## 5. Threat-Intelligence & Vulnerability-Matching Core

### 5.1 Feed Ingestion Pipeline (`domain/intelligence/`)
* **Fetch & Payload Guard (`sources/fetch.py`, `sources/payload.py`)**: Enforces `https://` URLs, caps redirects at 3 (blocking HTTPS $\rightarrow$ HTTP downgrades), enforces byte caps (20 MiB KEV, 64 MiB EPSS) and a 120s deadline, and protects memory during gzip decompression via `gunzip_limited`.
* **Parsers (`sources/cisa_kev.py`, `sources/first_epss.py`)**: Pure functions that skip malformed individual records while refusing the entire feed if invalid rows exceed strict thresholds (2% for KEV, 1% for EPSS) or if 0 valid rows exist.
* **Batched Atomic Upserts (`service.py`, `repository.py`)**: Commits once per feed import. EPSS streams in batches of 5,000 rows ($25,000$ bound parameters per statement) and uses `WHERE epss_scores.score_date <= excluded.score_date` so replaying an older EPSS file never overwrites newer scores.

### 5.2 CVE Matching Core (`cpe.py`, `versions.py`, `nvd.py`, `matcher.py`, `distro.py`, `host_platform.py`)
* **CPE Normalization (`cpe.py`)**: Unifies Nmap CPE 2.2 URIs (`cpe:/a:openbsd:openssh:6.6.1p1`) and NVD CPE 2.3 strings (`cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*`), joining split NVD `version` + `update` tokens and handling wildcard update comparisons.
* **Version Ordering (`versions.py`)**: Numerically compares version segments (`1.0 == 1.0.0`), ordering pre-releases before releases (`1.0rc1 < 1.0`) and patch suffixes after (`6.6.1 < 6.6.1p1 < 6.6.2`). Returns `None` on ambiguous strings so the matcher fails closed toward zero false alarms.
* **NVD API 2.0 Parser & Platform Filtering (`sources/nvd.py`, `records.py`, `matcher.py`, `host_platform.py`)**:
  * Extracts `CpeRange` rules from `vulnerable: true` matches while capturing required companion OS/platform CPEs from `AND` configuration blocks into `CpeRange.requires`.
  * Filters out platform-mismatched CVEs when host OS platform evidence is known (`host_platform.py`), and sets `CveMatch.needs_review = True` on `all_versions` or unresolved `conditional` matches so weak matches are never silently promoted to standard findings.
  * Detects Linux distribution packaging (`distro.py`, e.g., `Ubuntu 2ubuntu2.13`) where upstream version numbers may have backported security patches.

---

## 6. Roadmap & Next Architectural Slices

1. **CVE Database Persistence & Post-Scan Matching**: Store NVD CVE records and CPE ranges in PostgreSQL, run incremental syncs by `lastModified`, and automatically generate `confidence="inferred"`, `source="version_match"` findings enriched with `get_threat_signals()` (KEV + EPSS).
2. **Multi-Factor Risk Scorer (`domain/risk/`)**: Combine CVSS base score, EPSS exploitation probability, CISA KEV status, and asset context into a prioritized risk score.
3. **Per-User Target Ownership Verification**: Require users to prove control over public targets (via DNS TXT record or `.well-known` token) before scanning.
4. **Multi-Tenant Organizations & RBAC (`domain/organizations/`)**: Add organization tenancy and role-based access control.
5. **Five-Agent AI Pipeline (`domain/agents/`) & Next.js Frontend (`frontend/`)**: Layer the Verifier, Related-Findings, Chain-Analyzer, Evidence, and Mitigation agents alongside the Next.js/Tailwind dashboard.
