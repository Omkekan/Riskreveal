# RiskReveal – Rebuild Structure & File Plan

*Companion to `01_Conversation_Summary.md`, `02_RiskReveal_Master_Plan.md`, `03_Frontend_and_Full_Review.md`, and `04_Dev_Branch_Review.md`. This file answers one question: starting the rebuild, what is the target repository layout, and for every file that exists today in `main` or `dev`, do we keep it, rewrite it, or delete it — and what brand-new files need to be created.*

---

## 0. Starting decisions

These decisions shape everything below. They follow directly from the four prior review documents.

1. **Base the rebuild on `main`, not `dev`.** `04_…` §7 already concluded this: `dev` adds a live SQL-injection/XSS attack engine with WAF evasion (D-01), a regressed wildcard CORS policy (D-03), and the same leaked Fernet key (D-02), unchanged. Three `dev` modules are worth carrying forward deliberately (the risk scorer, the authenticated SSH/WinRM collector, and the widget-dashboard concept) — each is called out individually below with the specific fix it needs first.
2. **Move the backend from Flask to FastAPI now, not later.** `03_…` §7 originally said to defer this until Phase 5–8, because the urgent task at the time was stabilizing the running Flask app. That reasoning doesn't apply to a from-scratch rebuild: there is no running app to destabilize, and `02_…`'s target architecture, the Pydantic-based agent contracts, and the OpenAPI-generated frontend client all fit FastAPI directly. Rewriting routes once, into their final shape, is cheaper than rewriting them twice.
3. **Rename folders, drop spaces.** `Backend Riskreveal app` → `backend/`, `Frontend Riskreveal app` → `frontend/` (`03_…` R-05).
4. **Start a fresh Alembic baseline.** `dev`'s four committed migrations (`03_…` R-08 is fixed there) are good practice but describe the *old* schema. Because the data model changes substantially (persistent assets, new `Finding` fields, agent tables, organizations), carrying them forward and layering more revisions on top would encode the old structure permanently into history. Generate one clean baseline migration from the new models instead, and treat anything already deployed as a separate, manual migration project if that day comes.
5. **One repository, two deployable apps**, `backend/` and `frontend/`, plus shared `infra/` and `docs/`. Not a monorepo tool (Nx/Turborepo) yet — add one only if build times become a real problem.

---

## 1. Target repository layout

```
riskreveal/
├── backend/
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── alembic.ini
│   ├── Dockerfile                      # API image
│   ├── Dockerfile.worker               # Celery worker image(s)
│   ├── Dockerfile.scanner              # isolated Nmap/Nuclei engine image
│   ├── .env.example
│   ├── src/riskreveal/
│   │   ├── main.py                     # FastAPI app factory
│   │   ├── config.py                   # pydantic-settings, fails closed on missing secrets
│   │   ├── dependencies.py             # DB session, current_user, current_org DI
│   │   ├── logging.py                  # structlog setup
│   │   │
│   │   ├── core/
│   │   │   ├── security.py             # Argon2id hashing, JWT issue/verify
│   │   │   ├── exceptions.py           # RFC 9457 Problem Details handlers
│   │   │   ├── pagination.py
│   │   │   └── rate_limit.py
│   │   │
│   │   ├── db/
│   │   │   ├── base.py                 # declarative base, naming convention
│   │   │   ├── session.py
│   │   │   └── migrations/versions/
│   │   │
│   │   ├── domain/                     # business logic, one package per bounded context
│   │   │   ├── users/            {models.py, schemas.py, service.py, repository.py}
│   │   │   ├── organizations/    {models.py, schemas.py, service.py, repository.py, rbac.py}
│   │   │   ├── audit/            {models.py, service.py}
│   │   │   ├── credentials/      {models.py, schemas.py, service.py, vault.py}
│   │   │   ├── assets/           {models.py, schemas.py, service.py, repository.py, identity_resolution.py}
│   │   │   ├── scanning/         {models.py, schemas.py, service.py, scope_policy.py, profiles.py}
│   │   │   ├── findings/         {models.py, schemas.py, service.py, lifecycle.py, dedupe.py}
│   │   │   ├── intelligence/
│   │   │   │   ├── models.py             # CVE, CWE, CAPEC, KEV, EPSS, Exploit, Advisory
│   │   │   │   ├── matcher.py            # CPE + version-range matching
│   │   │   │   ├── sources/
│   │   │   │   │   ├── cvelistv5.py
│   │   │   │   │   ├── nvd.py                  # secondary source only (see §4)
│   │   │   │   │   ├── cisa_kev.py
│   │   │   │   │   ├── first_epss.py
│   │   │   │   │   ├── exploitdb.py
│   │   │   │   │   ├── osv.py
│   │   │   │   │   └── distro/{ubuntu.py, debian.py, redhat.py, msrc.py}
│   │   │   │   └── sync_tasks.py
│   │   │   ├── risk/             {scorer.py, schemas.py}
│   │   │   ├── agents/
│   │   │   │   ├── base.py               # Agent base class, tool whitelist, token/time budget
│   │   │   │   ├── schemas.py            # Pydantic I/O contracts (Appendix C of `02_…`)
│   │   │   │   ├── verifier.py
│   │   │   │   ├── related_findings.py
│   │   │   │   ├── chain_analyzer.py
│   │   │   │   ├── evidence.py
│   │   │   │   ├── mitigation.py
│   │   │   │   └── pipeline.py           # Celery chain/chord wiring
│   │   │   ├── reports/
│   │   │   │   ├── service.py            # own status/lifecycle, not Scan.status
│   │   │   │   ├── renderers/{pdf.py, docx.py, json_.py}
│   │   │   │   └── templates/
│   │   │   └── remediation/      {models.py, schemas.py, service.py}
│   │   │
│   │   ├── engines/                    # deterministic tool adapters — agents never call these directly
│   │   │   ├── base.py                 # Engine protocol (run, parse, normalize)
│   │   │   ├── discovery_engine.py     # naabu-based fast port sweep
│   │   │   ├── nmap_engine.py          # full XML parse incl. hostscript, -O, CPE
│   │   │   ├── nuclei_engine.py        # own severity/description, template filters
│   │   │   ├── script_classifier.py    # vuln-vs-informational allow-list
│   │   │   ├── normalizer.py           # RawFinding -> canonical Finding, dedupe
│   │   │   └── auth_collectors/
│   │   │       ├── ssh_collector.py    # dpkg/rpm/apk inventory
│   │   │       └── winrm_collector.py  # KB/hotfix/software inventory
│   │   │
│   │   ├── api/v1/
│   │   │   ├── router.py
│   │   │   └── routes/
│   │   │       ├── auth.py  users.py  organizations.py
│   │   │       ├── assets.py  credentials.py
│   │   │       ├── scans.py  findings.py  reports.py
│   │   │       ├── remediation.py  agents.py
│   │   │       ├── dashboard.py  widgets.py
│   │   │       └── admin_feeds.py      # feed health, manual sync trigger
│   │   │
│   │   ├── tasks/
│   │   │   ├── celery_app.py           # separate queues: scan/agents/reports/feeds
│   │   │   ├── scan_tasks.py
│   │   │   ├── agent_tasks.py
│   │   │   ├── report_tasks.py
│   │   │   ├── feed_tasks.py
│   │   │   └── beat_schedule.py
│   │   │
│   │   └── cli/
│   │       ├── __init__.py
│   │       └── commands.py             # typer: load-cves, load-kev, load-epss, load-cwes, load-exploits, load-osv, seed-widgets
│   │
│   ├── tests/
│   │   ├── unit/                       # parsers, matcher, scorer, dedupe — pure functions
│   │   ├── integration/                # DB + Celery via testcontainers
│   │   ├── fixtures/                   # recorded Nmap XML / Nuclei JSON (no live scanning in CI)
│   │   └── e2e/                        # full pipeline against the benchmark lab
│   │
│   └── scripts/
│       └── seed_dev_data.py            # replaces mega_seed.py / seed.py / seed_widgets.py / update_db*.py
│
├── frontend/
│   ├── package.json  pnpm-lock.yaml  next.config.mjs  tsconfig.json  components.json
│   ├── Dockerfile
│   ├── .env.example
│   ├── middleware.ts                   # auth redirect + CSP nonce
│   ├── app/
│   │   ├── (auth)/{login,register}/page.tsx
│   │   ├── (app)/
│   │   │   ├── layout.tsx              # sidebar, header, session guard
│   │   │   ├── dashboard/page.tsx
│   │   │   ├── scans/
│   │   │   │   ├── page.tsx  new/page.tsx
│   │   │   │   └── [id]/{page.tsx, findings/[findingId]/page.tsx}
│   │   │   ├── assets/{page.tsx, [id]/page.tsx}
│   │   │   ├── credentials/page.tsx
│   │   │   ├── remediation/page.tsx
│   │   │   └── settings/{profile,security,api-keys,organization}/page.tsx
│   │   ├── api/[...path]/route.ts      # BFF proxy: HttpOnly cookie -> bearer token
│   │   ├── error.tsx  global-error.tsx  not-found.tsx  loading.tsx
│   │   └── layout.tsx                  # root shell, fonts, metadata
│   ├── features/
│   │   ├── auth/  scans/  findings/  assets/  credentials/
│   │   ├── reports/  remediation/  dashboard-widgets/  attack-paths/
│   │   └── (each: components/, hooks/, schemas.ts)
│   ├── components/
│   │   ├── ui/                         # shadcn — only components actually imported
│   │   └── common/                     # SeverityBadge, DataTable, EmptyState, ConfirmDialog
│   ├── lib/
│   │   ├── api/                        # openapi-fetch client generated from backend OpenAPI
│   │   ├── format.ts  env.ts
│   └── tests/{unit,e2e}/
│
├── infra/
│   ├── docker-compose.yml              # full local stack: api, worker(s), beat, redis, postgres, minio, frontend, proxy
│   ├── docker-compose.override.yml.example
│   └── k8s/ (added later, Phase 8)
│
├── docs/
│   ├── architecture.md                 # the diagram from `02_…` §3, kept current
│   ├── api.md                          # points at the generated OpenAPI doc
│   ├── threat-model.md
│   └── archive/SecureLens_Project_Spec.md   # moved out of the repo root, R-03
│
├── .github/workflows/{ci.yml, images.yml}
├── SECURITY.md  CONTRIBUTING.md  CODEOWNERS  CHANGELOG.md
├── LICENSE
└── README.md
```

---

## 2. Legend for the file tables

| Verdict | Meaning |
|---|---|
| ✅ **REUSE** | Copy forward with only path/import changes. Logic is sound. |
| 🔧 **REUSE, FIX** | Same approach, but a specific named bug must be fixed as part of the move. |
| ♻️ **REWRITE** | The old file is a useful reference for *what* it should do, but the implementation is replaced. |
| 🆕 **NEW** | Does not exist in either branch today. |
| 🗑️ **DELETE** | Do not carry forward. |

Every row cites the finding IDs from the prior review docs (`01_…` #n, `03_…` F-n/C-n/R-n, `04_…` D-n) so the reasoning is traceable.

---

## 3. Backend — file by file

### 3.1 App bootstrap and config

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/__init__.py` (main & dev) | `src/riskreveal/main.py` | ♻️ REWRITE | Flask app factory → FastAPI app factory; blueprint registration → router includes |
| `riskreveal/config.py` (main & dev) | `src/riskreveal/config.py` | ♻️ REWRITE | Must fail startup on missing `JWT_SECRET_KEY`/`FERNET_KEY`/`DATABASE_URL` instead of silently defaulting (`01_…` #1, still present unchanged in `04_…` D-02); move to `pydantic-settings` |
| `riskreveal/extensions.py` (main) | `src/riskreveal/dependencies.py`, `db/session.py` | ♻️ REWRITE | Flask extension objects → FastAPI dependency-injected session/providers |
| `run.py`, `wsgi.py`, `gunicorn_start.py` | `src/riskreveal/main.py` + Dockerfile `CMD` | ♻️ REWRITE | Replace gevent Gunicorn with plain Uvicorn/Gunicorn workers (per the stack note: drop gevent from the API) |
| `celery_worker.py` | `tasks/celery_app.py` | 🔧 REUSE, FIX | Stop printing the DB URI (`01_…` #24); split into per-queue workers |
| `clear_queue.py` | `scripts/` (dev-only utility) | ✅ REUSE | Harmless ops helper |
| — | `.env.example` (both apps) | 🆕 NEW | Never existed (`03_…` R-10) |
| — | `src/riskreveal/logging.py` | 🆕 NEW | Structured, request/task-ID-tagged JSON logs |
| — | `core/rate_limit.py` | 🆕 NEW | Auth-route and API rate limiting (`01_…` #25) |

### 3.2 Models and database

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/models.py` (main & dev) | Split across `domain/*/models.py` | ♻️ REWRITE | One monolithic file → one module per bounded context; add the new `Finding` fields (`port`, `protocol`, `service_id`, `cpe`, `source`, `confidence`, `status`, `raw_evidence`, `first_seen`, `last_seen` — `01_…` §5.3); add `Asset`, `Service`, `Evidence`, `AttackPath`, `AgentRun`, `Organization`, `Membership`, `AuditLog` (none exist today) |
| `migrations/env.py`, `alembic.ini` (dev) | `db/migrations/env.py`, `alembic.ini` | ✅ REUSE | Alembic plumbing is fine as-is |
| `migrations/versions/*.py` (dev, 4 revisions) | — | 🗑️ DELETE, regenerate | Decision #4 above: schema changes too much to extend these; generate one new baseline from the rewritten models |

### 3.3 Auth, users, organizations, audit

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/auth/routes.py` (main) | `api/v1/routes/auth.py`, `core/security.py` | ♻️ REWRITE | Add refresh-token rotation, revocation, Argon2id (`03_…` F-04, F-37); one error shape (`03_…` C-01); route-level `get_jwt_identity()` vs `get_jwt()['user_id']` inconsistency becomes one `current_user()` dependency (`03_…` C-09) |
| `riskreveal/user/routes.py` (main) | `api/v1/routes/users.py` | 🔧 REUSE, FIX | Return `{id, role, org, permissions[], mfa_enabled}`, not just `{username, email}` (`03_…` C-04) |
| — | `domain/organizations/*` | 🆕 NEW | Multi-tenancy, RBAC (`03_…` §5, `02_…` Phase 8) |
| — | `domain/audit/*` | 🆕 NEW | Login, scan start, credential use, export, setting-change events (`03_…` §5, R-13) |

### 3.4 Credentials

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/credentials/routes.py` (main) | `api/v1/routes/credentials.py`, `domain/credentials/*` | ♻️ REWRITE | Fix the IDOR (`credential_id` never checked against owner — `01_…` #3); add credential *types* beyond username/password (`03_…` F-24); add "test connection" |
| — | `domain/credentials/vault.py` | 🆕 NEW | Envelope encryption (KMS/Vault-backed, not a single static Fernet key) |

### 3.5 Assets

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/assets/routes.py` (main) | `api/v1/routes/assets.py`, `domain/assets/*` | ♻️ REWRITE | Assets go from per-scan rows to a persistent inventory with identity resolution (`01_…` #22, `02_…` §4.1, `03_…` §5) |
| — | `domain/assets/identity_resolution.py` | 🆕 NEW | Match by MAC/hostname/cloud-instance-ID/IP history across scans |

### 3.6 Scanning engines

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/scans/tasks.py` — Nmap invocation + XML parse (main) | `engines/nmap_engine.py` | ♻️ REWRITE | Parse per-host `address`/`os`/`cpe`, parse `hostscript` (currently dropped — `01_…` #9), add `-O`/`-Pn`/`--host-timeout` (`01_…` #14), attribute findings by IP not just port (`01_…` #8) |
| `riskreveal/scans/tasks.py` — Nuclei invocation (main) | `engines/nuclei_engine.py` | ♻️ REWRITE | Use Nuclei's own severity/description/remediation (`01_…` #11), scan discovered web ports not just 80/443 |
| `riskreveal/scanner.py` — `WebScanner`, `WAFEvasionToolkit` (dev) | — | 🗑️ DELETE | Live SQLi/XSS payload firing + WAF evasion against the target — stop-ship per `04_…` D-01. Do not port any part of this. |
| `riskreveal/scanner.py` — crawling/form-discovery logic (dev), *if* the HTML survives review | `engines/` (a future, detection-only DAST module) | 🔧 REUSE, FIX, deferred | Only the non-destructive crawling, if any, and only after a full separate review. Payload lists and evasion code are excluded unconditionally. |
| — | `engines/discovery_engine.py` | 🆕 NEW | Fast port sweep (naabu) before `-sV`, per `02_…` §5 |
| — | `engines/script_classifier.py` | 🆕 NEW | Vulnerability-script allow-list vs informational scripts (`01_…` #7) |
| — | `engines/normalizer.py` | 🆕 NEW | Canonical `RawFinding` → `Finding`, with the `(asset, port, proto, vuln_id)` dedupe key (`01_…` #16) |
| `riskreveal/engine/auth_scanner.py` (dev) — `AuthenticatedScanner` | `engines/auth_collectors/ssh_collector.py`, `winrm_collector.py` | 🔧 REUSE, FIX | Real SSH/WinRM package-inventory collection is the right approach and mostly what `01_…` #14 asked for — but `set_missing_host_key_policy(AutoAddPolicy())` and `server_cert_validation='ignore'` must be replaced with real host-key/cert verification before reuse (`04_…` D-04) |

### 3.7 Intelligence (CVE/CWE/KEV/EPSS/advisories)

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/cli.py` — `load-cves` (main) | `domain/intelligence/sources/cvelistv5.py` | ♻️ REWRITE | Read CVSS from `adp` containers too, not just `cna` (`01_…` #12); one bad file must not roll back up to 999 uncommitted records (`01_…` #23) |
| `riskreveal/cli.py` — `load-cwes`, `load-exploits` (main) | `cli/commands.py` (CWE loader), `domain/intelligence/sources/exploitdb.py` | 🔧 REUSE, FIX | Exploit-DB matching should use the CSV `codes` column and many-to-many CVE links instead of reading the first 2 KB of each file (`01_…` #23) |
| `riskreveal/cli.py` (dev) — duplicate `register_cli_commands` | `cli/commands.py` | ♻️ REWRITE | The second definition silently shadows the first, so `load-cves` doesn't exist at runtime today (`04_…` D-08) — merge into one function under Typer, with a test asserting every expected command is registered |
| `riskreveal/engine/nvd_sync.py` **and** `riskreveal/engine/cve_sync.py` (dev — two competing, unwired implementations) | `domain/intelligence/sources/nvd.py` | ♻️ REWRITE, pick one | Merge into a single NVD sync, demoted to a **secondary** source — per this session's research, NIST now enriches only ~15–20% of new CVEs (KEV-listed and federally-critical software), so an NVD-only pipeline (`04_…` D-22) is no longer sufficient on its own |
| `riskreveal/engine/cpe_analyzer.py` (dev) — `get_exact_cve_matches` | `domain/intelligence/matcher.py` | ♻️ REWRITE | Current approach is a free-text `ILIKE` substring search despite being named/documented as exact CPE matching (`04_…` D-21) — replace with real CPE parsing and version-range comparison (`packaging`/`univers`) |
| — | `domain/intelligence/sources/cisa_kev.py` | 🆕 NEW | Daily KEV sync (`02_…` Phase 2) |
| — | `domain/intelligence/sources/first_epss.py` | 🆕 NEW | Daily EPSS sync |
| — | `domain/intelligence/sources/osv.py` | 🆕 NEW | Language-package vulnerabilities, independent of NVD |
| — | `domain/intelligence/sources/distro/{ubuntu,debian,redhat,msrc}.py` | 🆕 NEW | Needed for authenticated-scan accuracy (`02_…` Phase 3) and because NVD CPE coverage is shrinking |
| `riskreveal/Plugins/base.py`, `riskreveal/engine/__init__.py` (dev, empty stubs) | — | 🗑️ DELETE | Empty placeholders with no content (`04_…` D-23); reintroduce as a real extension point only when a concrete plugin need exists |

### 3.8 Risk scoring

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/engine/scorer.py` — `RiskPrioritizationEngine` (dev) | `domain/risk/scorer.py` | 🔧 REUSE, FIX | `04_…` §5 calls this a clean, testable first version of the Phase-4 risk score. Extend it with EPSS and KEV inputs (it currently covers CVSS + exploit availability + asset criticality but not threat-intel signals — `02_…` Phase 4 formula) |

### 3.9 AI agents

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| — (design only, never implemented) | `domain/agents/{base,verifier,related_findings,chain_analyzer,evidence,mitigation,pipeline,schemas}.py` | 🆕 NEW | Build per the five-agent design in `01_…` §3 and `02_…` Phase 5: deterministic tools only, Pydantic-validated I/O, fixed Celery chain/chord orchestration |

### 3.10 Reports

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/scans/tasks.py` — `generate_json_report` (dev) | `domain/reports/renderers/json_.py` | ✅ REUSE | `04_…` §5 confirms this streams valid JSON (fixes `01_…` #20) — the one thing `dev` got right in reporting |
| `riskreveal/scans/tasks.py` — PDF/DOCX generation (main; **absent** from dev despite routes still referencing it) | `domain/reports/renderers/pdf.py`, `docx.py` | ♻️ REWRITE | Must be restored (`04_…` D-11: currently an unhandled 500) and fixed: Jinja autoescape on, WeasyPrint URL fetcher restricted to `data:` URIs, filenames by report ID not `target_name` (`01_…` #5) |
| `riskreveal/scans/routes.py` — `generate_report`/download (main) | `api/v1/routes/reports.py`, `domain/reports/service.py` | ♻️ REWRITE | Separate `report_status` from `Scan.status` (`01_…` #19, `03_…` F-10, C-10); reports become their own addressable resource with retry |

### 3.11 Remediation

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `RemediationTicket` model, `auto_generate_tickets` (dev — model/logic exist) | `domain/remediation/{models.py, service.py}` | 🔧 REUSE, FIX | The model and generation logic are usable; join in `finding_name`/`asset_ip` so the API response doesn't require the frontend to do its own join (`04_…` D-05) |
| — (no route exists in either branch) | `api/v1/routes/remediation.py` | 🆕 NEW | `04_…` D-05: the frontend `/remediation` page currently calls an endpoint that was never built — build the route before the page ships, not after |

### 3.12 Dashboard widgets

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `riskreveal/widgets/routes.py` (dev) | `api/v1/routes/widgets.py` | ♻️ REWRITE | Fix the lowercase/`"critical"` vs stored `"Critical"` mismatch that zeroes the critical-count widget (`04_…` D-18); fix the duplicated unreachable `except` that swallows every error into an empty `200` (`04_…` D-19); add the missing `@jwt_required()` on `get_templates` (`04_…` D-20); relabel `PredictiveRiskWidget`'s two-point moving average honestly rather than presenting it as ML, unless real ML is built (`04_…` D-15) |
| `cli.py` — `seed-widgets` (dev) | `cli/commands.py` | 🔧 REUSE, FIX | Keep, but only seed widgets whose component is actually implemented in `WidgetContainer` (`04_…` D-12) |

### 3.13 Repo-root cleanup

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `mega_seed.py`, `seed.py`, `seed_widgets.py`, `update_db.py`, `update_db1.py` (dev) | `scripts/seed_dev_data.py` | ♻️ REWRITE, consolidate | Five overlapping one-off scripts → one documented dev-seed script (`04_…` D-24) |
| `Requirement.txt`, `pyproject.toml` (both, inconsistent/incomplete) | `pyproject.toml` + `uv.lock` | ♻️ REWRITE | One dependency source; must include every package actually imported — `cryptography`, `pandas`, `weasyprint`, `matplotlib` were missing in `main` (`01_…` #6); `aiohttp`, `beautifulsoup4`, `playwright`, `paramiko`, `pywinrm` etc. were missing in `dev` (`04_…` D-29) |
| `instance/reports/*.pdf/.docx/.json` (both — committed sample reports) | — | 🗑️ DELETE from git history | Contains target/IP/finding data (`03_…` R-01); add `instance/` to `.gitignore` |
| `riskreveal.egg-info/` (both) | — | 🗑️ DELETE | Build artifact (`03_…` R-02) |
| `.vs/` (dev only, ~72 MB) | — | 🗑️ DELETE | Local IDE state, never belongs in git (`04_…` D-26) |
| `SecureLens_Project_Spec.md` (main, repo root) | `docs/archive/SecureLens_Project_Spec.md` | ♻️ MOVE | Describes a different, contradictory product spec; keep for history but out of the active root (`03_…` R-03) |
| `nuclei/` (empty dir, both) | — | 🆕 decide | Either commit real custom templates here or delete the placeholder (`03_…` R-04) |
| Dockerfiles (both) | `Dockerfile`, `Dockerfile.worker`, `Dockerfile.scanner` | ♻️ REWRITE | Install Nmap and WeasyPrint system libs (missing in both), fix `"$PORT"` expansion, non-root user, healthchecks (`01_…` #24) |
| — | `infra/docker-compose.yml` | 🆕 NEW | Nothing currently runs the full stack in one command (`03_…` R-09) |

---

## 4. Frontend — file by file

### 4.1 Delete outright

| Old file(s) | Why |
|---|---|
| `public/App.js`, `public/index.js`, `public/pages/*.js`, `public/context/AuthContext.js`, associated CSS | Dead Create-React-App code that imports modules that don't exist, and because it lives in `public/` it is served to the internet as-is (`03_…` F-26) |
| `styles/globals.css` | Byte-different duplicate of `app/globals.css` (`03_…` F-27) |
| `components/ui/use-mobile.tsx`, `components/ui/use-toast.ts` | Duplicates of `hooks/use-mobile.tsx`, `hooks/use-toast.ts` (`03_…` F-27) |
| `components/ScanConsole.tsx` (dev) | Calls a route that doesn't exist and is imported nowhere (`04_…` D-07) — delete; rebuild properly against a real SSE endpoint (see §4.4) |
| ~40 of 50 `components/ui/*` shadcn files that are never imported | Dead weight and attack surface; re-add individually when a feature actually needs them (`03_…` F-27) |

### 4.2 Core app shell and routing

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `app/page.tsx` (main, 462 lines / dev, 56 KB — one giant client component with `useState` "views") | Split across `app/(auth)/*`, `app/(app)/*` per §1's tree | ♻️ REWRITE | No real routes today: no deep links, no working Back button, refresh drops you to the dashboard (`03_…` F-07); 462–560 lines mixing six feature areas in one file (`03_…` F-08); the entire app is one `"use client"` component with no server rendering (`03_…` F-09) |
| `app/dashboard/page.tsx` + `hooks/useDashboard.ts` (dev) | `app/(app)/dashboard/page.tsx` | 🔧 REUSE, FIX | `04_…` §5/§7 picks this as the implementation to keep over the page.tsx-inline version, but its `/widgets/...` calls (no `/api` prefix) must be reconciled with the blueprint's actual `/api/widgets` mount (`04_…` D-09) |
| `app/remediation/page.tsx` (dev) | `app/(app)/remediation/page.tsx` | 🔧 REUSE, FIX | Currently calls a backend route that doesn't exist (`04_…` D-05) — hold this page behind the new `api/v1/routes/remediation.py` (§3.11), and fix the `ticket.finding_name`/`ticket.asset_ip` field assumptions to match the actual (joined) API response |
| `app/layout.tsx` | `app/layout.tsx` | 🔧 REUSE, FIX | Replace `next/font/google` with `geist` (already installed, unused) so builds don't need internet access (`03_…` F-29) |
| `app/loading.tsx` | `app/loading.tsx` + per-route `loading.tsx` | 🔧 REUSE, FIX | Currently returns `null`; give it a real skeleton (`03_…` F-17) |
| — | `app/error.tsx`, `app/global-error.tsx`, `app/not-found.tsx` | 🆕 NEW | None exist today (`03_…` F-17) |
| — | `middleware.ts` | 🆕 NEW | Auth-redirect guard + CSP nonce (`03_…` F-03, F-30) |
| — | `app/api/[...path]/route.ts` | 🆕 NEW | BFF proxy: browser holds only an HttpOnly cookie, this route attaches the bearer token server-side (`03_…` F-03) |

### 4.3 Data layer

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `lib/api.ts` | `lib/api/` (generated client) + thin wrapper | ♻️ REWRITE | Hand-written `axios` calls with ad-hoc, drifting TS interfaces → `openapi-fetch` client generated from the backend's OpenAPI document (`03_…` C-03); also fixes the inconsistent `/api`-prefix bug that breaks Settings and half of the dev widget calls (`04_…` D-09) |
| (manual `useEffect` + `useState` polling throughout `page.tsx`) | `features/*/hooks/use*.ts` | ♻️ REWRITE | Replace with TanStack Query (`refetchInterval`, retries, caching) — fixes the probable infinite request loop from `user` being a fresh object every render (`03_…` F-02) and the one-shared-`loading`-boolean problem (`03_…` F-15) |
| `lib/utils.ts` | `lib/utils.ts` | ✅ REUSE | Generic `cn()` helper, no issues found |

### 4.4 Feature modules

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| Auth forms embedded in `page.tsx` | `features/auth/` (`LoginForm`, `RegisterForm`, schemas) | ♻️ REWRITE | Move to React Hook Form + zod, already installed but unused (`03_…` F-23); add `autoComplete`, password strength, lockout messaging |
| Scan start form + scan list embedded in `page.tsx` | `features/scans/` | ♻️ REWRITE | Add client-side target validation mirroring the new backend scope policy, and an authorization-attestation checkbox (`03_…` F-06) |
| `ScanResultsPage` (`<details>` list) | `features/findings/` (`FindingsTable`, `FindingDetail`) | ♻️ REWRITE | Severity is fetched but never rendered; no CVE link, filter, sort, search, grouping, or pagination — today's biggest product gap (`03_…` F-11). Rebuild with TanStack Table + virtualization, and a finding-detail route showing confidence, source, evidence, and (once built) the AI verdict |
| `AssetManagementPage` | `features/assets/` | 🔧 REUSE, FIX | Criticality `<Select>` is uncontrolled (`defaultValue`) with no optimistic-update rollback (`03_…` F-16) — make it controlled |
| Credentials tab | `features/credentials/` | ♻️ REWRITE | Add credential types beyond username/password (SSH key, WinRM, API token), "test connection", HTTPS-only warning (`03_…` F-24) |
| Report View/Download/Generate menus | `features/reports/` | ♻️ REWRITE | Make "Export" one menu against the new report-as-its-own-resource API; poll while `GENERATING_REPORT`, show a retry button on `FAILED_REPORT` (`03_…` F-10) |
| `components/widgets/{SeverityDonutWidget, TopAssetsWidget, TrendLineWidget, StatCardWidget}.tsx` (dev) | `features/dashboard-widgets/` | ✅ REUSE | These four have matching `WidgetContainer` cases and work (`04_…` D-12 implicitly confirms this subset is fine) |
| `components/widgets/{AutoRemediationWidget, DataHealthWidget, ExplainRiskWidget}.tsx` (dev) | `features/dashboard-widgets/` | 🔧 REUSE, FIX | Always render "Unknown Component" today because `WidgetContainer`'s switch has no case for them (`04_…` D-12) — add the cases, and for `AutoRemediationWidget` specifically, build the `/api/ai/remediation`-equivalent route it calls (none exists — `04_…` D-06) before re-enabling it |
| `components/widgets/WidgetContainer.tsx` (dev) | `features/dashboard-widgets/WidgetContainer.tsx` | 🔧 REUSE, FIX | Add the three missing switch cases above |
| `react-grid-layout` drag/resize dashboard (dev) | `features/dashboard-widgets/` | ✅ REUSE | Genuinely good enterprise feature per `04_…` §5, once merged into the single dashboard route decided in §4.2 rather than existing twice |
| — | `features/attack-paths/` | 🆕 NEW | React Flow / Cytoscape graph view for Agent 3's output (`02_…` Phase 5, 7) |
| — | `features/findings/ScanConsole.tsx` (rebuilt) | 🆕 NEW | Live scan log, properly wired to a real SSE endpoint this time, and actually imported from the scan detail page (`04_…` D-07 noted the old one never was) |

### 4.5 Shared UI

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `components/theme-provider.tsx` | same | ✅ REUSE | Works fine |
| `components/ui/*` actually imported (≈10 of 50) | `components/ui/*` | ✅ REUSE | Keep only what's used |
| Home-made message banner in `page.tsx` | replaced by `sonner` | ♻️ REWRITE | `sonner` is already installed and unused; the banner isn't fixed-position, has poor dark-mode contrast, and its timer is never cleared (`03_…` F-20) |
| `FloatingNav` (icon-only) | `components/common/Sidebar.tsx` + mobile bottom tabs | ♻️ REWRITE | Icon-only nav is undiscoverable and overlaps content on mobile (`03_…` F-21) |
| chart color constants, `getScoreBadge` | `components/common/SeverityBadge.tsx` + CSS variable tokens | ♻️ REWRITE | No shared severity design tokens today (`03_…` F-22) |

### 4.6 Config and build

| Old file(s) | New location | Verdict | Why |
|---|---|---|---|
| `next.config.mjs` | same | ♻️ REWRITE | Remove the committed personal LAN IP in `allowedDevOrigins`; turn off `typescript.ignoreBuildErrors`/`eslint.ignoreDuringBuilds` (`03_…` F-01... F-14, F-30); add security headers, `poweredByHeader: false` |
| `package.json` | same | ♻️ REWRITE | Rename from `my-v0-project`; drop meaningless `"type": "commonjs"`/`"main"`; pin `next-themes`; align `date-fns`/`react-day-picker` versions; **upgrade Next.js off 15.2.4**, which sits on the vulnerable side of a CVSS-10.0 RCE advisory in React Server Components (`03_…` F-01) |
| `Dockerfile` | same | ♻️ REWRITE | Non-root user, `output: "standalone"`, Node 22/24 LTS (Node 20 left maintenance in April 2026), pinned `pnpm` via `corepack`, and an `ARG`/`ENV` path so the image can actually reach the API (currently it cannot — `03_…` F-05, F-31) |
| `README.md` | same | ♻️ REWRITE | Says `npm install` though the repo uses `pnpm`; says `--pool=solo` though the code runs gevent (`03_…` R-10); `dev`'s README also regressed to a single paragraph versus `main`'s architecture diagram and feature list — restore and update it (`04_…` D-27) |

---

## 5. What this leaves you with

Rough proportions, to set expectations for the rebuild effort:

| | Backend | Frontend |
|---|---|---|
| ✅ Reused as-is | Small — mostly plumbing (Alembic config, `clear_queue.py`) | Small — unused-component trimming, theme provider |
| 🔧 Reused with a named fix | The risk scorer, the SSH/WinRM collector, the widget routes/components, the JSON report renderer, the remediation model | The four working dashboard widgets, the asset criticality select, loading/layout shells |
| ♻️ Rewritten (same purpose, new implementation) | Models, auth, credentials, assets, Nmap/Nuclei engines, CLI loaders, CVE/CPE matching, Docker, reports | Routing/pages, data layer, findings view, forms, nav, Docker, config |
| 🆕 New | Agents (all 5), organizations/RBAC, audit log, KEV/EPSS/OSV/distro sources, discovery engine, normalizer, script classifier, docker-compose | BFF proxy, middleware, error boundaries, attack-path view, remediation backend-matching route |
| 🗑️ Deleted | `WebScanner`/WAF evasion, duplicate CLI function, duplicate NVD syncers, committed reports/egg-info, `.vs/` | Legacy CRA app in `public/`, duplicate CSS/hooks, dead `ScanConsole.tsx`, ~40 unused shadcn components |

This is a genuine rebuild, not a patch — roughly a quarter of the existing code is salvageable as-is or with a small fix, and the rest is either restructured around the new architecture or new outright. That matches what `02_…`'s phased roadmap already implied; this document is the concrete file-level version of Phases 0–2 plus the groundwork for Phases 3–7.

---

## 6. Suggested build order against this structure

Mirrors `02_…` §6 but now points at actual paths:

1. **Skeleton:** `backend/src/riskreveal/{main.py, config.py, db/}`, `infra/docker-compose.yml`, `.github/workflows/ci.yml`. Get an empty FastAPI app and an empty Next.js shell talking to each other through the BFF proxy, in Docker, in CI, before any feature code.
2. **Domain core:** `users`, `organizations`, `auth` — real sessions, RBAC from day one so nothing later has to retrofit it.
3. **Assets, credentials, scanning (engines + normalizer + classifier)** — the accuracy-critical path from `01_…`/`02_…` Phase 1.
4. **Intelligence sources** — cvelistV5 + KEV + EPSS first (small, high value), then OSV and distro advisories.
5. **Risk scorer**, ported from `dev`'s `scorer.py`.
6. **Frontend findings experience** (`features/findings/`) as soon as real findings exist — this is the page that makes the rebuild feel real.
7. **Reports**, as their own resource, both renderers.
8. **Agents**, once findings are trustworthy enough to be worth verifying.
9. **Remediation, widgets/dashboard, attack-path view** — the features `dev` started; finish them end-to-end this time, one at a time, with a smoke test after each (`04_…` §6's closing recommendation).

Would you like me to generate the actual skeleton next — empty files with docstrings/TODOs in this exact structure, so you can `git init` the rebuild and start filling it in?
