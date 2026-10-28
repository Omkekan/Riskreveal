# RiskReveal – Conversation Summary

*Everything discussed so far: your goal, the AI-agent concept, and the full backend code review.*

---

## 1. Your Goal

You are building **RiskReveal**, a full-stack vulnerability scanner, and you want to:

1. Improve the **backend scanning engine** so its **accuracy** increases.
2. Integrate **AI agents** into the backend using a five-agent pipeline.
3. Eventually produce results comparable to industry tools such as **Nessus, Rapid7 InsightVM, and Qualys VMDR**.

Repository: `https://github.com/Omkekan/Riskreveal-Vulnerability-scanner`

---

## 2. Project Snapshot (from README + uploaded code)

| Area | Details |
|---|---|
| Backend | Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-JWT-Extended, Flask-Bcrypt, Celery + Redis |
| Scanning | Nmap (`-sV -sC`, optional `--script vuln`), Nuclei (CLI subprocess) |
| Intelligence data | CVEs (cvelistV5), CWEs (MITRE XML), Exploit-DB (git clone) loaded via Flask CLI |
| Frontend | Next.js, React, TypeScript, Tailwind, shadcn/ui |
| Reports | PDF (WeasyPrint), DOCX (python-docx), JSON |
| Database | SQLite (dev) / PostgreSQL (recommended) |
| Deployment | Two Dockerfiles (API + worker), gevent-based Gunicorn/Celery |

**Backend files reviewed:** `config.py`, `extensions.py`, `__init__.py`, `models.py`, `auth/`, `assets/`, `credentials/`, `user/`, `scans/routes.py`, `scans/tasks.py`, `cli.py`, `celery_worker.py`, `clear_queue.py`, `run.py`, `wsgi.py`, `gunicorn_start.py`, both Dockerfiles, `Requirement.txt`, `pyproject.toml`.

**Not reviewed:** the Next.js frontend and the Alembic migration scripts (none were committed).

> Note: In the first message I could only read the README. GitHub blocked automated access to the code folders, so the initial design was based on the stack only. The detailed review came after you uploaded the ZIP.

---

## 3. The Five-Agent Concept (Design Discussed)

### Core principle
**Agents reason; deterministic tools act.** An agent never runs arbitrary commands. It requests actions from a whitelist of tools that Celery workers execute, with scope checks enforced in code.

### The agents

| # | Agent | Input | Allowed tools | Output |
|---|---|---|---|---|
| 1 | **Verifier** | Finding + raw scan evidence | Targeted re-scan, banner/HTTP fetch, package query | Verdict (`confirmed` / `likely` / `false_positive` / `unverifiable`), confidence, reasoning, evidence refs |
| 2 | **Related-findings** | A confirmed finding | CWE/CAPEC lookups, other CVEs for the same product, follow-up scan requests | A list of *scan requests* (not results) |
| 3 | **Chain analyzer** | All verified findings for an asset/network | Graph builder, reachability data | Ranked attack paths with justification |
| 4 | **Evidence** | A confirmed finding | Safe validation checks, request/response capture | Stored, redacted evidence |
| 5 | **Mitigation** | Finding + evidence + advisory references | CVE references, vendor/distro advisories | Fix steps, workaround, verification step |

### Key design decisions
- **Agent 2** proposes checks; the scanner runs them; results go back through Agent 1. Loop depth capped at 2.
- **Agent 3** works on a graph built in code (`networkx`). Each finding has preconditions and postconditions. The LLM proposes edges; code validates them. This prevents invented attack chains. Map results to MITRE ATT&CK.
- **Agent 4** defines "proof" as **non-destructive evidence** (version output, headers, config snippets, detection-only template matches). It does not generate working exploits, which risks crashing production systems and creates legal exposure. Evidence is encrypted and redacted.
- **Agent 5** must cite fixed versions and advisory links from your reference data; otherwise it marks the advice "unverified". Fixes are grouped (one upgrade often closes many findings).
- **Orchestration:** a fixed Celery pipeline (chain per finding, chord for chain analysis), not free-form agent chat.
- **Security:** banners and HTTP bodies are attacker-controlled, so they are treated strictly as data (prompt-injection defense). Scope checks live in the tool layer, not the prompt.
- **Output:** validated JSON (Pydantic) from every agent.
- **Cost control:** run agents only above a severity threshold, cache by (product, version, CVE), use a smaller model for triage.
- **Measuring accuracy:** scan known-vulnerable targets (Metasploitable2, DVWA, Juice Shop) and record precision and recall before and after.

### Recommended confidence model
`inferred` (version match only) → `detected` (a check actually fired) → `confirmed` (verifier + evidence).

---

## 4. Code Review Results

I verified several findings by running code: installing `Requirement.txt` in a clean virtual environment, parsing your sample JSON report, and grepping the code.

### Critical – Security

| # | Issue | Where |
|---|---|---|
| 1 | Hard-coded fallback JWT secrets and Fernet key (the key is public in the repo) | `config.py` |
| 2 | Full Nmap command, **including the plaintext password**, written to logs | `tasks.py:151` |
| 3 | **Credential IDOR:** `credential_id` never checked against the scan owner | `routes.py:23`, `tasks.py:215` |
| 4 | Unvalidated `target` → Nmap argument injection; open registration + no scope control lets anyone scan internal hosts | `routes.py`, `tasks.py` |
| 5 | Reports: Jinja without autoescape + WeasyPrint; `target_name` used in file paths (traversal); report filenames collide across users; delete removes other users' reports | `tasks.py`, `routes.py` |
| 6 | App does not start from a clean install: Flask-JWT-Extended 4.4.0 incompatible with Flask 2.3.2; `cryptography`, `pandas`, `weasyprint`, `matplotlib` missing from requirements | `Requirement.txt` |

### Accuracy problems in the scan engine

| # | Issue |
|---|---|
| 7 | Every script output without a CVE becomes a "finding" (`http-title`, `ssh-hostkey`, "NOT VULNERABLE" results…) |
| 8 | Findings are matched to assets only by port number, so on CIDR scans they attach to the wrong hosts |
| 9 | Host-level script results (`hostscript`, many `smb-vuln-*`) are never parsed |
| 10 | `-sV` product/version/CPE data is discarded; no version-based CVE matching |
| 11 | Nuclei's own severity, description and remediation are ignored; only ports 80/443 scanned; two overlapping runs; no template filters |
| 12 | CVEs lacking CNA-provided CVSS (scores often live in the `adp` container) show as "Informational"; max score taken across CVSS versions; CVE ID dropped if not in local DB |
| 13 | Risk score uses CVSS only, despite README claiming asset criticality and exploit availability; `exploit_info` never filled |
| 14 | No `-O` (OS always "Unknown"), no `-Pn`, no `--host-timeout`; `vulscan/` must be installed separately; credentials only used as SMB script-args and break on commas/quotes |
| 15 | "AI context" is hard-coded heuristics; the XSS branch never matches; `attack_vector` always "Network" |
| 16 | No deduplication of findings |

### Reliability bugs

| # | Issue |
|---|---|
| 17 | No subprocess/Celery timeouts; task never checks `CANCELED` (gets overwritten with `COMPLETED`); crashed workers leave scans stuck in `RUNNING` |
| 18 | No `rollback()` in error paths; `finally: commit()` saves partial findings from failed scans |
| 19 | Report generation reuses `Scan.status`; during or after a failed report, `/results` returns 400 |
| 20 | JSON report is **invalid JSON** (double-quoted values), confirmed against your sample file |
| 21 | Sort bug: with `reverse=True`, findings with no score come first |
| 22 | `distinct(col, col)` is PostgreSQL-only; asset criticality is per scan; stats count rows per scan instead of unique assets |
| 23 | CLI loaders: one bad file rolls back up to 999 uncommitted CVEs; Exploit-DB matching reads only 2 KB and keeps one CVE per exploit (the CSV `codes` column is better) |
| 24 | Docker: Nmap not installed in either image; `"$PORT"` not expanded in JSON-form `CMD`; unused builder stage and `...` placeholders; WeasyPrint system libs missing; runs as root; worker prints DB URI; README says `--pool=solo` but code uses gevent |
| 25 | `get_json()` returns `None` → 500; no password policy; no login rate limiting; no pagination; hard-coded CORS; no tests; no committed migrations; real scan reports committed to the repo |

### Evidence from your own repo
- The committed sample report (scan of `testphp.vulnweb.com`, an intentionally vulnerable site) contains only two *Informational* items (`http-title`, `PTR Detected`), which suggests both **low recall** and **noise**.
- The sample JSON report fails to parse (`Expecting ',' delimiter`).

---

## 5. Conclusions

1. The scanner foundation needs fixing **before** AI agents are added. Otherwise the Verifier agent will spend its effort rejecting noise and mis-attributed findings.
2. Fix security items 1–6 first, then accuracy items 7–16.
3. The `VulnerabilityFinding` model needs new fields before agents can work:
   `port`, `protocol`, `service`, `product`, `version`, `cpe`, `source` (nmap / nuclei / version-match / authenticated), `confidence`, `status`, `raw_evidence`, `first_seen`, `last_seen`.
4. Use a separate `report_status` field instead of overloading `Scan.status`.

---

## 6. Next Step Proposed

I offered to patch the critical security issues and accuracy items (1–16) and return the modified files, including the new Finding model fields, so the agent pipeline can plug in afterwards.

The full build roadmap is in **`02_RiskReveal_Master_Plan.md`**.
