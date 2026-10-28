# RiskReveal – Review of the `dev` Branch (vs. `main`)

*Companion to `01_Conversation_Summary.md`, `02_RiskReveal_Master_Plan.md`, and `03_Frontend_and_Full_Review.md`. This file reviews `Riskreveal-Vulnerability-scanner-dev.zip` by diffing it against the `main` ZIP already reviewed, and reading every file that is new or changed.*

*Review date: 28 Oct 2026.*

---

## 0. What `dev` actually is

`dev` is not a cleanup of `main` — it is a **different, half-finished rewrite** layered on top of the same frontend monolith. It adds:

- A new scan engine (`riskreveal/scanner.py`, `riskreveal/engine/*`) that replaces the Nuclei-based scan with a **custom active web-exploitation module** (see §1, the headline finding).
- A customizable widget dashboard (`riskreveal/widgets/`, `components/widgets/*`, a new `app/dashboard/` route, `react-grid-layout`).
- A remediation-ticket data model and a `/remediation` page with **no backend route behind it**.
- An `AuthenticatedScanner` that logs into hosts over SSH/WinRM to pull software inventory.
- A `ScanConsole.tsx` live-log component that is **never imported anywhere**.

None of this replaces the old monolith frontend (`app/page.tsx`, now 56 KB, up from 51 KB) — it sits alongside it, partly duplicated inside it, and the new routed pages are not linked from the app's navigation at all. The result is less coherent than `main`, not more: more features were started, fewer of them work end-to-end, and the Critical security issues already flagged in `01_…` are still present, plus new ones.

**Bottom line: do not deploy or demo `dev` as-is.** The active-exploitation behaviour in §1 is a stop-ship issue on its own, independent of anything else in this document.

---

## 1. Critical — stop-ship

### D-01: The scanner now actively attacks the target, including a payload that tries to drop a database table

`riskreveal/scanner.py`'s `WebScanner` is wired into every **"advanced"** scan (`scans/tasks.py`, `perform_vulnerability_scan`). For each form or input field it finds, it fires real SQL-injection and XSS payloads at the live target, including:

```python
base_payloads = ["'", "' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users;--"]
```
```python
base_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
```

This is paired with a `WAFEvasionToolkit` that:
- Rotates user agents and spoofs `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, and `True-Client-IP` with **randomly generated fake IPs**, to make the traffic look like it comes from somewhere else.
- Obfuscates payloads (URL-encoding, full-width Unicode substitution for `script`) specifically to slip past web application firewalls.
- Uses Playwright with `playwright-stealth` to evade headless-browser/bot detection while crawling.

**Why this stops the ship, not just the one finding:**
- `'; DROP TABLE users;--` is not a detection probe, it is a destructive payload. If it ever lands on a database that doesn't parameterize queries, it can delete data. A vulnerability scanner that ships this against customer-authorized targets — let alone anything scanned without airtight authorization — creates real legal exposure (most computer-misuse laws, e.g. the U.S. CFAA or UK Computer Misuse Act, do not have an exception for "the vendor's tool did it").
- Spoofing origin headers and evading WAFs is behavior associated with attackers, not defenders. A legitimate scanner identifies itself; it does not try to hide from the target's security controls.
- This directly reverses a design decision already agreed on in this project (`01_Conversation_Summary.md` §3, Agent 4): *"does not generate working exploits, which risks crashing production systems and creates legal exposure."* `dev` does exactly what that decision ruled out, and does it unconditionally — any scan the user marks "advanced" runs it, with no separate opt-in, no rate limiting beyond `limit_per_host=5`, and no authorization check (the scope-control gap in `01_…` #4 / `03_…` F-06 is still open, so there is nothing stopping this from running against a target the user does not control).

**What to do:** remove `WebScanner`'s active-exploitation methods before this touches any target you don't own outright in a lab. If you want DAST later, the industry pattern (also in your own Master Plan's Phase-0/5 principles) is detection-only signatures and a verifier step, not live payload firing with WAF evasion. This is the single highest-priority item in this review.

### D-02: The hard-coded Fernet encryption key is still in the repo, unchanged

`config.py` still ships:
```python
FERNET_KEY = os.environ.get('FERNET_KEY') or 'sAIVKGyoFzKEtcjg6wSka1b1awM6PAP_FL96j_UinbM='
```
This is the exact key flagged as Critical #1 in `01_Conversation_Summary.md`. It is public (anyone with the repo can decrypt every stored scan credential if an operator forgets to set `FERNET_KEY`), and it has not been rotated or removed between `main` and `dev`.

### D-03: CORS now allows any origin, with credentials, on the whole API — a regression from `main`

`main` scoped CORS to `/api/*` from three localhost origins. `dev` changed this to:
```python
CORS(app,
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=True)
```
`origins: "*"` combined with `supports_credentials=True` is invalid per the Fetch/CORS spec in real browsers (they refuse to honor credentialed requests against a wildcard origin), so this will misbehave unpredictably across browsers — and where it does work, it opens every route under `/*`, not just `/api/*`, to any origin. This needs to go back to an explicit allow-list (ideally read from config, per `03_…` C-08), not forward.

### D-04: Credentials are used with host-key/certificate verification disabled

`riskreveal/engine/auth_scanner.py`, the new authenticated (SSH/WinRM) collector:
- SSH: `client.set_missing_host_key_policy(paramiko.AutoAddPolicy())` — silently trusts and stores the host key of whatever it connects to on first use, every time (not just first use network-wide), which is a textbook on-path (MITM) weakness.
- WinRM: `server_cert_validation='ignore'` — disables TLS certificate validation outright.

Both defeat the usual purpose of using saved credentials, which is to log into *known* machines. An attacker who can redirect traffic (ARP spoofing, DNS, a compromised switch) can harvest the customer's saved domain/SSH credentials. Pin or verify host identity, or at minimum make "trust on first use with a stored fingerprint" explicit and visible to the user, and never disable TLS verification.

---

## 2. High — confirmed broken or orphaned features

The frontend now calls several endpoints that do not exist in the backend, and ships UI for a feature with no backend behind it at all. I traced each one through the actual route files, not just by inspection of the frontend.

| ID | Broken call / feature | Evidence |
|---|---|---|
| **D-05** | **`/remediation` page has no backend.** `app/remediation/page.tsx` calls `GET /remediation/tickets`. There is no `remediation` blueprint, no route file, nothing registered in `riskreveal/__init__.py` — only `auth`, `scans`, `credentials`, `assets`, `user`, `widgets` are registered. The `RemediationTicket` model and the ticket-auto-generation logic (`auto_generate_tickets` in `tasks.py`) exist, but nothing ever serves them over HTTP. Even if a route were added, the frontend expects `ticket.finding_name` and `ticket.asset_ip` directly on the ticket, fields the model doesn't carry without a join. | Confirmed by reading every registered blueprint and every route file. |
| **D-06** | **"Auto Remediation (AI)" widget calls a route that doesn't exist.** `components/widgets/AutoRemediationWidget.tsx` posts to `/api/ai/remediation`. No `ai` blueprint exists anywhere in the backend. This is one of the 26 widgets seeded by `flask seed-widgets` and is explicitly advertised as an "AI Extension" that "Generates step-by-step fix scripts using AI" — today it can only ever show its own catch-block message, `"# Error connecting to Remediation Engine."` | Grepped every blueprint registration; none named `ai`. |
| **D-07** | **Live scan console calls a route that doesn't exist, and is never used.** `components/ScanConsole.tsx` polls `GET /scans/${scanId}/logs` every 3 seconds. `scans/routes.py` has no `/logs` route (start, list, results, stats, cancel, delete, report/generate, report/download — that's all of them). On top of that, `ScanConsole` is not imported by any page in the project — it is dead code that would also fail if wired up. | Grepped all `.tsx`/`.ts` files for `ScanConsole`; only its own definition matches. |
| **D-08** | **The CLI command that loads CVE data is silently shadowed and does not exist at runtime.** `riskreveal/cli.py` defines `def register_cli_commands(app):` **twice** (line 14 and line 145). Python keeps only the second definition; everything registered inside the first — including the `load-cves` command, the loader for your core CVE intelligence data — is dead code. The comment left in the file gives it away: `# ... (your existing load-cves command) ...` — this reads as an AI-assisted edit that was meant to *add to* the function and instead *replaced* it. Only `seed-widgets`, `load-cwes`, and `load-exploits` survive as runnable commands. | Confirmed by `grep -n "^def register_cli_commands"` → two hits; verified `load-cves` body sits entirely inside the first (dead) one. |
| **D-09** | **Two independent implementations of the widget dashboard, calling different URL prefixes — at least one is always broken.** `app/page.tsx` has its own inline fetch/add/remove/save-layout logic for widgets (calling `/api/widgets/...`, with the `/api` prefix). A second, newer implementation (`hooks/useDashboard.ts` + `app/dashboard/page.tsx`, the "Command Center" route) reimplements the same feature calling `/widgets/...` (no `/api` prefix). Since the widgets blueprint is mounted at `/api/widgets`, whichever convention `NEXT_PUBLIC_API_URL` isn't built around will 404. The same inconsistency hits Settings: `app/page.tsx` calls `/user/profile` and `/user/change-password` with no `/api` prefix, while nine other calls in the same file do include it — so Settings is broken by the same bug regardless of which convention you pick. | Extracted every `api.get/post/put/delete(...)` call across the dev frontend; prefixes are inconsistent within the same file. |
| **D-10** | **The new `/dashboard` and `/remediation` routes are not reachable from the app.** Neither is linked from navigation (`Navigation`, `FloatingNav`, or anywhere else) — no `next/link`, no `useRouter().push`, nothing. They only render if a user types the URL directly. Combined with D-05/D-09, both are effectively unfinished, unlinked prototypes shipped inside the main branch. | Grepped `app/page.tsx` for `router`, `next/navigation`, `next/link`, `/dashboard`, `/remediation` — no matches. |
| **D-11** | **PDF and DOCX report generation are gone from the code but still advertised by the API and the UI.** `scans/routes.py`'s `generate_report` still does `from .tasks import generate_pdf_report` / `generate_docx_report` for those formats. The rewritten `scans/tasks.py` defines only `generate_json_report` — the PDF task (WeasyPrint + matplotlib chart) and the DOCX task (python-docx) that existed in `main` were not carried over. Clicking "Generate → PDF" or "Generate → DOCX" in the UI will hit an `ImportError` inside the request handler and return an unhandled 500. | Diffed `scans/tasks.py` against `main`; confirmed only one `@celery_app.task` remains, `generate_json_report`; confirmed `routes.py`'s PDF/DOCX branches are unchanged and still try to import the missing names. |
| **D-12** | **Three of 26 seeded dashboard widgets will always render "Unknown Component."** `cli.py`'s `seed-widgets` command creates templates with `component_name` values `AutoRemediationWidget`, `DataHealthWidget`, and `ExplainRiskWidget` (1 template each). The component files exist on disk, but `components/widgets/WidgetContainer.tsx`'s `switch` only has cases for `SeverityDonutWidget`, `TopAssetsWidget`, `TrendLineWidget`, `PredictiveRiskWidget`, and `StatCardWidget` — the other three fall into the `default: return <div>Unknown Component</div>` branch. | Diffed the seeded `component_name` values against the `switch` cases in `WidgetContainer.tsx`. |
| **D-13** | **A global, platform-wide scan lock.** `tasks.py` wraps every scan in `task_lock("global_nmap_lock", ...)`, a single Redis key shared by **all users, all scans**. Only one scan can run at a time across the entire platform; every other queued scan sits at "Waiting for resource availability..." and retries every 30 seconds. This is a correctness regression for a multi-tenant product, not just a performance one — one user's 5-minute scan blocks every other user's scans for its duration. | Read `task_lock` and its single hard-coded `lock_name`. |
| **D-14** | **The scan task blocks the Celery worker for its full duration.** `perform_vulnerability_scan` creates a fresh `asyncio` event loop and calls `loop.run_until_complete(...)` synchronously inside the task, mixed with the `gevent`-based worker pool the Dockerfile and `Requirement.txt` still use (`gunicorn[gevent]`, `psycogreen`). Running a blocking asyncio loop inside a gevent-patched process is fragile and, at minimum, means the worker cannot do anything else — including respond to the cancel/revoke calls `scans/routes.py` already works around — while one scan's async phase runs. | Read `perform_vulnerability_scan`; cross-checked against `Requirement.txt`'s gevent stack. |
## 3. Medium

| ID | Problem | Where |
|---|---|---|
| **D-15** | **"Predictive risk" / "anomaly detection" is a two-point moving average, not ML.** `widgets/routes.py`'s `exploit_probability`/`anomaly`/`predictive_risk` handler computes `predicted_risk = (avg_risk + recent_momentum) / 2` and flags an "anomaly" purely as `actual > avg*2`. This is fine as a cheap heuristic, but it is presented to the user as AI/ML (`PredictiveRiskWidget`, widget category labels). Calling it a statistical placeholder internally, and either building real ML later or relabeling the widget now, avoids over-promising to anyone who evaluates the product on its stated capabilities. | `riskreveal/widgets/routes.py`, `agg_type in ['exploit_probability','anomaly','predictive_risk',...]` |
| **D-16** | **Severity collapsed to "Medium" for almost everything Nmap finds.** `main` had a `SCRIPT_SEVERITY_MAP` giving Critical/High ratings to known-dangerous Nmap NSE scripts (`smb-vuln-ms17-010`, `ssl-heartbleed`, backdoor checks, etc. — see `01_…` #7/#16 for the original gaps). `dev`'s rewritten `perform_vulnerability_scan` drops that map entirely: every Nmap script-output finding is hard-coded `severity="Medium"`, regardless of what the script actually found. This is a step backward on an accuracy problem the project was already trying to fix. | `scans/tasks.py`, the per-script `VulnerabilityFinding(..., severity="Medium", ...)` |
| **D-17** | **Nuclei is no longer called at all.** `main`'s scan pipeline ran Nuclei as a second detection engine (with its own, separate accuracy problems documented in `01_…` #11). `dev` removes that call entirely and replaces it with the custom `WebScanner` from D-01. Net effect: template-based detection coverage (CVEs, misconfigurations, exposed panels, etc. that Nuclei's community templates catch) is gone, replaced by a narrower SQLi/XSS/security-header checker. | `scans/tasks.py` vs `main`'s `run_nuclei_scan` |
| **D-18** | **`critical_count` widget is silently always zero.** `widgets/routes.py` filters `VulnerabilityFinding.severity == "critical"` (lowercase), but every writer in the codebase stores severity capitalized (`"Critical"`, `"High"`, `"Medium"` — see `RiskPrioritizationEngine`, the Nmap script findings, `get_severity_from_score` in `main`). The stat card for critical-finding count will show 0 regardless of actual data. | `widgets/routes.py`, `agg_type == "critical_count"` |
| **D-19** | **Every widget-data error is swallowed into a `200 OK` with empty data**, twice over — `get_widget_data` has a duplicated, unreachable second `except` block (copy-paste leftover) and the live one returns `jsonify([]), 200` on any exception. A broken query, a bad template config, or a DB error all look identical to "this user has no data." This will make production issues invisible. | `widgets/routes.py`, bottom of `get_widget_data` |
| **D-20** | **`GET /api/widgets/templates` has no `@jwt_required()`**, unlike every other route in the file (including every other widgets route). Minor exposure — it only lists public widget names/descriptions — but it's an inconsistency worth closing before it becomes a pattern. | `widgets/routes.py`, `get_templates` |
| **D-21** | **`cpe_analyzer.py`'s "exact CVE match" is a free-text `ILIKE` substring search**, not a real CPE/version-range match, despite the docstring calling it "Enterprise-grade" and the matching method `get_exact_cve_matches`. Substring-matching a product name and a truncated version number against free-text CVE descriptions will produce both false positives (unrelated CVEs that happen to mention the same words) and false negatives (real matches worded differently). This is the same class of problem flagged for the original engine in `01_…` #10, not a fix for it. | `riskreveal/engine/cpe_analyzer.py` |
| **D-22** | **Two near-duplicate NVD sync engines** (`riskreveal/engine/nvd_sync.py`'s `NVDSyncEngine` and `riskreveal/engine/cve_sync.py`'s `CVESyncEngine`) do almost the same thing — fetch from the NVD 2.0 API, upsert into `CVEData` — with different field names and no indication which one is actually wired up (neither is imported by `cli.py`, `tasks.py`, or any route). Pick one, delete the other, and schedule it (Celery beat, per the Master Plan's Phase 2). Also relevant: our stack research this session found NVD is scaling back enrichment for most CVEs — see `02_…` — so a single NVD-only sync engine is already not enough on its own. | `riskreveal/engine/nvd_sync.py`, `riskreveal/engine/cve_sync.py` |
| **D-23** | **`Plugins/base.py` and `engine/__init__.py` are empty stub files** committed with no content — placeholders for a plugin system that doesn't exist yet. Not harmful, but noise; either build the stub into a real extension point or remove it until you do. | `riskreveal/Plugins/base.py`, `riskreveal/engine/__init__.py` |
| **D-24** | **Five near-duplicate one-off scripts in the backend root**: `mega_seed.py`, `seed.py`, `seed_widgets.py`, `update_db.py`, `update_db1.py`, alongside the proper `flask seed-widgets` CLI command. `update_db1.py` strongly suggests `update_db.py` didn't work and was copied rather than fixed. These look like local debugging aids that were committed rather than cleaned up. | Backend app root |
| **D-25** | **Still no CPE/version-based matching, no dedup, no asset-vs-port correctness** (`01_…` #8–#10, #16) — these weren't addressed in `dev`'s rewrite either; the rewrite replaced one weak matching approach with another (D-21) rather than fixing the underlying gap. | `scans/tasks.py`, `engine/cpe_analyzer.py` |

---

## 4. Repository hygiene (new, specific to `dev`)

| ID | Problem | Fix |
|---|---|---|
| **D-26** | **A 72 MB Visual Studio workspace folder (`.vs/`) is committed**, including a 4.6 MB `slnx.sqlite` workspace database. This is local IDE state, not source — it bloats every clone and can leak local file paths. | Delete it; add `.vs/` to `.gitignore`. |
| **D-27** | **README.md was downgraded**, not improved: `main`'s README had a table of contents, a Mermaid architecture diagram, a features list, and badges; `dev`'s is a stripped-down single paragraph. If `dev` is meant to become the new `main`, the documentation needs to move forward, not backward. | Carry `main`'s README structure forward and update it for the new engine/widgets/remediation pieces (or remove references to features that don't work yet, per §2). |
| **D-28** | Migrations are present this time (`migrations/versions/*.py`, 4 revisions) — this fixes the empty-`versions/` gap flagged as R-08 in `03_…`. Good. But the newest migration (`add_created_at_to_scan`) and the models disagree with the finding-count code in `widgets/routes.py`'s trend widgets, which `GROUP BY func.date(Scan.created_at)` — confirm `created_at` is backfilled for scans created before this migration, or those scans silently drop out of every trend widget. | `migrations/versions/83124bf544ab_add_created_at_to_scan.py` |
| **D-29** | `Requirement.txt` still does not list the packages the new code actually imports: `aiohttp`, `beautifulsoup4`, `playwright`, `playwright-stealth`, `paramiko`, `pywinrm`, `pandas`. A clean install (`pip install -r Requirement.txt`) will crash on the first scan with `ModuleNotFoundError`, and Playwright additionally needs `playwright install chromium` as a separate step that is documented nowhere. This is the same class of bug as `01_…` #6, now wider. | Regenerate the dependency list (prefer a proper lockfile per the earlier stack recommendation — `uv`/Poetry) and document the Playwright browser install step. |

---

## 5. What `dev` got right (keep these)

Not everything in `dev` is a regression. Worth carrying forward once the Critical items are fixed:

| Improvement | Why it's good |
|---|---|
| **Migrations now exist** (`migrations/versions/*`), closing R-08 from `03_…`. | A real schema history; just verify it against a fresh database before relying on it. |
| **`RiskPrioritizationEngine` (`engine/scorer.py`)** is a clean, readable, unit-testable 0–100 contextual score (CVSS + exploit availability + asset criticality), closing part of `01_…` #13 (risk score ignoring exploit availability and criticality). It's a reasonable first version of the "RiskReveal Risk Score" the Master Plan's Phase 4 calls for. | Small, pure function — easy to test and tune. |
| **`AuthenticatedScanner` (`engine/auth_scanner.py`)** is a real step toward Phase 3 (credentialed scanning) — it actually pulls installed-package inventory over SSH (dpkg/rpm) and Windows software over WinRM. The approach is right; fix the host-key/cert-verification issue (D-04) and it's usable. | Once hardened, this is most of what `01_…`'s `#14` asked for (credentials only used as SMB script-args before). |
| **Redis-based task locking** is the right *mechanism* for preventing resource contention — it's just scoped too broadly today (D-13). Scope it per-target or per-worker-slot instead of globally and it becomes a real feature. | |
| **Customizable, per-user dashboard with saved layout** (`UserDashboardWidget`, drag/resize via `react-grid-layout`) is a genuinely good enterprise feature once it's wired up correctly and merged with the existing dashboard rather than duplicated (D-09). | Matches what the Master Plan's Phase 7 asks for under "Dashboards." |
| **JSON report writing now produces structurally valid JSON** (`generate_json_report` streams `json.dumps(...)` per record inside manually-written brackets, correctly handling the comma between entries) — this appears to fix the invalid-JSON bug from `01_…` #20, though the PDF/DOCX loss (D-11) means this is currently the only format that works at all. | Worth confirming with a real parse-test once PDF/DOCX are restored. |

---

## 6. Net comparison with `main`

| Area | `main` | `dev` |
|---|---|---|
| Scan behavior on the target | Passive (Nmap + Nuclei templates) | **Actively attacks the target with real SQLi/XSS payloads + WAF evasion (D-01)** |
| Secrets | Hard-coded Fernet key | Same hard-coded key, unchanged (D-02) |
| CORS | Scoped to `/api/*`, 3 localhost origins | Wildcard origin on `/*` with credentials (D-03) |
| Report formats | PDF, DOCX, JSON (JSON invalid) | **Only JSON, and it's valid** (D-11) |
| CVE data loading | Works (`flask load-cves`) | **Broken — command shadowed by a duplicate function name (D-08)** |
| CVE/version matching | Discarded `-sV` data entirely (`01_…` #10) | Still no real matching, now via brittle substring search (D-21) |
| Script-finding severity | Had a known-bad-script severity map | **Map removed — everything defaults to Medium (D-16)** |
| Credentialed scanning | SMB script-args only, fragile | Real SSH/WinRM collector, but host-key/cert checks disabled (D-04) |
| Dashboard | Static stat cards + one bar chart | Two separate, half-wired widget-dashboard implementations (D-09, D-10) |
| Remediation tracking | Doesn't exist | Data model + UI exist; **no backend route connects them (D-05)** |
| Migrations | Empty `versions/` | Four real migrations committed |
| Concurrency | One scan per Celery worker slot | **One scan at a time, platform-wide (D-13)** |
| Repo hygiene | Committed reports, egg-info, unrelated spec file | All of that, **plus a 72 MB `.vs/` folder (D-26)** |

**Read of the trajectory:** `dev` spent effort on the right *categories* of work (risk scoring, credentialed scanning, dashboards, remediation tracking) — these are genuinely on the path your Master Plan lays out. But the execution has a pattern worth naming directly: several pieces look AI-generated and merged without integration testing (the duplicated `register_cli_commands`, the two competing widget-dashboard implementations with mismatched URL prefixes, the UI built for `/remediation` with no corresponding backend route, the "AI remediation" widget pointed at a route that was never created). None of these would survive five minutes of manually clicking through the app or a single integration test. That is the gap to close before adding the next feature: **fewer new modules, more wiring the ones that exist all the way through, and a smoke-test pass (start a scan, view results, generate each report format, add a widget, open every page) before calling a change done.**

---

## 7. Recommended path forward

1. **Do not run `dev`'s scanner against anything you don't own in an isolated lab, until D-01 is resolved.** This is independent of everything else.
2. **Take `main` as the base**, not `dev` — `main`'s frontend structure is the one already being restructured per `03_Frontend_and_Full_Review.md`, and `main` doesn't carry the active-exploitation or wildcard-CORS regressions.
3. **Cherry-pick forward, deliberately, one piece at a time, with a smoke test after each:**
   - `engine/scorer.py` (risk scoring) — low risk, clean, valuable.
   - `engine/auth_scanner.py` (credentialed scanning) — after fixing D-04.
   - The widget dashboard — pick **one** implementation (the routed `/dashboard` + `useDashboard.ts` version fits the Phase-ahead App Router rewrite better), wire its URL prefix correctly, fill in the 3 missing `WidgetContainer` cases (D-12), and link it from navigation.
   - Remediation tickets — build the missing `/api/remediation/*` blueprint before shipping the page that calls it, or hide the page until it exists.
   - Migrations — bring the 4 committed revisions forward; verify `flask db upgrade` on a fresh database before relying on them.
4. **Fix `cli.py`'s duplicate function (D-08) immediately** regardless of what else you do — it's a two-line fix (merge the two `register_cli_commands` bodies into one) and it's currently the only way to load CVE data at all.
5. **Rebuild `Requirement.txt`/`pyproject.toml` from the union of what both branches actually import**, then pin it with a lockfile (`uv`/Poetry), per the earlier stack discussion.
6. Everything already listed in `01_Conversation_Summary.md` and `03_Frontend_and_Full_Review.md` still applies on top of this — this file only covers what's different in `dev`.

---

## 8. Assumptions and open questions

- I compared file contents and traced call paths by reading code; I did not run either backend (no network/Nmap/Playwright in this sandbox), so runtime-only behavior (e.g., exact browser CORS handling, whether `generate_json_report`'s output parses cleanly end-to-end) is inferred from the code, not executed. Please verify D-01 through D-04 and D-11 by smoke-testing in a real environment before relying on this assessment for a go/no-go decision.
- I assumed `dev` is a work-in-progress branch, not something already deployed. If any `dev` build has been run against real, externally-owned targets, treat D-01 as an incident to review (what was scanned, with what authorization, and whether `DROP TABLE` payloads executed), not just a code-review finding.
- I did not re-review `components/widgets/DataHealthWidget.tsx` and `ExplainRiskWidget.tsx` in full detail beyond confirming they exist and aren't wired into `WidgetContainer` (D-12); if you fix D-12, give those two a pass as well before relying on them.
