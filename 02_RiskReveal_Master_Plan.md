# RiskReveal – Master Plan
### From prototype to an industry-grade, AI-assisted vulnerability management platform

---

## 0. Vision and Honest Positioning

**Goal:** Give users scan results as trustworthy, actionable and well-prioritized as those from tools like **Nessus**, **Rapid7 InsightVM** and **Qualys VMDR**.

**Reality check (important for planning):**
Commercial tools are built by large research teams who write and maintain tens of thousands of vulnerability checks, run threat-intelligence pipelines and operate agent fleets. A solo developer will not match that breadth. What you *can* realistically match, and in places beat, is:

| Where you can compete | How |
|---|---|
| **Accuracy of what you report** | Confidence levels, verification, no noise, authenticated checks |
| **Prioritization** | Risk score using CVSS + EPSS + CISA KEV + exploit availability + asset criticality + exposure |
| **Explanations and remediation** | AI-generated, evidence-backed, grouped fixes |
| **Attack-path insight** | Vulnerability chaining (many scanners don't do this well) |
| **Usability and reporting** | Clear dashboards, executive and technical reports |

**Strategy:** Don't rebuild Nessus's plugin library. Instead, **orchestrate the best open-source detection engines** (Nmap, Nuclei, OpenVAS/Greenbone feeds, OSV/OVAL data), **normalize** their output, **verify** it with deterministic checks plus AI, then **prioritize and explain** it. Your value is the pipeline, the accuracy, and the intelligence layer.

---

## 1. What the Industry Tools Do vs. Where RiskReveal Is Today

| Capability | Nessus / InsightVM / VMDR | RiskReveal today | Target |
|---|---|---|---|
| Large, maintained check library | Yes (vendor research teams) | Nmap NSE + Nuclei templates | Add Greenbone/OpenVAS feed, curated Nuclei set, OVAL/USN-based checks |
| Version-to-CVE matching with CPE and ranges | Yes | **No** (version data discarded) | Yes, with confidence levels |
| Authenticated patch audits (SSH, WinRM, SMB) | Yes (core strength) | SMB script-args only | Yes: package and KB inventory |
| Agents on endpoints | Yes | No | Later phase (optional) |
| Persistent asset inventory with identity resolution | Yes | Assets are per-scan rows | Yes |
| Risk score using threat intel | Yes (VPR, Real Risk, TruRisk) | CVSS max only | Yes (RiskReveal Score) |
| False-positive handling / exceptions | Yes | No | Yes |
| Scan scheduling, diffing, trends | Yes | No | Yes |
| Remediation workflow, SLAs, ticketing | Yes | No | Yes (Jira/webhooks) |
| Compliance / config audits (CIS) | Yes | No | Later phase |
| Reports (exec + technical) | Yes | PDF/DOCX/JSON (with bugs) | Yes |
| API, integrations, RBAC, audit log | Yes | Basic JWT | Yes |
| Distributed scan engines | Yes | Single Celery worker | Yes |
| **Attack-path / chaining** | Limited | No | **Differentiator** |
| **AI verification + remediation** | Emerging | No | **Differentiator** |

---

## 2. Guiding Principles

1. **Accuracy over volume.** One verified finding beats ten guesses. Never show informational script output as a vulnerability.
2. **Every finding carries evidence and a confidence level.** `inferred → detected → confirmed`.
3. **Deterministic first, AI second.** Code detects and verifies; AI explains, correlates and proposes. AI never executes arbitrary commands.
4. **Authorized scanning only.** Target ownership and scope enforced in code.
5. **Measure everything.** Maintain a benchmark lab and track precision, recall and scan time per release.
6. **Security of the scanner itself.** A vulnerability scanner holds credentials and network access; treat it as a high-value target.

---

## 3. Target Architecture

```
┌──────────────┐     ┌────────────────────────────────────────────────┐
│  Next.js UI  │────▶│  API (Flask, JWT, RBAC, rate-limit, audit log)  │
└──────────────┘     └───────────────┬────────────────────────────────┘
                                     │ jobs (Celery/Redis)
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
┌───────────────┐          ┌───────────────────┐        ┌───────────────────┐
│ Discovery &   │          │ Detection engines │        │ Authenticated      │
│ Port scan     │─────────▶│ Nmap NSE, Nuclei, │        │ collectors (SSH/   │
│ (Nmap)        │          │ OpenVAS feed      │        │ WinRM/SMB): pkgs,  │
└───────────────┘          └─────────┬─────────┘        │ KBs, configs       │
                                     │                  └─────────┬─────────┘
                                     ▼                            ▼
                         ┌────────────────────────────────────────────┐
                         │ Normalizer → canonical Finding records      │
                         │ (asset, port, service, product, version,    │
                         │  CPE, CVE, source, confidence, evidence)    │
                         └───────────────────┬────────────────────────┘
                                             ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ Correlation: CPE/version-range match, OVAL/USN/DSA, dedupe    │
        └───────────────────┬──────────────────────────────────────────┘
                            ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ AI Agent Pipeline (Celery chain)                              │
        │ 1 Verifier → 4 Evidence → 2 Related → 3 Chain → 5 Mitigation  │
        └───────────────────┬──────────────────────────────────────────┘
                            ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ Risk engine (CVSS+EPSS+KEV+exploit+criticality+exposure)      │
        └───────────────────┬──────────────────────────────────────────┘
                            ▼
              PostgreSQL  ·  Redis  ·  Object storage (evidence/reports)
                            ▲
        ┌───────────────────┴──────────────────────────────────────────┐
        │ Intelligence feeds (scheduled): NVD, cvelistV5 (CNA+ADP),     │
        │ CISA KEV, EPSS, Exploit-DB, OSV, distro advisories            │
        └──────────────────────────────────────────────────────────────┘
```

**Stack decisions**
- **PostgreSQL only** (drop SQLite for anything beyond quick tests).
- **Celery** with separate queues: `discovery`, `scan`, `agents`, `reports`, `feeds`.
- **Pydantic** for all internal schemas (findings, agent I/O).
- **Object storage / encrypted files** for evidence and reports (not filenames derived from user input).
- **Docker Compose** for dev; **Kubernetes or Compose + workers** for production.
- Pin every dependency (`pip-compile` or Poetry lockfile).

---

## 4. Data Model Changes

### 4.1 Replace per-scan assets with a persistent inventory

| Table | Purpose | Key fields |
|---|---|---|
| `asset` | One row per real machine | `id`, `org_id`, `primary_ip`, `hostnames[]`, `mac`, `os_family`, `os_version`, `criticality`, `exposure` (internet/internal), `tags[]`, `first_seen`, `last_seen` |
| `scan` | A scan job | `id`, `org_id`, `profile_id`, `status`, `report_status`, timings, `scope_id` |
| `scan_asset` | Asset seen in a scan | `scan_id`, `asset_id`, `reachable`, `os_confidence` |
| `service` | Open port on an asset | `asset_id`, `port`, `proto`, `name`, `product`, `version`, `cpe`, `banner_hash`, `first_seen`, `last_seen` |

### 4.2 Findings with lifecycle

`finding` (one row per *asset + vulnerability + service*, updated across scans):

| Field | Notes |
|---|---|
| `asset_id`, `service_id`, `port`, `proto` | Fixes the "wrong host" bug |
| `vuln_id` (CVE or plugin/template ID), `cve_id` as plain text (not a hard FK) | Keeps CVEs missing from the local DB |
| `source` | `nmap_nse`, `nuclei`, `version_match`, `authenticated_pkg`, `agent_followup` |
| `confidence` | `inferred`, `detected`, `confirmed` |
| `status` | `open`, `in_progress`, `fixed`, `accepted_risk`, `false_positive`, `reopened` |
| `severity`, `cvss_*`, `epss`, `kev` (bool), `exploit_maturity`, `risk_score` | Risk inputs and output |
| `first_seen`, `last_seen`, `fixed_at` | Enables trends and SLAs |
| `verification` (JSON) | Verifier agent verdict, reasoning, timestamps |
| `ai_remediation`, `ai_summary` | Agent outputs, with source references |
| `suppression_id` | Link to exception / false-positive rule |

### 4.3 Supporting tables
- `evidence` (`finding_id`, `type`, `content_ref`, `redacted`, `sha256`, `collected_at`)
- `evidence_chain` / `attack_path` (`path_id`, ordered `finding_ids`, `score`, `explanation`)
- `cve`, `cve_affected` (product, CPE, version ranges: **new**, enables version matching), `cwe`, `exploit` (many-to-many with CVE)
- `kev`, `epss_score` (daily refresh)
- `credential` (encrypted, owner-scoped), `scan_scope` / `authorized_target`
- `audit_log`, `organization`, `membership`, `role`
- `report` (own status and path, separate from scan status)

---

## 5. The Roadmap

> Time estimates assume one focused developer and are rough. Phases 0–2 are the foundation; skipping them makes everything later unreliable.

### Phase 0: Stabilize and Secure *(≈ 1–2 weeks)*

**Goal:** A safe, reproducible baseline.

- [ ] Remove all fallback secrets; fail startup if `JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL` are missing. **Rotate** the leaked Fernet key.
- [ ] Never log credentials. Pass credentials to tools via temp files or env, not argv; scrub logs.
- [ ] Fix **credential IDOR**: verify `credential.user_id == current user` in the route *and* the task.
- [ ] **Target validation:** accept only IP, CIDR, or valid hostname (use `ipaddress` and a hostname regex); reject leading `-`, whitespace and shell metacharacters; pass `--` before the target when invoking Nmap.
- [ ] **Scope policy:** authorized-target list or ownership verification (DNS TXT / file token); block loopback, link-local (169.254.0.0/16) and internal ranges unless explicitly allowed by an admin.
- [ ] Jinja `Environment(autoescape=True)`; restrict WeasyPrint's `url_fetcher` to `data:` URIs only.
- [ ] Report filenames from IDs (`report_<scan_id>.pdf`), never from user input; per-user directories; fix delete.
- [ ] Separate `report_status` from `scan.status`.
- [ ] Fix dependencies: pin versions, upgrade **Flask-JWT-Extended** (≥ 4.5) or pin compatible Flask, add `cryptography`, `pandas`, `weasyprint`, `matplotlib`; add a lockfile.
- [ ] Fix Dockerfiles: install `nmap`, WeasyPrint libs, drop the unused builder stage, use shell-form or an entrypoint script for `$PORT`, add non-root `USER`, add `HEALTHCHECK`.
- [ ] `request.get_json(silent=True) or {}` plus schema validation (Pydantic/Marshmallow) on all routes.
- [ ] Rate-limit auth routes (Flask-Limiter); add password policy; consider email verification.
- [ ] Add `db.session.rollback()` in all error paths; add `soft_time_limit` / `time_limit` on tasks and `timeout=` on all `subprocess.run`.
- [ ] Fix JSON report (`json.dump` the whole object); fix sort bug; fix `DISTINCT ON` usage.
- [ ] Add CI (GitHub Actions): lint, type-check, tests, `pip-audit`, `bandit`, Docker build.

**Done when:** a fresh `docker compose up` works end-to-end, and a security review of auth, credentials, targets and reports finds no critical issues.

---

### Phase 1: Scan Engine Accuracy *(≈ 3–4 weeks)*

**Goal:** Stop reporting noise; attribute everything to the right host, port and service; keep all the data Nmap gives you.

1. **Parse Nmap XML properly**
   - Store per-host `address`, `hostnames`, `os/osmatch` (enable `-O` when privileged), per-port `service` (`name`, `product`, `version`, `extrainfo`, `cpe`, `tunnel`).
   - Parse both `port/script` **and** `hostscript/script`.
   - Add `ip` to every finding so multi-host (CIDR) scans attribute correctly.
   - Add `-Pn` as a profile option, `--host-timeout`, `--max-retries`, `--version-intensity`.
2. **Script-output classifier**
   - Maintain an allow-list of *vulnerability* scripts (the `vuln` and `exploit`-category checks you trust) versus *informational* scripts (`http-title`, `ssh-hostkey`, `ssl-cert`…).
   - Informational output goes to asset/service metadata, **not** the findings table.
   - Parse script state (`VULNERABLE`, `LIKELY VULNERABLE`, `NOT VULNERABLE`, errors) and drop negatives.
3. **Nuclei integration**
   - Use the web ports Nmap found (host:port with correct scheme), not just 80/443.
   - Use Nuclei's own severity, description, reference and remediation fields.
   - Filter: exclude intrusive/DoS/fuzz tags on production by default; add profiles (safe / standard / thorough).
   - Keep templates updated on a schedule; log template versions per scan for reproducibility.
4. **Canonical Finding normalizer**
   - All engines output one Pydantic `RawFinding`; one normalizer maps to DB rows.
   - **Dedupe key:** `(asset, port, proto, vuln_id)`. Merge multiple sources into one finding with combined evidence and a higher confidence.
5. **Confidence model** (`inferred / detected / confirmed`) shown in the UI.
6. **Scan profiles:** Discovery, Quick, Standard, Deep, Web-app, Authenticated. Each profile defines ports, scripts, templates, timing, and safety level.
7. **Progress and cancellation:** per-stage progress, a cancel flag checked between stages, kill the child process group on cancel, never overwrite `CANCELED`; a Celery beat job marks stale `RUNNING` scans as `FAILED`.
8. **Concurrency:** scan hosts in parallel with a cap; run Nuclei and Nmap in parallel per asset where safe.

**Done when:** scanning your benchmark lab (Section 7) shows ≥ 90 % of the *noise* findings gone and no cross-host misattribution.

---

### Phase 2: Vulnerability Intelligence Pipeline *(≈ 3–4 weeks)*

**Goal:** Accurate, current, enriched vulnerability data, the backbone of "industry-like" results.

- [ ] **CVE ingestion rewrite**
  - Read CVSS from the **`adp`** containers (CISA-ADP) as well as `cna`.
  - Ingest **affected products, CPE matches and version ranges** (from NVD API 2.0 / CVE records) into `cve_affected`.
  - Idempotent, batch-safe, resumable; one bad record never discards a batch.
  - Daily incremental updates (NVD modified feed or API with `lastModStartDate`).
- [ ] **CISA KEV** (Known Exploited Vulnerabilities): daily sync; flag `kev=true`.
- [ ] **EPSS** scores: daily sync; store the score and percentile.
- [ ] **Exploit-DB**: use the CSV `codes` column for CVE mapping; many-to-many; shallow `git clone --depth 1`.
- [ ] Optional exploit-maturity sources: public PoC repositories metadata, Metasploit module metadata (as *indicators*, not for execution).
- [ ] **Vendor/distro advisories** for authenticated accuracy: Ubuntu USN/OVAL, Debian security tracker, RHEL OVAL, plus **OSV.dev** for language packages. Windows: MSRC (KB-to-CVE mapping).
- [ ] **CVSS handling:** prefer v4.0 → v3.1 → v3.0 → v2 in that order for the *displayed* score; store all.
- [ ] **Feed scheduler** (Celery beat), feed health page, last-updated timestamps shown in reports.
- [ ] **Version-matching engine**
  - Normalize product names via the CPE dictionary and a vendor alias table.
  - Compare versions with proper schemes (semver, dpkg, rpm, Maven, PEP 440) and respect `versionStartIncluding` / `versionEndExcluding`.
  - Results are `inferred` unless a distro advisory or a check confirms them.
  - **Backport awareness:** for packaged software, never claim a vulnerability from the upstream version alone when the distro advisory says it is fixed.

**Done when:** a scan of a known-vulnerable host returns correct CVEs with KEV/EPSS flags, and a patched distro package does *not* produce a false positive.

---

### Phase 3: Authenticated (Credentialed) Scanning *(≈ 4–6 weeks)*

**Goal:** The single biggest accuracy jump, matching what Nessus and others rely on.

- [ ] **Credential vault:** per-organization, Fernet/KMS-encrypted, key rotation support, secrets never logged, optional SSH keys, sudo support.
- [ ] **Linux collector (SSH):** OS release, kernel, installed packages (`dpkg-query`, `rpm -qa`, `apk info`), running services, listening ports, key config files (read-only checks).
- [ ] **Windows collector (WinRM / SMB / WMI):** OS build, installed KBs/hotfixes, installed software (registry uninstall keys), services, key registry settings.
- [ ] **Package-to-advisory matching** using OVAL/USN/MSRC data from Phase 2 → findings with `confidence = confirmed`.
- [ ] Collect **inventory** (software list) per asset for later "which assets have X?" queries.
- [ ] **Safety:** read-only commands only, command allow-list, timeouts, connection limits, full audit trail of every command executed.
- [ ] **Credential testing:** a "verify access" step that reports login success/failure per host so users know whether a scan was truly authenticated (and tag reports as *Authenticated* / *Unauthenticated / Partial*).
- [ ] Later: network device checks via SSH/SNMPv3, database and cloud configuration checks.

**Done when:** credentialed scans of Ubuntu, Debian, RHEL-family and Windows hosts list correct missing patches, and the false-positive rate vs. unauthenticated scans drops measurably.

---

### Phase 4: The RiskReveal Risk Score *(≈ 1–2 weeks)*

**Goal:** Rank by *real* risk, not raw CVSS (what Nessus VPR, InsightVM Real Risk and VMDR TruRisk do conceptually).

**Inputs per finding:** CVSS base, EPSS, CISA KEV, exploit maturity (none / PoC / weaponized), attack vector and complexity, asset criticality, asset exposure (internet-facing vs. internal), whether the vulnerable service is actually reachable, age of the vulnerability, compensating controls (optional), and chain membership (Phase 5).

**Starting formula (tune with data):**

```
threat   = max( kev ? 1.0 : 0,
                0.5*epss + 0.5*exploit_maturity )       # 0..1
severity = cvss_base / 10                                # 0..1
likelihood = 0.6*threat + 0.4*attack_ease                # 0..1
context  = asset_criticality_weight * exposure_weight    # e.g. 0.6–1.5
risk     = min(100, 100 * (0.45*severity + 0.55*likelihood) * context)
```

- Bands: Critical ≥ 85, High 65–84, Medium 40–64, Low 15–39, Info < 15.
- Show the **score breakdown** ("why is this 92?") in the UI. Transparency builds trust.
- Store inputs with the score so results are reproducible and auditable.
- Let users override asset criticality and exposure; recompute instantly.

**Done when:** the top-10 list for a lab network matches what an experienced analyst would patch first.

---

### Phase 5: AI Agent Pipeline *(≈ 4–6 weeks, after Phases 1–2)*

**Goal:** Verification, related-vulnerability discovery, chaining, evidence and remediation, with deterministic guardrails.

#### 5.1 Framework
- A fixed **Celery chain** per finding: `Verifier → Evidence → Related → (merge) → Mitigation`; a **chord** per scan for `Chain analyzer` once all findings are verified.
- Each agent: a prompt template, a Pydantic **input/output schema**, a **tool whitelist**, token and time budgets, and a structured log of tool calls.
- A shared `AgentRun` table: `agent`, `finding_id`, `input_hash`, `output`, `tokens`, `latency`, `model`, `error`, so results are cacheable, auditable and measurable.
- Model tiering: a smaller model for Verifier triage, a larger one for chaining and remediation. Cache by `(product, version, vuln_id)`.
- **Threshold:** run only on findings above a configurable severity or risk score to control cost.

#### 5.2 Agent specifications

| Agent | Responsibilities | Tools (deterministic) | Output schema (essentials) | Guardrails |
|---|---|---|---|---|
| **1 Verifier** | Decide whether the finding is real. Check backports, banner vs. behavior, script state, version range correctness. | Targeted Nmap script, Nuclei template by ID, HTTP/banner fetch, package query (authenticated) | `status`, `confidence`, `reasoning`, `evidence_ids[]`, `needs_more_checks[]` | Must cite tool output; "unverifiable" is a valid answer; no free-form commands |
| **2 Related-findings** | From a confirmed finding, propose follow-up checks: same product's other CVEs, CWE/CAPEC-related weaknesses, neighbouring services, default configs | CWE/CAPEC graph, product-CVE lookup, scan-request builder | `scan_requests[]` (tool + params) | Output is *requests*, executed by the scanner and re-verified by Agent 1; depth ≤ 2; scope check in code |
| **3 Chain analyzer** | Build attack paths across findings | `networkx` graph, reachability data from scans, ATT&CK mapping table | `paths[]` (ordered finding IDs, preconditions, postconditions, ATT&CK techniques, score, explanation) | LLM proposes edges; **code validates** precondition/postcondition and reachability; no invented findings |
| **4 Evidence** | Collect and package proof for each confirmed finding | Safe validation checks, request/response capture, version/config extraction, screenshot of web pages (optional) | `evidence[]` (type, redacted content, hash, timestamp) | **Non-destructive only**: no exploit payloads; secrets redacted; stored encrypted; only against in-scope assets |
| **5 Mitigation** | Fix steps, workaround, verification step, grouped fixes ("upgrade X to Y closes 12 CVEs") | CVE references, vendor and distro advisories, package-manager fixed-version lookup | `fix_steps[]`, `fixed_version`, `workaround`, `verify_command`, `sources[]`, `confidence` | Every version and URL must come from reference data; else mark `unverified`; no invented patches |

#### 5.3 Safety and quality
- **Prompt injection:** banners, HTTP bodies and file content are attacker-controlled. Wrap them as quoted data, strip instruction-like text where possible, and never let model output choose arbitrary tools or targets.
- **Human override:** analysts can overrule any verdict; overrides feed the evaluation set.
- **Evaluation harness:** a labeled set of (finding, ground truth) from the lab; measure Verifier precision/recall, chain correctness and remediation accuracy per prompt/model change. Block releases that regress.
- **Privacy:** option for self-hosted or zero-retention model endpoints; never send credentials or raw secrets to a model; redact IPs/hostnames if the customer requires it.

**Done when:** on the benchmark, the Verifier removes most remaining false positives without dropping true positives, and chains and remediation advice are rated correct by a human reviewer ≥ 90 % of the time.

---

### Phase 6: Asset Management and Vulnerability Lifecycle *(≈ 3–4 weeks)*

- [ ] **Persistent assets** with identity resolution (match by MAC, hostname, cloud instance ID, or IP history) so repeated scans update one asset.
- [ ] **Finding lifecycle:** `open → in_progress → fixed → reopened`; automatic *fixed* detection when a finding disappears from a successful, same-scope scan.
- [ ] **Scan diff:** "new / fixed / unchanged / reopened" between any two scans.
- [ ] **Scheduling:** recurring scans (cron-like), blackout windows, scan-window safety.
- [ ] **Exceptions and false positives:** per-finding or per-rule suppression with reason, owner, and **expiry date**; audited.
- [ ] **Asset grouping and tagging:** by business unit, environment, owner; scans and reports can target a tag.
- [ ] **Remediation tracking:** owners, due dates, **SLAs by severity**, overdue flags.
- [ ] **Trends:** vulnerabilities over time, mean-time-to-remediate, risk-score trend per asset and group.

---

### Phase 7: Reporting, UX and Integrations *(≈ 3–4 weeks)*

- [ ] **Report templates:** *Executive summary* (risk posture, top risks, trends), *Technical* (per-asset, per-finding with evidence and fix), *Remediation plan* (grouped by fix, ordered by risk reduction), *Delta report*.
- [ ] **Remediation-first views:** "fixing these 5 actions removes 60 % of risk", the feature users love in commercial tools.
- [ ] **Dashboards:** risk by group, top vulnerable assets, KEV exposure, aging, SLA compliance, attack-path graph visualization.
- [ ] **Finding detail page:** score breakdown, confidence, evidence, AI explanation with sources, related findings, attack paths, fix steps, history.
- [ ] **Exports:** PDF, DOCX, CSV, JSON, and **SARIF/CycloneDX VEX** where relevant.
- [ ] **Public REST API** with API keys, pagination, filtering, OpenAPI docs.
- [ ] **Integrations:** Jira / ServiceNow / GitHub Issues tickets, Slack/Teams/email notifications, generic webhooks, SIEM export (syslog/JSON).
- [ ] **Accessibility and polish:** loading/error states, empty states, large-table virtualization, saved filters.
- [ ] Fix the report pipeline: asynchronous generation with its own status, download links by ID, regeneration, retention policy.

---

### Phase 8: Scale, Operations and Platform Security *(ongoing; ≈ 4–6 weeks for the core)*

- [ ] **Multi-tenancy:** `organization`, `membership`, **RBAC** (admin, analyst, viewer, auditor), per-org data isolation enforced in every query.
- [ ] **Audit log:** logins, scans started, credentials used, setting changes, report downloads.
- [ ] **Authentication hardening:** MFA (TOTP), SSO (OIDC/SAML) optional, refresh tokens and token revocation, short-lived access tokens.
- [ ] **Distributed scan engines:** remote scanners (Docker image) that register with the platform and pull jobs, for internal networks; mutual TLS or signed tokens.
- [ ] **Optional endpoint agent:** lightweight agent that reports package/KB inventory (Phase 3 collectors packaged for continuous assessment).
- [ ] **Observability:** structured logs, metrics (Prometheus), tracing, Celery monitoring (Flower), alerting on feed failures and stuck scans.
- [ ] **Data protection:** encrypted backups, secret management (Vault/KMS), TLS everywhere, retention and deletion policies, GDPR-style export/delete.
- [ ] **Performance:** DB indexes on all foreign keys and filter columns, pagination everywhere, caching of CVE lookups, partition large tables.
- [ ] **Quality:** unit tests for parsers, matchers and scoring; integration tests with recorded Nmap/Nuclei outputs; end-to-end tests against the lab; coverage gate in CI.
- [ ] **Release engineering:** semantic versions, migrations committed and tested, changelog, rollback plan.

---

## 6. Suggested Milestones

| Milestone | Contents | Cumulative effort (rough) |
|---|---|---|
| **M1 – Safe baseline** | Phase 0 | 1–2 weeks |
| **M2 – Trustworthy results** | Phases 1 and 2 | 7–10 weeks |
| **M3 – Authenticated accuracy** | Phase 3 | 11–16 weeks |
| **M4 – Real risk ranking** | Phase 4 | 12–18 weeks |
| **M5 – AI pipeline** | Phase 5 | 16–24 weeks |
| **M6 – Vulnerability management** | Phases 6 and 7 | 22–32 weeks |
| **M7 – Platform and scale** | Phase 8 | 26–38 weeks |

> A **credible demo-able product** is reachable at **M4–M5**: accurate findings, real risk scoring, AI verification and remediation. Phases 6–8 turn it from a scanner into a platform.

---

## 7. Validation and Benchmarking (Do This From Day One)

### 7.1 Build a lab
- **Intentionally vulnerable targets:** Metasploitable 2/3, DVWA, OWASP Juice Shop, WebGoat, VulnHub VMs, vulnerable Docker images (e.g., old Apache/Nginx/OpenSSH containers).
- **Patched equivalents:** fully updated Ubuntu/Debian/Windows, to measure **false positives**.
- **Ground truth file:** for each lab target, a YAML list of *known* vulnerabilities and *known-not-vulnerable* items.

### 7.2 Metrics (tracked per release)

| Metric | Definition | Target |
|---|---|---|
| Precision | confirmed true findings ÷ reported findings | ≥ 90 % |
| Recall | known vulnerabilities found ÷ known present | ≥ 80 % (unauth), ≥ 95 % (authenticated, patch-level) |
| Misattribution rate | findings on the wrong host/port | 0 % |
| Noise ratio | informational items shown as vulnerabilities | 0 % |
| Scan time | per host per profile | tracked and bounded |
| Agent verdict accuracy | Verifier vs. ground truth | ≥ 90 % |
| Remediation correctness | human-rated | ≥ 90 % |

### 7.3 Comparison testing
Run the **same lab** through **Greenbone/OpenVAS** (free) and **Nessus Essentials** (free, limited to 16 IPs) where licensing permits, and compare: which findings each tool found, which are false positives, and where RiskReveal differs. This is the most honest way to measure "industry-level" results.

---

## 8. Legal, Ethical and Safety Requirements

- **Only scan assets the user is authorized to scan.** Require an explicit authorization acknowledgment, log it, and enforce scope in code.
- **Safe-by-default scan profiles:** no DoS-class checks, brute-forcing or intrusive templates unless an admin explicitly enables them per scan.
- **No weaponized exploitation.** "Proof" means non-destructive evidence. Do not build features that deploy exploits against targets.
- **Credential handling:** least privilege (read-only accounts recommended), encryption at rest, never logged, deletable on request.
- **Data protection:** scan results are sensitive security data; encrypt, restrict access, set retention, and document the data flow, especially when using third-party AI APIs.
- **Third-party license compliance:** Nmap (NPSL), Nuclei templates (MIT/custom), Exploit-DB, NVD/CVE terms, Greenbone feed terms, EPSS and KEV usage terms. Document attribution.
- **Responsible disclosure policy** and a `SECURITY.md` for the project itself.

---

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scope creep toward "build Nessus" | Never ships | Orchestrate existing engines; stick to the phased plan |
| AI hallucinations in verdicts/fixes | Wrong or harmful advice | Deterministic tools, schema validation, citation requirement, evaluation harness, human override |
| Prompt injection via scanned content | Agent manipulation | Treat target data as untrusted; tool whitelist; no arbitrary execution |
| False positives from version matching | Loss of trust | Confidence levels, distro advisories, Verifier agent, backport awareness |
| Scanner abused as an attack tool | Legal and reputational | Authorization, scope enforcement, rate limits, audit log |
| Stale intelligence feeds | Wrong prioritization | Scheduled sync, health monitoring, show feed age in reports |
| Cost of LLM calls | Budget overrun | Thresholds, caching, model tiering, token budgets |
| Credential leakage | Severe | Vault, no logging, rotation, least privilege, secret scanning in CI |
| Single-developer bus factor | Stalls | Tests, docs, CI, small modular components |

---

## 10. First Two Weeks: Concrete Checklist

**Week 1: Safety and stability**
1. Remove fallback secrets; rotate the Fernet key; update `.env.example`.
2. Fix dependency pins and Dockerfiles; confirm `docker compose up` works from a clean clone.
3. Add target validation and the `--` separator; add the scope/authorization check.
4. Fix the credential IDOR and stop logging passwords.
5. Autoescape templates; restrict the WeasyPrint fetcher; ID-based report filenames.
6. Add `report_status`; fix the JSON report and the sort bug; add rollbacks and timeouts.
7. Set up CI (lint, tests, `pip-audit`, `bandit`).

**Week 2: Start the accuracy work**
1. Create the new `service` table and extend `VulnerabilityFinding` (`port`, `proto`, `service_id`, `source`, `confidence`, `status`, `cve_id` as text, `first_seen`, `last_seen`).
2. Rewrite the Nmap parser (per-host findings, `hostscript`, service/CPE capture).
3. Add the script classifier (vulnerability vs. informational; drop "NOT VULNERABLE").
4. Use Nuclei's own severity/description/remediation and scan the discovered web ports.
5. Build the lab and the first ground-truth file; record **baseline** precision/recall.
6. Commit Alembic migrations.

---

## 11. Definition of "Industry-Level" for RiskReveal

You can credibly claim parity-in-experience (not parity-in-library-size) when all of these are true:

- [ ] Authenticated scans of mainstream Linux and Windows hosts report missing patches accurately, with `confirmed` confidence.
- [ ] Unauthenticated results are clean: no informational noise, correct host/port attribution, version-matched CVEs labelled `inferred`.
- [ ] Findings are ranked by a transparent, threat-aware risk score with KEV/EPSS/exploit/criticality inputs.
- [ ] Every confirmed finding has evidence, a verification trail, and grouped, source-backed remediation.
- [ ] Assets persist across scans; trends, diffs, SLAs and exceptions work.
- [ ] Attack paths highlight how findings combine into real compromise routes.
- [ ] Reports are executive-ready and technical-ready, with an API and ticketing integration.
- [ ] Benchmarks show measurable, repeatable precision/recall and are published per release.

---

## Appendix A: Finding Lifecycle

```
            detected by engine
                   │
                   ▼
   inferred ──(verifier / check)──▶ detected ──(evidence)──▶ confirmed
        │                                  │
        └───────────── false_positive ◀────┘   (agent or analyst, with reason)

   open ──▶ in_progress ──▶ fixed ──(reappears)──▶ reopened
     └────▶ accepted_risk (exception with owner and expiry)
```

## Appendix B: Recommended Libraries and Tools

| Need | Suggestion |
|---|---|
| Schemas and validation | Pydantic |
| Scheduling | Celery beat |
| Graph analysis | networkx |
| Version comparison | `packaging`, `semver`, `python-apt`/`rpm` logic, or `univers` |
| CPE parsing | `cpe` / `nvdlib` |
| Rate limiting | Flask-Limiter |
| Security tests in CI | `bandit`, `pip-audit`, `trivy` for images |
| Reports | WeasyPrint (hardened) or headless Chromium; `python-docx` |
| Secrets | HashiCorp Vault or cloud KMS |
| Observability | Prometheus, Grafana, Sentry, Flower |
| Intelligence | NVD API 2.0, cvelistV5, CISA KEV, FIRST EPSS, OSV.dev, Ubuntu/Debian/RHEL advisories, MSRC |

## Appendix C: Agent I/O Examples (Pydantic-style)

```python
class VerifierOutput(BaseModel):
    status: Literal["confirmed", "likely", "false_positive", "unverifiable"]
    confidence: float            # 0..1
    reasoning: str
    evidence_ids: list[str]
    needs_more_checks: list[ToolRequest] = []

class ToolRequest(BaseModel):
    tool: Literal["nmap_script", "nuclei_template", "http_fetch", "pkg_query"]
    params: dict                 # validated per-tool, scope-checked in code

class AttackPath(BaseModel):
    finding_ids: list[int]       # ordered
    preconditions: list[str]
    postconditions: list[str]
    attack_techniques: list[str] # MITRE ATT&CK IDs
    score: float
    explanation: str

class MitigationOutput(BaseModel):
    fix_steps: list[str]
    fixed_version: str | None
    workaround: str | None
    verify_command: str | None
    sources: list[HttpUrl]       # must exist in reference data
    verified: bool               # False if any item lacks a source
```

---

*This plan is a living document. Update it after each milestone with the measured benchmark results.*
