# Security Policy & Responsible Use

---

## 1. Strict Prohibition of Unauthorized Use & Liability Disclaimer

**RiskReveal is a defensive vulnerability scanning and risk management platform. Using this software to scan, probe, test, or assess any host, network, or computer system without explicit, prior written authorization from the rightful system owner is strictly prohibited and may violate local, national, and international laws.**

* **Authorized Targets Only**: You are solely responsible for ensuring and documenting that you have lawful permission before initiating any scan. For safe local smoke testing, Nmap provides `scanme.nmap.org` under strict conditions (single light scans only, no automated loops or flooding).
* **Zero Owner Liability**: As stated in [`LICENSE`](LICENSE), this software is provided `"AS IS"` without warranty of any kind. **The repository owner (`@Omkekan`) assumes zero responsibility or liability for any misuse, unauthorized scanning, network disruption, data loss, legal actions, or damages of any kind arising from the use or misuse of this software.**
* **Technical Safeguards Are Not Legal Permission**: While RiskReveal enforces a pre-scan **Target Scope Policy** (`domain/scanning/scope_policy.py`) and an **Operator Allowlist** (`domain/scanning/authorization.py`), these technical controls exist to prevent accidental misconfiguration and Server-Side Request Forgery (SSRF)—they do not replace legal authorization.

---

## 2. Supported Versions

RiskReveal v2 is currently in active, pre-release development. Security fixes are applied directly to the active v2 rebuild repository (`Omkekan/Riskreveal`).

| Version / Repository | Status | Security Updates |
| :--- | :--- | :--- |
| **RiskReveal (`main` / `dev`)** | Active Rebuild (Pre-release) | ✅ Supported |
| **Legacy v1 Prototype (`Riskreveal-Vulnerability-scanner`)** | Deprecated / Archived | ❌ Not Supported |

---

## 3. Reporting a Vulnerability in RiskReveal

If you discover a security vulnerability within RiskReveal's codebase, **do NOT open a public GitHub Issue, Discussion, or Pull Request.** Publicly disclosing an unpatched vulnerability puts anyone running the code at risk.

### How to Report Privately

Please report vulnerabilities privately using **GitHub Private Vulnerability Reporting**:

1. Navigate to the [**Security** tab of this repository](https://github.com/Omkekan/Riskreveal/security).
2. Click **"Report a vulnerability"** (or visit `https://github.com/Omkekan/Riskreveal/security/advisories/new`).
3. Provide a clear, reproducible report containing:
   * **Affected Component & File Path**: (e.g., `backend/src/riskreveal/domain/scanning/scope_policy.py`).
   * **Vulnerability Class**: (e.g., SSRF / scope bypass, argument injection, IDOR, authentication bypass, XXE, or denial of service).
   * **Step-by-Step Reproduction / Proof of Concept (PoC)**: Exact inputs, commands, or unit test cases demonstrating the issue.
   * **Impact Assessment**: What an attacker could achieve and under what conditions (e.g., unauthenticated vs. authenticated user, malicious scan target vs. compromised threat feed).

### What to Expect

* **Acknowledgment**: Reports are reviewed by the repository owner (`@Omkekan`).
* **Remediation & Verification**: Valid vulnerabilities will be fixed with regression and mutation unit tests before being merged to `main`.
* **Coordinated Disclosure**: Please allow time for the fix to be developed, verified, and merged before sharing any details publicly.

---

## 4. Scope for Security Reports

### High-Priority In-Scope Areas

We are especially interested in reports demonstrating a verifiable bypass of RiskReveal's core security boundaries:

1. **Target Scope Policy Bypasses (`domain/scanning/scope_policy.py`)**:
   * Bypassing the blocklist for cloud metadata (`169.254.169.254`), loopback, link-local, multicast, reserved ranges, IPv4-mapped IPv6, or IPv6 transition ranges (NAT64, 6to4, Teredo) when `SCAN_PRIVATE_RANGES_ALLOWED=false`.
   * Bypassing DNS IP pinning or the 5-second DNS lookup timeout (`system_resolver`).
   * Leaking resolved internal IP addresses through error messages.
2. **Public Target Allowlist Bypasses (`domain/scanning/authorization.py`)**:
   * Scanning a public target not covered by `SCAN_PUBLIC_ALLOWLIST`.
3. **Subprocess & Argument Injection (`engines/nmap_engine.py`, `domain/scanning/profiles.py`)**:
   * Passing arbitrary flags or shell metacharacters into the Nmap subprocess.
4. **Authentication, Cryptography & Tenant Isolation (`core/security.py`, `domain/users/`, `api/v1/routes/`)**:
   * JWT signature/algorithm confusion (`alg=none`), token-type confusion (`refresh` used as `access`), or login timing oracles.
   * Cross-user data access (IDOR) allowing one user to view, cancel, or enumerate another user's scans, findings, or assets.
5. **Untrusted Input Parsers & Decompression Guards (`engines/nmap_engine.py`, `domain/intelligence/sources/`)**:
   * XML External Entity (XXE) or parser crashes in `parse_nmap_xml`.
   * Bypassing the bounded-memory gzip decompression bomb guard (`gunzip_limited` in `payload.py`) or HTTPS redirect downgrade checks (`fetch.py`).
6. **Secret & Traceback Exposure (`main.py`, `config.py`, `cli/commands.py`)**:
   * Leaking `JWT_SECRET_KEY`, `FERNET_KEY`, `DATABASE_URL`, or submitted user passwords in HTTP error responses, logs, or CLI tracebacks.

---

### Out of Scope (Already Documented Pre-Production Roadmap Items)

Because RiskReveal v2 is being built in verified vertical slices, several features are intentionally deferred and already documented in [`docs/threat-model.md`](docs/threat-model.md). **Please do not submit vulnerability reports for the following known roadmap items:**

* **Account Enumeration on Registration (`POST /api/v1/auth/register`)**: Returning `409 Conflict` for an existing email is a known interim behavior until email verification is implemented.
* **Stateless Refresh Tokens**: Refresh tokens carry a `jti` claim, but database/Redis-backed token revocation and rotation are scheduled for a later slice.
* **In-Process Memory Rate Limiting**: `slowapi` currently uses in-memory storage for single-worker development; switching to `settings.redis_url` and adding per-account lockouts is already tracked for multi-worker deployment.
* **Operator-Wide Public Allowlist vs. Per-User Target Verification**: `SCAN_PUBLIC_ALLOWLIST` is an operator-level control; per-user cryptographic target ownership verification (DNS TXT / `.well-known`) is planned in Step E before multi-user deployment.
* **JSON-Body Token Delivery**: Moving refresh tokens to `HttpOnly` cookies will be evaluated when the Next.js frontend is wired up.

For full details on RiskReveal's trust boundaries and implemented mitigations, see [`docs/threat-model.md`](docs/threat-model.md).
