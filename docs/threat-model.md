# RiskReveal - Threat Model

RiskReveal is a network and vulnerability scanner that executes external discovery binaries against remote hosts, parses untrusted network banners and XML outputs, and ingests third-party threat-intelligence feeds from the internet. Because the platform sits at the boundary between operator credentials, internal/external networks, and untrusted target responses, security controls are built directly into the domain and engine layers.

---

## 1. Protected Assets

1. **Host Operating System & Container Infrastructure**: The machine running the FastAPI server and Celery scan worker must never execute arbitrary shell commands supplied by API callers or remote targets.
2. **Internal, Loopback & Cloud Metadata Networks**: The network environment surrounding the scanner host (RFC 1918 private networks, `127.0.0.0/8`, `::1`, link-local `169.254.0.0/16`, cloud metadata `169.254.169.254`, and IPv6 transition ranges) must be protected against Server-Side Request Forgery (SSRF) and unauthorized probing.
3. **Unauthorized Third-Party Public Systems**: Public internet targets must not be scanned unless explicitly authorized.
4. **Application Secrets & Cryptographic Keys**: `DATABASE_URL`, `JWT_SECRET_KEY`, and `FERNET_KEY` must never leak via API error responses, debug pages, or CLI tracebacks.
5. **User Accounts & Tenant Data**: User password hashes, JWT tokens, scan histories, discovered assets, and findings must remain isolated per owner.
6. **Database Integrity & Availability**: PostgreSQL must be protected against connection exhaustion during slow scans, oversized banner crashes, NUL-byte injection, and partial/corrupted state transitions.

---

## 2. Trust Boundaries

```text
  [1. Untrusted API Client]
             │  (JSON over HTTP / Bearer JWT)
             ▼
  ═══════════════════════════ Trust Boundary A: API Ingress ═══════════════════════════
  [FastAPI App + Scope Policy + Allowlist Gate]
             │  (JSON Task Payload over Redis)
             ▼
  [Celery Worker + Nmap Subprocess]
             │  (Raw TCP/IP Packets to Validated IPs)
  ═══════════════════════════ Trust Boundary B: Target Network ════════════════════════
             ▼
  [2. Hostile / Untrusted Scan Target]
             │  (Service Banners, CPEs, NSE Output -> Nmap XML)
             ▼
  ═══════════════════════════ Trust Boundary C: Scanner Output Parser ═════════════════
  [defusedxml Parser + Normalizer + String Clipping/NUL Stripping -> PostgreSQL]
             ▲
  ═══════════════════════════ Trust Boundary D: External Threat Feeds ═════════════════
             │  (HTTPS JSON / Gzip CSV)
  [3. External Threat Feeds (CISA KEV, FIRST EPSS, NVD API 2.0)]
```

---

## 3. Threat Scenarios & Implemented Mitigations

### T-01: Command Injection or Argument Injection via Scan Target
* **Threat**: An authenticated user submits a target string such as `127.0.0.1; whoami`, `-iL /etc/passwd`, `--script=http-Raw`, or `scanme.nmap.org -oN pwn.txt` to execute arbitrary commands or pass dangerous flags to Nmap.
* **Mitigations Implemented**:
  1. `validate_target` (`domain/scanning/scope_policy.py`) rejects any target starting with `-`, containing whitespace, commas, semicolons, URLs, or zone IDs (`%`), or failing strict IP/CIDR/ASCII-hostname validation **before any DNS lookup or subprocess call**.
  2. Users select a scan profile by name (`"quick"` or `"standard"` in `profiles.py`) and can never supply Nmap flags.
  3. `run_nmap` (`engines/nmap_engine.py`) invokes Nmap as an explicit argument list with `shell=False`.

---

### T-02: SSRF, Internal Network Probing & DNS Rebinding
* **Threat**: An attacker attempts to scan cloud metadata (`169.254.169.254`), internal RFC 1918 networks, IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`), NAT64/6to4/Teredo transition addresses, numeric look-alike IPs (`2130706433`, `127.1`), or a hostname whose DNS record flips from a public IP to `127.0.0.1` between validation and scanning.
* **Mitigations Implemented**:
  1. **Unconditional Blocklist**: Unspecified (`0.0.0.0`, `::`), multicast, link-local (`169.254.0.0/16`, `fe80::/10`), reserved ranges, and IPv6 transition ranges (`64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `2001::/32`) are blocked unconditionally regardless of configuration flags.
  2. **Private Range Default-Deny**: Loopback, RFC 1918, and CGNAT addresses are rejected unless the operator explicitly sets `SCAN_PRIVATE_RANGES_ALLOWED=true`.
  3. **IPv4-Mapped IPv6 Unwrapping**: `::ffff:x.x.x.x` addresses are unwrapped and evaluated against the IPv4 rules.
  4. **DNS Pinning & Double Validation**: `validate_target` resolves the hostname (with a 5-second timeout in `system_resolver`), verifies that **every** resolved IP passes the scope policy, and places the **resolved IP addresses**-not the hostname-into `ValidatedTarget.scan_args`. Nmap is invoked with `-n` (disable DNS resolution) so it scans the exact validated IPs. Furthermore, the worker re-runs `validate_target` and `check_authorized` immediately before launching Nmap.
  5. **Blind Error Responses**: Scope policy error messages never echo the resolved IP addresses of a rejected hostname, preventing attackers from using error messages as an internal DNS oracle.

---

### T-03: Unauthorized Scanning of Public Targets
* **Threat**: A logged-in user attempts to use the RiskReveal server to scan arbitrary third-party hosts on the public internet.
* **Mitigations Implemented**:
  1. `check_authorized` (`domain/scanning/authorization.py`) requires every public target to match `SCAN_PUBLIC_ALLOWLIST` (exact hostname, single IP, or CIDR no wider than `/16` IPv4 or `/48` IPv6).
  2. `SCAN_PUBLIC_ALLOWLIST` defaults to empty, meaning **zero public scanning is permitted by default**.

---

### T-04: Malicious Target Banners, XML Entities (XXE) & Database Crashes
* **Threat**: A hostile target under scan returns an XML payload trigger, a 10 MB service banner, NUL bytes (`\x00`), or XSS payloads in its SSH/HTTP banner to crash the worker or execute script injection in downstream viewers.
* **Mitigations Implemented**:
  1. **XML Hardening**: `parse_nmap_xml` uses `defusedxml.ElementTree` to block XML External Entity (XXE) and entity-expansion ("billion laughs") attacks.
  2. **NUL Stripping & Length Clipping**: `domain/scanning/service.py` strips `\x00` bytes (which PostgreSQL `VARCHAR`/`TEXT` rejects) and clips every string field (`hostname`, `os_name`, `service`, `product`, `version`, `cpe`, `raw_evidence`) to its exact column limit before database insertion.
  3. **Compact List Endpoints**: `GET /api/v1/findings` omits `raw_evidence`, returning it only on the single-finding detail endpoint (`GET /api/v1/findings/{id}`).

---

### T-05: Malicious, Oversized, or Corrupted Threat-Intelligence Feeds
* **Threat**: A compromised upstream mirror, MITM downgrade, gzip decompression bomb, or malformed CVE record attempts to exhaust server memory, corrupt the intelligence tables, or overwrite fresh EPSS scores with stale data.
* **Mitigations Implemented**:
  1. **HTTPS & Redirect Enforcement (`sources/fetch.py`)**: Only `https://` URLs are allowed, redirects are capped at 3, and any redirect landing on `http://` is refused. Downloads are bounded by strict byte caps (20 MiB KEV, 64 MiB EPSS) and a 120-second deadline.
  2. **Bounded-Memory Gzip Guard (`sources/payload.py`)**: `gunzip_limited` streams decompression in chunks and aborts immediately if uncompressed output exceeds `max_bytes`, stopping decompression bombs before memory allocation spikes.
  3. **Strict ASCII Validation & Error Thresholds**: CVE IDs must match `^CVE-[0-9]{4}-[0-9]{4,10}$` (ASCII digits only, enforced in Python and via PostgreSQL `CHECK` constraints). EPSS rejects `NaN`, `inf`, and out-of-range floats. If invalid rows exceed 2% (KEV) or 1% (EPSS), the entire import raises `FeedParseError` and rolls back the transaction.
  4. **Stale Replay Guard**: EPSS upserts include `WHERE epss_scores.score_date <= excluded.score_date`, preventing an older feed file from overwriting newer exploitation scores.

---

### T-06: Credential Stuffing, Timing Oracles, Token Replay & Secret Leaks
* **Threat**: Attackers probe `/auth/login` to enumerate registered emails via response timing, replay a leaked refresh token as an access token, send `alg: "none"` JWTs, or trigger validation/CLI errors to leak secrets in tracebacks.
* **Mitigations Implemented**:
  1. **Login Timing-Oracle Defense**: `authenticate` (`domain/users/service.py`) always runs `verify_password` against a random dummy Argon2id hash generated at import time when the requested email does not exist.
  2. **JWT Pinning & Claim Separation**: `decode_token` (`core/security.py`) pins the expected HMAC algorithm (`alg=none` rejected) and verifies the `type` claim (`access` vs. `refresh`).
  3. **Traceback & Error Sanitization**: `FastAPI(debug=False)` is hardcoded in `main.py`; the 422 handler strips `input` and `ctx`; `Scan.error` stores only fixed, safe strings; and `cli/commands.py` sets `pretty_exceptions_show_locals=False` on Typer so `Settings` secrets are never printed in terminal stack traces.

---

## 4. Residual Risks & Pre-Production Blockers

Before exposing RiskReveal to untrusted multi-user environments, the following planned controls must be completed:

1. **Per-User Target Ownership Verification**: Replace the operator-wide `SCAN_PUBLIC_ALLOWLIST` with per-user cryptographic proof of ownership (DNS TXT record or `.well-known` HTTP token verification with IP pinning).
2. **Redis-Backed Rate Limiting**: Switch `slowapi` from in-process memory to `settings.redis_url` before running multiple Uvicorn workers, and add per-account lockout alongside per-IP rate limiting.
3. **Refresh Token Revocation (`jti` Store)**: Persist and rotate refresh token `jti` claims so logged-out or compromised refresh tokens can be revoked prior to expiration.
4. **AI Agent Prompt-Injection Isolation**: When the 5-agent pipeline (`domain/agents/`) is implemented, all scan banners and `raw_evidence` must be passed inside strict structured data envelopes-never interpolated as system instructions-and agents must only invoke deterministic, scope-checked tools.
