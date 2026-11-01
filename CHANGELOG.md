# Changelog

All notable changes to RiskReveal are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
doesn't have a stable release yet — everything below is tracked under
`Unreleased` until the first tagged version. See "How to use this file"
at the bottom before adding to it.

## [Unreleased]

### Added

- **Project foundation:** rebuilt backend on FastAPI (from the original
  Flask codebase), `src`-layout package, `uv` for dependency management,
  PostgreSQL via Docker Compose for local infrastructure, fail-closed
  configuration (`config.py` refuses to start the app if `JWT_SECRET_KEY`,
  `FERNET_KEY`, or `DATABASE_URL` are missing or malformed, rather than
  falling back to an insecure default).
- **Auth:** `User` model, Argon2id password hashing, JWT access/refresh
  tokens with an explicit `type` claim checked on decode (so a leaked
  refresh token can't be replayed as an access token), timing-safe login
  behavior.
- **Scanning:** Nmap engine (subprocess, `defusedxml`-parsed XML, real
  host/port/service/script extraction including `hostscript`), a scope
  policy gate (target validation, argument-injection hardening, private/
  loopback-range blocking by default, DNS-resolution pinning to avoid a
  TOCTOU re-resolution race), a result normalizer, owner-scoped `Asset`,
  `Scan`, and `Finding` models, a Celery task pipeline (`--pool=solo` on
  Windows), and API routes for creating and viewing scans and findings.
  **Milestone:** register → log in → scan `scanme.nmap.org` → see real,
  persisted findings, verified end to end.
- **Threat intelligence:** CISA KEV and FIRST EPSS feed ingestion (shared
  downloader with decompression-bomb and oversized-payload guards, HTTPS
  enforcement, per-record skip-and-continue parsing so one bad record
  doesn't abort a batch), `feed_syncs` tracking, a migration adding the
  intelligence tables.
- **CVE matching core:** CPE 2.2/2.3 parsing (`cpe.py`), a dependency-free
  version comparator built for real-world version strings like `6.6.1p1`
  and `1.0.2k` (`versions.py`), an NVD CVE-record parser handling AND/OR
  configuration nodes and platform ("conditional") requirements
  (`sources/nvd.py`), and a matcher (`matcher.py`) that classifies each
  match as `exact_version`, `version_range`, or `all_versions`, flags weak
  matches (`all_versions`, platform-conditional) as `needs_review` so
  they're never auto-reported as findings, and carries platform
  requirements (`requires`) for a future OS-aware filter.

### Fixed

- A Starlette behavior where `debug=True` on the FastAPI app returned a
  full HTML traceback for any unhandled exception *before* any custom
  exception handler ran — bypassing the app's own error handling entirely
  and leaking exception details (including anything sensitive in an error
  message) straight into the HTTP response, even just in local development.
  Fixed by never tying FastAPI's own `debug` flag to `settings.debug`, and
  having the custom exception handler decide what to reveal instead.
- The CVE matcher silently missing a real, NVD-listed vulnerability
  (CVE-2020-12062 against OpenSSH 8.2p1) because an NVD entry with a
  wildcarded *update* field (`version=8.2, update=*`, meaning "every patch
  level of 8.2") was being compared against the scanned host's full
  version *including* its own patch level, rather than against the host's
  base version alone — found only once the matcher was run against real
  NVD data, not synthetic fixtures.
- `pydantic-settings`'s default case-sensitivity setting silently breaking
  the standard UPPERCASE-environment-variable / lowercase-field convention.
- `pydantic-settings`'s default JSON-decoding of list-typed settings
  rejecting a plain comma-separated `CORS_ORIGINS` value before a custom
  parser ever ran; fixed with the library's own `NoDecode` annotation.

### Known gaps (tracked, not yet done)

- No frontend.
- No AI agent pipeline (verification, chaining, evidence, remediation).
- No per-user target-ownership verification in front of the scan API
  beyond the scan-owner check — **do not expose this API beyond its owner
  until that exists.**
- No scheduled stale-scan reaper or automatic feed refresh.
- CVE matching doesn't yet account for distro-backported patches (a
  detected Ubuntu/Debian/RHEL package can show as vulnerable upstream
  while actually carrying a backported fix).
- No risk scorer (CVSS + EPSS + KEV + asset criticality combined into one
  prioritized score) yet — findings aren't ranked beyond raw CVSS.

## How to use this file

- Add entries under `[Unreleased]` as you go, in the same PR as the change
  they describe — not as a separate pass later, when details are harder to
  recall accurately.
- Group entries under `Added`, `Changed`, `Fixed`, `Removed`, `Security`
  (standard Keep a Changelog categories) — use `Security` specifically for
  anything a user should know affects their safety, even if it's also
  technically a `Fixed` bug.
- When the first version gets tagged, rename `[Unreleased]` to
  `[0.1.0] - YYYY-MM-DD` and start a fresh empty `[Unreleased]` above it.
