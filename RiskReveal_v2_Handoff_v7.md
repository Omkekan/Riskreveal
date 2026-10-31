# RiskReveal v2 - Handoff (v7)

> Short handoff for the **vulnerability-matching core** step (Step D, slice 1).
> It builds on `RiskReveal_v2_Project_Work_Report.md` (the full picture up to
> the KEV + EPSS importers) and `RiskReveal_v2_Handoff_v6.md`. Read those for
> anything not repeated here.
>
> **Status words.** *Verified* = the owner showed real output.
> *Sandbox-verified* = executed in the assistant's sandbox, which has NO ruff,
> mypy, SQLAlchemy, httpx, Docker or network, so it is useful evidence, not
> proof. *Delivered, not run* = written, never executed. *Pending* = still to do.

---

## 0. TL;DR

- Delivered `riskreveal_matching_core.zip` (15 files, extracts at the repo
  root): a **pure-Python CVE matching core** (CPE parsing, version comparison,
  NVD response parser, range matcher, distro detection), a **DNS timeout**
  fix, and a **live comparison script** that checks our matcher against the
  real NVD.
- No database, migration, network code or API change: nothing here touches
  the running system until it is used. That was deliberate (see section 3).
- **The next thing that matters is a real-data check**: run
  `scripts/nvd_match_demo.py` on your machine and send back any
  `NOT MATCHED` lines. Everything in this slice was tested only on synthetic
  data; the real NVD feed has not been seen yet.

## 1. State before this step (from the report, not re-verified here)

Verified by the owner: register/login/refresh/me; scan pipeline end to end
with real Nmap (22/tcp OpenSSH 6.6.1p1, 80/tcp Apache 2.4.7 on
`scanme.nmap.org`); KEV (1,764 entries) and EPSS (398,142 scores) loaded from
the live feeds; 241 unit and 58 integration tests passing; migration test
passing. Pending from that session: `uv run mypy src`, commit of the
threat-intel slice. In the zip received for this step the SIM300 test line was
already fixed.

Two parallel assistant sessions overlapped here. This step's earlier draft
included its own KEV and EPSS parsers; those were **dropped** because the other
session's versions are tested against real data and its database tables exist.
Only code that does not overlap was kept.

## 2. What was delivered

| File | Status in tree | Purpose |
|---|---|---|
| `domain/intelligence/cpe.py` | new | Parse CPE 2.2 URIs (Nmap) and CPE 2.3 strings (NVD) into one `Cpe`; never raises |
| `domain/intelligence/versions.py` | new | Parse and order versions such as `6.6.1p1`, `1.0.2k`, `1.0rc1`; unparseable -> `None` |
| `domain/intelligence/records.py` | new | `CpeRange`, `CveRecord`, `severity_from_cvss` (stdlib + `Severity` only) |
| `domain/intelligence/sources/nvd.py` | replaces empty stub | Parse NVD CVE API 2.0 JSON into `CveRecord`s |
| `domain/intelligence/matcher.py` | replaces empty stub | `match_cves(cpe, records)`: which CVEs list this version as vulnerable |
| `domain/intelligence/distro.py` | new | Detect distro-packaged software (Ubuntu, Debian, RHEL ...) from Nmap strings |
| `domain/scanning/scope_policy.py` | replaces (one change) | `system_resolver` now has a 5 s timeout |
| `scripts/nvd_match_demo.py` | new | Live comparison of NVD vs our matcher; `--kev` marks KEV CVEs |
| `tests/fixtures/nvd_sample.json` | new | SYNTHETIC NVD page (made-up ids `CVE-2099-*`, vendor `examplecorp`) |
| `tests/unit/test_cpe.py`, `test_versions.py`, `test_distro.py`, `test_nvd_parser.py`, `test_cve_matcher.py`, `test_dns_resolver.py` | new | 169 test cases |

It reuses the other session's shared helpers: `normalize_cve_id`
(`cve_id.py`), `FeedParseError` (`errors.py`), `clean_text` (`textutil.py`),
the hardened `download()` and `parse_kev()`. Only `scope_policy.py` among
existing files is replaced, and its diff against your copy is the DNS change
alone (new `threading` import, `DNS_TIMEOUT_SECONDS`, a rewritten
`system_resolver`).

## 3. Why no database yet

Matching needs CVE data stored somewhere, and a table design chosen before
seeing real NVD data tends to be wrong. The core was built first as pure
functions so it could be tested thoroughly and checked against the real feed
cheaply. Once the demo script shows agreement, the storage design (slice 2) is
informed by facts.

## 4. Behaviour worth knowing

- **A match is a hint, not proof.** It means the advertised version lies in a
  vulnerable range. Findings built from it must use `confidence="inferred"`.
- **"Don't know" means no claim.** No version, an unparseable version
  (`1.0.2k-fips`, `2:8.4p1`), or an unparseable range bound -> no match. The
  tests check this explicitly.
- **Versions.** Numbers compare numerically; `1.0 == 1.0.0`; `1.0rc1 < 1.0`;
  `6.6.1 < 6.6.1p1 < 6.6.2`; OpenSSL-style `1.0.2 < 1.0.2k`. Known ambiguity:
  a single letter always counts as *post*-release, so Python-style `1.0b1`
  (beta) is ordered wrongly. Rare in what Nmap reports.
- **NVD splitting.** NVD writes OpenSSH `6.6.1p1` as version `6.6.1` + update
  `p1`; Nmap keeps it as one string. Both are joined before comparing.
- **NVD configurations.** Only entries marked `vulnerable: true` are kept (the
  others describe the platform). A configuration joined with AND is flagged
  `conditional`. Negated nodes are skipped. `Rejected` CVEs are skipped.
- **CVSS choice.** v4.0, then v3.1, v3.0, v2; the "Primary" score first.
- **Distro back-ports.** `distro.py` only *recognises* the situation
  (e.g. `6.6.1p1 Ubuntu 2ubuntu2.13`). Nothing downgrades a match yet; that
  needs the Ubuntu/Debian/Red Hat advisory feeds.
- **Known limit: vendor/product names** are compared as written. If Nmap and
  the NVD spell a product differently (renames, aliases), nothing matches. The
  demo script exists to find such cases from real data.
- **DNS.** `system_resolver` waits at most 5 s; the lookup thread is a daemon
  and is abandoned on timeout. Any resolver error becomes the fixed message
  "The hostname could not be resolved." or "...lookup timed out."

## 5. Verification record

**Sandbox-verified only** (stand-ins for `pytest` and `defusedxml`; no ruff or
mypy available):

- Baseline on the received tree: 171 pure tests pass. With this delivery
  applied to a clean copy of that tree: **340 pass, 0 fail** (the 171 plus 169
  new cases).
- **Mutation checks, 15 of 15 caught:** reversed version order; post-release
  letters sorting wrongly; each of the four bound types treated as inclusive or
  exclusive; unparseable bound ignored; non-vulnerable platform entries kept;
  each of the two "rejected CVE" signals ignored separately; AND-configurations
  not flagged; CVE id not validated; description not cleaned; wrong severity
  threshold; wildcard vendor accepted; DNS timeout ignored. An earlier round
  found four survivors (no test for `start_excluding`; each rejection signal
  hid behind the other); tests were added until all were caught.
- Manual style checks over all 14 Python files: no line over 100 characters,
  no trailing whitespace, no tabs, no non-ASCII, no unused imports, compiles
  with warnings as errors. (Eleven over-long lines were found and fixed this
  way; ruff would have rejected them.)
- The demo script's logic was run offline with a fake network: normal run, not
  a CPE, no version, `--kev`, and API key sent but never printed.

**Not verified at all:** `ruff`, `mypy src`, real pytest, the real NVD
response shape, the script's real network calls.

## 6. Pending - what the owner runs

```powershell
# 0. Make sure the previous slice is committed first (two clean commits are easier to undo)
Set-Location "D:\WORK\VS Code\riskreveal"
git --no-pager status --short

# 1. Apply this delivery at the repo root, then look at what changed
#    (use the real path where the browser saved the zip)
Expand-Archive -Path "<path-to>\riskreveal_matching_core.zip" -DestinationPath . -Force
git --no-pager status --short
git --no-pager diff --stat

# 2. Quality gates, from backend\
Set-Location backend
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration        # Docker Desktop running; should be unchanged

# 3. Real-data check (needs internet; one NVD request each)
uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7" --kev
uv run python scripts/nvd_match_demo.py "cpe:/a:openbsd:openssh:6.6.1p1" --nvd-cpe-name "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"
```

Send back: any gate that fails (first error plus the file/line), and the
**`NOT MATCHED` lines** with the command used. Those lines are the whole point
of step 3: each is a real example of a gap in the matcher.

Likely first failures (cheap to fix): a `mypy` complaint in `nvd.py` or
`versions.py`; a `ruff` import-order nit (`uv run ruff check . --fix`); the NVD
answering HTTP 404 for the OpenSSH name (hence the explicit `--nvd-cpe-name`);
HTTP 403/429 if the NVD rate-limits (wait a minute).

Also still open from earlier: `DEBUG=true` in `backend\.env` (noisy SQL logs),
and the bigger gaps listed in the report section 14.

## 7. What comes next

1. **Resolve whatever the real-data check shows** (matcher fixes with real
   examples; add them as tests).
2. **Step D slice 2 - storage and wiring**, designed from the real data:
   - Tables for CVE records and their CPE ranges (and indexes on
     vendor/product), an NVD sync (full once, then incremental by
     `lastModified`) using the existing `download()` pattern and one-transaction
     imports.
   - A matching step after a scan: for each finding with a CPE, `match_cves`,
     then create findings with `source="version_match"`,
     `confidence="inferred"`, CVSS-derived severity, and KEV/EPSS from
     `get_threat_signals()`. This needs a migration (relax
     `ck_findings_source_valid`, which allows only `nmap`; add CVE columns;
     `first_seen` / `last_seen`) and must **read the generated migration before
     applying it**.
   - Down-rank or flag matches on distro-packaged hosts using `distro.py`.
3. Risk scorer (CVSS + EPSS + KEV + exploit maturity + asset context).
4. **Per-user target ownership verification** before anyone but the owner uses
   the API (report section 15, step E).
5. Remaining hardening: Compose password variable (check `infra\.env` exists
   first), scheduled stale-scan reaper, scheduled feed refresh.

## 8. Standing rules (unchanged)

Windows-native, one small verified step at a time, `uv run` from `backend\`,
never paste `.env`, no destructive Docker commands, always
`docker compose -p riskreveal-v2`, route modules without
`from __future__ import annotations`, scan and feed data are untrusted, and
always say plainly what was and was not run.
