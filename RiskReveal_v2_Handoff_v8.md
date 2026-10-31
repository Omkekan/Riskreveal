# RiskReveal v2 - Handoff (v8)

> Delta handoff. It records the **real-data check** of the matching core and
> a small follow-up delivery (`riskreveal_matching_core_2.zip`). It builds on
> `RiskReveal_v2_Handoff_v7.md` (what the matching core is) and
> `RiskReveal_v2_Project_Work_Report.md` (everything before it).
>
> **Status words.** *Verified* = the owner showed real output.
> *Sandbox-verified* = executed in the assistant's sandbox (no ruff, mypy,
> SQLAlchemy, httpx, Docker or network; stand-ins for pytest and defusedxml).
> *Delivered, not run* = written, never executed on the owner's machine.

---

## 1. Verified results from the owner's machine (v7 delivery applied)

| Check | Result |
|---|---|
| `mypy src` | clean, 145 files |
| Unit tests | 410 passed |
| `ruff check .` | 1 cosmetic error: `I001` in `records.py` (one missing blank line). Fixed in the new zip; `ruff check . --fix` also fixes it |
| NVD parser on the **real** feed | 121 + 53 CVEs parsed, 0 skipped |
| KEV list through the shared downloader | 1,766 entries, 0 skipped |
| Matcher vs NVD, `cpe:/a:apache:http_server:2.4.7` | agrees on **121 of 121** |
| Matcher vs NVD, `cpe:/a:openbsd:openssh:6.6.1p1` (NVD name `...:6.6.1:p1:...`) | agrees on **53 of 53** |
| KEV marks (Apache 2.4.7) | CVE-2021-40438 and CVE-2024-38475 |

Meaning: **the matcher misses nothing the NVD lists** for these two versions,
and the parser handles the real NVD shape. That covers recall only. It does not
show the matcher avoids false alarms, because the matcher was run over CVEs the
NVD had already selected for that exact version.

## 2. What the real output revealed (precision risks)

Some matches are weak:

- **`all_versions`** (the NVD lists the product with no version limit):
  OpenSSH rows CVE-2007-2768, CVE-2023-51767, and CVE-2008-3844 (also
  conditional, CVSS 9.3). All-version entries are typically disputed or
  unfixable issues.
- **`conditional`** (the NVD says it needs an extra platform): Apache rows
  CVE-2014-3523, CVE-2020-13938, CVE-2022-28330, CVE-2024-40898,
  CVE-2024-43394, and CVE-2008-3844 above.

The assistant *believes* the conditional Apache rows are Windows-specific and
CVE-2008-3844 is a Red Hat-specific package problem, so none of them would
apply to the Linux/Ubuntu hosts scanned so far. **This is unconfirmed**: the
platform was being discarded at parse time. The follow-up zip records it so the
next run can confirm it from real data (`--show-review` prints the platform and
description).

Separately, `scanme.nmap.org` runs Ubuntu with back-ported fixes, so even the
"strong" matches (121 for Apache alone) overstate real exposure. `distro.py`
recognises such hosts but nothing uses that yet.

## 3. Follow-up delivery: `riskreveal_matching_core_2.zip` (6 files)

Extract at the repo root, replacing the six files. No new files, no changes to
the database, API or existing tests.

| File | Change |
|---|---|
| `domain/intelligence/records.py` | `CpeRange.requires`: `vendor:product` of the platforms a conditional entry needs. Fixes the `I001` blank line |
| `domain/intelligence/sources/nvd.py` | Collects platform entries (the non-vulnerable ones) of AND configurations into `requires`; ignores negated nodes and garbage entries; sorted, de-duplicated, capped at 50 |
| `domain/intelligence/matcher.py` | `CveMatch.requires` and `CveMatch.needs_review` (True for `conditional` or `all_versions`). Rule: **do not turn `needs_review` matches into ordinary findings automatically** |
| `scripts/nvd_match_demo.py` | Marks `REVIEW` rows and lists their platform; `--show-review` prints a one-line description (control characters stripped); new `--compare-with CPE` **precision check** (see below) |
| `tests/unit/test_nvd_parser.py`, `test_cve_matcher.py` | 12 new cases (352 pure tests in the sandbox, up from 340) |

**Precision check.** `--compare-with` asks the NVD about two versions of the
same product and uses the NVD's own two answers as the reference. For each
version it lists `EXTRA` (we claim a CVE the NVD did not list for that CPE:
a false alarm unless the row is REVIEW) and `MISSED` (the NVD listed it, we do
not match it). The summary counts only problems that matter.

## 4. Verification of the follow-up (sandbox only)

- Whole pure suite on a clean copy of the tree: 352 pass, 0 fail.
- Mutation checks on the new behaviour: 8 of 8 caught (needs_review ignoring
  `all_versions`; ignoring `conditional`; `requires` dropped; attached to
  non-conditional ranges; never attached; vulnerable entries counted as
  platforms; negated nodes used; platforms unsorted). The last one first
  *survived* because set ordering can hide it; the test was strengthened
  (eight platforms in reverse order) and then caught on five different
  hash seeds.
- The script was run offline against a fake NVD: consistent data, a matcher that
  over-claims, a matcher that misses (a defect found in the first version of the
  script: the second CPE's misses were silently reported as "good"; fixed), and
  a description containing a terminal escape sequence (neutralised).
- Manual style checks (line length, whitespace, ASCII, unused imports, blank
  lines before definitions, warnings-as-errors compile): clean.

**Not verified:** `ruff`, `mypy`, real `pytest` on this delta; the script's real
network behaviour for `--compare-with` and `--show-review`.

## 5. Pending - what the owner runs

```powershell
Set-Location "D:\WORK\VS Code\riskreveal"
Expand-Archive -Path "<path-to>\riskreveal_matching_core_2.zip" -DestinationPath . -Force
Set-Location backend
uv run ruff check .
uv run mypy src
uv run pytest tests/unit

# Precision checks (2 NVD requests each; wait ~30 s between the two commands if rate-limited)
uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7" --compare-with "cpe:/a:apache:http_server:2.4.41" --show-review
uv run python scripts/nvd_match_demo.py "cpe:/a:openbsd:openssh:6.6.1p1" --nvd-cpe-name "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*" --compare-with "cpe:/a:openbsd:openssh:8.2p1" --compare-nvd-cpe-name "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*" --show-review
```

Send back: any failing gate, every `EXTRA` / `MISSED` line, and the `REVIEW`
block (platforms and descriptions). Then commit the matching core as its own
commit, separate from earlier work.

## 6. Next steps (decisions the real data now informs)

1. **Read the precision output.** `EXTRA`/`MISSED` rows are real matcher bugs
   to fix with tests; the `requires` values show whether a platform filter is
   worth building (for example: skip a Windows-only CVE on a host known to run
   Linux, using Nmap OS information and `distro.py`).
2. **Slice 2: storage and wiring.** CVE and CPE-range tables (keeping
   `requires`, `conditional`, the match reason); NVD sync (full once, then by
   `lastModified`) with the existing `download()` pattern and single-transaction
   imports; a matching step after a scan that creates findings only for strong
   matches, with `source="version_match"`, `confidence="inferred"`,
   CVSS-derived severity and KEV/EPSS from `get_threat_signals()`. Needs a
   migration (relax `ck_findings_source_valid`, which allows only `nmap`; add
   CVE columns). **Read the generated migration before applying it.**
3. Handle distro-packaged hosts (lower confidence or a "verify package
   version" note; later Ubuntu/Debian/Red Hat advisory feeds).
4. Risk scorer; per-user target ownership verification (before anyone but the
   owner uses the API); scheduled stale-scan reaper and feed refresh; Compose
   password variable (check `infra\.env` exists first); `DEBUG=true` in
   `backend\.env` makes logs noisy.

## 7. Standing rules (unchanged)

Windows-native; one small verified step at a time; `uv run` from `backend\`;
never paste `.env`; no destructive Docker commands; always
`docker compose -p riskreveal-v2`; route modules without
`from __future__ import annotations`; scan and feed data are untrusted; always
say plainly what was and was not run.
