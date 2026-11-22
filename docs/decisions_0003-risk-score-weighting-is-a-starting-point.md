# 0003. Risk score weighting: severity as the base, threat evidence as a boost

**Status:** Accepted
**Date:** 2026-11-04

## Context

With CVSS, CISA KEV, and FIRST EPSS all now stored per finding, the data
for a combined risk score existed but nothing used it — `findings/models.py`'s
own docstring flagged `risk_score` as deliberately not built yet.

The first implementation used the master plan's original sketch: a plain
50/50 weighted average of a severity component (CVSS) and a threat
component (KEV/EPSS):

```
value = (severity * 0.5 + threat * 0.5) * 100
```

Writing a band-boundary test for this immediately exposed a real problem,
not a test bug: a CVSS 9.8 finding with **no** KEV/EPSS evidence capped at
49 — squarely in the *Medium* band. Under a straight average, severity can
never contribute more than half the score, so nothing can reach High or
Critical without threat evidence actively confirming exploitation.

That's backwards for what a scanner is for. A critical-severity,
not-yet-exploited vulnerability is exactly what you want flagged as
high-priority — patching it *before* it's exploited is the point. Capping
it at Medium until CISA or FIRST catches up would mean the tool
systematically under-prioritizes the vulnerabilities most worth acting on
early.

## Decision

Severity (CVSS) is the base of the score, not half of an average with
threat evidence. Threat evidence (KEV/EPSS) boosts that base by up to 30%:

```
value = severity * 100 * (0.7 + 0.3 * threat) * asset_criticality
```

A maxed-out CVSS with zero threat evidence lands at 70 (High). The same
CVSS with confirmed active exploitation (KEV) reaches 100 (Critical).
Separately, any KEV listing floors the score at 50 (Medium) regardless of
how low the CVSS is — CISA's inclusion criteria already imply real-world
significance a raw CVSS number can miss (e.g. a low-severity auth-bypass
step used inside a larger attack chain). A KEV entry also flagged for
ransomware use floors the score at 95, on top of the KEV floor.

## Consequences

- A finding with no CVSS and no KEV listing still returns `None` rather
  than a fabricated number — EPSS alone isn't a severity signal, so it
  can't carry a score by itself. This is unchanged from the original
  design and still the right call.
- The exact weights (70/30 split, the 50 and 95 floors) are reasoned
  defaults, not empirically calibrated against real outcome data — there
  isn't any yet. **Revisit once there's enough real finding/remediation
  history to check whether these bands actually track what practitioners
  treat as urgent**, not before.
- `asset_criticality` defaults to 1.0 (neutral) for every caller today,
  since `Asset` has no criticality field yet. The multiplier exists in the
  formula now so that adding the field later is a one-line change at the
  call site, not a rewrite of the scoring function.
- Found and fixed by writing the test *before* trusting the formula, not
  by reasoning about it on paper — consistent with this project's standing
  rule in `CONTRIBUTING.md`: verify, don't assume.
