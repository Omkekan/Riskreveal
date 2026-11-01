# Contributing to RiskReveal

This document is written for whoever is working on RiskReveal right now —
today, that's the project owner plus AI coding-assistant sessions continuing
the build — and it's written to still make sense the day an outside
contributor shows up. The rules below aren't bureaucracy; they're the exact
discipline that's already caught several real bugs in this project (a
config setting that silently broke environment-variable matching, a
Starlette behavior that leaked full tracebacks in local dev, a JWT library
edge case, a CVE-matching bug only real NVD data exposed). Skipping them
doesn't save time — it just moves the bug discovery from "before it merged"
to "after it shipped."

## Before you write any code

1. Read `docs/architecture.md` and the current state of whatever module
   you're touching. Don't assume a file's contents from a summary or an
   earlier conversation — open it.
2. If you're continuing work from a handoff document, verify its claims
   against the actual repository (`git status`, the actual file contents)
   before building on top of them. A handoff describes what was true when
   it was written, not necessarily what's true now.

## The gates every change must pass

Run these from `backend/` before you consider a change done:

```powershell
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration   # needs Docker running (testcontainers)
```

All four must be clean. `mypy` runs in `--strict` mode — don't add
`# type: ignore` to make a real type error disappear; fix the type, or if
the ignore is genuinely correct, explain why in a comment next to it the
way the existing code does.

If you touched anything under `domain/*/models.py`:

```powershell
uv run alembic revision --autogenerate -m "describe the change"
```

**Read the generated migration before applying it.** Autogenerate is a
starting point, not an answer — check that it only contains the change you
intended (no unrelated drift from a prior out-of-sync model), that it
doesn't touch tables it shouldn't, and that `downgrade()` actually reverses
`upgrade()`. Then verify the round trip for real:

```powershell
uv run alembic upgrade head
uv run alembic downgrade base
uv run alembic upgrade head
```

## "Verify, don't assume"

This is the single most important habit in this codebase. Concretely:

- **Test behavior, not just the code's appearance.** Reading a function and
  concluding it's correct is not the same as running it against inputs that
  would reveal whether it's correct. Several bugs in this project's history
  looked completely correct on a read-through and failed the moment they
  were actually executed.
- **Real data finds bugs synthetic fixtures don't.** The CVE-matching core
  passed every synthetic test before it was run against real NVD data —
  which is exactly when it revealed a real false-negative bug (a wildcard
  CPE update field wasn't being compared correctly). When a module parses
  or matches against external data (NVD, KEV, EPSS, Nmap XML), test it
  against at least one real sample before calling it done, not only against
  hand-built fixtures.
- **Say plainly what was and wasn't run.** When describing work (in a PR
  description, a commit message, a handoff note), distinguish clearly
  between "I ran this and saw it pass" and "I wrote this and expect it to
  pass." Don't let the second one read like the first.
- **A green test suite on a stale assumption is still wrong.** If you
  changed a shared module, re-run the tests for everything that depends on
  it, not just the tests for the module you touched.

## Git and GitHub workflow

- **Branching:** trunk-based. `main` should always be in a state you'd be
  comfortable deploying. Create a short-lived branch per change
  (`feat/nvd-matcher-wildcard-fix`, `fix/scope-policy-ipv6-loopback`), open
  a PR, merge, delete the branch.
- **Even solo, use PRs.** Opening a PR against yourself isn't theater — it's
  what triggers CI, gives you a diff view that catches things a local
  `git status` doesn't, and creates a permanent, linkable record of *why* a
  change was made (the PR description), which a bare commit history loses.
- **Commit messages:** [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`). This costs
  nothing extra and makes the history scannable, and later lets tooling
  generate changelog entries automatically if that's ever worth setting up.
- **PR description should state:** what changed, why, which of the gates
  above were actually run (and their result), and whether a migration was
  generated and verified. If something wasn't run (no Docker available, no
  real feed access), say so explicitly rather than leaving it implied.
- **Before merging:** all four gates green, migration round-trip verified
  if applicable, no secrets in the diff (check `.env`-shaped additions
  especially — this project has a documented history of exactly this
  mistake in an earlier codebase).
- **Issues:** use them for anything that isn't an immediate, obvious fix —
  especially findings from real-data verification (like the matcher's
  `EXTRA`/`MISSED` precision-check output) that need triage before they
  become a code change.

## Code style

- Formatting and most style rules are enforced by `ruff` (see
  `pyproject.toml`'s `[tool.ruff]` section) — run `uv run ruff check . --fix`
  for what's auto-fixable, but review the diff.
- `from __future__ import annotations` is used throughout domain/model/
  utility modules; **route modules are the deliberate exception** (FastAPI's
  dependency injection needs real, non-deferred type objects at runtime in
  some cases) — don't add it to files under `api/v1/routes/`.
- Favor functions that return `None` or a typed error/result over raising
  for "this input was bad, try the next one" conditions in parsers that
  process many records from an external feed — one bad record shouldn't
  abort the whole batch. Reserve exceptions for genuinely exceptional,
  caller-must-stop conditions.
- New modules handling untrusted input (scan output, feed data, user input)
  should default closed: reject what's not understood rather than guess.

## Commands reference (Windows-native)

```powershell
cd backend
uv sync                                    # install/update dependencies
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
uv run celery -A riskreveal.tasks.celery_app worker --pool=solo --loglevel=info
uv run alembic upgrade head
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration
```

```powershell
cd infra
docker compose -p riskreveal-v2 up -d
docker compose -p riskreveal-v2 ps
docker compose -p riskreveal-v2 down        # keeps data
```

Never `docker compose down -v` without explicit confirmation — it deletes
the local database volume.
