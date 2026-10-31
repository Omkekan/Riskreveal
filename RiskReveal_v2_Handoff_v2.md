# RiskReveal v2 — Handoff (v2)

> **This document supersedes `RiskReveal_v2_Handoff_Updated.md`.** It
> carries forward everything still true from that file (Section 1 of
> that doc — the three reconciliation items — **has not been resolved
> yet and still applies**; see §1 below) and adds the `User` model and
> the password/JWT module written and tested since then. Read §1 first.

---

## 1. Still open from the prior handoff — not yet resolved

These three items from `RiskReveal_v2_Handoff_Updated.md` §1 have **not**
been checked against the actual repository yet. Nothing in this session
resolved them; they're restated here so they don't get lost:

1. **Docker ports/project name**: verified-working setup uses Postgres
   `5433` / Redis `6380` / Compose project `riskreveal-v2`. A different
   chat session's `infra/docker-compose.yml` used the defaults
   (`5432`/`6379`, no explicit project name). Check which is actually on
   disk before running `docker compose up`.
2. **Two `main.py` designs**: one proposal wires `GET /api/v1/health`
   through `api/v1/router.py` with a static response; the tested version
   uses `GET /healthz` directly on the app with a real database check,
   CORS, and exception handling that closes a confirmed Starlette
   debug-mode traceback leak. Check which is actually in
   `backend/src/riskreveal/main.py` before building more routes on top
   of it.
3. **`.env.example` port accuracy** — depends on (1) being resolved.

**If these still haven't been checked, check them now, before reading
further** — everything below assumes the tested `config.py`/`db/
session.py`/`main.py` from the previous handoff are the ones in the
repository, and building auth routes on top of the other `main.py`
proposal (no DB-backed health check, no CORS, no debug-leak fix) would
mean redoing part of this batch's verification against different
underlying code.

---

## 2. What changed in this session

The build order was revised (see §3) before writing new code: the
original plan had full multi-tenant organizations/RBAC as the very next
step after the skeleton, before anything resembling the actual product
existed. That's now deliberately deferred. This session wrote the first
two pieces of a thin vertical slice instead — a bare `User` model (no
organization, no roles yet) and the password/token module that will
back the login flow.

### 2.1 Written, run, and verified this session

Same bar as the previous batch: syntax-compiled, `ruff` clean, `mypy
--strict` clean (7 source files total, including everything from the
prior batch, checked together), and exercised with real behavioral
tests — not just written and assumed correct.

| File | What it does | What was actually tested |
|---|---|---|
| `backend/src/riskreveal/domain/users/models.py` | The `User` table: UUID primary key (Python-generated via `uuid.uuid4`, not database-generated — portable, and not sequentially enumerable), `email` (unique + indexed), `hashed_password`, optional `full_name`, `is_active`. Deliberately **no** `organization_id`, no roles — see §3. | Column set, nullability, and primary-key/unique flags inspected directly. The actual Postgres DDL (`CREATE TABLE` + `CREATE UNIQUE INDEX`) was compiled via SQLAlchemy's `postgresql` dialect and checked for the naming convention from `db/base.py` (`pk_users`, `ix_users_email`) — without needing a live Postgres connection. `repr(user)` confirmed to never include `hashed_password`. |
| `backend/src/riskreveal/domain/users/__init__.py` | Re-exports `User` so other modules can `from riskreveal.domain.users import User`. | Syntax/import only. |
| `backend/src/riskreveal/core/security.py` | Argon2id password hashing (`hash_password`, `verify_password`, `needs_rehash`); JWT issue/verify (`create_access_token`, `create_refresh_token`, `decode_token`), with a `type` claim checked on decode so a leaked refresh token can't be replayed as an access token. | Full round trip for both token types; wrong-type rejection in both directions; expired-token rejection; tampered-signature rejection; wrong-secret-key rejection; missing-claim rejection; and specifically an `alg=none` token (a classic JWT library vulnerability class) — confirmed rejected because the algorithm is explicitly pinned on decode. Password hashing: correct/wrong password, a corrupted hash string (returns `False`, doesn't raise), and `needs_rehash` correctly flags a hash made with weaker cost parameters than the current default. |

### 2.2 A finding worth knowing about, not a bug this time

While testing `models.py`, a test assertion expected a separate named
`UNIQUE CONSTRAINT` on `email` and didn't find one in the compiled DDL.
Investigating (not assuming) showed why: `unique=True` combined with
`index=True` on the same column makes SQLAlchemy create a single
**unique index** (`ix_users_email`) instead of a separate unique
constraint plus a separate plain index. That's actually the more
efficient outcome for a column that needs both fast lookup and
uniqueness — the test's assumption was wrong, not the model. Fixed the
test, and left a comment in `models.py` explaining this so a future
reader doesn't make the same wrong assumption.

### 2.3 Known pitfall carried forward, now with one addition

Everything in the prior handoff's "do not reintroduce" list (§4.3 of
`RiskReveal_v2_Handoff_Updated.md` — the `case_sensitive` setting, the
`NoDecode` CORS parsing requirement, the `FastAPI(debug=...)` must stay
`False` rule, the deprecated 422 constant) still applies unchanged. One
addition from this session:

5. **A login flow built on top of `verify_password` must call it even
   when no user is found**, against a dummy hash, rather than skipping
   straight to "no such user." Hashing is deliberately slow and a failed
   DB lookup is fast — skipping the hash check when the email doesn't
   exist creates a timing difference an attacker can use to enumerate
   which emails are registered. This is documented in `security.py`'s
   module docstring for whoever writes `api/v1/routes/auth.py` next.

---

## 3. Revised build order (the actual change this session)

**Original plan** (from the rebuild plan and the first handoff): full
users/organizations/RBAC, *then* assets/scanning/findings.

**Why it changed:** six files existed before this session — all
infrastructure (config, DB session management, the FastAPI app shell).
Zero product code existed — no scanning, no findings, nothing
resembling what RiskReveal actually does. Building a complete
multi-tenant RBAC layer as the next step, before any real working path
through the system exists, means designing organizations and
permissions in the abstract, against nothing. It's also exactly the
condition that let two sessions independently invent two different
`main.py` designs (§1, item 2) — nothing real existed yet to anchor
either decision against.

**Revised order — get one real path working end to end first:**

1. ~~`domain/users/models.py`~~ — **done, this session**
2. ~~`core/security.py`~~ — **done, this session**
3. First Alembic migration, generated from the `User` model — **next**
4. `api/v1/routes/auth.py` — register/login, single-user, no role checks
5. **Pivot point** — skip organizations/RBAC here; go straight to:
   `domain/assets/models.py`, `domain/scanning/models.py`,
   `domain/findings/models.py` (minimal versions — enough to store a
   scan and its findings, not the full data model from the rebuild plan)
6. `engines/nmap_engine.py` — a real Nmap wrapper and XML parser
7. `tasks/celery_app.py` + `tasks/scan_tasks.py` — Celery wired up
   (`--pool=solo` on Windows — the default `prefork` pool needs
   `os.fork()`, which doesn't exist there)
8. `api/v1/routes/scans.py` + `api/v1/routes/findings.py` — trigger a
   scan, list results
9. **Milestone**: register → log in → scan `scanme.nmap.org` (Nmap's own
   public test target — safe to scan, no authorization concerns) → see
   real findings stored in the database

Only after that loop works end to end does the plan return to
organizations/RBAC, the threat-intelligence feeds, the risk scorer,
Nuclei, the AI agents, reports, and the frontend — the original order
from the rebuild plan, now picked back up with something real to anchor
those decisions against instead of building them speculatively.

**This session's two files fit both orderings** — a bare `User` model
without `organization_id` is exactly what step 1 of the revised order
needed, and it's not wasted work if organizations get added back later
(that's an additive migration, not a rewrite).

---

## 4. Everything still true, unchanged from the prior handoff

Carried forward without modification — see
`RiskReveal_v2_Handoff_Updated.md` for the full text:

- §2 (Project and local environment): Windows/PowerShell, no WSL, repo
  at `D:\WORK\VS Code\riskreveal`, Python 3.12.16, `src` layout, `uv`
  for dependency management.
- §3 (Architecture decisions): `main` branch baseline, FastAPI, fresh
  Alembic baseline, fail-closed secrets, no `dev` branch attack-engine
  code — unchanged, except the build-order sub-point, which §3 above
  revises.
- §5 (Docker work completed): Compose at `infra\docker-compose.yml`,
  project name `riskreveal-v2`, Postgres/Redis only, last verified
  healthy — **re-check it's still running**, per §1 above.
- §6 (Commands) and the `.env` working-directory gotcha: unchanged —
  always `Set-Location` into `backend\` before launching Uvicorn, or
  settings silently fail to load from `backend\.env`.
- §9 (Operating instructions): unchanged — read-only audit first, never
  paste `.env` contents into chat, no destructive Docker commands
  without approval, small verified steps, PowerShell not Bash.

---

## 5. Commands for this session's work specifically

Nothing runnable changed yet from a clean-environment perspective —
these two files add Python dependencies (`argon2-cffi`, `pyjwt`) that
need installing, and there's no new route or migration to hit yet.

```powershell
Set-Location "D:\WORK\VS Code\riskreveal\backend"
uv add argon2-cffi pyjwt   # if not already present in pyproject.toml
uv sync
```

No new HTTP endpoint exists from this batch — `core/security.py` and
`domain/users/models.py` are building blocks for step 3 (the Alembic
migration) and step 4 (`auth.py`) in §3's order, not yet wired into
anything requestable. The existing `/healthz` (or whichever health
endpoint is actually on disk, per §1) is still the only thing to check
after `uvicorn riskreveal.main:app --reload`.

---

## 6. What's actually next

**Step 3 from §3: the first Alembic migration.**

Concretely: `alembic init` (if not already run), point `env.py` at
`Base.metadata` from `db/base.py` and make sure it imports
`riskreveal.domain.users.models` (directly or via
`riskreveal.domain.users`) so `User` is registered on `Base.metadata`
before autogenerate runs — a model that's never imported anywhere is
invisible to Alembic's autogenerate, even though it inherits from the
right `Base`. Then `alembic revision --autogenerate -m "create users
table"` and `alembic upgrade head` — this is the point where the
`riskreveal-v2` database actually gets its first real table.

After that: `api/v1/routes/auth.py` (register/login), then the pivot to
assets/scanning/findings per §3.

---

## 7. Known vs. still unverified (updated)

### Known

- Everything in the prior handoff's "Known" section (§8 there) still
  holds.
- `domain/users/models.py` and `core/security.py` were written, run,
  and verified this session — see §2.1 for exactly what that covered.
- No Alembic setup has been run yet in this session — `User` exists as
  a Python class with no corresponding database table.

### Must be checked before continuing

- Everything in the prior handoff's "must be checked" list (§8 there)
  — none of it has been resolved by this session's work.
- Whether `alembic init` has already been run in this project (check
  for an `alembic/` or `migrations/` directory and `alembic.ini`'s
  contents) before assuming it needs to be run fresh.
- Whether `argon2-cffi` and `pyjwt` are already in `pyproject.toml` from
  a prior session, or need adding now.
