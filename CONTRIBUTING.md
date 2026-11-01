# Contributing to RiskReveal

---

## 🛑 0. Prior Owner Permission Required

**RiskReveal is an actively architected security platform under strict owner control. No external contributions, pull requests, or code submissions are accepted without prior written permission from the repository owner (`@Omkekan`).**

* **Do NOT open unsolicited Pull Requests.** Any pull request submitted without prior explicit approval from `@Omkekan` will be closed immediately without review.
* **How to Request Permission**:
  1. Open a **GitHub Issue** describing the bug fix, architectural improvement, or feature slice you wish to work on.
  2. Wait for **`@Omkekan`** to review the proposal and explicitly assign the issue or grant written approval to proceed.
  3. All approved contributions are governed by [`CODEOWNERS`](CODEOWNERS), which requires mandatory review and sign-off from `@Omkekan` on all paths—especially security-critical modules (`core/security.py`, `domain/scanning/scope_policy.py`, `domain/scanning/authorization.py`, `config.py`, `infra/`, and `.github/`).

---

## 1. Before You Write Any Code

This section and the rules below apply to the repository owner, authorized contributors, and AI coding-assistant sessions continuing the build. These engineering gates have already caught real bugs in this codebase (a config setting that broke environment-variable matching, a Starlette debug-mode traceback leak, a JWT `alg=none` edge case, and a wildcard CPE update bug exposed by live NVD data).

1. **Read the Architecture & Threat Model First**: Review [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and the actual files on disk before modifying any module. Never assume a file's contents from an older summary.
2. **Verify Against Disk**: If you are continuing work from a handoff document, check `git --no-pager status --short` and inspect the actual files in the repository before building on top of them.

---

## 2. The Four Quality Gates Every Change Must Pass

Run all four commands from `backend/` before considering any change complete:

```powershell
Set-Location "backend"
uv run ruff check .
uv run mypy src
uv run pytest tests/unit
uv run pytest tests/integration   # requires Docker Desktop running (Testcontainers)
```

* All four gates **must** pass cleanly.
* `mypy` runs in `--strict` mode. Do not slap `# type: ignore` onto a real type error to make it disappear—fix the underlying types, or if an override is genuinely required for an untyped third-party library, configure it cleanly with an explanation.

### Database Migrations Gate

If you modified or added any SQLAlchemy model under `domain/*/models.py`:

1. Ensure the model module is imported in **both** `backend/src/riskreveal/db/migrations/env.py` and `backend/tests/conftest.py`, and update `_EXPECTED_TABLES` in `backend/tests/integration/test_migrations.py`.
2. Generate the migration:
   ```powershell
   uv run alembic revision --autogenerate -m "describe the schema change"
   ```
3. **Read the generated migration file line by line before applying it.** Verify that it contains only the intended schema changes, does not alter unrelated tables, and has a complete `downgrade()` function.
4. Verify the full migration round-trip:
   ```powershell
   uv run alembic upgrade head
   uv run alembic check
   uv run alembic downgrade -1
   uv run alembic upgrade head
   ```

---

## 3. "Verify, Don't Assume"

* **Exercise Real Behavior**: Reading a function and concluding it looks right is not verification. Run it against edge cases, malformed inputs, and boundary conditions.
* **Test Parsers & Matchers Against Real Data**: Synthetic fixtures are necessary for fast unit tests, but any module that parses or matches external data (Nmap XML, CISA KEV, FIRST EPSS, NVD CVE API 2.0) must also be verified against real data (`scripts/smoke_nmap.py`, `scripts/nvd_match_demo.py`, `python -m riskreveal.cli`).
* **Be Explicit About Verification Status**: In every PR description, commit summary, or handoff note, distinguish clearly between:
  * **Verified**: Executed on the target machine with real output confirmed.
  * **Sandbox-Verified**: Executed in an isolated test harness without full infrastructure.
  * **Delivered, Not Run**: Written and compile-checked, awaiting execution.

---

## 4. Code & Security Invariants (Do Not Violate)

1. **No `from __future__ import annotations` in Route Modules**: Files under `api/v1/routes/` and `core/pagination.py` must keep runtime type objects intact for FastAPI and `slowapi`.
2. **Services Commit; `get_db` Never Auto-Commits**: Keep each logical operation in a single transaction that rolls back completely on failure.
3. **Never Echo Secrets or Raw Tool Errors**: Keep `FastAPI(debug=False)`, keep Typer's `pretty_exceptions_show_locals=False`, never return raw `exc.errors()` in 422 handlers, and never write raw subprocess `stderr` or tracebacks into `Scan.error`.
4. **Never Bypass the Scope Policy or Allowlist**: Only `ValidatedTarget.scan_args` produced by `validate_target()` and approved by `check_authorized()` may ever be passed to a scanner engine.
5. **Untrusted Input Default-Closed**: Strip NUL bytes (`\x00`), clip strings to column lengths, and fail closed toward zero false alarms when version or range data cannot be parsed unambiguously.

---

## 5. Git & Pull Request Workflow

* **Commits**: Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
* **Secret Check Before Staging**: Always run `git --no-pager status --short` and `git --no-pager diff` before committing to ensure `.env` files, credentials, `.venv`, or `frontend/node_modules` are never staged.
* **Pull Requests**: Include what changed, why, which quality gates and live checks were executed, and whether any database migrations were added.
