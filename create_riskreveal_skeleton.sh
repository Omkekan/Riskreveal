#!/usr/bin/env bash
# RiskReveal rebuild — skeleton generator
#
# Creates the full folder/file structure from
# `05_Rebuild_Structure_and_File_Plan.md` §1, with every file pre-filled
# with a one-line TODO pointing back at the relevant table in that doc.
#
# Usage:
#   bash create_riskreveal_skeleton.sh [target-dir]
#
# Default target-dir is "riskreveal". Safe to re-run: existing files are
# left untouched (never overwritten), so you can run this once, start
# editing, and run it again later if the plan grows new files.
#
# NOT created here on purpose (generate these with their own tools
# instead of hand-writing them):
#   backend/uv.lock          -> run `uv lock` after writing pyproject.toml
#   frontend/pnpm-lock.yaml  -> run `pnpm install` after writing package.json
#   backend/src/riskreveal/db/migrations/* -> run `alembic init` once
#       models exist, or regenerate the baseline per plan decision #4

set -euo pipefail

ROOT="${1:-riskreveal}"

mkf() {
  local relpath="$1"
  local full="$ROOT/$relpath"
  local base
  base="$(basename "$relpath")"

  mkdir -p "$(dirname "$full")"

  if [ -e "$full" ]; then
    echo "skip (exists):   $relpath"
    return
  fi

  case "$base" in
    *.gitkeep)
      : > "$full"
      ;;
    *.py)
      printf '"""TODO: %s\n\nSee 05_Rebuild_Structure_and_File_Plan.md for what belongs here.\n"""\n' \
        "$relpath" > "$full"
      ;;
    *.ts|*.tsx)
      printf '// TODO: %s\n// See 05_Rebuild_Structure_and_File_Plan.md for what belongs here.\n' \
        "$relpath" > "$full"
      ;;
    *.md)
      printf '# %s\n\nTODO.\n' "$base" > "$full"
      ;;
    *.json)
      printf '{}\n' > "$full"
      ;;
    *.yml|*.yaml)
      printf '# TODO: %s\n' "$relpath" > "$full"
      ;;
    *)
      printf '# TODO: %s\n' "$relpath" > "$full"
      ;;
  esac
  echo "created:         $relpath"
}

FILES=(
  # ---------------------------------------------------------------- backend
  "backend/pyproject.toml"
  "backend/alembic.ini"
  "backend/Dockerfile"
  "backend/Dockerfile.worker"
  "backend/Dockerfile.scanner"
  "backend/.env.example"

  "backend/src/riskreveal/__init__.py"
  "backend/src/riskreveal/main.py"
  "backend/src/riskreveal/config.py"
  "backend/src/riskreveal/dependencies.py"
  "backend/src/riskreveal/logging.py"

  "backend/src/riskreveal/core/__init__.py"
  "backend/src/riskreveal/core/security.py"
  "backend/src/riskreveal/core/exceptions.py"
  "backend/src/riskreveal/core/pagination.py"
  "backend/src/riskreveal/core/rate_limit.py"

  "backend/src/riskreveal/db/__init__.py"
  "backend/src/riskreveal/db/base.py"
  "backend/src/riskreveal/db/session.py"
  "backend/src/riskreveal/db/migrations/env.py"
  "backend/src/riskreveal/db/migrations/versions/.gitkeep"

  "backend/src/riskreveal/domain/__init__.py"

  "backend/src/riskreveal/domain/users/__init__.py"
  "backend/src/riskreveal/domain/users/models.py"
  "backend/src/riskreveal/domain/users/schemas.py"
  "backend/src/riskreveal/domain/users/service.py"
  "backend/src/riskreveal/domain/users/repository.py"

  "backend/src/riskreveal/domain/organizations/__init__.py"
  "backend/src/riskreveal/domain/organizations/models.py"
  "backend/src/riskreveal/domain/organizations/schemas.py"
  "backend/src/riskreveal/domain/organizations/service.py"
  "backend/src/riskreveal/domain/organizations/repository.py"
  "backend/src/riskreveal/domain/organizations/rbac.py"

  "backend/src/riskreveal/domain/audit/__init__.py"
  "backend/src/riskreveal/domain/audit/models.py"
  "backend/src/riskreveal/domain/audit/service.py"

  "backend/src/riskreveal/domain/credentials/__init__.py"
  "backend/src/riskreveal/domain/credentials/models.py"
  "backend/src/riskreveal/domain/credentials/schemas.py"
  "backend/src/riskreveal/domain/credentials/service.py"
  "backend/src/riskreveal/domain/credentials/vault.py"

  "backend/src/riskreveal/domain/assets/__init__.py"
  "backend/src/riskreveal/domain/assets/models.py"
  "backend/src/riskreveal/domain/assets/schemas.py"
  "backend/src/riskreveal/domain/assets/service.py"
  "backend/src/riskreveal/domain/assets/repository.py"
  "backend/src/riskreveal/domain/assets/identity_resolution.py"

  "backend/src/riskreveal/domain/scanning/__init__.py"
  "backend/src/riskreveal/domain/scanning/models.py"
  "backend/src/riskreveal/domain/scanning/schemas.py"
  "backend/src/riskreveal/domain/scanning/service.py"
  "backend/src/riskreveal/domain/scanning/scope_policy.py"
  "backend/src/riskreveal/domain/scanning/profiles.py"

  "backend/src/riskreveal/domain/findings/__init__.py"
  "backend/src/riskreveal/domain/findings/models.py"
  "backend/src/riskreveal/domain/findings/schemas.py"
  "backend/src/riskreveal/domain/findings/service.py"
  "backend/src/riskreveal/domain/findings/lifecycle.py"
  "backend/src/riskreveal/domain/findings/dedupe.py"

  "backend/src/riskreveal/domain/intelligence/__init__.py"
  "backend/src/riskreveal/domain/intelligence/models.py"
  "backend/src/riskreveal/domain/intelligence/matcher.py"
  "backend/src/riskreveal/domain/intelligence/sync_tasks.py"
  "backend/src/riskreveal/domain/intelligence/sources/__init__.py"
  "backend/src/riskreveal/domain/intelligence/sources/cvelistv5.py"
  "backend/src/riskreveal/domain/intelligence/sources/nvd.py"
  "backend/src/riskreveal/domain/intelligence/sources/cisa_kev.py"
  "backend/src/riskreveal/domain/intelligence/sources/first_epss.py"
  "backend/src/riskreveal/domain/intelligence/sources/exploitdb.py"
  "backend/src/riskreveal/domain/intelligence/sources/osv.py"
  "backend/src/riskreveal/domain/intelligence/sources/distro/__init__.py"
  "backend/src/riskreveal/domain/intelligence/sources/distro/ubuntu.py"
  "backend/src/riskreveal/domain/intelligence/sources/distro/debian.py"
  "backend/src/riskreveal/domain/intelligence/sources/distro/redhat.py"
  "backend/src/riskreveal/domain/intelligence/sources/distro/msrc.py"

  "backend/src/riskreveal/domain/risk/__init__.py"
  "backend/src/riskreveal/domain/risk/scorer.py"
  "backend/src/riskreveal/domain/risk/schemas.py"

  "backend/src/riskreveal/domain/agents/__init__.py"
  "backend/src/riskreveal/domain/agents/base.py"
  "backend/src/riskreveal/domain/agents/schemas.py"
  "backend/src/riskreveal/domain/agents/verifier.py"
  "backend/src/riskreveal/domain/agents/related_findings.py"
  "backend/src/riskreveal/domain/agents/chain_analyzer.py"
  "backend/src/riskreveal/domain/agents/evidence.py"
  "backend/src/riskreveal/domain/agents/mitigation.py"
  "backend/src/riskreveal/domain/agents/pipeline.py"

  "backend/src/riskreveal/domain/reports/__init__.py"
  "backend/src/riskreveal/domain/reports/service.py"
  "backend/src/riskreveal/domain/reports/renderers/__init__.py"
  "backend/src/riskreveal/domain/reports/renderers/pdf.py"
  "backend/src/riskreveal/domain/reports/renderers/docx.py"
  "backend/src/riskreveal/domain/reports/renderers/json_.py"
  "backend/src/riskreveal/domain/reports/templates/.gitkeep"

  "backend/src/riskreveal/domain/remediation/__init__.py"
  "backend/src/riskreveal/domain/remediation/models.py"
  "backend/src/riskreveal/domain/remediation/schemas.py"
  "backend/src/riskreveal/domain/remediation/service.py"

  "backend/src/riskreveal/engines/__init__.py"
  "backend/src/riskreveal/engines/base.py"
  "backend/src/riskreveal/engines/discovery_engine.py"
  "backend/src/riskreveal/engines/nmap_engine.py"
  "backend/src/riskreveal/engines/nuclei_engine.py"
  "backend/src/riskreveal/engines/script_classifier.py"
  "backend/src/riskreveal/engines/normalizer.py"
  "backend/src/riskreveal/engines/auth_collectors/__init__.py"
  "backend/src/riskreveal/engines/auth_collectors/ssh_collector.py"
  "backend/src/riskreveal/engines/auth_collectors/winrm_collector.py"

  "backend/src/riskreveal/api/__init__.py"
  "backend/src/riskreveal/api/v1/__init__.py"
  "backend/src/riskreveal/api/v1/router.py"
  "backend/src/riskreveal/api/v1/routes/__init__.py"
  "backend/src/riskreveal/api/v1/routes/auth.py"
  "backend/src/riskreveal/api/v1/routes/users.py"
  "backend/src/riskreveal/api/v1/routes/organizations.py"
  "backend/src/riskreveal/api/v1/routes/assets.py"
  "backend/src/riskreveal/api/v1/routes/credentials.py"
  "backend/src/riskreveal/api/v1/routes/scans.py"
  "backend/src/riskreveal/api/v1/routes/findings.py"
  "backend/src/riskreveal/api/v1/routes/reports.py"
  "backend/src/riskreveal/api/v1/routes/remediation.py"
  "backend/src/riskreveal/api/v1/routes/agents.py"
  "backend/src/riskreveal/api/v1/routes/dashboard.py"
  "backend/src/riskreveal/api/v1/routes/widgets.py"
  "backend/src/riskreveal/api/v1/routes/admin_feeds.py"

  "backend/src/riskreveal/tasks/__init__.py"
  "backend/src/riskreveal/tasks/celery_app.py"
  "backend/src/riskreveal/tasks/scan_tasks.py"
  "backend/src/riskreveal/tasks/agent_tasks.py"
  "backend/src/riskreveal/tasks/report_tasks.py"
  "backend/src/riskreveal/tasks/feed_tasks.py"
  "backend/src/riskreveal/tasks/beat_schedule.py"

  "backend/src/riskreveal/cli/__init__.py"
  "backend/src/riskreveal/cli/commands.py"

  "backend/tests/unit/.gitkeep"
  "backend/tests/integration/.gitkeep"
  "backend/tests/fixtures/.gitkeep"
  "backend/tests/e2e/.gitkeep"

  "backend/scripts/seed_dev_data.py"

  # --------------------------------------------------------------- frontend
  "frontend/package.json"
  "frontend/next.config.mjs"
  "frontend/tsconfig.json"
  "frontend/components.json"
  "frontend/Dockerfile"
  "frontend/.env.example"
  "frontend/middleware.ts"

  "frontend/app/(auth)/login/page.tsx"
  "frontend/app/(auth)/register/page.tsx"
  "frontend/app/(app)/layout.tsx"
  "frontend/app/(app)/dashboard/page.tsx"
  "frontend/app/(app)/scans/page.tsx"
  "frontend/app/(app)/scans/new/page.tsx"
  "frontend/app/(app)/scans/[id]/page.tsx"
  "frontend/app/(app)/scans/[id]/findings/[findingId]/page.tsx"
  "frontend/app/(app)/assets/page.tsx"
  "frontend/app/(app)/assets/[id]/page.tsx"
  "frontend/app/(app)/credentials/page.tsx"
  "frontend/app/(app)/remediation/page.tsx"
  "frontend/app/(app)/settings/profile/page.tsx"
  "frontend/app/(app)/settings/security/page.tsx"
  "frontend/app/(app)/settings/api-keys/page.tsx"
  "frontend/app/(app)/settings/organization/page.tsx"
  "frontend/app/api/[...path]/route.ts"
  "frontend/app/error.tsx"
  "frontend/app/global-error.tsx"
  "frontend/app/not-found.tsx"
  "frontend/app/loading.tsx"
  "frontend/app/layout.tsx"

  "frontend/features/auth/components/.gitkeep"
  "frontend/features/auth/hooks/.gitkeep"
  "frontend/features/auth/schemas.ts"

  "frontend/features/scans/components/.gitkeep"
  "frontend/features/scans/hooks/.gitkeep"
  "frontend/features/scans/schemas.ts"

  "frontend/features/findings/components/.gitkeep"
  "frontend/features/findings/hooks/.gitkeep"
  "frontend/features/findings/schemas.ts"

  "frontend/features/assets/components/.gitkeep"
  "frontend/features/assets/hooks/.gitkeep"
  "frontend/features/assets/schemas.ts"

  "frontend/features/credentials/components/.gitkeep"
  "frontend/features/credentials/hooks/.gitkeep"
  "frontend/features/credentials/schemas.ts"

  "frontend/features/reports/components/.gitkeep"
  "frontend/features/reports/hooks/.gitkeep"
  "frontend/features/reports/schemas.ts"

  "frontend/features/remediation/components/.gitkeep"
  "frontend/features/remediation/hooks/.gitkeep"
  "frontend/features/remediation/schemas.ts"

  "frontend/features/dashboard-widgets/components/.gitkeep"
  "frontend/features/dashboard-widgets/hooks/.gitkeep"
  "frontend/features/dashboard-widgets/schemas.ts"

  "frontend/features/attack-paths/components/.gitkeep"
  "frontend/features/attack-paths/hooks/.gitkeep"
  "frontend/features/attack-paths/schemas.ts"

  "frontend/components/ui/.gitkeep"
  "frontend/components/common/.gitkeep"

  "frontend/lib/api/.gitkeep"
  "frontend/lib/format.ts"
  "frontend/lib/env.ts"

  "frontend/tests/unit/.gitkeep"
  "frontend/tests/e2e/.gitkeep"

  # ------------------------------------------------------------------ infra
  "infra/docker-compose.yml"
  "infra/docker-compose.override.yml.example"

  # ------------------------------------------------------------------- docs
  "docs/architecture.md"
  "docs/api.md"
  "docs/threat-model.md"
  "docs/archive/.gitkeep"

  # ----------------------------------------------------------------- CI/CD
  ".github/workflows/ci.yml"
  ".github/workflows/images.yml"

  # ------------------------------------------------------------- repo root
  "SECURITY.md"
  "CONTRIBUTING.md"
  "CODEOWNERS"
  "CHANGELOG.md"
  "LICENSE"
  "README.md"
)

echo "Creating RiskReveal skeleton under: $ROOT/"
echo

for f in "${FILES[@]}"; do
  mkf "$f"
done

echo
echo "Done. ${#FILES[@]} paths processed under $ROOT/."
echo
echo "Next steps:"
echo "  1. cd $ROOT"
echo "  2. git init && git add -A && git commit -m 'Scaffold: empty rebuild structure'"
echo "  3. Fill in backend/pyproject.toml, then: cd backend && uv lock"
echo "  4. Fill in frontend/package.json, then: cd frontend && pnpm install"
echo "  5. Once backend/src/riskreveal/domain/*/models.py exist, run"
echo "     'alembic init' (or your chosen baseline-migration approach) to"
echo "     populate backend/src/riskreveal/db/migrations/ for real."
