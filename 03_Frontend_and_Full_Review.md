# RiskReveal – Frontend & Full-Project Review (Enterprise Lens)

*Companion to `01_Conversation_Summary.md` (backend review) and `02_RiskReveal_Master_Plan.md` (roadmap). This file covers the frontend, the frontend↔backend contract, repository and delivery issues that were still open, a keep / change / remove decision list, and the recommended tech stack.*

*Review date: 28 Oct 2026. Reviewed: the full uploaded ZIP (frontend, backend routes, Dockerfiles, README, `SecureLens_Project_Spec.md`, repo layout).*

---

## 0. How this was reviewed, and what is NOT verified

**Done:** read every non-generated frontend file (`app/page.tsx`, `lib/api.ts`, configs, Dockerfile, lockfile versions, the legacy `public/` files), read the backend routes the UI calls, and compared the two. Checked the pinned Next.js / React versions against the published security advisory.

**Not done, so treat accordingly:**
- I did **not build or run** the frontend. There is no `node_modules` in the ZIP and my sandbox has no network. Findings below come from reading the code. The ones where runtime behaviour matters are marked *(verify in browser)*.
- I could not type-check. Because `ignoreBuildErrors` is on, the number of hidden TypeScript errors is unknown.
- Items from the backend review (`01_…`, #1–#25) are not repeated here unless the frontend is affected.

---

## 1. Verdict

| Area | State | Enterprise-ready? |
|---|---|---|
| UI look and feel (shadcn/ui, dark mode, confirm dialogs) | Clean and consistent | Good base |
| Frontend architecture | One 51 KB client component with in-memory "views", no routes | **No** – rewrite structure |
| Security (frontend) | Known-RCE framework version, token in `localStorage`, no CSP | **No** |
| Correctness | A probable request-loop bug, unpolled report status, wrong timestamps | **No** |
| Findings / results UX | Minimal; severity never displayed | **No** – this is the core product |
| Accessibility | Zero `aria-label`s, icon-only buttons | **No** |
| Delivery (Docker, CI, tests, docs) | Docker image cannot reach the API; no CI; no tests | **No** |
| Tech-stack choice (Next.js + TS + Tailwind + shadcn) | Sound | **Keep** |

**Bottom line:** the *stack* is right; the *code structure and engineering around it* are prototype-grade. You do not need to throw the UI away. You need to re-structure it into routed pages, move to a typed data layer, harden auth, and fix the findings experience, which is the part customers actually pay for.

---

## 2. Frontend findings

Severity: **Critical** = fix before anyone else uses it · **High** = fix before a pilot · **Medium** = fix before GA · **Low** = polish.

### 2.1 Critical

| ID | Where | Problem | Fix |
|---|---|---|---|
| **F-01** | `package.json`, `pnpm-lock.yaml` | **Next.js 15.2.4 + React 19.1.0 are locked.** The App Router is in use (`app/`), which is the affected configuration for CVE-2025-55182 / CVE-2025-66478, an unauthenticated remote-code-execution flaw in React Server Components (CVSS 10.0). The Next.js advisory lists **15.2.6** as the fix for the 15.2 line and says there is no workaround. A vulnerability scanner shipping a known-RCE framework would be embarrassing in a customer's own scan. | Upgrade to the latest patched release of a supported Next.js line (check the current release at upgrade time), then run `pnpm audit`. More Next.js advisories were published after this one; I verified only this one. Add Dependabot/Renovate and an audit step in CI so this cannot recur. |
| **F-02** | `app/page.tsx`, the `useEffect` that loads dashboard data, plus `fetchUserProfile` / `fetchCredentials` / `fetchAssets` / `fetchDashboardStats` *(verify in browser)* | **Probable infinite request loop.** `user` is in the effect's dependency list. `fetchUserProfile` ends with `setUser(prev => ({...prev, ...data}))`, which always creates a new object, so `user` changes after every response, the effect re-runs, and four endpoints are called again, forever. A second bug sits on top: the effect cleanup calls `clearInterval(pollingRef.current)` but never sets the ref to `null`, and `startPolling` only starts when the ref is empty. After the first re-render, scan polling never restarts, so progress bars stop updating, including for scans started afterwards. | Check in DevTools → Network on the dashboard (you should see repeating `/credentials/`, `/assets/`, `/scans/stats`, `/user/profile`). Fix: depend on a boolean `isAuthenticated`, not the `user` object; never `setUser` with a fresh object unless a field changed; null the ref in cleanup. Better: replace all of this with TanStack Query (`refetchInterval`, pause when the tab is hidden). |
| **F-03** | `lib/api.ts`, `handleLogin`, `handleLogout` | **JWT and user profile stored in `localStorage`.** Any XSS (or any compromised npm dependency) can read the token and take over the account, which in this product also exposes stored scan credentials and findings. There is also no Content-Security-Policy. | Move to an HttpOnly + Secure + SameSite cookie session. Cleanest pattern: Next.js route handlers act as a backend-for-frontend (BFF): the browser holds only the cookie, the BFF attaches the bearer token to calls to the Flask API. This also removes CORS from the picture. Add a nonce-based CSP in middleware. |
| **F-04** | `lib/api.ts`; all `catch` blocks | **No session-expiry handling.** The backend token lives 1 hour (`JWT_ACCESS_TOKEN_EXPIRES = 3600`); there is no refresh token. The UI treats "a token string exists" as "logged in". After expiry every call fails, the UI shows generic "Failed to load…" banners, and the user is never sent back to login. Also, `flask-jwt-extended` replies `{"msg": …}` while your routes reply `{"message": …}`; the UI reads only `.message`, so JWT errors are never shown. | Axios/fetch interceptor: on 401 → try refresh once → else clear session and redirect to `/login?next=…`. Backend: add JWT error loaders so every error uses one shape (see C-01), add refresh tokens and short access-token lifetimes. |
| **F-05** | `Dockerfile`, `.dockerignore`, `lib/api.ts`, README | **The Docker image cannot reach the API.** `NEXT_PUBLIC_API_URL` is inlined at *build* time. The Dockerfile has no `ARG`/`ENV` for it, and `.dockerignore` excludes `.env` files, so the built image has `baseURL = undefined` and sends API calls to its own origin. The variable is not documented anywhere (README, no `.env.example`). The README also says `npm install` although only `pnpm-lock.yaml` exists. | Prefer same-origin `/api/*` through a reverse proxy or Next.js rewrites/BFF so there is **no** build-time URL at all. Add `.env.example` for both apps and fix the README. |
| **F-06** | Scan form (`DashboardPage`), `handleStartScan` | **No scope control or authorization attestation in the UI.** The target is free text with no validation, there is no "I am authorized to scan this" step, no allow-list, and no block on loopback / link-local / cloud-metadata ranges (`169.254.169.254`, `127.0.0.0/8`, internal RFC1918 ranges when not intended). The backend does not enforce any either (`01_…` #4). This is the single biggest legal and abuse risk of the product. | Validate type (IP / CIDR / hostname / URL) client- *and* server-side; per-organization allow-lists; domain-ownership verification for external targets; an attestation checkbox whose acceptance is written to the audit log; an approval workflow for large CIDRs. |

### 2.2 High

| ID | Where | Problem | Fix |
|---|---|---|---|
| **F-07** | `app/page.tsx` (`currentView` state) | **No routing.** Pages are `useState` "views". No URLs, so no deep links, no working Back button, no bookmarking or sharing of a finding, and **refreshing the results page drops you on the dashboard** (the selected scan is only in memory). The dashboard "tabs" are also state, not URLs. | App Router pages: `/login`, `/register`, `/dashboard`, `/scans`, `/scans/[id]`, `/scans/[id]/findings/[findingId]`, `/assets`, `/assets/[id]`, `/credentials`, `/settings`. Route groups `(auth)` and `(app)`; `middleware.ts` redirects unauthenticated users. |
| **F-08** | `app/page.tsx` | **A 462-line, 51 KB single file.** Six lines exceed 1,500 characters (longest 4,066). `DashboardPage` is effectively one line. Components are defined *after* the component that uses them, props are `[key: string]: any`, and every page receives 15–20 callbacks through props. It cannot be code-reviewed, unit-tested, or safely changed by more than one person. | Split into `features/{auth,scans,findings,assets,credentials,settings}/` with their own hooks (`useScans`, `useFindings`), components and schemas. Enforce Prettier so lines wrap. |
| **F-09** | `app/page.tsx` line 1 (`"use client"`) | **The whole app is one client component.** No server rendering, no streaming, no route-level code-splitting. Recharts and every Radix primitive load for the login screen. | Server Components for shells and data-heavy pages; client components only for interactive leaves; `next/dynamic` for charts and the attack-graph. |
| **F-10** | `fetchScans`, scan-history row, `getStatusBadge` | **Report generation is effectively invisible and cannot be retried.** (a) Polling stops unless a scan is `RUNNING`/`QUEUED`, so `GENERATING_REPORT` is never polled and the UI never learns the report is ready. (b) The View / Download / Generate buttons render only when status is `COMPLETED`, so during `GENERATING_REPORT` and after `FAILED_REPORT` there is no View and no retry button, although the backend allows retry from `FAILED_REPORT`. (c) Generate and Download are two separate menus; downloading before generating gives a 404 banner. Root cause is the backend reusing `Scan.status` (`01_…` #19). | Make "report" its own resource with its own status: `POST /scans/{id}/reports {format}` → `report_id`; `GET /reports/{id}` for status; one "Export" menu that generates if needed, shows progress, then downloads. Use `Content-Disposition` from the server for filenames. |
| **F-11** | `ScanResultsPage` | **The findings view is too thin to be a product.** `severity` is fetched but **never rendered**; `prioritized_vector` and `open_ports` are fetched but not shown; no CVE ID or link; no filter, sort, search, or grouping; all findings are `<details>` blocks in one long list (no pagination or virtualization, so hundreds of findings will freeze the page); no finding detail page; no status/assignee; no confidence or source (essential once AI verification exists). | Build the findings table (TanStack Table + virtualization): severity, risk score, CVE (linked), asset, port/service, confidence, source, status, first/last seen; saved filters; group by asset / by fix; finding detail route with score breakdown, evidence, AI verdict, references, history. |
| **F-12** | `DashboardWidgets`, `/scans/stats` | **Dashboard numbers do not reconcile.** The chart omits Informational findings but "Vulnerabilities Found" counts all of them, so the bars do not sum to the headline. No trend over time, no date range, no per-group view. Asset counts are per-scan rows (`01_…` #22). | Define each metric once (server-side), include all severities, add trend lines (new / fixed / open over time), aging, KEV exposure, SLA compliance. |
| **F-13** | `new Date(scan.start_time)`; backend `datetime.utcnow()` + `.isoformat()` | **Wrong times for every user outside UTC.** The backend stores naive UTC and returns ISO strings with no offset; browsers parse offset-less ISO strings as *local* time. For a user in India (UTC+5:30), scan times appear 5½ hours early. | Backend: timezone-aware UTC (`datetime.now(timezone.utc)`, `DateTime(timezone=True)`), serialize with `Z`. Frontend: format with `Intl.DateTimeFormat` plus relative time ("3 min ago"). |
| **F-14** | `next.config.mjs`, `package.json` | **All quality gates are switched off.** `typescript.ignoreBuildErrors: true` and `eslint.ignoreDuringBuilds: true`. There is a `lint` script but no ESLint dependency. 15 `catch (error: any)`, `any` props, **zero tests** of any kind. | Turn both flags off, fix the errors, add ESLint (`next/core-web-vitals`, `typescript-eslint`, `jsx-a11y`), `tsc --noEmit` and tests as required CI checks. |
| **F-15** | `loading` state in `RiskRevealApp` | **One global `loading` boolean** is shared by login, register, scan start, credentials, confirm-dialog, report actions and the asset table. Doing one thing disables or spins unrelated buttons, e.g. the asset table shows its spinner while a dialog action runs. | Per-mutation pending state (TanStack Query `useMutation`). |
| **F-16** | `AssetManagementPage` | **Asset criticality `<Select>` is uncontrolled (`defaultValue`)** and the update is optimistic with no rollback. After a refetch, or if the PUT fails, the dropdown shows the wrong value. | Controlled `value`; optimistic update with rollback on error; confirm on bulk changes. |
| **F-17** | startup `useEffect` | **Crash risk and no error boundaries.** `JSON.parse(localStorage.user)` is unguarded, so a corrupted value white-screens the whole app. There is no `error.tsx`, `global-error.tsx` or `not-found.tsx`; `loading.tsx` returns `null`. | Add the boundary files, guard parsing (or drop `localStorage` for session data per F-03). |
| **F-18** | `handleStartScan`, `handleAddCredential`, `handleConfirmAction`, `handleGenerateReport` | **Server error messages are discarded.** These show a generic "Failed to…" even when the API returned a precise reason (400/404). Users cannot tell *why* a scan did not start. | Surface the server's message; field-level errors on forms (see C-01). |

### 2.3 Medium

| ID | Where | Problem | Fix |
|---|---|---|---|
| **F-19** | whole UI | **Accessibility.** `aria-label` appears **0** times. Icon-only buttons (theme toggle, floating nav, delete-credential, user menu) have no accessible name; the logo is a clickable `<div>`; no `<main>` landmark; the dashboard tabs are CSS-hidden `div`s rather than an ARIA tablist; status is partly colour-only; the message banner has no `role="status"`. Enterprise procurement asks for WCAG 2.2 AA / a VPAT. | `eslint-plugin-jsx-a11y`, `@axe-core/playwright` in CI, shadcn `Tabs`, proper labels, focus management in dialogs, contrast check on severity colours. |
| **F-20** | `message` banner in `RiskRevealApp` | **Home-made notifications.** The banner is not fixed (invisible when scrolled), uses `bg-green-100 text-green-800` (unreadable/inconsistent in dark mode), and the `setTimeout` is never cleared, so an earlier timer can hide a newer message. `sonner` and shadcn `Toaster` are already in the project but unused. | Use `sonner`. |
| **F-21** | `FloatingNav` | Bottom floating nav shows **icons only** (labels only in tooltips), overlaps content on mobile, and is undiscoverable. | Sidebar (desktop) + bottom tab bar with labels (mobile); active route highlighting. |
| **F-22** | chart colours, `getScoreBadge` | **No design tokens for severity.** Hex colours hard-coded in the chart and Tailwind palette classes in badges; no dark-mode variants; contrast unchecked. | CSS variables `--sev-critical…--sev-info` (light/dark), one `<SeverityBadge>` used everywhere. |
| **F-23** | login / register / settings forms | Manual `useState` forms with no schema validation, although `react-hook-form` and `zod` are installed and unused. No password policy or strength feedback, no `autoComplete` attributes (password managers), no show/hide, no lockout or rate-limit message. Registration is open to anyone. | RHF + zod, shared schemas with the API; invite-only or SSO for enterprise tenants. |
| **F-24** | Credentials tab | **Only username + password** (effectively SMB-style). Enterprise needs credential *types* (SSH key/agent, WinRM, SNMPv3, API token, cloud role), edit/rotate, "test connection", per-credential scope, last-used and audit trail. No warning if `baseURL` is plain HTTP, which would send passwords in clear. | Typed credential forms, vault-backed storage, usage audit, HTTPS-only enforcement. |
| **F-25** | `startPolling` | Fixed 5 s polling of the **whole, unpaginated** scan list, even in background tabs. | TanStack Query `refetchInterval` with `refetchIntervalInBackground: false`; later SSE/WebSocket for live progress; paginate. |
| **F-26** | `public/` folder | **Abandoned Create-React-App code inside `public/`**: `App.js`, `index.js`, `pages/*.js`, `context/AuthContext.js`, CSS. It imports modules that do not exist (`react-router-dom`, `./components/PrivateRoute`, `./assets/logo.png`, `../api/axiosConfig`), so it can never run. Everything in `public/` is **served to the internet as static files**, so this is dead code that is also publicly downloadable. | Delete it. |
| **F-27** | duplicates / unused | `styles/globals.css` (different palette) duplicates `app/globals.css`; `components/ui/use-mobile.tsx` and `use-toast.ts` are byte-identical copies of `hooks/`; **40 of 50** shadcn components are never imported; `zod`, `@hookform/resolvers`, `date-fns`, `geist` are imported nowhere. | Remove; add `knip` to CI to catch unused files and dependencies. |
| **F-28** | `package.json` | Housekeeping: package name `my-v0-project`; `"type": "commonjs"` and `"main": "index.js"` are meaningless for a Next app; license field `ISC` vs `MIT` in `LICENSE`; `next-themes: "latest"` is unpinned; pinned and caret ranges are mixed; no `engines`; `date-fns` 4.x alongside `react-day-picker` 8.10 (I believe 8.x supports date-fns 2/3 only; not verified). | Clean the manifest, pin everything through the lockfile, set `engines` and `.nvmrc`. |
| **F-29** | `app/layout.tsx` | `next/font/google` (Inter) needs internet access **at build time**, which breaks air-gapped or locked-down CI. `geist` is installed but unused. | Use `geist` or self-host the font files. |
| **F-30** | `next.config.mjs` | A personal LAN address (`http://192.168.40.1:3000`) is committed in `allowedDevOrigins`. No security headers (CSP, HSTS, `frame-ancestors`/X-Frame-Options, Referrer-Policy, Permissions-Policy); `X-Powered-By` is left on. | Remove the IP; set headers in `next.config` / middleware; `poweredByHeader: false`. |
| **F-31** | `Dockerfile` | Runs as **root**; copies the whole `node_modules` (dev + prod) instead of Next's `standalone` output; `npm install -g pnpm` takes whatever version is current; no `NODE_ENV=production`, no `HEALTHCHECK`; `node:20-alpine` (Node 20 left upstream maintenance in April 2026 — please verify against the Node release schedule). | `output: "standalone"`, non-root user, pinned pnpm via `corepack`, Node 22 or 24 LTS, healthcheck, image scan with Trivy in CI. |
| **F-32** | whole UI | No tests, no CI, no Storybook/visual regression, no error monitoring. | Vitest + Testing Library, Playwright E2E (login → scan → results → export), MSW for API mocks, Sentry. |

### 2.4 Low

| ID | Problem |
|---|---|
| **F-33** | Landing page, login and dashboard share one shell; login uses `min-h-screen` inside a layout that already has a 64 px sticky header, so it scrolls unnecessarily. |
| **F-34** | No favicon / manifest / per-page titles; metadata is a single static title. |
| **F-35** | No i18n; dates and numbers use default `toLocaleString()`. Plan for `next-intl` if you sell outside English-speaking markets. |
| **F-36** | `user` (including email) is persisted in `localStorage`, which is unnecessary PII at rest in the browser. Resolved by F-03. |
| **F-37** | Logout only clears the browser; the token stays valid until expiry (no server-side revocation). Needs a backend denylist or short-lived tokens plus refresh rotation. |
| **F-38** | `dangerouslySetInnerHTML` appears only in shadcn's unused `chart.tsx`, and finding text/evidence is rendered through React (auto-escaped), so there is **no stored-XSS issue in the results page today**. Keep it that way: never render evidence or banners as HTML, and sanitize if you ever add Markdown for AI explanations. |

---
## 3. Frontend ↔ backend contract problems

These sit between the two apps, so they are easy to miss when reviewing either one alone.

| ID | Problem | Fix |
|---|---|---|
| **C-01** | **Two error shapes.** Your routes return `{"message": …}`; `flask-jwt-extended` returns `{"msg": …}` (no custom error loaders are registered); validation failures return nothing structured. The UI cannot show auth errors or field-level errors. | One format everywhere, e.g. RFC 9457 *Problem Details* (`type`, `title`, `status`, `detail`, `errors[]`), plus JWT error loaders. |
| **C-02** | **No pagination, filtering or sorting** on `/scans/`, `/assets/`, `/scans/{id}/results`. The UI loads everything and polls it every 5 s. | Cursor pagination + `?severity=&status=&q=&sort=` on every list endpoint. |
| **C-03** | **No API specification.** The UI's TypeScript interfaces are hand-written inside `page.tsx` and can silently drift from the Flask responses. | Publish an OpenAPI document from the backend and generate the TS client and types from it (`openapi-typescript`). |
| **C-04** | `GET /user/profile` returns only `username` and `email`: no id, role, organization, permissions. The UI cannot gate features by role; `is_admin` exists only inside the JWT. | Return `{id, username, email, org, role, permissions[], mfa_enabled}`. |
| **C-05** | Login returns only `access_token`. No refresh token, no expiry, no user object, so the UI invents `{username, email: ""}` after login. | Return session metadata; refresh-token rotation; `POST /auth/logout` with revocation. |
| **C-06** | `/results` omits what the UI will need once the engine is fixed: port, protocol, service, product, version, CPE, source, confidence, status, first/last seen, AI verdict. `/scans/stats` omits Informational. | Extend the Finding schema as listed in `01_…` §5.3; add `include=` options. |
| **C-07** | `POST /scans/start` returns `202` + `scan_id`, but the UI neither navigates to the scan nor shows validation errors; there is no idempotency key, so a double-click can start two scans. | Navigate to `/scans/{id}`; `Idempotency-Key` header; structured validation errors. |
| **C-08** | **CORS is hard-coded** to `localhost:3000/3001` for `/api/*` only, so production needs a code change; `supports_credentials=True` is unnecessary with header tokens. | Read allowed origins from config, or remove CORS entirely by using the same-origin BFF proxy (F-03). |
| **C-09** | **Mixed identity access.** Some routes use `get_jwt_identity()` (a string), others `get_jwt()['user_id']` (an int). Works today, but it invites bugs and will matter once org/tenant scoping is added. | One `current_user()` helper that returns a typed principal (user, org, role) and is the only way routes get identity. |
| **C-10** | **File names are decided in two places.** The server builds report names from `target_name`; the client builds its own download name. Collisions between users and path-traversal risk are already noted in `01_…` #5. | Reports addressed by ID; server sets `Content-Disposition`; storage keys are UUIDs. |
| **C-11** | **No real-time channel.** Scan progress, report status and agent steps all rely on polling. | Server-Sent Events first (simple, works with gevent); WebSockets only if you need two-way. |

---

## 4. Repository, delivery and process issues still open

| ID | Problem | Fix |
|---|---|---|
| **R-01** | **Real scan output is committed**: `Backend…/instance/reports/*.pdf|docx|json`. These may contain target names, IPs and findings. | Add `instance/` to `.gitignore`; remove from history (`git filter-repo` or BFG) and treat any exposed target data as disclosed. |
| **R-02** | `riskreveal.egg-info/` (a build artefact) is committed. | Remove; ignore `*.egg-info/`. |
| **R-03** | `SecureLens_Project_Spec.md` (45 KB) sits in the repo root. It specifies a **different product** (FastAPI, Semgrep SAST, ML triage) and contradicts RiskReveal's own plan. It confuses contributors and AI coding assistants pointed at the repo. | Move to `docs/archive/` or a separate repo; keep one source of truth for the roadmap. |
| **R-04** | `nuclei/` is an empty directory. | Either commit your custom templates there, document it as a submodule, or delete it. |
| **R-05** | Folder names contain spaces (`Backend Riskreveal app`, `Frontend Riskreveal app`), which breaks Docker contexts, CI paths and shell scripts. | Rename to `backend/` and `frontend/`. |
| **R-06** | **No CI/CD at all** (no `.github/`), no pre-commit hooks, no Dependabot/Renovate, no SAST or secret scanning. | GitHub Actions: lint, type-check, unit + E2E tests, `pip-audit`/`pnpm audit`, Semgrep, gitleaks, Trivy on images; required checks on `main`. |
| **R-07** | **No tests** in either app. | Backend: pytest with recorded Nmap/Nuclei fixtures. Frontend: see F-32. Coverage gate on parsers, scoring and auth. |
| **R-08** | `migrations/` has `env.py` and `alembic.ini` but **no `versions/`**, so schema changes cannot be applied to an existing database. | Generate and commit the baseline migration; test upgrade and downgrade in CI. |
| **R-09** | **Nothing runs the whole stack**: no `docker-compose.yml` (API, worker, Redis, Postgres, frontend), no Helm/Terraform. | Compose for dev and demo; Helm or Kustomize + Argo CD for production later. |
| **R-10** | Docs: no `.env.example` (either app), README says `npm install` (repo uses pnpm) and `--pool=solo` (code uses gevent), no architecture doc, API doc, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG`, `CODEOWNERS`. | Write them; `SECURITY.md` matters for a security product. |
| **R-11** | Dependencies are declared in both `Requirement.txt` and `pyproject.toml`, with a non-standard filename. | One source (uv/Poetry lockfile). |
| **R-12** | **Licensing and legal.** Repo is MIT; Nmap's licence restricts bundling it in distributed proprietary products (see my stack note; confirm with a lawyer). No Terms of Service covering authorized scanning, no privacy policy, no data-retention policy. | Decide the commercial licence model; get a legal review before shipping any image containing Nmap or other copyleft tools. |
| **R-13** | No threat model, no data-flow diagram, no retention or deletion policy. Security buyers ask for these first. | Write a short threat model (STRIDE) for the API, workers, evidence store and AI pipeline. |

---

## 5. Enterprise capability gaps (what a buyer will ask for)

Mapped to your Master Plan phases so nothing is duplicated.

| Capability | Today | Needed | Plan phase |
|---|---|---|---|
| SSO (OIDC/SAML), MFA, SCIM | Username + password, open registration | Yes | 8 |
| Organizations, teams, RBAC (admin / analyst / viewer / auditor) | `is_admin` flag only | Yes | 8 |
| Audit log (logins, scans, credential use, exports, setting changes) | None | Yes, exportable | 8 |
| Scan policies / templates, scheduling, maintenance windows | Three hard-coded scan types | Yes | 1, 6 |
| Scan-engine / agent management (health, version, network zone) | None | Yes | 8 |
| Asset inventory with groups, tags, owners, business units | Per-scan asset rows | Persistent inventory | 6 |
| Finding lifecycle (new / open / fixed / reopened), assignee, SLA, risk acceptance with expiry | None | Yes | 6 |
| Delta / compare scans, trends, aging | None | Yes | 6, 7 |
| Ticketing and chat (Jira, ServiceNow, GitHub, Slack/Teams), webhooks, SIEM export | None | Yes | 7 |
| Public REST API with API keys, rate limits, OpenAPI | Internal only | Yes | 7 |
| Report types (executive, technical, remediation plan, delta, compliance) | One layout per format | Yes | 7 |
| AI results in the UI: verdict, confidence, evidence viewer, citations, attack-path graph | None | Yes | 5 |
| Data retention, export/delete (GDPR-style), encryption at rest, backups | None documented | Yes | 8 |
| Accessibility (WCAG 2.2 AA), i18n, white-label | None | Accessibility yes | 7 |
| Status/health page, in-app notices for feed freshness | None | Yes | 8 |

---

## 6. Keep / Change / Remove

### 6.1 KEEP (these decisions are good)

| Item | Why |
|---|---|
| **Next.js + TypeScript + Tailwind + shadcn/ui** | Right stack for an enterprise dashboard; large ecosystem, easy to hire for. The issue is *how* it is used, not the choice. (After patching: F-01.) |
| `next-themes` light/dark/system | Works; enterprises like dark mode for SOC use. |
| `lucide-react`, Radix primitives via shadcn | Accessible primitives; keep only the components you use. |
| Recharts for simple charts | Fine for now; move dense dashboards to ECharts later. |
| Async scan model (`202 Accepted` + Celery + status polling) | Correct pattern; the UI never blocks on scans. Keep it and add SSE. |
| Confirm dialog before cancel / delete | Good UX for destructive actions. |
| **pnpm** with a committed lockfile | Keep and make official (README, Docker, CI). |
| Separate API and worker images | Right separation of concerns. |
| Evidence rendered through React (no raw HTML) | Prevents stored XSS from attacker-controlled banners. |
| Credentials list returns no secrets | Correct. Keep when you add types. |

### 6.2 CHANGE

| From | To | Why |
|---|---|---|
| `useState` "views" in one file | App Router routes + feature folders | F-07, F-08, F-09 |
| JWT in `localStorage` | HttpOnly cookie session via a BFF; refresh rotation | F-03, F-04 |
| Hand-written `api.get` + local state + manual polling | TanStack Query + generated typed client | F-02, F-15, F-25, C-03 |
| One global `loading` | Per-mutation pending state | F-15 |
| `<details>` list of findings | TanStack Table + virtualization, filters, detail route | F-11 |
| Home-made banner | `sonner` | F-20 |
| Manual forms | React Hook Form + zod (already installed) | F-23 |
| Scan statuses overloaded with report states | Separate `report` resource | F-10 |
| Naive timestamps | Timezone-aware UTC, `Z`-suffixed | F-13 |
| `ignoreBuildErrors`, `ignoreDuringBuilds` | Enforced type-check, lint, tests in CI | F-14 |
| `next/font/google` | `geist` or self-hosted fonts | F-29 |
| Dockerfile (root, full `node_modules`, Node 20) | Standalone output, non-root, Node 22/24 LTS, healthcheck | F-31 |
| Open registration | Invite-only / SSO | F-23 |
| Next.js 15.2.4 | Latest patched supported release | F-01 |
| Folder names with spaces | `backend/`, `frontend/` | R-05 |

### 6.3 REMOVE

| Item | Why |
|---|---|
| `public/App.js`, `index.js`, `pages/`, `context/`, `*.css` (legacy CRA app) | Dead, broken, publicly served (F-26) |
| `styles/globals.css`, `components/ui/use-*.ts(x)` duplicates | Duplicates (F-27) |
| 40 unused shadcn components and unused dependencies (`zod` etc. until used) | Maintenance and attack surface (F-27); re-add when needed |
| `allowedDevOrigins` LAN IP | Personal network detail (F-30) |
| `instance/reports/*`, `riskreveal.egg-info/` from git | R-01, R-02 |
| `SecureLens_Project_Spec.md` from repo root | R-03 |
| Hard-coded fallback secrets (backend) | `01_…` #1 |

---

## 7. Recommended tech stack (frontend-focused, aligned with your plan)

This refines the stack note from earlier in our conversation. One correction to that note: **I would not rewrite Flask to FastAPI right now.** Your backend needs correctness and security work first (Phases 0–2), and a framework swap on top would slow that down. What the frontend actually needs is an **OpenAPI contract and consistent schemas**, which you can get on Flask with `flask-smorest`, `APIFlask` or `spectree` (Pydantic-based). Revisit FastAPI around Phase 5–8, when live streaming, agents and async I/O become real requirements, and migrate module by module.

### 7.1 Frontend

| Layer | Choice | Notes |
|---|---|---|
| Framework | **Next.js (latest patched, App Router)** + React 19 + TypeScript `strict` | Server Components for shells; client components only where interactive |
| Auth/session | HttpOnly cookie via a Next.js **BFF** (route handlers proxying to the API); **Auth.js** if you add an external IdP, otherwise a thin cookie session | Backend stays the authority (OIDC/SAML later via Keycloak/Authentik or WorkOS/Auth0) |
| Data fetching | **TanStack Query** | Caching, `refetchInterval`, optimistic updates, retries |
| API client | **`openapi-typescript` + `openapi-fetch`** generated from backend OpenAPI | Drops hand-written types; axios can go |
| URL state | `nuqs` (type-safe query params) | Filters, sort, page live in the URL so views are shareable |
| Forms | **React Hook Form + zod** | Share schemas with API docs where possible |
| Tables | **TanStack Table + TanStack Virtual** | Thousands of findings |
| Charts | Recharts now → **Apache ECharts** for dense dashboards | |
| Graph | **React Flow** (or Cytoscape.js for large graphs) | Attack-path view (Phase 5) |
| UI | shadcn/ui + Tailwind with **design tokens** (severity colours, spacing) | Keep only components you use |
| Notifications | `sonner` | |
| Real-time | **SSE** for scan/report/agent progress | Polling as fallback |
| i18n (later) | `next-intl` | |
| Fonts | `geist` (already installed) or self-hosted | |

### 7.2 Quality, security, delivery

| Need | Choice |
|---|---|
| Lint / format | ESLint (`next/core-web-vitals`, `typescript-eslint`, `jsx-a11y`), Prettier, Husky + lint-staged |
| Types | `tsc --noEmit` as a required check |
| Unit / component | Vitest + Testing Library; **MSW** to mock the API |
| End-to-end + a11y | **Playwright** + `@axe-core/playwright` |
| Dead-code check | `knip` |
| Security in CI | `pnpm audit`, Dependabot/Renovate, Semgrep, gitleaks, Trivy on images, CodeQL |
| Runtime hardening | Nonce-based **CSP**, HSTS, `frame-ancestors`, Referrer-Policy, `poweredByHeader: false` |
| Monitoring | Sentry (browser errors) + OpenTelemetry web vitals |
| Container | `output: "standalone"`, Node 22/24 LTS, non-root, pinned pnpm via `corepack`, HEALTHCHECK |
| Supply chain | SBOM (CycloneDX) and cosign-signed images for your own releases |
| Docs | Storybook for the design system (optional, valuable once more than one person builds UI) |

### 7.3 Target folder layout

```
frontend/
  app/
    (auth)/login/page.tsx
    (auth)/register/page.tsx
    (app)/layout.tsx                 # sidebar, header, session guard
    (app)/dashboard/page.tsx
    (app)/scans/page.tsx
    (app)/scans/new/page.tsx
    (app)/scans/[id]/page.tsx
    (app)/scans/[id]/findings/[findingId]/page.tsx
    (app)/assets/page.tsx
    (app)/assets/[id]/page.tsx
    (app)/credentials/page.tsx
    (app)/settings/{profile,security,api-keys}/page.tsx
    api/[...path]/route.ts           # BFF proxy: cookie -> bearer
    error.tsx  global-error.tsx  not-found.tsx
  features/{auth,scans,findings,assets,credentials,reports}/
  components/{ui,common}/            # SeverityBadge, DataTable, EmptyState…
  lib/{api,format,env}.ts
  middleware.ts                      # auth redirect + CSP nonce
  tests/{unit,e2e}/
```

---

## 8. Priority order

### Week 1 – Stop the bleeding
1. **F-01** Patch Next.js/React; add `pnpm audit` and Dependabot.
2. **F-02** Confirm and fix the request loop (DevTools check first).
3. **F-05 / R-10** Fix the Docker + env story; add both `.env.example` files.
4. **F-26 / F-27 / R-01 / R-02 / R-03** Delete dead code and committed artefacts; rotate anything exposed.
5. **F-14** Turn on type-check and lint; fix what they report.
6. **F-13** Timezone-aware timestamps (backend + UI).
7. **F-04 / C-01** One error format, 401 handling, redirect to login.

### Weeks 2–3 – Re-structure
8. **F-07 / F-08 / F-09** Routes, feature folders, server/client split.
9. **F-03** BFF + cookie session + CSP.
10. **C-03** OpenAPI from the backend, generated client, TanStack Query.
11. **R-06 / R-07** CI with required checks; first Playwright flow.
12. **F-06** Target validation, allow-list, authorization attestation (with the backend scope checks).

### Weeks 4–6 – Make the core product good (with backend Phases 1–2)
13. **F-11 / F-12** Findings table, finding detail page, correct dashboard metrics.
14. **F-10 / C-10** Reports as their own resource and workflow.
15. **F-19** Accessibility pass; axe in CI.
16. **C-02** Pagination, filters, saved views.

### Later (Phases 5–8)
17. AI verdict, evidence viewer, attack-path graph, remediation grouping.
18. RBAC/org management, SSO/MFA, audit-log viewer, scheduling, integrations, SLA dashboards, API keys.

---

## 9. "Enterprise-ready frontend" definition of done

- [ ] No known-vulnerable framework or dependency versions (CI-enforced).
- [ ] Session in HttpOnly cookie; strict CSP; no secrets or tokens readable by JS.
- [ ] TypeScript `strict` with zero errors; no `any` in feature code; ESLint clean.
- [ ] Every page has a URL; Back, refresh and deep links work.
- [ ] Types generated from the API's OpenAPI; one error format; pagination everywhere.
- [ ] Findings: filter, sort, search, group, virtualized; detail page with evidence, confidence, references, history.
- [ ] Exports run asynchronously with visible status and retry.
- [ ] WCAG 2.2 AA verified by automated (axe) and manual keyboard/screen-reader checks.
- [ ] E2E tests for login → start scan → results → export; unit tests for critical UI logic; runs in CI.
- [ ] Docker image: standalone, non-root, health-checked, scanned, signed; no build-time dependency on the public internet.
- [ ] Audit-relevant UI actions (scan start, credential use, export) emit events the backend logs.
- [ ] Documentation: README, `.env.example`, architecture, API docs, `SECURITY.md`, threat model.

---

## 10. Assumptions and open questions

- I assumed **multi-tenant SaaS or customer-hosted enterprise deployment**, not a single-user tool. If it is single-tenant and internal only, R-12/R-13 and parts of §5 shrink, but F-01 through F-06 do not.
- I assumed the backend will keep **Flask** for now (§7). If you decide to move to FastAPI, the frontend plan does not change; only the OpenAPI source does.
- **Please verify in the browser:** F-02 (request loop) and F-13 (time offset). Both follow from the code, but I have not run them.
- Not reviewed: the Alembic history (none committed) and anything outside the ZIP (for example, your deployment environment or GitHub settings).
