# RiskReveal – Dev Environment Setup for Dual-Boot Fedora + Windows 11

*Companion to `06_Tech_Stack_Installation_List.md`, which assumed Ubuntu/Debian/macOS. This file replaces those commands with ones that fit your actual setup: dual-boot Fedora and Windows 11.*

---

## 0. The one decision that simplifies everything

**Don't develop the backend natively on Windows. Run it inside WSL2 on the Windows side, using Fedora as the WSL distro.**

This isn't about preference — several things in this stack genuinely don't work well on native Windows:

- **Celery's `prefork` pool uses `os.fork()`**, a POSIX-only system call. Celery on native Windows is limited to the `solo` or `threads` pools, which isn't how you'd run it in production, so bugs you hit in dev won't match reality.
- **WeasyPrint needs GTK (Pango, Cairo, GDK-Pixbuf)** on the system. On Linux that's one package-manager command; on native Windows it means a separate GTK runtime install that's a known source of breakage.
- **Nmap's raw-socket scan types need Npcap and admin rights** on Windows; they just work on Linux.
- Your Docker containers and eventual production servers are **Linux**. Developing against native Windows Python/Node risks path-separator and process-model differences that only surface at deploy time.

Once Fedora is running inside WSL2, a convenient side effect: **the exact same `dnf` commands you run on your native Fedora boot also work inside WSL2 on Windows.** You maintain one set of instructions, not two. Frontend (Next.js/Node) has no such restriction and would run fine natively on Windows, but keeping it inside the same WSL2 shell as the backend is simpler and avoids any cross-environment surprises — do both there.

So the real shape of your setup is: **two doors into the same kind of Linux environment** — booting into Fedora directly, or opening a WSL2 Fedora shell from Windows. Everything below reflects that.

---

## 1. One-time Windows-side setup (do this once, not per project)

Open **PowerShell as Administrator**:

```powershell
# Installs WSL2 itself (may prompt for a reboot the first time)
wsl --install

# See the current list of installable distros — version numbers shown below
# were current as of this write-up; check the live list before you install
wsl --list --online

# Install Fedora as a WSL distro (adjust the version number if a newer one
# is listed above — Fedora 43 was current as of October 2026)
wsl --install FedoraLinux-43
```

Reboot if prompted. Launch **Fedora Linux 43** from the Start menu once — it'll ask you to create a Linux username and password (independent of your Windows login). This drops you into a real `dnf`-based Fedora shell running inside Windows.

Then install, via **winget** in an ordinary (non-admin) PowerShell or Terminal window:

```powershell
winget install Git.Git
winget install Microsoft.VisualStudioCode
winget install Docker.DockerDesktop
```

- **VS Code:** after installing, open it and install the **WSL** extension (`ms-vscode-remote.remote-wsl`). This lets you open your project with `code .` from inside the Fedora WSL shell and have VS Code edit the Linux files directly, with the Linux toolchain, while the window itself runs on Windows.
- **Docker Desktop:** after installing, open **Settings → Resources → WSL Integration**, and toggle it **on** for your `FedoraLinux-43` distro. This gives you a working `docker` command inside the Fedora WSL shell without installing Docker Engine a second time in there.
- **Git on Windows** is mainly for convenience (e.g., `winget`-installed GUI tools); the Git you actually commit with should be the one **inside** the Fedora WSL shell (§2 installs it there too), so line endings and hooks behave like they will in CI.

---

## 2. The shared setup — identical on native Fedora and WSL2 Fedora

Run every command in this section **on both**: your native Fedora boot, and inside the Fedora WSL2 shell on Windows. They're the same OS, so they're the same commands.

**Where to put the project in WSL2:** clone it inside the Linux filesystem (`~/projects/riskreveal`), **not** under `/mnt/c/...`. Files under `/mnt/c` are physically on the Windows NTFS drive and WSL2's I/O across that boundary is slow — `pnpm install`, `uv sync`, and Docker bind mounts will all feel noticeably sluggish if you clone into your Windows user folder instead.

### 2.1 Base tools

```bash
sudo dnf update -y
sudo dnf install -y git curl gcc make
```

### 2.2 Python — let `uv` manage the version, not `dnf`

Fedora's bundled Python version shifts with each release, so rather than chasing the right `dnf` package name, let `uv` install and pin the interpreter itself:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# restart your shell or `source ~/.bashrc`, then:
uv python install 3.12
```

This gives you an identical Python 3.12 on both boots regardless of what Fedora version each one happens to be running.

### 2.3 Node.js and pnpm — same reasoning, use `nvm`

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
# restart your shell, then:
nvm install 24
nvm use 24
corepack enable
corepack prepare pnpm@latest --activate
```

(Node 24 is the current Active LTS line, as noted in `06_…`. If you ever check and a newer LTS has since taken over, install that instead — the `nvm install <major>` command doesn't change.)

### 2.4 Scanning engines

```bash
sudo dnf install -y nmap
```

```bash
# Nuclei and naabu are Go binaries — same install method on any Linux,
# including Fedora WSL2. If you don't already have Go:
sudo dnf install -y golang

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# add Go's bin dir to PATH if it isn't already (put this in ~/.bashrc too)
export PATH="$PATH:$(go env GOPATH)/bin"

nuclei -update-templates
```

> **Nmap license reminder from the earlier stack review still applies:** fine to run locally and on your own servers; get it confirmed before bundling it into any image or installer you distribute.

### 2.5 CI-adjacent security tools (useful locally too)

```bash
sudo dnf install -y trivy gitleaks
```

> If either isn't in Fedora's default repos on your release, grab the release binary from the project's GitHub releases page instead (Trivy: `aquasecurity/trivy`; gitleaks: `gitleaks/gitleaks`).

### 2.6 Backend Python dependencies

Identical to `06_…` §2 — `uv` doesn't care which Linux you're on:

```bash
cd backend
uv add fastapi "uvicorn[standard]" pydantic pydantic-settings python-multipart \
  "sqlalchemy>=2.0" alembic "psycopg[binary,pool]" redis \
  celery \
  pyjwt argon2-cffi cryptography slowapi \
  defusedxml httpx paramiko pywinrm \
  packaging univers cpe \
  networkx \
  anthropic tenacity \
  weasyprint python-docx matplotlib \
  structlog sentry-sdk opentelemetry-sdk opentelemetry-instrumentation-fastapi \
  typer

uv add --dev pytest pytest-asyncio pytest-cov hypothesis testcontainers ruff mypy pre-commit
```

WeasyPrint's system libraries, via `dnf` instead of `apt`:

```bash
sudo dnf install -y pango cairo gdk-pixbuf2
```

### 2.7 Frontend dependencies

Identical to `06_…` §3:

```bash
cd frontend
pnpm add next react react-dom \
  lucide-react next-themes sonner geist class-variance-authority clsx tailwind-merge \
  @tanstack/react-query @tanstack/react-table @tanstack/react-virtual \
  openapi-fetch nuqs \
  react-hook-form zod @hookform/resolvers \
  recharts @xyflow/react \
  @sentry/nextjs

pnpm add -D typescript @types/react @types/react-dom @types/node \
  openapi-typescript \
  vitest @testing-library/react @testing-library/jest-dom @testing-library/user-event \
  msw @playwright/test @axe-core/playwright \
  eslint eslint-config-next @typescript-eslint/parser @typescript-eslint/eslint-plugin eslint-plugin-jsx-a11y \
  prettier husky lint-staged knip
```

---

## 3. Where native Fedora and WSL2 Fedora genuinely differ

| Area | Native Fedora boot | WSL2 Fedora (on Windows) |
|---|---|---|
| **Docker** | Install Docker Engine directly (below) | Don't install it separately — use Docker Desktop's WSL integration from §1 |
| **Firewall** | `firewalld` is active by default. Dev ports (3000, 8000, 5432, 6379) bound to `localhost` don't need any rule. Only add one if another device on your LAN needs to reach a port: `sudo firewall-cmd --add-port=8000/tcp --zone=FedoraWorkstation` | No `firewalld` involved; WSL2 forwards `localhost` ports to Windows automatically on Windows 11 |
| **SELinux** | Enforcing by default. If Docker bind-mounts fail with permission errors, add `:z` (shared) or `:Z` (private) to the volume mount in `docker-compose.yml` rather than disabling SELinux | Not applicable inside WSL2 |
| **GUI apps / browser** | Everything runs natively | `localhost:3000` etc. open fine in your normal Windows browser — no extra config needed on Windows 11 |

**Docker Engine on native Fedora** (not needed on the WSL2 side — Docker Desktop handles that):

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
# log out and back in for the group change to take effect
```

---

## 4. Keeping the two boots in sync

Dual boot means two genuinely separate filesystems — Fedora can't see your WSL2 files and vice versa without extra steps, and you don't want those steps. Use **Git as the sync mechanism**, the same way you'd sync between any two machines:

- Push before you shut down / switch boots; pull as the first thing you do after switching.
- Add a `.gitattributes` at the repo root so line endings stay consistent no matter which side last touched a file:

  ```
  * text=auto eol=lf
  ```

- `.env` files are (correctly) git-ignored, so they won't sync automatically. Keep your real values in a password manager or a private note, and paste them into `.env` on each side once. Same goes for anything else listed in `.gitignore` that you still need locally (e.g., a downloaded Nuclei template cache).
- If you use **VS Code Settings Sync** (sign in with the same GitHub/Microsoft account on both the native-Fedora VS Code and the Windows VS Code), your editor settings and extension list follow you — though extensions used *inside* a WSL window still need a one-time "Install in WSL" click the first time, since those run in the Linux side specifically.

---

## 5. Quick-reference: full sequence for a fresh machine

1. **Windows side, once:** `wsl --install`, `wsl --install FedoraLinux-43`, reboot, create Linux user; `winget install Git.Git Microsoft.VisualStudioCode Docker.DockerDesktop`; enable WSL integration for the Fedora distro in Docker Desktop; install the VS Code WSL extension.
2. **On native Fedora, and separately inside the Fedora WSL2 shell:** run §2.1–§2.7 above, plus the Docker Engine install in §3 **only on the native Fedora side**.
3. **Clone the repo** into `~/projects/riskreveal` on both (inside the Linux filesystem on the WSL2 side, not `/mnt/c/...`).
4. `cd backend && uv sync` / `cd frontend && pnpm install` on whichever side you're working from.
5. `docker compose -f infra/docker-compose.yml up -d` to bring up Postgres/Redis identically on either side.
6. Work, commit, push. On the other boot: pull, and you're back where you left off.
