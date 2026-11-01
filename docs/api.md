# RiskReveal - API & CLI Reference

This document describes the HTTP REST API and Command-Line Interface (CLI) currently implemented in the RiskReveal v2 backend.

* **Base URL (Local Development)**: `http://127.0.0.1:8000`
* **Versioned API Prefix**: `/api/v1`
* **Interactive Swagger UI**: `http://127.0.0.1:8000/docs`
* **Interactive ReDoc**: `http://127.0.0.1:8000/redoc`

---

## 1. Authentication & Security Conventions

1. **Bearer Authentication**: All protected endpoints require an `Authorization: Bearer <access_token>` header using an access token issued by `/api/v1/auth/login` or `/api/v1/auth/refresh`.
2. **Token Type Isolation**: Access tokens (`type: "access"`) and refresh tokens (`type: "refresh"`) are strictly separated. Presenting a refresh token to a resource endpoint-or an access token to `/api/v1/auth/refresh`-is rejected with `401 Unauthorized`.
3. **Owner Scoping & Resource Isolation**: Every scan, asset, and finding is scoped to the authenticated user (`owner_id`). Requesting a UUID that belongs to another user returns `404 Not Found` (identical to a non-existent UUID) to prevent resource enumeration.
4. **Sanitized Validation Errors (`422 Unprocessable Content`)**: Validation errors return a sanitized JSON payload containing only `type`, `loc`, and `msg` per field error-never echoing raw submitted inputs (such as passwords) or internal Python exception objects.
5. **Untrusted Banner Evidence**: Fields populated from target network responses (`hostname`, `os_name`, `service`, `product`, `version`, `cpe`, `raw_evidence`) originate from untrusted remote hosts. API consumers and frontends must render them strictly as plain text, never as raw HTML.

---

## 2. Health Endpoint

### `GET /healthz`

Performs a live database round-trip (`SELECT 1`) to verify application and PostgreSQL readiness. Does not require authentication.

* **Response `200 OK`**:
  ```json
  {
    "status": "ok",
    "database": "reachable"
  }
  ```
* **Response `503 Service Unavailable`**:
  ```json
  {
    "status": "degraded",
    "database": "unreachable"
  }
  ```

---

## 3. Authentication Endpoints (`/api/v1/auth`)

All `/auth/register`, `/auth/login`, and `/auth/refresh` endpoints are rate-limited per IP via `AUTH_RATE_LIMIT` (default: `5/minute`). Exceeding the limit returns `429 Too Many Requests`.

### `POST /api/v1/auth/register`

Registers a new active user account. Unknown fields in the JSON body are rejected (`extra="forbid"`).

* **Request Body**:
  ```json
  {
    "email": "analyst@example.com",
    "password": "CorrectHorseBatteryStaple!23",
    "full_name": "Security Analyst"
  }
  ```
  * `email`: Valid email address, trimmed, lowercased, $\le 254$ characters.
  * `password`: $12$ to $128$ characters, must contain at least one non-whitespace character.
  * `full_name`: Optional string, $\le 255$ characters.

* **Response `201 Created`** (`UserRead`):
  ```json
  {
    "id": "b4a7f2c4-8c2d-4e9a-9f1b-3a5e7c9d1e2f",
    "email": "analyst@example.com",
    "full_name": "Security Analyst",
    "is_active": true,
    "created_at": "2026-10-30T14:00:00Z"
  }
  ```
* **Error Responses**:
  * `409 Conflict`: Email address is already registered.
  * `422 Unprocessable Content`: Password too short, invalid email, or unexpected fields.
  * `429 Too Many Requests`: Rate limit exceeded.

---

### `POST /api/v1/auth/login`

Authenticates a user and returns an access/refresh token pair. To prevent timing-oracle account enumeration, this endpoint always runs an Argon2id verification (`verify_password`) even when the email does not exist in the database.

* **Request Body**:
  ```json
  {
    "email": "analyst@example.com",
    "password": "CorrectHorseBatteryStaple!23"
  }
  ```
* **Response `200 OK`** (`TokenPair`):
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer"
  }
  ```
* **Error Responses**:
  * `401 Unauthorized`: Unknown email, wrong password, or disabled account (uniform message).
  * `429 Too Many Requests`: Rate limit exceeded.

---

### `POST /api/v1/auth/refresh`

Exchanges a valid refresh token for a fresh access and refresh token pair after verifying the user account still exists and is active.

* **Request Body**:
  ```json
  {
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }
  ```
* **Response `200 OK`** (`TokenPair`): Same structure as `/login`.
* **Error Responses**:
  * `401 Unauthorized`: Expired, tampered, wrong token type (`access` token passed), or inactive user.

---

### `GET /api/v1/auth/me`

Returns the profile of the currently authenticated user.

* **Headers**: `Authorization: Bearer <access_token>`
* **Response `200 OK`** (`UserRead`): Same structure as `/register`.
* **Error Responses**: `401 Unauthorized`.

---

## 4. Scan Endpoints (`/api/v1/scans`)

### `POST /api/v1/scans`

Validates a scan target against the **Scope Policy** and **Operator Allowlist**, enforces the per-user active scan limit (`SCAN_MAX_ACTIVE_PER_USER`, default `3`), creates a `queued` scan record, and dispatches the job to the Celery worker queue. Rate-limited via `SCAN_RATE_LIMIT` (default: `10/minute`).

* **Headers**: `Authorization: Bearer <access_token>`
* **Request Body** (`ScanCreate`):
  ```json
  {
    "target": "scanme.nmap.org",
    "profile": "quick"
  }
  ```
  * `target`: Single IPv4/IPv6 address, CIDR block (up to 256 hosts), or hostname (resolving to at most 16 addresses).
  * `profile`: Fixed profile name-either `"quick"` (top 100 ports, 300s timeout) or `"standard"` (top 1000 ports, 900s timeout). Defaults to `"quick"`. Users cannot pass raw Nmap flags.

* **Response `201 Created`** (`ScanRead`):
  ```json
  {
    "id": "6d8e1a20-4b3c-4f1a-8e2d-9c0b1a2f3e4d",
    "target": "scanme.nmap.org",
    "profile": "quick",
    "status": "queued",
    "scanned_addresses": ["45.33.32.156"],
    "started_at": null,
    "finished_at": null,
    "error": null,
    "created_at": "2026-10-30T14:05:00Z",
    "updated_at": "2026-10-30T14:05:00Z"
  }
  ```
* **Error Responses**:
  * `422 Unprocessable Content`: Target rejected by the scope policy (e.g., private IP when `SCAN_PRIVATE_RANGES_ALLOWED=false`, link-local/cloud metadata address, DNS timeout, or unknown profile name) or not present in `SCAN_PUBLIC_ALLOWLIST`.
  * `429 Too Many Requests`: User already has 3 active (`queued` or `running`) scans, or rate limit exceeded.
  * `503 Service Unavailable`: Scan could not be queued to Redis/Celery (the scan row is automatically marked `failed`).

---

### `GET /api/v1/scans`

Lists scans belonging to the authenticated user, ordered newest first.

* **Headers**: `Authorization: Bearer <access_token>`
* **Query Parameters**:
  * `limit`: $1 \dots 100$ (default `50`)
  * `offset`: $0 \dots 1,000,000$ (default `0`)
  * `status`: Optional filter (`queued`, `running`, `completed`, `failed`, `cancelled`)
* **Response `200 OK`** (`ScanPage`):
  ```json
  {
    "items": [
      {
        "id": "6d8e1a20-4b3c-4f1a-8e2d-9c0b1a2f3e4d",
        "target": "scanme.nmap.org",
        "profile": "quick",
        "status": "completed",
        "scanned_addresses": ["45.33.32.156"],
        "started_at": "2026-10-30T14:05:01Z",
        "finished_at": "2026-10-30T14:05:10Z",
        "error": null,
        "created_at": "2026-10-30T14:05:00Z",
        "updated_at": "2026-10-30T14:05:10Z"
      }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
  }
  ```

---

### `GET /api/v1/scans/{scan_id}`

Returns a single scan owned by the current user.

* **Response `200 OK`**: `ScanRead`
* **Error Responses**: `404 Not Found` (if non-existent or owned by another user).

---

### `POST /api/v1/scans/{scan_id}/cancel`

Cancels a `queued` or `running` scan owned by the current user. If the scan is currently running in Nmap, the conditional completion check in the worker ensures its results are discarded when the subprocess finishes.

* **Response `200 OK`**: `ScanRead` (with `"status": "cancelled"`)
* **Error Responses**:
  * `404 Not Found`: Scan does not exist or belongs to another user.
  * `409 Conflict`: Scan is already in a terminal state (`completed`, `failed`, or `cancelled`).

---

## 5. Finding Endpoints (`/api/v1/findings`)

### `GET /api/v1/findings`

Lists findings across scans owned by the authenticated user. The list view returns `FindingSummary` objects (which omit `raw_evidence` to keep list payloads compact).

* **Headers**: `Authorization: Bearer <access_token>`
* **Query Parameters**:
  * `limit`: $1 \dots 100$ (default `50`)
  * `offset`: $0 \dots 1,000,000$ (default `0`)
  * `scan_id`: Optional UUID filter
  * `asset_id`: Optional UUID filter
  * `severity`: Optional filter (`informational`, `low`, `medium`, `high`, `critical`)
  * `status`: Optional filter (`open`, `resolved`, `accepted_risk`, `false_positive`)
* **Response `200 OK`** (`FindingPage`):
  ```json
  {
    "items": [
      {
        "id": "e1c2b3a4-5d6e-4f7a-8b9c-0d1e2f3a4b5c",
        "scan_id": "6d8e1a20-4b3c-4f1a-8e2d-9c0b1a2f3e4d",
        "asset_id": "a9b8c7d6-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "source": "nmap",
        "confidence": "detected",
        "severity": "informational",
        "status": "open",
        "title": "Open port 22/tcp (ssh)",
        "description": "Port 22/tcp is open running ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13).",
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
        "cpe": "cpe:/a:openbsd:openssh:6.6.1p1",
        "created_at": "2026-10-30T14:05:10Z",
        "updated_at": "2026-10-30T14:05:10Z"
      }
    ],
    "total": 2,
    "limit": 50,
    "offset": 0
  }
  ```

---

### `GET /api/v1/findings/{finding_id}`

Returns the full detail of a single finding owned by the authenticated user, including `raw_evidence`.

* **Response `200 OK`** (`FindingDetail`): Includes all `FindingSummary` fields plus `"raw_evidence": "..."`.
* **Error Responses**: `404 Not Found`.

---

## 6. Asset Endpoints (`/api/v1/assets`)

### `GET /api/v1/assets`

Lists discovered host assets belonging to the authenticated user. Assets are deduplicated per `(owner_id, address)` and updated on each completed scan.

* **Headers**: `Authorization: Bearer <access_token>`
* **Query Parameters**: `limit` ($1 \dots 100$, default `50`), `offset` ($0 \dots 1,000,000$, default `0`).
* **Response `200 OK`** (`AssetPage`):
  ```json
  {
    "items": [
      {
        "id": "a9b8c7d6-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "address": "45.33.32.156",
        "hostname": "scanme.nmap.org",
        "os_name": null,
        "last_scanned_at": "2026-10-30T14:05:10Z",
        "created_at": "2026-10-30T14:05:10Z",
        "updated_at": "2026-10-30T14:05:10Z"
      }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
  }
  ```

---

### `GET /api/v1/assets/{asset_id}`

Returns a single asset owned by the authenticated user.

* **Response `200 OK`**: `AssetRead`
* **Error Responses**: `404 Not Found`.

---

## 7. Command-Line Interface (`python -m riskreveal.cli`)

Run all CLI commands from the `backend/` directory using `uv run`:

| Command | Description |
| :--- | :--- |
| `uv run python -m riskreveal.cli load-kev` | Downloads the official CISA Known Exploited Vulnerabilities JSON catalog over HTTPS and atomically upserts all valid records into `kev_entries` and updates `feed_syncs`. |
| `uv run python -m riskreveal.cli load-kev --file <PATH>` | Imports a CISA KEV JSON catalog from a local file path. |
| `uv run python -m riskreveal.cli load-epss` | Streams and decompresses the daily FIRST EPSS `.csv.gz` feed (`~400,000` rows) in batches of 5,000 within a single transaction into `epss_scores` and updates `feed_syncs`. |
| `uv run python -m riskreveal.cli load-epss --file <PATH>` | Imports a FIRST EPSS `.csv` or `.csv.gz` file from a local file path. |
| `uv run python -m riskreveal.cli feed-status` | Prints a status table of all synchronized threat-intelligence feeds (`source`, `record_count`, `version`, `last_success_at`). |
