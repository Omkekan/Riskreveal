# RiskReveal v2 --- Virtual Environment (venv) Setup & Troubleshooting Handoff

## Project location

-   Repository: `D:\WORK\VS Code\riskreveal`
-   Backend directory: `D:\WORK\VS Code\riskreveal\backend`
-   Intended backend virtual environment:
    `D:\WORK\VS Code\riskreveal\backend\.venv`
-   Python version previously noted: Python 3.12.16
-   Shell: Windows PowerShell in VS Code

## Work completed / findings

### Activating the venv

From the backend directory:

``` powershell
Set-Location "D:\WORK\VS Code\riskreveal\backend"
.\.venv\Scripts\Activate.ps1
```

A successful activation usually adds `(.venv)` to the prompt. However,
that prompt alone does not confirm that the correct environment is
active. Verify the interpreter path.

### Interpreter path check

Command used:

``` powershell
python -c "import sys; print(sys.executable)"
```

The output shown was:

``` text
D:\WORK\VS Code\.venv\Scripts\python.exe
```

This is the parent-folder environment, **not** the intended backend
environment. Expected path:

``` text
D:\WORK\VS Code\riskreveal\backend\.venv\Scripts\python.exe
```

### SQLAlchemy check

Commands used:

``` powershell
python -m pip show SQLAlchemy
python -c "from sqlalchemy.orm import DeclarativeBase; print('SQLAlchemy import works')"
```

SQLAlchemy was found and the import succeeded. Reported details:

-   Version: `2.0.41`
-   Installed location: `D:\WORK\VS Code\.venv\Lib\site-packages`

This verifies SQLAlchemy in the parent environment, but does not yet
verify it in `backend\.venv`. The earlier Pylance unresolved-import
warnings may be caused by VS Code using the wrong interpreter.

### `uv sync` error

From the backend directory, these were attempted:

``` powershell
uv sync
uv run uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
```

The warning indicated that `VIRTUAL_ENV=D:\WORK\VS Code\.venv` did not
match the project environment `.venv`.

The package build failed with:

``` text
OSError: Readme file does not exist: README.md
```

This is a packaging metadata issue separate from the SQLAlchemy import.
The fix below was suggested but has **not been confirmed as completed**.

## Suggested next steps

### 1. Check for the backend README

From the backend directory:

``` powershell
Test-Path .\README.md
```

If it returns `False`, create a basic README:

``` powershell
@"
# RiskReveal Backend

Backend API service for RiskReveal v2.

## Development

Run the API locally using Uvicorn.
"@ | Set-Content .\README.md
```

### 2. Deactivate the parent venv and activate the backend venv

``` powershell
deactivate
.\.venv\Scripts\Activate.ps1
```

Verify:

``` powershell
python -c "import sys; print(sys.executable)"
```

Expected:

``` text
D:\WORK\VS Code\riskreveal\backend\.venv\Scripts\python.exe
```

### 3. Sync dependencies in the active environment

``` powershell
uv sync --active
```

If this succeeds, start the API:

``` powershell
uv run --active uvicorn riskreveal.main:app --reload --host 127.0.0.1 --port 8000
```

These are next steps; server startup has not yet been confirmed.

## Configure VS Code / Pylance

1.  Press `Ctrl + Shift + P`.

2.  Choose **Python: Select Interpreter**.

3.  Select this exact interpreter:

    ``` text
    D:\WORK\VS Code\riskreveal\backend\.venv\Scripts\python.exe
    ```

4.  If diagnostics remain, run **Python: Restart Language Server**.

## Verification checklist

Run these from the backend directory:

``` powershell
Set-Location "D:\WORK\VS Code\riskreveal\backend"
.\.venv\Scripts\Activate.ps1
python -c "import sys; print(sys.executable)"
python -m pip show SQLAlchemy
python -c "from sqlalchemy.orm import DeclarativeBase; print('SQLAlchemy import works')"
Test-Path .\README.md
uv sync --active
```

## Status based on the output shared

-   [x] Terminal prompt showed `(.venv)`.
-   [x] SQLAlchemy import succeeded in the environment active at that
    time.
-   [x] SQLAlchemy 2.0.41 was found in `D:\WORK\VS Code\.venv`.
-   [ ] Confirm the interpreter is `backend\.venv` using
    `sys.executable`.
-   [ ] Confirm `backend\README.md` exists; create it if missing.
-   [ ] Successfully run `uv sync --active`.
-   [ ] Set VS Code/Pylance to the backend interpreter.
-   [ ] Start the API and verify the health endpoint.

## Cleanup note

Do not delete the venv or run Docker volume cleanup for these issues.
Current evidence points to an interpreter mismatch and a missing README
referenced by project metadata. Neither requires deleting PostgreSQL or
Redis data volumes.
