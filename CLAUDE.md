# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Database (Docker)
make pgup           # Start PostgreSQL container
make pgdown         # Stop PostgreSQL container

# Dev server
make run            # Start uvicorn on :8080 with --reload

# Code quality
make format         # Auto-fix with ruff (lint + format)
make check_format   # Check only (no changes)
make check_type     # mypy type check (package: learn_auth)

# Migrations
uv run alembic revision --autogenerate -m "<description>"   # Generate migration
uv run alembic upgrade head                                  # Apply migrations
uv run alembic downgrade -1                                  # Roll back one step
```

## Architecture

**Request flow:** `endpoints/` → `services/` → ORM models. No business logic in endpoints, no HTTP concerns in services.

**DB session** (`core/deps.py`): Synchronous `Session` injected via `Depends(get_db)`. Note: `.envrc` has an `asyncpg` URL — this is a mismatch; the engine uses `psycopg2`.

**Schema isolation:** All models set `__table_args__ = {"schema": settings.SCHEMA}` (default: `"learn_auth"`). Alembic's `env.py` filters autogenerate to this schema only, preventing spurious DROP statements for tables in `public`.

**Model auto-discovery:** Both `init_db()` and Alembic's `env.py` use `pkgutil.iter_modules` to import every module under `app/models/`, so new model files are picked up automatically — no manual registration needed.

**Alembic revision IDs** use a custom date-serial format (`YYYY_MM_DD_NNN`), not the default hex. This is handled by `process_revision_directives` in `alembic/env.py`.

**Startup behavior** (`main.py` lifespan):
- `SKIP_DB_INIT=True` (default) — skips `create_all`; rely on Alembic for schema changes.
- `DEBUG=True` (default) — seeds from `localdev/data/seed_data.json` if the todos table is empty.

**Auth stubs:** `app/models/auth.py` and `app/core/security.py` are empty — JWT/bcrypt auth is not yet implemented.

## Environment

Secrets live in `.envrc` (loaded by direnv). Required vars: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT`, `DATABASE_URL`.

Settings are loaded by `pydantic-settings` from `.envrc` (`env_file=".envrc"`).
