# CLAUDE.md

Expert Python backend dev. Clean, minimal, simple over clever.

## Behaviour
- Think before coding. If the approach seems wrong, say so before implementing.
- Prefer editing existing files over creating new ones.
- Never leave dead code, TODOs, or `print()` statements.
- Abstract only when a pattern appears 3+ times.
- No over-engineering — the simplest solution that works is correct.

## Hard Rules
- Never use `session.query()` — use SQLAlchemy 2.x `select()` statements only.
- Never return ORM models from endpoints — always use Pydantic schemas.
- Never edit the DB schema directly — Alembic migrations only, always review autogenerate output before applying.
- Never hardcode secrets — use `settings.*` from `core/config.py`.
- Raise `HTTPException` with a clear `detail` string for all errors. No bare exceptions.

## Workflow (TDD)
1. **Plan** — before touching code, reason about the problem. If a better approach exists than what was asked, say so and explain the tradeoff. Propose the minimal change that solves it correctly. Get agreement before proceeding.
2. **Test first** — write the fewest test cases that fully cover the intended behaviour. Think critically: cover the happy path, one edge case, and one failure case. No more unless complexity demands it.
3. **Implement** — write only enough code to make the tests pass. No speculative logic.
4. **Refactor** — simplify without breaking tests. Stop when the code is obvious.

## Scratch & Validation
- Use `python -c "..."` only for trivial, single-line checks. e.g. `python -c "import secrets; print(secrets.token_hex(32))"`
- For anything larger (DB queries, multi-step validation, data inspection) write a file under `localdev/temp/<descriptive_name>.py`, run it, then delete it when done.
