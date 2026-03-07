# Part 2: Database Models & Alembic — Building the Foundation

## Table of Contents
1. [What Tables Do We Need?](#1-what-tables-do-we-need)
2. [Understanding Alembic in This Project](#2-understanding-alembic-in-this-project)
3. [Alembic Workflow — The Golden Rule](#3-alembic-workflow--the-golden-rule)
4. [The User Model](#4-the-user-model)
5. [The RefreshToken Model](#5-the-refreshtoken-model)
6. [The EmailVerification & PasswordReset Models](#6-the-emailverification--passwordreset-models)
7. [Updating config.py for JWT Settings](#7-updating-configpy-for-jwt-settings)
8. [Generating and Applying the Migration](#8-generating-and-applying-the-migration)
9. [Common Alembic Mistakes and How to Avoid Them](#9-common-alembic-mistakes-and-how-to-avoid-them)

---

## 1. What Tables Do We Need?

For a full production JWT auth system, we need four tables:

```
users               — the account (email, password hash, profile, flags)
refresh_tokens      — one row per active session (device, IP, expiry)
email_verifications — temporary tokens for email confirmation
password_resets     — temporary tokens for password reset emails
```

Let's understand why each exists:

| Table | Why it exists |
|---|---|
| `users` | Core entity. Stores identity, profile, and account state flags |
| `refresh_tokens` | Stateful sessions. Lets you revoke access without waiting for access token expiry |
| `email_verifications` | Email confirmation links are single-use, expiring tokens — perfect for a DB table |
| `password_resets` | Same pattern as email verification — send link, user clicks, validate token, reset |

---

## 2. Understanding Alembic in This Project

### What Alembic Does

Alembic is a **database migration tool** for SQLAlchemy. It solves this problem: your Python models define what the database *should* look like, but the database doesn't automatically change when you change a model. Alembic creates SQL scripts ("migrations") that evolve the schema safely.

### How This Project Is Set Up

Look at `alembic/env.py` — it has several important customizations:

1. **Schema isolation:** Only generates migrations for the `learn_auth` schema. This prevents Alembic from generating DROP statements for `public` schema tables it doesn't own.

2. **Auto-discovery of models:** Uses `pkgutil.iter_modules` to scan `app/models/`. Any new `.py` file you add there is automatically picked up — you don't register models anywhere.

3. **Custom revision IDs:** Uses `YYYY_MM_DD_NNN` format instead of hex, which is much more readable in the `versions/` folder.

### Current State

You already have one migration:
```
alembic/versions/2026_03_03_001_initial_schema.py  ← created the todos table
```

We will add a second migration that creates the auth tables.

---

## 3. Alembic Workflow — The Golden Rule

**Never edit the database schema directly (no `CREATE TABLE` in psql). Always go through Alembic.**

The workflow is always:

```
1. Edit/create your SQLAlchemy model(s)
2. Generate a migration: uv run alembic revision --autogenerate -m "description"
3. REVIEW the generated file in alembic/versions/ — fix anything wrong
4. Apply it: uv run alembic upgrade head
```

### Why Review Before Running?

Alembic compares your models to the database's current state and generates SQL. It gets it right 90% of the time, but it can:
- Miss renamed columns (it sees a DROP + ADD instead of RENAME)
- Generate `server_default` differently than you expect
- Generate DROP statements for things in other schemas (fixed in this project, but watch for it)

**Always open the generated file and read it before running `upgrade head`.**

### Alembic Commands Reference

```bash
# See current state: which migration is applied?
uv run alembic current

# See migration history
uv run alembic history --verbose

# Generate a new migration (autogenerate from models)
uv run alembic revision --autogenerate -m "add auth tables"

# Apply all pending migrations
uv run alembic upgrade head

# Apply exactly one step forward
uv run alembic upgrade +1

# Roll back one step
uv run alembic downgrade -1

# Roll back to a specific revision
uv run alembic downgrade 2026_03_03_001

# Roll back ALL migrations (careful!)
uv run alembic downgrade base

# Show what SQL would run (without executing)
uv run alembic upgrade head --sql
```

### When to Create a Migration?

Any time you:
- Add a new model (new table)
- Add/remove a column
- Add/remove an index
- Add/remove a constraint or foreign key
- Change a column type

---

## 4. The User Model

### What Goes in User?

```python
# src/learn_auth/app/models/auth.py

from datetime import datetime
from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from learn_auth.app.core.config import settings
from learn_auth.app.core.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": settings.SCHEMA}

    # --- Primary Key ---
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # --- Identity ---
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- Profile ---
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Account State Flags ---
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="user", nullable=False)

    # --- Brute Force Protection ---
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # soft delete

    # --- Relationships ---
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
```

### Column-by-Column Explanation

**`email`** — the primary identifier. `unique=True` enforces no duplicates at the DB level (belt-and-suspenders alongside your Python validation). `index=True` speeds up the `WHERE email = ?` query on login.

**`hashed_password`** — never store plaintext passwords. Bcrypt hash is ~60 characters; 255 gives you room.

**`is_active`** — admin can deactivate an account without deleting it. Deactivated users cannot log in.

**`is_verified`** — email verification flag. Unverified users can be given reduced access (e.g., cannot post, but can browse).

**`is_locked`** — either manual admin lock or automatic brute-force lock.

**`role`** — simple RBAC (Role-Based Access Control). `"user"` and `"admin"` cover most apps. You can expand to an enum or a separate roles table later.

**`failed_login_attempts` + `locked_until`** — brute-force protection. We increment on every failed login and set `locked_until = now() + 15 minutes` after N failures.

**`deleted_at`** — soft delete. Instead of `DELETE FROM users`, we set `deleted_at = now()`. The account is recoverable. You can run a cron job to hard-delete very old soft-deleted accounts.

---

## 5. The RefreshToken Model

```python
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = {"schema": settings.SCHEMA}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # --- Link to user ---
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(f"{settings.SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # --- Token identity ---
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # We store a hash of the token, not the raw token.
    # If the DB is breached, raw tokens cannot be used.

    jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    # jti = JWT ID — the same jti is embedded in the JWT payload.
    # Lets us look up this DB row when a refresh request arrives.

    # --- Token family (for theft detection) ---
    family_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    # All tokens in one login chain share the same family_id.
    # If token reuse is detected → revoke all tokens with this family_id.

    # --- Session metadata ---
    device_info: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # IPv6 max = 39 chars, but we use 45 for mapped IPv4-in-IPv6

    # --- Lifecycle ---
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Setting revoked_at marks a token as invalid without deleting the row.
    # This is important: we KEEP the row after use (rotation) so we can detect reuse.
    # When a token is rotated: set revoked_at, insert new row.
    # When reuse is detected: the old row has revoked_at set but someone used the jti again.

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # --- Relationship ---
    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
```

### Why Store a `token_hash` Instead of the Raw Token?

If your database is breached, raw tokens are as good as passwords — an attacker could use them to log in. By storing a SHA-256 hash, a breach only reveals hashes. The attacker cannot derive the original token from its hash.

```python
import hashlib

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# When storing:
token_hash = hash_token(raw_refresh_token)

# When validating:
incoming_hash = hash_token(token_from_cookie)
db_token = session.query(RefreshToken).filter_by(token_hash=incoming_hash).first()
```

### Why Keep Revoked Tokens in the DB?

To detect **token reuse** (theft):

```
Login           → issue token_A (jti=abc, revoked_at=NULL)
Refresh (legit) → revoke token_A (set revoked_at), issue token_B (jti=def)
Refresh (thief) → sends token_A again
                  → lookup jti=abc → revoked_at is SET → THEFT DETECTED
                  → revoke all tokens with the same family_id
                  → user must re-login
```

If we deleted token_A after rotation, the server would have no record of it and might accept it again (depending on implementation). Keeping it with `revoked_at` is the key.

**Cleanup:** Schedule a daily job to `DELETE FROM refresh_tokens WHERE expires_at < now() - interval '30 days'` to keep the table from growing forever.

---

## 6. The EmailVerification & PasswordReset Models

Both follow the same pattern: temporary single-use tokens stored in the database.

```python
class EmailVerification(Base):
    __tablename__ = "email_verifications"
    __table_args__ = {"schema": settings.SCHEMA}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(f"{settings.SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship()


class PasswordReset(Base):
    __tablename__ = "password_resets"
    __table_args__ = {"schema": settings.SCHEMA}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(f"{settings.SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship()
```

**`token_hash`** — same reason as refresh tokens: store the hash, send the raw token in the email link.

**`used_at`** — marks the token as already used. A reset link should work exactly once. Check: `expires_at > now()` AND `used_at IS NULL`.

**`expires_at`** — typical values:
- Email verification: 24 hours
- Password reset: 1 hour (shorter because it's sensitive)

---

## 7. Updating config.py for JWT Settings

Add JWT configuration to `src/learn_auth/app/core/config.py`:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".envrc",
        extra="allow",
        case_sensitive=True,
    )

    # General
    APP_NAME: str = "learn_auth"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = True
    SCHEMA: str = "learn_auth"
    SKIP_DB_INIT: bool = True

    # Database (from .envrc)
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = ""

    # JWT — add these to .envrc too!
    JWT_SECRET_KEY: str = ""                # 256-bit random secret — REQUIRED
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Security
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15


settings = Settings()
```

And add to your `.envrc`:
```bash
# Generate this with: python -c "import secrets; print(secrets.token_hex(32))"
export JWT_SECRET_KEY="your-64-char-hex-secret-here"
```

---

## 8. Generating and Applying the Migration

### Step 1 — Write All Your Models First

Put all auth models in `src/learn_auth/app/models/auth.py`. The project auto-discovers all files in `app/models/`, so no registration is needed.

### Step 2 — Check the Current State

```bash
uv run alembic current
# Output: 2026_03_03_001 (head)
# This means the last applied migration is the initial schema (todos table only)
```

### Step 3 — Generate the Migration

```bash
uv run alembic revision --autogenerate -m "add auth tables"
```

This creates a new file: `alembic/versions/2026_03_07_002_add_auth_tables.py`

### Step 4 — REVIEW the Migration

Open the generated file and verify:

```python
# What to check:
# 1. Are all 4 tables listed in upgrade()? (users, refresh_tokens, email_verifications, password_resets)
# 2. Are foreign keys pointing to learn_auth.users? (schema prefix required)
# 3. Are indexes created for email, jti, token_hash, user_id fields?
# 4. Does downgrade() drop tables in the right order? (children before parents)
#    → drop refresh_tokens, email_verifications, password_resets BEFORE users
#    → because they have FKs pointing to users

# If anything is wrong, EDIT the file manually before running upgrade.
```

**Critical FK pattern for this project:**

```python
# Alembic should generate something like this:
sa.ForeignKeyConstraint(
    ["user_id"],
    ["learn_auth.users.id"],  # ← must include schema prefix
    ondelete="CASCADE",
)
```

If the schema prefix is missing, the FK will fail at runtime.

### Step 5 — Apply

```bash
uv run alembic upgrade head
```

Expected output:
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade 2026_03_03_001 -> 2026_03_07_002, add auth tables
```

### Step 6 — Verify

Connect to Postgres and check:
```bash
# Using psql or any DB tool:
# docker exec -it <container> psql -U <user> -d <db>
\dt learn_auth.*
# Should show: todos, users, refresh_tokens, email_verifications, password_resets
```

---

## 9. Common Alembic Mistakes and How to Avoid Them

### Mistake 1: Running autogenerate without the DB running

```
sqlalchemy.exc.OperationalError: could not connect to server
```
**Fix:** `make pgup` first, then generate the revision.

### Mistake 2: Forgetting the schema prefix in ForeignKey

```python
# WRONG — Alembic might generate this:
ForeignKey("users.id")

# RIGHT — must include schema for this project:
ForeignKey(f"{settings.SCHEMA}.users.id")
```
Always double-check FK references in generated migrations.

### Mistake 3: Editing an already-applied migration

If you apply a migration, then edit it, the next `alembic current` will show a checksum mismatch or the changes will never be applied (since Alembic thinks it's already done).

**Fix:** If you need to change a schema, create a **new** migration. Never edit applied ones (except in local dev before you've committed).

### Mistake 4: Multiple heads

If two people create migrations from the same parent, you get two "heads." 

```bash
uv run alembic history
# You'll see two branches: 001 → 002a AND 001 → 002b

# Fix: create a merge migration
uv run alembic merge 002a 002b -m "merge heads"
uv run alembic upgrade head
```

### Mistake 5: Dropping tables in wrong order in downgrade()

If `refresh_tokens` has a FK to `users`, dropping `users` first in `downgrade()` will fail with a FK constraint error.

```python
# CORRECT downgrade order (children before parents):
def downgrade():
    op.drop_table("password_resets", schema="learn_auth")
    op.drop_table("email_verifications", schema="learn_auth")
    op.drop_table("refresh_tokens", schema="learn_auth")
    op.drop_table("users", schema="learn_auth")  # ← last, because others reference it
```

### Mistake 6: `server_default` vs Python `default`

```python
# server_default: the DB provides the value during INSERT
# ✓ Works even if you insert a row outside of SQLAlchemy (e.g., raw SQL)
created_at: Mapped[datetime] = mapped_column(server_default=func.now())

# default: Python provides the value — the DB never knows about it
# ✗ Broken for raw SQL inserts; not reflected in the DB schema
created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
```

For timestamps, always use `server_default=func.now()`.

---

## What's Next

**Part 3** implements the first 5 endpoints (Register, Login, Logout, Refresh, Logout-all) using the models defined here. We'll also update `security.py` to add JWT creation and validation functions.
