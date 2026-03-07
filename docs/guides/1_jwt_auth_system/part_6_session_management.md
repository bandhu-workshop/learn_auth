# Part 6: Session Management — List & Revoke Sessions

## Table of Contents
1. [What Are Sessions in a JWT System?](#1-what-are-sessions-in-a-jwt-system)
2. [Schemas](#2-schemas)
3. [Service Functions](#3-service-functions)
4. [Endpoints](#4-endpoints)
5. [What Can Go Wrong](#5-what-can-go-wrong)

---

## 1. What Are Sessions in a JWT System?

In traditional session-based auth, a "session" is a server-side record tied to a cookie. In our JWT system, **sessions are our refresh token records in the database**.

Each row in `refresh_tokens` represents one active session — one device/browser where the user is logged in.

| Column | Purpose in Session Management |
|---|---|
| `id` | Unique session identifier, used for revocation |
| `device_info` | The User-Agent string — helps users identify the device |
| `ip_address` | IP when the session was created |
| `created_at` | When the user logged in on this device |
| `expires_at` | When this session will auto-expire |
| `revoked_at` | NULL = active; SET = revoked |

We **only show active sessions** (where `revoked_at IS NULL` and `expires_at > now()`).

---

## 2. Schemas

Add to `src/learn_auth/app/schemas/auth.py`:

```python
class SessionResponse(BaseModel):
    """Public representation of one active session."""
    id: int
    device_info: str | None
    ip_address: str | None
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}
```

Notice: we don't expose `token_hash`, `jti`, or `family_id` to the user. Those are internal.

---

## 3. Service Functions

Add to `src/learn_auth/app/services/users.py`:

```python
from datetime import UTC, datetime
from learn_auth.app.models.auth import RefreshToken


# ---------------------------------------------------------------------------
# Feature 15: List Active Sessions
# ---------------------------------------------------------------------------

def list_sessions(db: Session, user_id: int) -> list[RefreshToken]:
    """
    Return all active (non-revoked, non-expired) refresh tokens for this user.
    Each token = one logged-in device.
    """
    now = datetime.now(UTC)
    return (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > now,
        )
        .order_by(RefreshToken.created_at.desc())
        .all()
    )


# ---------------------------------------------------------------------------
# Feature 16: Revoke Specific Session
# ---------------------------------------------------------------------------

def revoke_session(db: Session, user_id: int, session_id: int) -> None:
    """
    Revoke a specific session by its ID.

    Security check: verify the session belongs to this user before revoking.
    Without the user_id check, a user could revoke OTHER users' sessions
    by guessing session IDs.
    """
    rt = db.query(RefreshToken).filter(
        RefreshToken.id == session_id,
        RefreshToken.user_id == user_id,   # ← critical: ownership check
        RefreshToken.revoked_at.is_(None),
    ).first()

    if rt is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already revoked",
        )

    rt.revoked_at = datetime.now(UTC)
    db.commit()
```

---

## 4. Endpoints

Add to `src/learn_auth/app/api/v1/endpoints/users.py`:

```python
from learn_auth.app.schemas.auth import SessionResponse
from learn_auth.app.services import users as user_service


# ---------------------------------------------------------------------------
# Feature 15: List Active Sessions
# ---------------------------------------------------------------------------

@router.get("/me/sessions", response_model=list[SessionResponse])
def list_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all active sessions for the current user.
    Shows the device, IP, and when each session was created.

    Use this to: identify unfamiliar sessions (possible account compromise).
    """
    return user_service.list_sessions(db, current_user.id)


# ---------------------------------------------------------------------------
# Feature 16: Revoke Specific Session
# ---------------------------------------------------------------------------

@router.delete("/me/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke a specific session by its ID.
    Use this to log out from a specific device without affecting others.
    """
    user_service.revoke_session(db, current_user.id, session_id)
```

### Example Response for GET /me/sessions

```json
[
  {
    "id": 42,
    "device_info": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit...",
    "ip_address": "192.168.1.1",
    "created_at": "2026-03-05T10:23:00Z",
    "expires_at": "2026-03-12T10:23:00Z"
  },
  {
    "id": 38,
    "device_info": "okhttp/4.9.3",  ← mobile app
    "ip_address": "10.0.0.5",
    "created_at": "2026-03-01T08:00:00Z",
    "expires_at": "2026-03-08T08:00:00Z"
  }
]
```

---

## 5. What Can Go Wrong

### Session ID Enumeration (IDOR)

**IDOR** = Insecure Direct Object Reference. Without the `user_id` check in `revoke_session`:

```python
# VULNERABLE:
rt = db.query(RefreshToken).filter(RefreshToken.id == session_id).first()
# User A sends: DELETE /me/sessions/99
# Session 99 belongs to User B → User A revokes User B's session!

# SAFE:
rt = db.query(RefreshToken).filter(
    RefreshToken.id == session_id,
    RefreshToken.user_id == user_id,  # ← always scope to the authenticated user
).first()
```

This mistake is extremely common and is one of the OWASP Top 10 vulnerabilities. Always scope DB queries to the authenticated user's data.

### Showing Revoked Sessions

If you forget the `revoked_at.is_(None)` filter, revoked sessions (already logged out devices) appear in the list, confusing users. Always filter them out.

### Token Rotation Creates Many Rows

Over 7 days of active use, a single login session will create 7×24×(60/15) = 672 rotated token records. Old revoked records accumulate. Schedule a cleanup:

```python
# Run daily via cron or a background task library (APScheduler, Celery, ARQ)
def cleanup_old_tokens(db: Session) -> int:
    from datetime import timedelta
    cutoff = datetime.now(UTC) - timedelta(days=30)
    result = db.query(RefreshToken).filter(
        RefreshToken.expires_at < cutoff
    ).delete()
    db.commit()
    return result  # number of rows deleted
```

---

## What's Next

**Part 7** covers Admin endpoints (Features 17–25) — viewing any user, locking/unlocking accounts, soft-delete management, listing all users with filters, forcing logout, and role management.
