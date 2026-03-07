# Part 7: Admin Endpoints — User Management, Locking, Roles

## Table of Contents
1. [Admin Authorization Pattern](#1-admin-authorization-pattern)
2. [Admin Schemas](#2-admin-schemas)
3. [Admin Service Functions](#3-admin-service-functions)
4. [Admin Endpoints](#4-admin-endpoints)
5. [Filtering Users — Query Params vs Body](#5-filtering-users--query-params-vs-body)
6. [Security Considerations](#6-security-considerations)

---

## 1. Admin Authorization Pattern

All admin endpoints use `get_current_admin` — the dependency we defined in Part 3:

```python
def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Extends get_current_user by requiring role == 'admin'."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
```

This creates a **two-layer check**:
1. Valid JWT access token (from `get_current_user`)
2. Role must be `"admin"` (from `get_current_admin`)

A regular user with a valid token gets `403 Forbidden`, not `401 Unauthorized`. The distinction matters:
- `401` = not authenticated (no valid token)
- `403` = authenticated but not authorized (valid token, wrong role)

---

## 2. Admin Schemas

Add to `src/learn_auth/app/schemas/auth.py`:

```python
class AdminUserResponse(BaseModel):
    """Full user details for admin view — includes internal flags."""
    id: int
    email: str
    full_name: str | None
    role: str
    is_active: bool
    is_verified: bool
    is_locked: bool
    failed_login_attempts: int
    locked_until: datetime | None
    created_at: datetime
    updated_at: datetime | None
    deleted_at: datetime | None

    model_config = {"from_attributes": True}


class AssignRoleRequest(BaseModel):
    role: str = Field(pattern=r"^(user|admin|moderator)$")
    # Use a regex pattern to restrict to known roles
    # Adjust the pattern as your app grows


class UserFilterParams(BaseModel):
    """Query parameters for listing users."""
    is_active: bool | None = None
    is_verified: bool | None = None
    is_locked: bool | None = None
    is_deleted: bool | None = None  # True = show only deleted
    search: str | None = None       # search by email or name
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
```

---

## 3. Admin Service Functions

Create `src/learn_auth/app/services/admin.py`:

```python
# src/learn_auth/app/services/admin.py
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from learn_auth.app.core.config import settings
from learn_auth.app.models.auth import RefreshToken, User
from learn_auth.app.schemas.auth import UserFilterParams
from learn_auth.app.services.auth import logout_all_devices


# ---------------------------------------------------------------------------
# Feature 17: Get Any User
# ---------------------------------------------------------------------------

def get_user_by_id(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


# ---------------------------------------------------------------------------
# Feature 18: Lock Account
# ---------------------------------------------------------------------------

def lock_account(db: Session, user_id: int, duration_minutes: int = 60 * 24) -> User:
    """
    Manually lock an account for a specified duration (default: 24 hours).
    This is for manual admin intervention — different from auto-lock on brute force.
    """
    user = get_user_by_id(db, user_id)
    user.is_locked = True
    user.locked_until = datetime.now(UTC) + timedelta(minutes=duration_minutes)
    # Revoke all sessions — kick them out immediately
    logout_all_devices(db, user_id)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 19: Unlock Account
# ---------------------------------------------------------------------------

def unlock_account(db: Session, user_id: int) -> User:
    """
    Manually unlock an account and reset failed login counter.
    """
    user = get_user_by_id(db, user_id)
    user.is_locked = False
    user.locked_until = None
    user.failed_login_attempts = 0
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 20: Deactivate Account
# ---------------------------------------------------------------------------

def deactivate_account(db: Session, user_id: int) -> User:
    """
    Set is_active = False. The user cannot log in, but the account still exists.
    Use for: ToS violations, payment failures, etc.
    Different from lock: deactivation is indefinite, lock is temporary.
    """
    user = get_user_by_id(db, user_id)
    user.is_active = False
    logout_all_devices(db, user_id)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 21: Reactivate Account
# ---------------------------------------------------------------------------

def reactivate_account(db: Session, user_id: int) -> User:
    """Restore is_active = True."""
    user = get_user_by_id(db, user_id)
    user.is_active = True
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 22: Restore Soft-Deleted Account
# ---------------------------------------------------------------------------

def restore_account(db: Session, user_id: int) -> User:
    """
    Un-delete a soft-deleted account by clearing deleted_at and re-activating.
    """
    user = get_user_by_id(db, user_id)
    if user.deleted_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is not deleted",
        )
    user.deleted_at = None
    user.is_active = True
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 23: List All Users (with filters)
# ---------------------------------------------------------------------------

def list_users(db: Session, filters: UserFilterParams) -> tuple[list[User], int]:
    """
    Return a paginated list of users with optional filters.
    Returns (users, total_count).
    """
    query = db.query(User)

    # Apply filters
    if filters.is_active is not None:
        query = query.filter(User.is_active == filters.is_active)

    if filters.is_verified is not None:
        query = query.filter(User.is_verified == filters.is_verified)

    if filters.is_locked is not None:
        query = query.filter(User.is_locked == filters.is_locked)

    if filters.is_deleted is True:
        query = query.filter(User.deleted_at.is_not(None))
    elif filters.is_deleted is False:
        query = query.filter(User.deleted_at.is_(None))
    # If filters.is_deleted is None → no filter (show both deleted and not)

    if filters.search:
        search_term = f"%{filters.search}%"
        query = query.filter(
            or_(
                User.email.ilike(search_term),
                User.full_name.ilike(search_term),
            )
        )

    # Count before pagination (for "total X results")
    total = query.count()

    # Pagination
    offset = (filters.page - 1) * filters.page_size
    users = query.order_by(User.created_at.desc()).offset(offset).limit(filters.page_size).all()

    return users, total


# ---------------------------------------------------------------------------
# Feature 24: Force Logout User (Revoke All Their Sessions)
# ---------------------------------------------------------------------------

def force_logout_user(db: Session, user_id: int) -> int:
    """Revoke all sessions for a specific user. Returns number of sessions revoked."""
    return logout_all_devices(db, user_id)


# ---------------------------------------------------------------------------
# Feature 25: Assign / Remove Role
# ---------------------------------------------------------------------------

def assign_role(db: Session, user_id: int, role: str) -> User:
    """
    Assign a new role to a user.
    Valid roles are enforced by the AssignRoleRequest schema validator.
    """
    user = get_user_by_id(db, user_id)
    user.role = role
    # Revoke sessions so new role takes effect on next login
    # (existing access tokens still carry the old role until they expire)
    logout_all_devices(db, user_id)
    db.commit()
    db.refresh(user)
    return user
```

---

## 4. Admin Endpoints

Create `src/learn_auth/app/api/v1/endpoints/admin.py`:

```python
# src/learn_auth/app/api/v1/endpoints/admin.py
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from learn_auth.app.core.deps import get_current_admin, get_db
from learn_auth.app.models.auth import User
from learn_auth.app.schemas.auth import AdminUserResponse, AssignRoleRequest, UserFilterParams
from learn_auth.app.services import admin as admin_service

router = APIRouter()


@router.get("/users/{user_id}", response_model=AdminUserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 17: Get full details of any user."""
    return admin_service.get_user_by_id(db, user_id)


@router.post("/users/{user_id}/lock", response_model=AdminUserResponse)
def lock_account(
    user_id: int,
    duration_minutes: int = Query(default=1440, ge=1),  # default: 24 hours
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 18: Lock an account for N minutes."""
    return admin_service.lock_account(db, user_id, duration_minutes)


@router.post("/users/{user_id}/unlock", response_model=AdminUserResponse)
def unlock_account(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 19: Unlock an account and reset failure counter."""
    return admin_service.unlock_account(db, user_id)


@router.post("/users/{user_id}/deactivate", response_model=AdminUserResponse)
def deactivate_account(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 20: Deactivate account (is_active = False)."""
    return admin_service.deactivate_account(db, user_id)


@router.post("/users/{user_id}/reactivate", response_model=AdminUserResponse)
def reactivate_account(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 21: Reactivate a deactivated account."""
    return admin_service.reactivate_account(db, user_id)


@router.post("/users/{user_id}/restore", response_model=AdminUserResponse)
def restore_account(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 22: Restore a soft-deleted account."""
    return admin_service.restore_account(db, user_id)


@router.get("/users", response_model=dict)
def list_users(
    is_active: bool | None = Query(default=None),
    is_verified: bool | None = Query(default=None),
    is_locked: bool | None = Query(default=None),
    is_deleted: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """
    Feature 23: List all users with optional filters.
    Example: GET /admin/users?is_active=false&is_verified=false&page=1
    """
    filters = UserFilterParams(
        is_active=is_active,
        is_verified=is_verified,
        is_locked=is_locked,
        is_deleted=is_deleted,
        search=search,
        page=page,
        page_size=page_size,
    )
    users, total = admin_service.list_users(db, filters)
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [AdminUserResponse.model_validate(u) for u in users],
    }


@router.post("/users/{user_id}/logout", status_code=status.HTTP_200_OK)
def force_logout(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 24: Revoke all sessions for a user."""
    count = admin_service.force_logout_user(db, user_id)
    return {"message": f"Revoked {count} session(s)"}


@router.put("/users/{user_id}/role", response_model=AdminUserResponse)
def assign_role(
    user_id: int,
    data: AssignRoleRequest,
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """Feature 25: Assign a role to a user. Also revokes their sessions."""
    return admin_service.assign_role(db, user_id, data.role)
```

Register in `routers.py`:

```python
from learn_auth.app.api.v1.endpoints.admin import router as admin_router

router.include_router(admin_router, prefix="/admin", tags=["admin"])
# Full prefix: /api/v1/admin/users/{id}
```

---

## 5. Filtering Users — Query Params vs Body

Admin list endpoints typically use **query parameters** for filtering, not a request body. This is the REST convention:

```
# Filter examples:
GET /api/v1/admin/users?is_active=false
GET /api/v1/admin/users?is_locked=true&page=2
GET /api/v1/admin/users?is_deleted=true
GET /api/v1/admin/users?search=alice&page_size=50
GET /api/v1/admin/users?is_verified=false&is_active=true
```

Query parameters are bookmarkable, loggable, and cacheable — the right tool for filtering/searching.

---

## 6. Security Considerations

### Protect Admin Routes Beyond the Dependency

Even with `get_current_admin`, add these layers in production:

1. **IP allowlist:** Restrict `/api/v1/admin/*` to known IPs (your office, VPN) using a reverse proxy (nginx, Caddy).

2. **Audit logging:** Every admin action should be logged with who did what to whom and when. Write a simple audit log table or use structured logging.

3. **Admin cannot admin themselves:** You might want to prevent an admin from locking/deleting themselves:
```python
def lock_account(db, user_id: int, admin_id: int, ...):
    if user_id == admin_id:
        raise HTTPException(400, "You cannot lock your own account")
```

4. **Role escalation:** When assigning roles, ensure an admin cannot create a "super-admin" above themselves unless you have a hierarchy. Simplest: only allow setting `"user"` or `"admin"`.

5. **Role change takes effect on next login:** Changing `user.role` only affects the DB. The user's **current access token still carries the old role** until it expires (up to 15 minutes). If you need immediate effect, force logout (`logout_all_devices`) when changing roles — which is what our service does.

---

## What's Next

**Part 8** covers the security hardening features (26–30) — brute force protection, timing-safe login, refresh token rotation/reuse detection, token family revocation, and password strength validation. Most of these are already embedded in the service code from Parts 3–7. Part 8 explains the theory deeply and shows how to test/verify each one.
