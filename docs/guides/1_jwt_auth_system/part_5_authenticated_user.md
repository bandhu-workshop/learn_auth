# Part 5: Authenticated User Endpoints — /me, Profile, Change Password, Delete Account

## Table of Contents
1. [Overview](#1-overview)
2. [Schemas](#2-schemas)
3. [Service Functions](#3-service-functions)
4. [Endpoints](#4-endpoints)
5. [Protecting Endpoints with Dependencies](#5-protecting-endpoints-with-dependencies)
6. [What Can Go Wrong](#6-what-can-go-wrong)

---

## 1. Overview

These endpoints require the user to be logged in (a valid access token). They operate on **the currently authenticated user** — the user identified by the JWT they send with the request.

| # | Endpoint | Method | Description |
|---|---|---|---|
| 10 | `/users/me` | GET | Return current user data |
| 11 | `/users/me/profile` | GET | Return public profile |
| 12 | `/users/me/profile` | PATCH | Update name, avatar, bio |
| 13 | `/users/me/password` | PUT | Change password (needs current password) |
| 14 | `/users/me` | DELETE | Soft-delete account (needs password confirmation) |

All use `Depends(get_current_user)` — the dependency we built in Part 3.

---

## 2. Schemas

Add to `src/learn_auth/app/schemas/auth.py`:

```python
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class UserResponse(BaseModel):
    """Full user data — includes sensitive flags, but no password."""
    id: int
    email: str
    full_name: str | None
    avatar_url: str | None
    bio: str | None
    is_verified: bool
    is_active: bool
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ProfileResponse(BaseModel):
    """Public-facing profile — minimal data."""
    id: int
    full_name: str | None
    avatar_url: str | None
    bio: str | None

    model_config = {"from_attributes": True}


class UpdateProfileRequest(BaseModel):
    """All fields optional — PATCH semantics."""
    full_name: str | None = Field(default=None, max_length=255)
    avatar_url: str | None = Field(default=None, max_length=512)
    bio: str | None = Field(default=None, max_length=1000)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain an uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain a lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Must contain a digit")
        return v


class DeleteAccountRequest(BaseModel):
    password: str  # confirmation — prevent accidental deletion
```

---

## 3. Service Functions

Create `src/learn_auth/app/services/users.py`:

```python
# src/learn_auth/app/services/users.py
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from learn_auth.app.core.security import get_password_hash, verify_password
from learn_auth.app.models.auth import User
from learn_auth.app.schemas.auth import ChangePasswordRequest, UpdateProfileRequest
from learn_auth.app.services.auth import logout_all_devices


# ---------------------------------------------------------------------------
# Feature 10 & 11: get_me / get_profile
# ---------------------------------------------------------------------------
# These are trivial — the endpoint just returns the User object from the
# get_current_user dependency. No service function needed.
# The schemas control what fields are exposed.


# ---------------------------------------------------------------------------
# Feature 12: Update Profile
# ---------------------------------------------------------------------------

def update_profile(db: Session, user: User, data: UpdateProfileRequest) -> User:
    """
    Update mutable profile fields.
    Uses PATCH semantics: only update fields that are explicitly provided.

    The challenging part: how do you know if a field was omitted vs set to None?

    When the request is:
      {"full_name": "Alice"}            → update full_name only
      {"full_name": null}               → clear full_name (set to None)
      {}                                → update nothing

    Pydantic v2 helps here: we use model_fields_set to see what was actually sent.
    """
    update_data = data.model_dump(exclude_unset=True)
    # exclude_unset=True: only includes fields that were explicitly set in the request
    # Omit fields that were not sent at all (they keep their current DB value)

    for field, value in update_data.items():
        setattr(user, field, value)

    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 13: Change Password
# ---------------------------------------------------------------------------

def change_password(db: Session, user: User, data: ChangePasswordRequest) -> None:
    """
    Change password: requires current password for verification.
    After change, revokes all other sessions for security.
    The current session's access token remains valid until it expires (~15 min).
    """
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    user.hashed_password = get_password_hash(data.new_password)

    # Revoke all sessions — anyone using an old refresh token must re-login
    # (The user's current request used an access token, which expires on its own)
    logout_all_devices(db, user.id)

    db.commit()


# ---------------------------------------------------------------------------
# Feature 14: Delete Account (Soft Delete)
# ---------------------------------------------------------------------------

def delete_account(db: Session, user: User, password: str) -> None:
    """
    Soft-delete the user's account.

    Soft delete means: set deleted_at = now(). The row stays in the database.
    This allows:
    - Account recovery (admin can undelete within a grace period)
    - Audit trails (who did what, even for deleted accounts)
    - Referential integrity (todos/posts linked to this user still exist)

    After deletion: revoke all sessions immediately.
    """
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password confirmation failed",
        )

    user.deleted_at = datetime.now(UTC)
    user.is_active = False  # immediately prevent any new logins

    logout_all_devices(db, user.id)  # force logout everywhere
    db.commit()
```

---

## 4. Endpoints

Create `src/learn_auth/app/api/v1/endpoints/users.py`:

```python
# src/learn_auth/app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from learn_auth.app.core.deps import get_current_user, get_db
from learn_auth.app.models.auth import User
from learn_auth.app.schemas.auth import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    ProfileResponse,
    UpdateProfileRequest,
    UserResponse,
)
from learn_auth.app.services import users as user_service

router = APIRouter()


# ---------------------------------------------------------------------------
# Feature 10: Get Current User
# ---------------------------------------------------------------------------

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Return the currently authenticated user's full details.
    No DB call needed — get_current_user already loaded the user.
    """
    return current_user


# ---------------------------------------------------------------------------
# Feature 11: Get Profile
# ---------------------------------------------------------------------------

@router.get("/me/profile", response_model=ProfileResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    """
    Return the public profile fields only.
    """
    return current_user


# ---------------------------------------------------------------------------
# Feature 12: Update Profile
# ---------------------------------------------------------------------------

@router.patch("/me/profile", response_model=UserResponse)
def update_profile(
    data: UpdateProfileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update profile fields. All fields are optional — only sent fields are updated.
    """
    updated = user_service.update_profile(db, current_user, data)
    return updated


# ---------------------------------------------------------------------------
# Feature 13: Change Password
# ---------------------------------------------------------------------------

@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    data: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Change the current user's password.
    Requires the current password for confirmation.
    Revokes all existing sessions after the change.
    """
    user_service.change_password(db, current_user, data)


# ---------------------------------------------------------------------------
# Feature 14: Delete Account
# ---------------------------------------------------------------------------

@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    data: DeleteAccountRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Soft-delete the current user's account.
    Requires password confirmation to prevent accidents.
    """
    user_service.delete_account(db, current_user, data.password)
```

---

## 5. Protecting Endpoints with Dependencies

`get_current_user` (from `deps.py`) is your primary protection. Here's how it works step by step when a request arrives:

```
Request: GET /api/v1/users/me
Headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

1. HTTPBearer() reads the Authorization header
   → extracts "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

2. decode_access_token()
   → verifies signature (was this token issued by us?)
   → checks `exp` claim (has it expired?)
   → checks `type` == "access"
   → if anything fails → raises JWTError → endpoint gets 401

3. Extract user_id from `sub` claim

4. Query DB: SELECT * FROM users WHERE id = user_id
   → user not found → 401
   → user.is_active == False → 401
   → user.deleted_at is not None → 401

5. Return the User ORM object
   → endpoint receives it as `current_user`
```

No additional code needed in your endpoint — just `Depends(get_current_user)`.

### Optional Dependencies

Some endpoints might want the user if they're logged in, but also work anonymously. Use an optional version:

```python
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Depends, Request

optional_bearer = HTTPBearer(auto_error=False)

def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_bearer),
    db: Session = Depends(get_db),
) -> User | None:
    if credentials is None:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload.get("sub"))
        return db.query(User).filter(User.id == user_id).first()
    except Exception:
        return None
```

---

## 6. What Can Go Wrong

### PATCH vs PUT — Understanding the Difference

- **PUT** replaces the entire resource. If you send `{"full_name": "Alice"}` with PUT, it would clear `avatar_url`, `bio`, etc. to null.
- **PATCH** updates only the fields you send. We use PATCH for profile update.

The key is `model_dump(exclude_unset=True)`:

```python
# Request body: {"full_name": "Alice"}  (no avatar_url or bio)
data = UpdateProfileRequest(full_name="Alice")
data.model_dump()                      # {"full_name": "Alice", "avatar_url": None, "bio": None}
data.model_dump(exclude_unset=True)    # {"full_name": "Alice"}  ← correct!
```

### "Current password" Timing Attack

If you check `verify_password` and it's slow when wrong (bcrypt ~100ms) but instant on `None` when the column is blank — that's a timing leak. The implementation above always calls `verify_password` properly, so this isn't an issue.

### Soft-Delete and get_current_user

After a user calls DELETE `/me`, their access token is still valid for up to 15 minutes. The `get_current_user` dependency already checks `deleted_at is not None` → 401. So there's no window where a deleted account can still use API endpoints.

### Not Registering the Users Router

Add to `src/learn_auth/app/api/v1/routers.py`:
```python
from learn_auth.app.api.v1.endpoints.users import router as users_router

router.include_router(users_router, prefix="/users", tags=["users"])
```

---

## What's Next

**Part 6** covers Session Management — listing active sessions (Feature 15) and revoking a specific one (Feature 16). These endpoints let users see all their logged-in devices and selectively log out from one.
