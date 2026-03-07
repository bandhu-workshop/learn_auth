# Part 3: Core Auth — Register, Login, Logout, Refresh, Logout All

## Table of Contents
1. [Package Dependencies](#1-package-dependencies)
2. [Updated security.py — JWT Functions](#2-updated-securitypy--jwt-functions)
3. [Schemas](#3-schemas)
4. [Auth Service](#4-auth-service)
5. [Auth Endpoints](#5-auth-endpoints)
6. [Wire It Up (Router Registration)](#6-wire-it-up-router-registration)
7. [What Can Go Wrong](#7-what-can-go-wrong)
8. [Testing the Endpoints](#8-testing-the-endpoints)

---

## 1. Package Dependencies

Add to `pyproject.toml`:
```bash
uv add python-jose[cryptography] python-multipart
```

- `python-jose` — JWT encode/decode (battle-tested, supports HS256, RS256)
- `python-multipart` — required for FastAPI's OAuth2PasswordRequestForm (form data)

---

## 2. Updated security.py — JWT Functions

Replace `src/learn_auth/app/core/security.py` with the full version:

```python
# src/learn_auth/app/core/security.py
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

from learn_auth.app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Password helpers (already existed)
# ---------------------------------------------------------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# Token helpers (new)
# ---------------------------------------------------------------------------

def create_access_token(user_id: int, email: str, role: str) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),       # Subject: who the token is about
        "email": email,
        "role": role,
        "type": "access",          # Custom claim: distinguish from refresh
        "iat": now,                # Issued At
        "exp": expire,             # Expiry
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: int, family_id: str | None = None) -> tuple[str, str, str]:
    """
    Create a long-lived refresh token.

    Returns:
        (raw_token, jti, family_id)
        - raw_token: the JWT string to send to the client
        - jti: unique token ID embedded in the JWT, used to look up the DB row
        - family_id: shared across all tokens in one login chain (theft detection)
    """
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    family_id = family_id or str(uuid.uuid4())  # new family on fresh login

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": jti,
        "family_id": family_id,
        "iat": now,
        "exp": expire,
    }
    raw_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return raw_token, jti, family_id


def decode_access_token(token: str) -> dict:
    """
    Decode and validate an access token.
    Raises JWTError on any problem (expired, invalid, wrong type).
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],  # ← always restrict algorithms!
        )
    except JWTError:
        raise

    if payload.get("type") != "access":
        raise JWTError("Not an access token")

    return payload


def decode_refresh_token(token: str) -> dict:
    """Decode and validate a refresh token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError:
        raise

    if payload.get("type") != "refresh":
        raise JWTError("Not a refresh token")

    return payload


def hash_token(raw_token: str) -> str:
    """SHA-256 hash of a token for safe DB storage."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_urlsafe_token() -> str:
    """Generate a random URL-safe token for email links."""
    return secrets.token_urlsafe(32)  # 32 bytes = 256 bits of randomness
```

### Why Two `decode_*` Functions?

Access and refresh tokens look similar but serve completely different purposes. Explicitly separating them prevents a class of attacks where a client sends a refresh token where an access token is expected (or vice versa). The `type` claim check enforces this.

---

## 3. Schemas

Create `src/learn_auth/app/schemas/auth.py`:

```python
# src/learn_auth/app/schemas/auth.py
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Enforce minimum password complexity."""
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # Note: refresh_token is NOT here — it's set as an HttpOnly cookie


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str | None
    is_verified: bool
    role: str

    model_config = {"from_attributes": True}  # allows Pydantic to read SQLAlchemy models
```

---

## 4. Auth Service

Create `src/learn_auth/app/services/auth.py`. This is where all the business logic lives. Endpoints will call these functions:

```python
# src/learn_auth/app/services/auth.py
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from learn_auth.app.core.config import settings
from learn_auth.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    get_password_hash,
    hash_token,
    verify_password,
)
from learn_auth.app.models.auth import RefreshToken, User
from learn_auth.app.schemas.auth import RegisterRequest


# ---------------------------------------------------------------------------
# Feature 1: Register
# ---------------------------------------------------------------------------

def register_user(db: Session, data: RegisterRequest) -> User:
    """
    Create a new user account.

    What can go wrong:
    - Email already exists → 409 Conflict
    """
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=data.email,
        hashed_password=get_password_hash(data.password),
        full_name=data.full_name,
        is_active=True,
        is_verified=False,  # must verify email
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Feature 2: Login
# ---------------------------------------------------------------------------

def login_user(
    db: Session,
    email: str,
    password: str,
    ip_address: str | None = None,
    device_info: str | None = None,
) -> tuple[str, str]:
    """
    Authenticate user and issue tokens.

    Returns:
        (access_token, raw_refresh_token)

    Security: Same error and timing for "email not found" and "wrong password".
    This prevents email enumeration.
    """
    # --- Lookup user ---
    user = db.query(User).filter(User.email == email).first()

    # --- Timing-safe: always verify a password even if user is None ---
    # Without this, a missing user returns instantly (timing leak).
    dummy_hash = "$2b$12$AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # noqa: S105
    password_to_verify = user.hashed_password if user else dummy_hash
    password_ok = verify_password(password, password_to_verify)

    # --- Brute force check (before lock to avoid timing difference) ---
    if user and user.is_locked:
        if user.locked_until and user.locked_until > datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked. Try again later.",
            )
        else:
            # Lock window expired — reset
            user.is_locked = False
            user.failed_login_attempts = 0
            db.commit()

    # --- Validate credentials ---
    if not user or not password_ok or not user.is_active or user.deleted_at is not None:
        if user:
            _record_failed_attempt(db, user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",  # ← intentionally vague
        )

    # --- Reset failed attempts on success ---
    user.failed_login_attempts = 0
    user.is_locked = False
    user.locked_until = None

    # --- Issue tokens ---
    access_token = create_access_token(user.id, user.email, user.role)
    raw_refresh, jti, family_id = create_refresh_token(user.id)

    # --- Persist refresh token ---
    rt = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh),
        jti=jti,
        family_id=family_id,
        device_info=device_info,
        ip_address=ip_address,
        expires_at=datetime.now(UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    db.commit()

    return access_token, raw_refresh


def _record_failed_attempt(db: Session, user: User) -> None:
    """Increment failed login counter and lock if threshold reached."""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
        user.is_locked = True
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
    db.commit()


# ---------------------------------------------------------------------------
# Feature 3: Logout
# ---------------------------------------------------------------------------

def logout_user(db: Session, raw_refresh_token: str) -> None:
    """
    Revoke the refresh token for the current session.
    The access token will expire on its own (within 15 minutes).
    """
    token_hash = hash_token(raw_refresh_token)
    rt = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if rt:
        db.delete(rt)
        db.commit()
    # Even if token not found (already revoked/expired), we succeed silently.
    # This prevents the client from discovering whether a token exists.


# ---------------------------------------------------------------------------
# Feature 4: Refresh Token
# ---------------------------------------------------------------------------

def refresh_access_token(
    db: Session,
    raw_refresh_token: str,
    ip_address: str | None = None,
    device_info: str | None = None,
) -> tuple[str, str]:
    """
    Exchange a valid refresh token for a new access token + rotated refresh token.

    Returns: (new_access_token, new_raw_refresh_token)

    Implements:
    - Token rotation (old refresh token is revoked, new one issued)
    - Reuse detection (old revoked token presented again → family revoked)
    """
    # --- Decode the JWT (check signature and expiry) ---
    try:
        payload = decode_refresh_token(raw_refresh_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    jti = payload.get("jti")
    family_id = payload.get("family_id")
    user_id = int(payload.get("sub"))

    # --- Look up the token in DB ---
    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()

    if rt is None:
        # Token was never issued by us (forged) or already deleted
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if rt.revoked_at is not None:
        # ⚠️ REUSE DETECTED: This token was already rotated (revoked_at is set),
        # but someone is presenting it again. This means the old token was stolen.
        # Revoke the entire family.
        _revoke_token_family(db, family_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected. All sessions revoked. Please log in again.",
        )

    if rt.expires_at < datetime.now(UTC):
        db.delete(rt)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    # --- Get the user ---
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active or user.deleted_at is not None or user.is_locked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")

    # --- Rotate: mark old token as revoked (DON'T delete — needed for reuse detection) ---
    rt.revoked_at = datetime.now(UTC)

    # --- Issue new tokens ---
    new_access = create_access_token(user.id, user.email, user.role)
    new_raw_refresh, new_jti, _ = create_refresh_token(user.id, family_id=family_id)
    # ↑ same family_id: the new token belongs to the same login chain

    new_rt = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        jti=new_jti,
        family_id=family_id,
        device_info=device_info or rt.device_info,
        ip_address=ip_address or rt.ip_address,
        expires_at=datetime.now(UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_rt)
    db.commit()

    return new_access, new_raw_refresh


def _revoke_token_family(db: Session, family_id: str) -> None:
    """Revoke ALL active tokens in a family (theft response)."""
    now = datetime.now(UTC)
    tokens = db.query(RefreshToken).filter(
        RefreshToken.family_id == family_id,
        RefreshToken.revoked_at.is_(None),
    ).all()
    for t in tokens:
        t.revoked_at = now
    db.commit()


# ---------------------------------------------------------------------------
# Feature 5: Logout All Devices
# ---------------------------------------------------------------------------

def logout_all_devices(db: Session, user_id: int) -> int:
    """
    Revoke all active refresh tokens for a user.
    Forces re-login on all devices.
    Returns the number of sessions revoked.
    """
    now = datetime.now(UTC)
    tokens = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    ).all()
    count = len(tokens)
    for t in tokens:
        t.revoked_at = now
    db.commit()
    return count
```

---

## 5. Auth Endpoints

Create `src/learn_auth/app/api/v1/endpoints/auth.py`:

```python
# src/learn_auth/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from learn_auth.app.core.deps import get_current_user, get_db
from learn_auth.app.schemas.auth import RegisterRequest, TokenResponse, UserResponse
from learn_auth.app.services import auth as auth_service

router = APIRouter()

REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days in seconds


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Helper: set the refresh token as an HttpOnly cookie."""
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,           # JS cannot read this
        secure=True,             # HTTPS only (set False locally if not using HTTPS)
        samesite="lax",          # "strict" breaks OAuth redirects; "lax" is a safe default
        max_age=REFRESH_COOKIE_MAX_AGE,
        path="/api/v1/auth",     # Cookie only sent to auth endpoints — minimizes exposure
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Helper: delete the refresh cookie by making it expire immediately."""
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
    )


# ---------------------------------------------------------------------------
# Feature 1: Register
# ---------------------------------------------------------------------------

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create a new user account.
    Password is hashed immediately — the plain password is never stored.
    Returns the created user (without password hash).
    """
    user = auth_service.register_user(db, data)
    return user


# ---------------------------------------------------------------------------
# Feature 2: Login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
def login(request: Request, response: Response, data: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate and receive tokens.
    - access_token: returned in the response body, short-lived (15 min)
    - refresh_token: set as HttpOnly cookie, long-lived (7 days)
    """
    ip = request.client.host if request.client else None
    device_info = request.headers.get("User-Agent")

    access_token, refresh_token = auth_service.login_user(
        db, data.email, data.password, ip_address=ip, device_info=device_info
    )

    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(access_token=access_token)


# ---------------------------------------------------------------------------
# Feature 3: Logout
# ---------------------------------------------------------------------------

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Revoke the current session's refresh token.
    The access token will expire naturally within its TTL.
    """
    raw_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    if raw_refresh:
        auth_service.logout_user(db, raw_refresh)
    _clear_refresh_cookie(response)


# ---------------------------------------------------------------------------
# Feature 4: Refresh
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access token.
    The refresh token is rotated: old one is revoked, new one issued.
    """
    raw_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_refresh:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="No refresh token")

    ip = request.client.host if request.client else None
    device_info = request.headers.get("User-Agent")

    new_access, new_refresh = auth_service.refresh_access_token(
        db, raw_refresh, ip_address=ip, device_info=device_info
    )

    _set_refresh_cookie(response, new_refresh)
    return TokenResponse(access_token=new_access)


# ---------------------------------------------------------------------------
# Feature 5: Logout All Devices
# ---------------------------------------------------------------------------

@router.post("/logout-all", status_code=status.HTTP_200_OK)
def logout_all(
    response: Response,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # requires valid access token
):
    """
    Revoke all refresh tokens for the current user.
    Forces re-login on all other devices.
    """
    count = auth_service.logout_all_devices(db, current_user.id)
    _clear_refresh_cookie(response)
    return {"message": f"Logged out from {count} device(s)"}
```

---

### But wait — what is `get_current_user`?

This dependency validates the access token on every protected request. Add it to `src/learn_auth/app/core/deps.py`:

```python
# src/learn_auth/app/core/deps.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from learn_auth.app.core.database import SessionLocal
from learn_auth.app.core.security import decode_access_token
from learn_auth.app.models.auth import User


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


bearer_scheme = HTTPBearer()  # Reads "Authorization: Bearer <token>" header


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency: validate access token and return the current user.
    Use as: current_user: User = Depends(get_current_user)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None or not user.is_active or user.deleted_at is not None:
        raise credentials_exception

    return user


def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency: require admin role.
    Use as: admin: User = Depends(get_current_admin)
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user
```

---

## 6. Wire It Up (Router Registration)

Update `src/learn_auth/app/api/v1/routers.py`:

```python
from fastapi import APIRouter

from learn_auth.app.api.v1.endpoints.auth import router as auth_router
from learn_auth.app.api.v1.endpoints.todos import router as todo_router

router = APIRouter()
router.include_router(auth_router, prefix="/auth", tags=["auth"])
router.include_router(todo_router, prefix="/todos", tags=["todos"])
```

The full path for auth endpoints becomes: `POST /api/v1/auth/login`, etc.

---

## 7. What Can Go Wrong

### `LoginRequest` not found

In the endpoint file, `LoginRequest` must be imported. Since it's defined in `schemas/auth.py`:
```python
from learn_auth.app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
```

### `httponly=True` but you still see the cookie in devtools

`HttpOnly` means JavaScript cannot read it, but browser devtools *can* see it. This is normal and intended.

### Refresh works in Postman but not from the browser

This is a `SameSite` + `path` cookie issue. The cookie has `path="/api/v1/auth"` — the refresh request must go to a URL that starts with that path. The `SameSite=lax` setting is fine for browsers (as long as requests are same-origin or use GET redirects).

### `422 Unprocessable Entity` on login

FastAPI expects JSON body. If you're testing with curl, use:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecretPass1"}'
```

### `"Could not validate credentials"` on protected endpoints

You must send the access token:
```bash
curl -X GET http://localhost:8080/api/v1/todos \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## 8. Testing the Endpoints

### Manual Flow with curl

```bash
# 1. Register
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "AlicePass1", "full_name": "Alice"}'
# → {"id": 1, "email": "alice@example.com", "full_name": "Alice", ...}

# 2. Login (save the access_token and cookie)
curl -s -c cookies.txt -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "AlicePass1"}'
# → {"access_token": "eyJ...", "token_type": "bearer"}

# 3. Use the access token
ACCESS_TOKEN="eyJ..."
curl -s -X GET http://localhost:8080/api/v1/todos \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 4. Refresh (sends cookie automatically)
curl -s -c cookies.txt -b cookies.txt -X POST http://localhost:8080/api/v1/auth/refresh
# → {"access_token": "eyJ...", "token_type": "bearer"}  (new token)

# 5. Logout
curl -s -c cookies.txt -b cookies.txt -X POST http://localhost:8080/api/v1/auth/logout

# 6. Logout all devices
curl -s -X POST http://localhost:8080/api/v1/auth/logout-all \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### FastAPI Swagger UI

Open `http://localhost:8080/docs` — click "Authorize" and enter your access token. All protected routes will send it automatically.

---

### Summary: What Each Feature Does

| # | Endpoint | Auth required | What happens |
|---|---|---|---|
| 1 | `POST /auth/register` | No | Creates user, hashes password |
| 2 | `POST /auth/login` | No | Issues access + refresh token |
| 3 | `POST /auth/logout` | No (uses cookie) | Revokes current refresh token |
| 4 | `POST /auth/refresh` | No (uses cookie) | Rotates refresh token, issues new access token |
| 5 | `POST /auth/logout-all` | Yes (access token) | Revokes all refresh tokens for user |

## What's Next

**Part 4** covers email verification (Feature 6–7) and password reset (Features 8–9). These require sending emails — we'll use a simple SMTP setup and explain the token-in-link pattern.
