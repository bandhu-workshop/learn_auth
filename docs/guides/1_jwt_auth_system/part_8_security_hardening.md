# Part 8: Security Hardening — Behind the Scenes

## Table of Contents
1. [Feature 26: Brute Force Lockout](#1-feature-26-brute-force-lockout)
2. [Feature 27: Timing-Safe Login](#2-feature-27-timing-safe-login)
3. [Feature 28: Refresh Token Rotation](#3-feature-28-refresh-token-rotation)
4. [Feature 29: Token Family Revocation](#4-feature-29-token-family-revocation)
5. [Feature 30: Password Strength Validation](#5-feature-30-password-strength-validation)
6. [How to Verify Each Security Feature](#6-how-to-verify-each-security-feature)
7. [Additional Hardening Recommendations](#7-additional-hardening-recommendations)

---

## 1. Feature 26: Brute Force Lockout

### The Attack

An attacker knows someone has an account at your site. They run a script trying thousands of common passwords:

```
POST /auth/login {"email": "victim@example.com", "password": "123456"}
POST /auth/login {"email": "victim@example.com", "password": "password"}
POST /auth/login {"email": "victim@example.com", "password": "qwerty"}
... 10,000 attempts ...
```

Without protection, they might eventually guess the password.

### Our Implementation

Already embedded in `login_user` in Part 3. Here's the full logic flow with explanation:

```python
def _record_failed_attempt(db: Session, user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
        user.is_locked = True
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
    db.commit()


def login_user(db, email, password, ...):
    user = db.query(User).filter(User.email == email).first()

    # Step 1: Check if account is locked
    if user and user.is_locked:
        if user.locked_until and user.locked_until > datetime.now(UTC):
            raise HTTPException(429, "Account temporarily locked")
        else:
            # Lock expired — reset
            user.is_locked = False
            user.failed_login_attempts = 0

    # Step 2: Verify credentials (timing-safe — always runs bcrypt)
    dummy_hash = "$2b$12$AAAA..."
    hash_to_check = user.hashed_password if user else dummy_hash
    password_ok = verify_password(password, hash_to_check)

    # Step 3: If wrong → record failure
    if not user or not password_ok:
        if user:
            _record_failed_attempt(db, user)
        raise HTTPException(401, "Invalid credentials")

    # Step 4: Success → reset counter
    user.failed_login_attempts = 0
    user.is_locked = False
    ...
```

### Configuration (in Settings)

```python
MAX_FAILED_LOGIN_ATTEMPTS: int = 5    # lock after 5 failures
ACCOUNT_LOCKOUT_MINUTES: int = 15     # locked for 15 minutes
```

### What About IP-Based Rate Limiting?

Account lockout is **per-account** (protects one user's account). But an attacker could target thousands of different accounts with 4 attempts each (just under the lockout threshold).

**IP-based rate limiting** is the complementary protection. Implement it at the reverse proxy level (nginx, Caddy) or with a middleware:

```python
# Using slowapi (rate limiting for FastAPI)
# uv add slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post("/login")
@limiter.limit("10/minute")  # max 10 login attempts per IP per minute
def login(request: Request, ...):
    ...
```

---

## 2. Feature 27: Timing-Safe Login

### The Attack (Timing Side Channel)

If your login endpoint returns instantly when the email doesn't exist, but takes 100ms when bcrypt verifies a wrong password, an attacker can distinguish between "email doesn't exist" and "wrong password" based on response time — even if both return the same error message:

```
POST /login {"email": "unknown@example.com", "password": "test"}  → response in 1ms  ← email doesn't exist
POST /login {"email": "alice@example.com", "password": "test"}    → response in 105ms ← wrong password
```

This is **email enumeration via timing side-channel**.

### Our Fix: Always Run Argon2

```python
from learn_auth.app.core.security import _DUMMY_HASH, verify_password

def login_user(db, email, password, ...):
    user = db.query(User).filter(User.email == email).first()

    # ALWAYS run Argon2 — even when user is None.
    # _DUMMY_HASH is a pre-computed valid Argon2 hash, generated once at
    # module load time in security.py. verify() on it takes the same time
    # as verifying a real hash, so timing is identical regardless of whether
    # the email exists in the DB or not.
    hash_to_verify = user.hashed_password if user else _DUMMY_HASH
    password_ok = verify_password(password, hash_to_verify)

    if not user or not password_ok:
        raise HTTPException(401, "Invalid credentials")
```

The Argon2 `verify_password` call always completes in constant time. An attacker measuring response times gets no useful signal.

**Why `_DUMMY_HASH` instead of an empty string?** If you pass `""` as the hash, pwdlib raises `UnknownHashError` immediately — no Argon2 work happens, the function returns instantly, and the timing difference becomes measurable again. `_DUMMY_HASH` is a real Argon2 hash, so the full hashing work runs every time.

```python
# In security.py — generated once at module load, reused forever:
password_hash = PasswordHash.recommended()
_DUMMY_HASH: str = password_hash.hash("__timing_dummy__")
```

---

## 3. Feature 28: Refresh Token Rotation

### What Is Rotation?

Rotation means: every time a refresh token is used, the old one is invalidated and a brand new one is issued.

```
Login           → token_1 issued (jti=aaa, revoked_at=NULL)
Refresh #1      → token_1 is revoked (revoked_at=NOW), token_2 issued (jti=bbb)
Refresh #2      → token_2 is revoked (revoked_at=NOW), token_3 issued (jti=ccc)
```

### Why Rotate?

If a refresh token is stolen, it's only useful until the legitimate user uses it. As soon as the real user does a refresh, the stolen token is revoked. The attacker's next attempt with the stolen token is rejected.

Without rotation, a stolen refresh token is valid for its entire 7-day lifetime.

### Our Implementation (from Part 3)

```python
def refresh_access_token(db, raw_refresh_token, ...):
    payload = decode_refresh_token(raw_refresh_token)
    jti = payload.get("jti")
    family_id = payload.get("family_id")

    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()

    # ... validity checks ...

    # ROTATION: mark old token as revoked (don't delete — needed for reuse detection)
    rt.revoked_at = datetime.now(UTC)

    # Issue new token
    new_raw, new_jti, _ = create_refresh_token(user.id, family_id=family_id)
    new_rt = RefreshToken(
        jti=new_jti,
        family_id=family_id,  # ← same family
        token_hash=hash_token(new_raw),
        ...
    )
    db.add(new_rt)
    db.commit()

    return new_access, new_raw
```

---

## 4. Feature 29: Token Family Revocation

### The Theft Detection Problem

With rotation, if an attacker steals token_1 and the legitimate user refreshes:
- Legitimate user uses token_1 → get token_2 (token_1 becomes revoked)
- Attacker uses token_1 → **this is a revoked token** → THEFT DETECTED

But which action happened first? We don't know. Both the attacker and the user might have used token_1, and one of them gets token_2 while the other gets rejected.

This is why we use **family revocation**: when reuse is detected, we revoke the **entire login chain** — all tokens from this login session — and force re-login.

### The Family ID

All tokens from one login share a `family_id`:

```
Login              → token_1 (jti=aaa, family_id=XYZ, revoked_at=NULL)
Refresh            → token_1 revoked, token_2 issued (jti=bbb, family_id=XYZ)
Refresh            → token_2 revoked, token_3 issued (jti=ccc, family_id=XYZ)

Theft detected     → revoke ALL tokens where family_id=XYZ
                   → user must log in again
```

### Our Implementation

```python
def refresh_access_token(db, raw_refresh_token, ...):
    ...
    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()

    if rt is None:
        raise HTTPException(401, "Invalid token")

    if rt.revoked_at is not None:
        # ← This token was already used (rotated). Seeing it again = THEFT
        _revoke_token_family(db, rt.family_id)
        raise HTTPException(401, "Token reuse detected. All sessions revoked.")

    ...

def _revoke_token_family(db: Session, family_id: str) -> None:
    """Revoke all active tokens in the same login chain."""
    now = datetime.now(UTC)
    (
        db.query(RefreshToken)
        .filter(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
        .update({"revoked_at": now})
    )
    db.commit()
```

### Scenario Walkthrough

```
Alice logs in on her laptop:
  → token_1 (jti=aaa, family=XYZ, revoked_at=NULL)

Attacker steals token_1 (from a compromised network, XSS, etc.)

Alice refreshes (Monday morning):
  → token_1 presented → valid → rotated
  → token_1.revoked_at = NOW
  → token_2 (jti=bbb, family=XYZ) issued to Alice

Attacker now tries to use token_1:
  → presents jti=aaa
  → DB lookup: token found, but revoked_at IS SET
  → THEFT DETECTED → all family=XYZ tokens revoked
  → token_2 also revoked → Alice's session killed

Next time Alice tries to use token_2 (for refresh):
  → DB lookup: revoked_at IS SET
  → 401 Unauthorized → Alice must log in again
  → Alice sees a warning: "Your session was terminated due to suspicious activity"
```

This is the gold standard for refresh token security.

---

## 5. Feature 30: Password Strength Validation

### On Registration

Already in `RegisterRequest` schema (Part 3):

```python
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v
```

FastAPI automatically returns a `422 Unprocessable Entity` with a clear error when validation fails.

### Centralizing Validation Logic

Don't duplicate the validator in multiple schemas. Create a reusable function:

```python
# In src/learn_auth/app/core/security.py

def validate_password_strength(password: str) -> None:
    """Raise ValueError if password is too weak."""
    import re
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a number")
    if errors:
        raise ValueError(f"Password must contain: {', '.join(errors)}")
```

Then use in validators:

```python
@field_validator("password")
@classmethod
def check_strength(cls, v: str) -> str:
    validate_password_strength(v)
    return v
```

### Common Password List (Optional, High Value)

Block the most common passwords (rockyou list, etc.):

```python
# Load once at startup
COMMON_PASSWORDS: set[str] = set()
with open("data/common_passwords.txt") as f:
    COMMON_PASSWORDS = {line.strip().lower() for line in f}

def validate_password_strength(password: str) -> None:
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("This password is too common. Choose a stronger one.")
    # ... rest of checks
```

---

## 6. How to Verify Each Security Feature

### Verify Brute Force Lockout

> Note: Argon2 is intentionally slow and memory-hard (by design). Each failed login attempt will take noticeable time — this is the protection, not a bug.

```bash
# Try 5 wrong passwords in a row
for i in $(seq 1 6); do
  curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "alice@example.com", "password": "WrongPass1"}' | python3 -m json.tool
done
# 5th attempt → 401 Invalid credentials
# 6th attempt → 429 Account temporarily locked
```

### Verify Timing Safety

```bash
# Compare response times for unknown vs known email
time curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -d '{"email": "nobody@nowhere.com", "password": "test"}' \
  -H "Content-Type: application/json"
# Should take the same time as a real user (Argon2 running on _DUMMY_HASH)

time curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -d '{"email": "alice@example.com", "password": "wrongpass"}' \
  -H "Content-Type: application/json"
# Should take the same time — Argon2 running on the real hash
# Times should be indistinguishable
```

### Verify Token Rotation

```bash
# Login, save cookie
curl -c cookies.txt -X POST .../auth/login -d '...'

# Refresh #1 — this rotates the token
curl -c cookies.txt -b cookies.txt -X POST .../auth/refresh

# Refresh again with the OLD cookie (simulate theft)
# At this point, cookies.txt has the NEW cookie. Manually use the old one:
curl -X POST .../auth/refresh --cookie "refresh_token=<old_token>"
# → 401 Token reuse detected
```

### Verify Family Revocation

In your database, after the above test:
```sql
SELECT jti, family_id, revoked_at FROM learn_auth.refresh_tokens ORDER BY created_at;
-- All tokens in the family should have revoked_at set
```

### Verify Password Strength

```bash
curl -X POST .../auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "weak"}'
# → 422 with detailed error about requirements
```

---

## 7. Additional Hardening Recommendations

These are not in the original feature list but are production-grade additions:

### HTTPS in Production

All tokens travel over the wire. Without HTTPS, every token is visible to anyone on the network. Use Let's Encrypt (free) with Caddy, nginx, or your cloud provider's load balancer.

### Token Blacklist for Access Tokens (Advanced)

Access tokens can't be individually revoked (they're stateless). If you need immediate revocation (admin action, suspected compromise), maintain a Redis-based blacklist:

```python
import redis

r = redis.Redis()

def blacklist_token(jti: str, expires_in_seconds: int) -> None:
    r.setex(f"blacklist:{jti}", expires_in_seconds, "1")

def is_blacklisted(jti: str) -> bool:
    return r.exists(f"blacklist:{jti}") > 0

# In decode_access_token:
def decode_access_token(token: str) -> dict:
    payload = jwt.decode(...)
    jti = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise JWTError("Token has been revoked")
    return payload
```

This adds a Redis lookup to every request but gives you true instant revocation.

### Secure Headers

Add security headers with a middleware:

```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

# Only allow HTTPS (redirect HTTP → HTTPS)
# app.add_middleware(HTTPSRedirectMiddleware)  # enable in production

# Security headers
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

### CORS Configuration

For a production frontend:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourfrontend.com"],  # NOT "*" in production
    allow_credentials=True,    # Needed for cookies
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## Summary: Security Features Map

| Feature | Where It Lives | How to Enable |
|---|---|---|
| Brute force lockout | `services/auth.py` → `_record_failed_attempt` | Already in login_user flow |
| Timing-safe login | `services/auth.py` → `login_user` | Always run bcrypt with dummy hash |
| Refresh token rotation | `services/auth.py` → `refresh_access_token` | Rotate on every refresh |
| Family revocation | `services/auth.py` → `_revoke_token_family` | Triggered by reuse detection |
| Password strength | `schemas/auth.py` validators | Pydantic field validators |
| IP rate limiting | `slowapi` middleware | `@limiter.limit("10/minute")` |
| Secure cookie flags | `endpoints/auth.py` | `httponly=True, secure=True` |
| Algorithm restriction | `security.py` → decode functions | `algorithms=["HS256"]` |
| HTTPS | Reverse proxy (nginx/Caddy) | Infrastructure-level |
| CORS | FastAPI middleware | `CORSMiddleware` |

---

## What's Next

**Part 9** covers the Integration Guide — how to protect your existing endpoints (todos, etc.) with JWT auth, how the request/response cycle works with tokens, frontend patterns, and industry best practices.
