# Part 1: JWT Fundamentals — How Auth Works, Tokens, and Security Risks

## Table of Contents
1. [What Is Authentication vs Authorization?](#1-what-is-authentication-vs-authorization)
2. [Session-Based vs Token-Based Auth](#2-session-based-vs-token-based-auth)
3. [What Is a JWT?](#3-what-is-a-jwt)
4. [Access Token vs Refresh Token](#4-access-token-vs-refresh-token)
5. [Security Risks and How JWT Handles Them](#5-security-risks-and-how-jwt-handles-them)
6. [The Full Auth Flow (Diagram)](#6-the-full-auth-flow-diagram)
7. [Best Practices Checklist](#7-best-practices-checklist)

---

## 1. What Is Authentication vs Authorization?

These two words are often confused. They are different:

| Term | Question answered | Example |
|---|---|---|
| **Authentication (AuthN)** | *Who are you?* | Logging in with email + password |
| **Authorization (AuthZ)** | *What are you allowed to do?* | Only admins can delete users |

In this guide we focus on **authentication** — proving identity. Authorization (role checks, permissions) is layered on top after auth is established.

---

## 2. Session-Based vs Token-Based Auth

### Session-Based (Traditional)

```
Browser                 Server                  Database
  |                       |                         |
  |-- POST /login ------->|                         |
  |                       |-- SELECT user --------->|
  |                       |<-- user found ----------|
  |                       |-- INSERT session ------->|
  |                       |<-- session_id ----------|
  |<-- Set-Cookie: sid ---|                         |
  |                       |                         |
  |-- GET /profile ------>|                         |
  |   Cookie: sid=abc     |-- SELECT session ------->|
  |                       |<-- session data --------|
  |<-- 200 OK ------------|                         |
```

**Problems:**
- The server must store every session in the database → stateful
- Every request hits the database to validate the session
- Hard to scale horizontally (multiple servers must share session store)
- CSRF attacks are easy (cookies are sent automatically by the browser)

### Token-Based (JWT)

```
Browser                 Server                  Database
  |                       |                         |
  |-- POST /login ------->|                         |
  |                       |-- SELECT user --------->|
  |                       |<-- user found ----------|
  |                       | (create JWT, sign it)   |
  |<-- { access_token }---|                         |
  |                       |                         |
  |-- GET /profile ------>|                         |
  |   Authorization:      | (verify JWT signature)  |
  |   Bearer <token>      | (no DB call needed!)    |
  |<-- 200 OK ------------|                         |
```

**Benefits:**
- Server is **stateless** — no session stored, just verify the signature
- Scales easily across multiple servers
- Works naturally for APIs, mobile apps, microservices
- No CSRF (not a cookie by default)

**Trade-offs:**
- You cannot instantly invalidate a token (until it expires) — this is solved by refresh tokens + a revocation DB table (covered in Part 3)
- Tokens can be stolen if stored insecurely

---

## 3. What Is a JWT?

JWT = **JSON Web Token**. It is a compact, URL-safe string made of three base64url-encoded parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Header
.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ  ← Payload
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

### Header

```json
{
  "alg": "HS256",   // signing algorithm
  "typ": "JWT"
}
```

### Payload (Claims)

Claims are statements about the user. Some are standard (registered), some are custom:

```json
{
  "sub": "user_id_123",       // Subject (who the token is about) — STANDARD
  "iat": 1709500000,           // Issued At — STANDARD (Unix timestamp)
  "exp": 1709503600,           // Expiry — STANDARD (Unix timestamp, 1 hour later)
  "jti": "uuid-unique-id",     // JWT ID — STANDARD (unique per token, used for revocation)
  "type": "access",            // CUSTOM: "access" or "refresh"
  "email": "user@example.com", // CUSTOM
  "role": "user"               // CUSTOM
}
```

> **IMPORTANT:** The payload is **NOT encrypted** — it is only **base64url encoded**. Anyone who holds the token can read it. Never put passwords, credit cards, or secrets in JWT payload. Only put data you are comfortable being public.

### Signature

The signature is what makes JWTs trustworthy:

```
HMACSHA256(
  base64url(header) + "." + base64url(payload),
  SECRET_KEY
)
```

The server creates the signature using a secret key. When the server receives a token, it re-computes the signature and compares. If it matches → the token was issued by this server and has not been tampered with.

If an attacker changes the payload (e.g., changes `"role": "user"` to `"role": "admin"`), the signature will no longer match → **rejected**.

### Decoding a JWT in Python

```python
import jwt  # pip install python-jose[cryptography] or PyJWT

SECRET_KEY = "your-256-bit-secret"
ALGORITHM = "HS256"

# Create a token
payload = {
    "sub": "123",
    "email": "user@example.com",
    "exp": 1709503600
}
token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Verify and decode
try:
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    print(decoded)  # {'sub': '123', 'email': 'user@example.com', 'exp': ...}
except jwt.ExpiredSignatureError:
    print("Token has expired")
except jwt.InvalidTokenError:
    print("Token is invalid")
```

---

## 4. Access Token vs Refresh Token

This is the most important concept to understand before building anything.

### The Problem

If tokens are short-lived (15 minutes), users get logged out constantly. If tokens are long-lived (30 days), a stolen token is valid for 30 days — a disaster.

**Solution:** Use two tokens with different jobs.

### Access Token

| Property | Value |
|---|---|
| **Purpose** | Prove identity for API calls |
| **Lifetime** | **Short** — 15 minutes to 1 hour |
| **Storage** | Memory (JavaScript variable) or HTTP-only cookie |
| **Sent with** | Every API request |
| **Stored in DB?** | **No** — stateless, validated by signature alone |
| **Contains** | user_id, email, role, exp, iat |

When the access token expires, the client uses the refresh token to get a new one — silently, without re-logging in.

### Refresh Token

| Property | Value |
|---|---|
| **Purpose** | Get a new access token when the old one expires |
| **Lifetime** | **Long** — 7 to 30 days |
| **Storage** | HTTP-only secure cookie (preferred) |
| **Sent with** | Only to `POST /auth/refresh` endpoint |
| **Stored in DB?** | **Yes** — must be stored to allow revocation |
| **Contains** | A `jti` (unique ID) used to look it up in DB |

### Token Lifecycle

```
Login
  → Server issues: access_token (15min) + refresh_token (7d, stored in DB)
  → Client stores both

API Request
  → Client sends: Authorization: Bearer <access_token>
  → Server: verify signature + check exp → no DB call needed

Access Token Expires (after 15 min)
  → Client sends refresh_token to POST /auth/refresh
  → Server: look up refresh_token in DB → still valid?
  → YES → issue new access_token (+ rotate refresh_token)
  → NO  → force re-login

Refresh Token Expires (after 7 days)
  → Client must login again (provide email + password)

Logout
  → Delete refresh_token from DB (access token will expire naturally)
  → Client discards both tokens
```

### Why does the refresh token live in the database?

Because you need to be able to **invalidate** it. If a refresh token is compromised or the user logs out, you delete the DB record. The next refresh attempt fails even if the token hasn't expired yet.

The access token is **not** stored — it lives only as long as its `exp` claim. This is the trade-off: you accept that a stolen access token is valid for up to 15 minutes. The short window makes this acceptable.

### Quick Reference: Which Token Do I Use When?

```
User logs in               → receive both tokens
Calling /todos, /profile   → send access_token
Access token expired       → send refresh_token to /auth/refresh → get new access_token
Logging out                → send refresh_token to /auth/logout (server deletes it from DB)
Forgot password            → email/password flow, no tokens involved
```

---

## 5. Security Risks and How JWT Handles Them

### Risk 1: Token Theft (XSS)

**What:** JavaScript on your page reads tokens from `localStorage` and sends them to an attacker's server.

**Solution:**
- Store access tokens in **memory** (JS variable), not `localStorage`
- Store refresh tokens in **`HttpOnly; Secure; SameSite=Strict`** cookies — JS cannot read these
- Use [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

```python
# FastAPI: set refresh token as HttpOnly cookie
from fastapi import Response

response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,          # JS cannot read this
    secure=True,            # Only sent over HTTPS
    samesite="strict",      # Not sent in cross-site requests
    max_age=7 * 24 * 3600, # 7 days in seconds
)
```

### Risk 2: Token Tampering

**What:** Attacker changes `"role": "user"` to `"role": "admin"` in the payload.

**Solution:** The signature. Changing the payload invalidates the signature. The server rejects it.

```python
# This will always fail if the payload was tampered with
try:
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
except jwt.InvalidSignatureError:
    raise HTTPException(status_code=401, detail="Token tampered")
```

### Risk 3: Weak Secret Key

**What:** The signing secret is short (e.g., "secret") and can be brute-forced offline.

**Solution:** Use a cryptographically random 256-bit (32-byte) key:
```bash
# Generate a secure secret
python -c "import secrets; print(secrets.token_hex(32))"
# → 3d6f45a5fc12445dbac2f59aef2f8c2b1e...  (64 hex chars = 32 bytes = 256 bits)
```
Store it in `.envrc`, never commit it to git.

### Risk 4: Replay Attack (Stolen Refresh Token)

**What:** Attacker steals a refresh token and uses it to repeatedly get new access tokens.

**Solution: Refresh Token Rotation + Family Revocation**
- Every time a refresh token is used, **delete the old one and issue a new one**
- If the **old** token is used again (after being rotated), that means it was stolen → **revoke the entire token family** (all sessions for this login chain)

This is covered in depth in Part 8.

### Risk 5: Brute Force Login

**What:** Attacker tries thousands of passwords for a known email.

**Solution:**
- Rate limit login attempts per IP
- After N consecutive failures, lock the account for a time window
- Use Argon2 via pwdlib (already in your `security.py`) — it is intentionally slow and memory-hard

### Risk 6: Email Enumeration

**What:** `"No account found with this email"` vs `"Wrong password"` — tells attacker which emails exist in the system.

**Solution:** Always return the **same error message** and take the **same time** to respond:
```python
# Wrong: tells attacker the email doesn't exist
if not user:
    raise HTTPException(status_code=401, detail="No account with this email")

# Right: same message, same timing
if not user or not verify_password(password, user.hashed_password):
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

### Risk 7: Token Not Expiring (Forgotten Session)

**What:** A user's account is compromised, but their old access token (that you issued last year) is still valid.

**Solution:**
- Short access token TTL (15–60 minutes)
- Refresh token rotation so old tokens are invalidated on use
- "Logout all devices" endpoint that revokes all refresh tokens for a user

### Risk 8: Man-in-the-Middle

**What:** Attacker intercepts tokens in transit.

**Solution:** **HTTPS always.** No exceptions. Set `Secure` on cookies.

### Risk 9: Algorithm Confusion (`alg: none`)

**What:** Old JWT libraries accepted `"alg": "none"` — attacker strips the signature.

**Solution:** Always **explicitly specify which algorithms you accept**:
```python
# WRONG — accepts any algorithm including "none"
jwt.decode(token, key)

# RIGHT — only accept HS256
jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

---

## 6. The Full Auth Flow (Diagram)

```
                    REGISTER
User → POST /auth/register {email, password}
     ← 201 Created {user_id, email}

                    LOGIN
User → POST /auth/login {email, password}
     ← 200 OK {
           access_token: "eyJ...",   (15 min, in body)
           token_type: "bearer"
       }
       Set-Cookie: refresh_token=eyJ...  (7d, HttpOnly)

                    AUTHENTICATED API CALL
User → GET /api/v1/todos
       Authorization: Bearer <access_token>
     ← 200 OK {todos: [...]}

                    ACCESS TOKEN EXPIRED
User → GET /api/v1/todos
       Authorization: Bearer <expired_access_token>
     ← 401 Unauthorized {"detail": "Token expired"}

                    REFRESH
User → POST /auth/refresh
       Cookie: refresh_token=eyJ...    (sent automatically)
     ← 200 OK {
           access_token: "eyJ...",    (new 15-min token)
       }
       Set-Cookie: refresh_token=eyJ... (new rotated token)

                    LOGOUT
User → POST /auth/logout
       Cookie: refresh_token=eyJ...
     ← 200 OK
       Set-Cookie: refresh_token=; Max-Age=0  (delete cookie)
       (DB: refresh token record deleted)

                    REFRESH TOKEN STOLEN SCENARIO
Attacker → POST /auth/refresh  (using old, already-used refresh token)
         ← 401 Unauthorized
         (Server detects reuse → revokes ENTIRE token family → user must re-login)
```

---

## 7. Best Practices Checklist

Before starting implementation, internalize these:

- [ ] **Access token: short-lived** (15–60 min), no DB storage
- [ ] **Refresh token: long-lived** (7–30 days), stored in DB, rotated on every use
- [ ] **Refresh token in HttpOnly cookie**, access token in memory or Authorization header
- [ ] **Secret key: 256-bit random**, stored in environment variable, never committed to git
- [ ] **Always specify accepted algorithms** in `jwt.decode()`
- [ ] **Same error message** for "email not found" and "wrong password"
- [ ] **Same response time** for failed login regardless of reason (avoid timing attacks)
- [ ] **HTTPS only** in production
- [ ] **Rotate refresh tokens** — new token on every refresh
- [ ] **Revoke entire family** if token reuse is detected
- [ ] **Argon2 via `pwdlib`** for password hashing (already done in `security.py`)
- [ ] **Brute-force lockout** — track failed attempts, lock after N failures
- [ ] **Password strength validation** — minimum length, complexity
- [ ] **Soft-delete accounts** — don't destroy data immediately
- [ ] Store `jti` (unique token ID) in refresh tokens for pinpoint revocation

---

## What's Next

- **Part 2:** Database models (`User`, `RefreshToken`) and Alembic migrations — creating the tables you need
- **Part 3:** Implementing Register, Login, Logout, Refresh, and Logout-all-devices
- **Part 4:** Email verification and password reset flow
- **Part 5–9:** Profile, sessions, admin, security hardening, and integration

Each part builds on the previous. Read them in order.
