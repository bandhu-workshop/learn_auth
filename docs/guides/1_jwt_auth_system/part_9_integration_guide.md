# Part 9: Integration Guide — Protecting Existing Endpoints & Industry Standards

## Table of Contents
1. [Do I Send My Token on Every Request?](#1-do-i-send-my-token-on-every-request)
2. [Integrating Auth with the Todos Endpoints](#2-integrating-auth-with-the-todos-endpoints)
3. [The Complete Request-Response Cycle](#3-the-complete-request-response-cycle)
4. [Frontend Token Storage and Management](#4-frontend-token-storage-and-management)
5. [Industry Standard: How Auth Is Done in FastAPI](#5-industry-standard-how-auth-is-done-in-fastapi)
6. [Endpoint Protection Patterns](#6-endpoint-protection-patterns)
7. [Common Patterns and Recipes](#7-common-patterns-and-recipes)
8. [Everything Together: Full File Structure](#8-everything-together-full-file-structure)

---

## 1. Do I Send My Token on Every Request?

**Yes** — the access token is sent with every API call that requires authentication.

But let's be precise about *what* exactly is sent and *why*:

```
Every protected API request:
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The token replaces the concept of "being logged in." The server has no memory of you. Each request must prove your identity from scratch using the token.

**What the token replaces:**
- Your username/password (you don't resend those every time)
- A server-side session lookup (no DB check on every request)
- Any other form of "who are you?"

**What the token contains** (decoded from the JWT):
```json
{
  "sub": "123",
  "email": "alice@example.com",
  "role": "user",
  "exp": 1709503600
}
```

The endpoint knows who you are without touching the database. The signature proves this information wasn't tampered with.

---

## 2. Integrating Auth with the Todos Endpoints

Your existing todos are currently public — anyone can CRUD them. Let's make them auth-protected and user-scoped.

### Step 1: Add user_id to the Todo Model

```python
# src/learn_auth/app/models/todos.py
from sqlalchemy import ForeignKey
from learn_auth.app.core.config import settings

class Todo(Base):
    __tablename__ = "todos"
    __table_args__ = {"schema": settings.SCHEMA}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_completed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Add: which user owns this todo?
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey(f"{settings.SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(...)
    updated_at: Mapped[datetime | None] = mapped_column(...)
    deleted_at: Mapped[datetime | None] = mapped_column(...)

    # Relationship back to user
    owner: Mapped["User"] = relationship()
```

Then generate and apply a migration:
```bash
uv run alembic revision --autogenerate -m "add user_id to todos"
# Review the generated file — verify the FK points to learn_auth.users.id
uv run alembic upgrade head
```

### Step 2: Update the Todos Service

All queries must be **scoped to the current user**. This is mandatory — without it, any user can read or delete any other user's todos (another IDOR vulnerability):

```python
# src/learn_auth/app/services/todos.py
from sqlalchemy.orm import Session
from learn_auth.app.models.todos import Todo


def get_todos(db: Session, user_id: int) -> list[Todo]:
    """Get only THIS user's todos."""
    return (
        db.query(Todo)
        .filter(
            Todo.user_id == user_id,        # ← scope to user
            Todo.deleted_at.is_(None),      # ← exclude soft-deleted
        )
        .all()
    )


def create_todo(db: Session, user_id: int, title: str, description: str | None) -> Todo:
    todo = Todo(title=title, description=description, user_id=user_id)
    db.add(todo)
    db.commit()
    db.refresh(todo)
    return todo


def get_todo_by_id(db: Session, user_id: int, todo_id: int) -> Todo:
    todo = db.query(Todo).filter(
        Todo.id == todo_id,
        Todo.user_id == user_id,     # ← ALWAYS include user scope
        Todo.deleted_at.is_(None),
    ).first()
    if not todo:
        raise HTTPException(status_code=404, detail="Todo not found")
    return todo


def update_todo(db: Session, user_id: int, todo_id: int, **kwargs) -> Todo:
    todo = get_todo_by_id(db, user_id, todo_id)  # ← already scoped
    for key, value in kwargs.items():
        if value is not None:
            setattr(todo, key, value)
    db.commit()
    db.refresh(todo)
    return todo


def delete_todo(db: Session, user_id: int, todo_id: int) -> None:
    todo = get_todo_by_id(db, user_id, todo_id)
    todo.deleted_at = datetime.now(UTC)
    db.commit()
```

### Step 3: Update the Todos Endpoints

```python
# src/learn_auth/app/api/v1/endpoints/todos.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from learn_auth.app.core.deps import get_current_user, get_db
from learn_auth.app.models.auth import User
from learn_auth.app.services import todos as todo_service

router = APIRouter()


@router.get("/")
def list_todos(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # ← ADD THIS
):
    return todo_service.get_todos(db, current_user.id)  # ← pass user_id


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_todo(
    data: TodoCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # ← ADD THIS
):
    return todo_service.create_todo(db, current_user.id, data.title, data.description)


@router.get("/{todo_id}")
def get_todo(
    todo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # ← ADD THIS
):
    return todo_service.get_todo_by_id(db, current_user.id, todo_id)


@router.delete("/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_todo(
    todo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # ← ADD THIS
):
    todo_service.delete_todo(db, current_user.id, todo_id)
```

**That's all you change in the endpoint.** The dependency does all the auth work:

```python
current_user: User = Depends(get_current_user)
```

This single line:
1. Reads the `Authorization: Bearer <token>` header
2. Validates the JWT signature
3. Checks the token hasn't expired
4. Loads the User from the database
5. Ensures the user is active and not deleted
6. Returns the User object to the endpoint function

---

## 3. The Complete Request-Response Cycle

Let's trace a `GET /api/v1/todos/` request from a logged-in client:

```
Client                          FastAPI                        Database
  |                                |                               |
  | GET /api/v1/todos/             |                               |
  | Authorization: Bearer eyJ...  |                               |
  |-----------------------------→ |                               |
  |                                |                               |
  |                         ①  HTTPBearer reads header            |
  |                             extracts "eyJ..."                 |
  |                                |                               |
  |                         ②  decode_access_token("eyJ...")      |
  |                             - verify signature (HS256)         |
  |                             - check exp claim                  |
  |                             - check type == "access"           |
  |                             → payload: {sub: "123", ...}       |
  |                                |                               |
  |                         ③  SELECT * FROM users WHERE id=123   |
  |                                |-------SELECT u FROM users----→|
  |                                |←--------User object------------|
  |                             - is_active == True? ✓             |
  |                             - deleted_at is None? ✓            |
  |                                |                               |
  |                         ④  current_user = User(id=123, ...)   |
  |                             call get_todos(db, user_id=123)    |
  |                                |                               |
  |                         ⑤  SELECT * FROM todos               |
  |                             WHERE user_id=123                  |
  |                             AND deleted_at IS NULL             |
  |                                |------SELECT todos WHERE -----→|
  |                                |←--------[todo1, todo2]--------|
  |                                |                               |
  |  200 OK                        |                               |
  |  [{"id":1,...}, {"id":2,...}] |                               |
  |←-------------------------------|                               |
```

The only DB calls are:
1. Load the user (in `get_current_user`) — **always happens on protected routes**
2. Load the todos (in the service) — business logic

The JWT verification (step ②) is pure computation — no database call.

### When the Access Token Is Expired

```
Client                          FastAPI
  |                                |
  | GET /api/v1/todos/             |
  | Authorization: Bearer eyJ...  |  (expired token)
  |-----------------------------→ |
  |                                |
  |                         ①  decode_access_token raises ExpiredSignatureError
  |                             → JWTError caught
  |                             → 401 Unauthorized
  |                                |
  | 401 {"detail": "Could not validate credentials"}
  |←-------------------------------|

Client silently refreshes:
  |                                |
  | POST /api/v1/auth/refresh      |
  | Cookie: refresh_token=eyJ...  |
  |-----------------------------→ |
  |                                |  (look up refresh token in DB,
  |                                |   rotate, issue new access token)
  | 200 {"access_token": "eyJ..."} |
  |←-------------------------------|
  |                                |
  | (retry original request)       |
  | GET /api/v1/todos/             |
  | Authorization: Bearer eyJ...  |  (new access token)
  |-----------------------------→ |
  | 200 [...]                      |
  |←-------------------------------|
```

This refresh-and-retry is handled **client-side** (JavaScript, mobile app). The API just returns 401.

---

## 4. Frontend Token Storage and Management

### Recommended Storage Strategy

| Token | Storage | Why |
|---|---|---|
| Access token | JavaScript memory (variable) | Fast access; lost on page refresh (intentional) |
| Refresh token | HttpOnly cookie | Cannot be read by JavaScript; auto-sent by browser |

### Why NOT localStorage for Tokens?

localStorage is readable by any JavaScript on the page. An XSS vulnerability (injected script) immediately steals all tokens. HTTP-only cookies are immune to XSS.

### JavaScript Pattern (React/Vanilla)

```javascript
// AuthContext or auth module
let accessToken = null;  // stored in memory

async function login(email, password) {
  const res = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',           // ← sends/receives cookies
    body: JSON.stringify({email, password})
  });
  const data = await res.json();
  accessToken = data.access_token;  // store in memory only
}

async function apiFetch(url, options = {}) {
  // Try request with current access token
  let res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`,
    }
  });

  // If 401 → try refreshing
  if (res.status === 401 && accessToken) {
    const refreshed = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include',   // sends refresh_token cookie
    });

    if (refreshed.ok) {
      const data = await refreshed.json();
      accessToken = data.access_token;  // update in-memory token

      // Retry original request with new token
      res = await fetch(url, {
        ...options,
        credentials: 'include',
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${accessToken}`,
        }
      });
    } else {
      // Refresh failed → logged out
      accessToken = null;
      window.location.href = '/login';
      return;
    }
  }

  return res;
}
```

**Key points:**
- `credentials: 'include'` — required for the browser to send and receive cookies
- Access token lives in a module-level variable (reset on page refresh = good, but requires silent refresh on page load)
- Silent refresh on page load: call `/auth/refresh` immediately when the app starts (the cookie is still there)

### Silent Refresh on App Load

```javascript
async function initApp() {
  // On startup: try to get a new access token using the stored cookie
  const res = await fetch('/api/v1/auth/refresh', {
    method: 'POST',
    credentials: 'include',
  });

  if (res.ok) {
    const data = await res.json();
    accessToken = data.access_token;
    // User is logged in — load the app
  } else {
    // No valid cookie or it expired — user must log in
    // Show login page
  }
}
```

---

## 5. Industry Standard: How Auth Is Done in FastAPI

### The `Depends()` Pattern Is The Standard

FastAPI's dependency injection is the idiomatic way to handle auth:

```python
@router.get("/resource")
def protected_route(current_user: User = Depends(get_current_user)):
    ...
```

This is used by:
- FastAPI's own documentation and examples
- All major FastAPI boilerplates (full-stack-fastapi-template, etc.)
- Production apps (Pydantic's own internal tools, etc.)

### What the OAuth2 Standard Says

OAuth2 is the industry standard for delegated authorization. HTTP Bearer tokens are the standard transport for JWTs. FastAPI provides built-in support:

```python
from fastapi.security import HTTPBearer, OAuth2PasswordBearer

# Option 1: HTTPBearer — reads Authorization: Bearer <token>
# Most common for pure API usage (mobile apps, SPA backends)
bearer = HTTPBearer()

# Option 2: OAuth2PasswordBearer — also reads Bearer, plus provides OpenAPI docs integration
# Better for tools that use the OpenAPI spec (Swagger UI "Authorize" button, etc.)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
```

Both do the same thing at the HTTP level. `OAuth2PasswordBearer` adds a "tokenUrl" hint to the OpenAPI schema so Swagger UI knows where to POST to get a token.

### Using OAuth2PasswordBearer in deps.py

```python
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def get_current_user(
    token: str = Depends(oauth2_scheme),  # ← directly gets the token string
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_access_token(token)
        user_id = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user
```

This version is slightly simpler — `OAuth2PasswordBearer` gives you the token string directly (instead of the credentials object from `HTTPBearer`).

### OpenAPI / Swagger UI Integration

With `OAuth2PasswordBearer`, Swagger UI (`/docs`) shows a lock icon on protected routes. Clicking "Authorize" opens a form where you paste your access token — then all subsequent requests in the UI use it automatically.

---

## 6. Endpoint Protection Patterns

### Pattern 1: Always Require Auth

```python
@router.get("/private")
def private(current_user: User = Depends(get_current_user)):
    return {"user": current_user.email}
```

### Pattern 2: Optional Auth (Public + Private Content)

```python
@router.get("/posts/{post_id}")
def get_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    post = get_post_or_404(db, post_id)
    # Show full content if logged in, preview if anonymous
    if current_user:
        return {"post": post, "full_content": True}
    return {"post": {"title": post.title, "preview": post.content[:200]}}
```

### Pattern 3: Role-Based Access

```python
@router.delete("/admin/users/{user_id}")
def admin_delete(
    user_id: int,
    _admin: User = Depends(get_current_admin),  # 403 if not admin
    db: Session = Depends(get_db),
):
    ...
```

### Pattern 4: Resource Ownership

```python
@router.put("/todos/{todo_id}")
def update_todo(
    todo_id: int,
    data: TodoUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Always scope to current_user.id — prevents IDOR
    todo = get_todo_by_id(db, current_user.id, todo_id)  # 404 if not owned
    ...
```

### Pattern 5: Require Email Verification

```python
def get_verified_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Please verify your email address to access this resource",
        )
    return current_user

@router.post("/premium-feature")
def premium(current_user: User = Depends(get_verified_user)):  # ← verified only
    ...
```

---

## 7. Common Patterns and Recipes

### Recipe: Protect an Entire Router

Instead of adding `Depends(get_current_user)` to every endpoint, protect the whole router:

```python
from fastapi import APIRouter, Depends
from learn_auth.app.core.deps import get_current_user

# All endpoints on this router require auth automatically
router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/")           # ← automatically protected
def list_todos(): ...

@router.post("/")          # ← automatically protected
def create_todo(): ...
```

**But:** when you do this, `current_user` is not available as a parameter (it's not explicitly in the function signature). You need to still declare it if the endpoint needs the user object:

```python
router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/")
def list_todos(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # declare again to use the value
):
    return todo_service.get_todos(db, current_user.id)
```

This causes `get_current_user` to run twice (two DB calls). Prefer explicit `Depends` per endpoint if you need the user object in most endpoints.

### Recipe: Returning User Info in Other Responses

You don't need to embed user info in every response. The client already knows who they are — they sent the token! Only return user info explicitly when the client needs to display it.

```python
# DON'T do this — return user data only when relevant:
@router.get("/todos/")
def list_todos(current_user: User = Depends(get_current_user)):
    todos = get_todos(db, current_user.id)
    return {
        "user": current_user.email,  # ← unnecessary, client already knows
        "todos": todos,
    }

# DO this:
@router.get("/todos/")
def list_todos(current_user: User = Depends(get_current_user)):
    return get_todos(db, current_user.id)  # just the data
```

### Recipe: Versioned Auth

As your API evolves, you may need to issue v2 access tokens with different claims. The `type` claim can be extended:

```python
# v1 token: {"type": "access", ...}
# v2 token: {"type": "access.v2", "permissions": [...], ...}

def decode_access_token(token: str) -> dict:
    payload = jwt.decode(...)
    token_type = payload.get("type", "")
    if not token_type.startswith("access"):
        raise JWTError("Not an access token")
    return payload
```

---

## 8. Everything Together: Full File Structure

After implementing all 30 features, your project structure looks like this:

```
src/learn_auth/
├── main.py                        ← FastAPI app, lifespan
└── app/
    ├── api/
    │   └── v1/
    │       ├── routers.py         ← registers auth, users, todos, admin routers
    │       └── endpoints/
    │           ├── auth.py        ← register, login, logout, refresh, logout-all
    │           │                     verify-email, resend-verification,
    │           │                     forgot-password, reset-password
    │           ├── users.py       ← /me, /me/profile, /me/password, /me/sessions
    │           ├── todos.py       ← CRUD todos (now auth-protected)
    │           └── admin.py       ← admin user management
    ├── core/
    │   ├── config.py              ← Settings + JWT config
    │   ├── database.py            ← SQLAlchemy session + Base
    │   ├── deps.py                ← get_db, get_current_user, get_current_admin
    │   ├── security.py            ← Argon2 (pwdlib) + JWT functions
    │   └── email.py               ← email sending utility
    ├── models/
    │   ├── auth.py                ← User, RefreshToken, EmailVerification, PasswordReset
    │   └── todos.py               ← Todo (now with user_id FK)
    ├── schemas/
    │   ├── auth.py                ← All auth-related Pydantic schemas
    │   └── todos.py               ← Todo schemas
    └── services/
        ├── auth.py                ← register, login, logout, refresh, email/pw reset
        ├── users.py               ← profile update, password change, delete account
        ├── admin.py               ← admin functions
        └── todos.py               ← todo CRUD (scoped to user)

alembic/versions/
    ├── 2026_03_03_001_initial_schema.py     ← todos table
    ├── 2026_03_07_002_add_auth_tables.py    ← users, refresh_tokens, email_verifications, password_resets
    └── 2026_03_07_003_add_user_id_to_todos.py ← todos.user_id FK
```

### Final API Surface

```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout-all
GET    /api/v1/auth/verify-email?token=...
POST   /api/v1/auth/resend-verification
POST   /api/v1/auth/forgot-password
POST   /api/v1/auth/reset-password

GET    /api/v1/users/me
GET    /api/v1/users/me/profile
PATCH  /api/v1/users/me/profile
PUT    /api/v1/users/me/password
DELETE /api/v1/users/me
GET    /api/v1/users/me/sessions
DELETE /api/v1/users/me/sessions/{session_id}

GET    /api/v1/todos/
POST   /api/v1/todos/
GET    /api/v1/todos/{id}
PUT    /api/v1/todos/{id}
DELETE /api/v1/todos/{id}

GET    /api/v1/admin/users
GET    /api/v1/admin/users/{id}
POST   /api/v1/admin/users/{id}/lock
POST   /api/v1/admin/users/{id}/unlock
POST   /api/v1/admin/users/{id}/deactivate
POST   /api/v1/admin/users/{id}/reactivate
POST   /api/v1/admin/users/{id}/restore
POST   /api/v1/admin/users/{id}/logout
PUT    /api/v1/admin/users/{id}/role
```

---

## Summary: Key Principles to Internalize

1. **Every protected request sends the access token** — it's how the server knows who you are
2. **The refresh token is invisible to most of the app** — it only goes to `/auth/refresh`
3. **Always scope queries to the current user's data** — prevents IDOR vulnerabilities
4. **`Depends(get_current_user)` is the single point of auth** — don't duplicate auth logic in endpoints
5. **The access token is stateless** — the server doesn't store it, just validates the signature
6. **The refresh token is stateful** — it must be in the DB to be revocable
7. **Rotate refresh tokens on every use** — limits damage from theft
8. **Return generic errors for auth failures** — never reveal whether an email exists
9. **Alembic for all schema changes** — never directly edit the DB schema
10. **Test the security features explicitly** — timing attacks, brute force, token reuse

These principles don't change between frameworks or languages. Once you understand them in FastAPI + PostgreSQL, you'll apply them confidently in any stack.
