# Part 4: Email Features — Verify Email & Password Reset

## Table of Contents
1. [How Email Token Flows Work](#1-how-email-token-flows-work)
2. [Email Sending Setup](#2-email-sending-setup)
3. [Feature 6: Verify Email](#3-feature-6-verify-email)
4. [Feature 7: Resend Verification Email](#4-feature-7-resend-verification-email)
5. [Feature 8: Forgot Password](#5-feature-8-forgot-password)
6. [Feature 9: Reset Password](#6-feature-9-reset-password)
7. [Putting It Together — Endpoints](#7-putting-it-together--endpoints)
8. [Security Considerations](#8-security-considerations)
9. [Local Development (No Real Email)](#9-local-development-no-real-email)

---

## 1. How Email Token Flows Work

Email-based verification and password reset follow the same pattern:

```
User requests action (e.g., forgot password)
  ↓
Server: generate random token → hash it → store hash in DB
  ↓
Server: send email with a link containing the RAW token
  (e.g., https://yourapp.com/reset-password?token=abc123)
  ↓
User clicks link → browser sends token to your API
  ↓
Server: hash the incoming token → look up the hash in DB
  → found + not expired + not used → perform the action
  → mark token as used (set used_at)
```

### Why Store the Hash and Send the Raw Token?

Same reason as refresh tokens (Part 2): if your database is compromised, the attacker cannot use the hashes to generate valid reset links. Only the person who received the email has the raw token.

### Why Not Use JWTs for This?

You could, but there's an important limitation: JWTs cannot be invalidated before they expire. If a user requests a password reset and then immediately wants to cancel it (or requests another one), the first JWT link is still valid. 

With DB-stored tokens, you can:
- Immediately invalidate old tokens when a new one is issued
- Explicitly mark them as used
- See exactly when they were used

---

## 2. Email Sending Setup

For a real app, use an email service (SendGrid, AWS SES, Mailgun, Resend). For local development, use MailHog (a local SMTP server that captures all email in a web UI).

### Add Dependencies

```bash
uv add fastapi-mail  # simple email sending for FastAPI
```

### config.py additions

```python
# Add to Settings in src/learn_auth/app/core/config.py

# Email configuration
MAIL_USERNAME: str = ""
MAIL_PASSWORD: str = ""
MAIL_FROM: str = "noreply@yourapp.com"
MAIL_SERVER: str = "localhost"
MAIL_PORT: int = 1025          # MailHog default; use 587 for real SMTP (TLS)
MAIL_STARTTLS: bool = False    # True for real SMTP
MAIL_SSL_TLS: bool = False     # True only if port 465

# App URL for generating links in emails
APP_FRONTEND_URL: str = "http://localhost:3000"
```

### Email Utility

Create `src/learn_auth/app/core/email.py`:

```python
# src/learn_auth/app/core/email.py
import asyncio

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType

from learn_auth.app.core.config import settings

_conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=bool(settings.MAIL_USERNAME),
)

_mailer = FastMail(_conf)


def send_email_sync(to: str, subject: str, body: str) -> None:
    """
    Send an email synchronously.
    (We call asyncio.run because FastMail is async, but our service layer is sync.)
    In production, use a task queue (Celery, ARQ) instead.
    """
    message = MessageSchema(
        subject=subject,
        recipients=[to],
        body=body,
        subtype=MessageType.html,
    )
    asyncio.run(_mailer.send_message(message))


def build_verification_email(to: str, token: str) -> tuple[str, str]:
    """Returns (subject, html_body) for email verification."""
    url = f"{settings.APP_FRONTEND_URL}/verify-email?token={token}"
    subject = "Verify your email address"
    body = f"""
    <p>Thanks for registering! Please verify your email address by clicking the link below.</p>
    <p><a href="{url}">Verify Email</a></p>
    <p>This link expires in 24 hours.</p>
    <p>If you did not create an account, you can ignore this email.</p>
    """
    return subject, body


def build_password_reset_email(to: str, token: str) -> tuple[str, str]:
    """Returns (subject, html_body) for password reset."""
    url = f"{settings.APP_FRONTEND_URL}/reset-password?token={token}"
    subject = "Reset your password"
    body = f"""
    <p>You requested a password reset. Click the link below to set a new password.</p>
    <p><a href="{url}">Reset Password</a></p>
    <p>This link expires in 1 hour.</p>
    <p>If you did not request this, you can safely ignore this email.</p>
    """
    return subject, body
```

---

## 3. Feature 6: Verify Email

### What Happens

1. After registration, a verification email is sent (covered separately — you'd call this from the register service or a background task)
2. User clicks the link: `GET /auth/verify-email?token=<raw_token>`
3. Server looks up the hashed token, validates, marks user as verified

### Service Logic

```python
# In src/learn_auth/app/services/auth.py

from datetime import UTC, datetime, timedelta
from learn_auth.app.core.security import generate_urlsafe_token, hash_token
from learn_auth.app.models.auth import EmailVerification, User


EMAIL_VERIFICATION_EXPIRE_HOURS = 24


def create_email_verification_token(db: Session, user: User) -> str:
    """
    Generate a verification token, store its hash, return the raw token.
    Invalidates any previous unused tokens for this user.
    """
    # Invalidate old tokens
    db.query(EmailVerification).filter(
        EmailVerification.user_id == user.id,
        EmailVerification.used_at.is_(None),
    ).delete()

    raw_token = generate_urlsafe_token()
    ev = EmailVerification(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=EMAIL_VERIFICATION_EXPIRE_HOURS),
    )
    db.add(ev)
    db.commit()
    return raw_token


def verify_email(db: Session, raw_token: str) -> User:
    """
    Validate a verification token and mark the user as verified.
    Returns the user on success.
    """
    token_hash = hash_token(raw_token)

    ev = db.query(EmailVerification).filter(
        EmailVerification.token_hash == token_hash,
    ).first()

    if ev is None:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")

    if ev.used_at is not None:
        raise HTTPException(status_code=400, detail="Verification link already used")

    if ev.expires_at < datetime.now(UTC):
        raise HTTPException(status_code=400, detail="Verification link expired")

    # Mark token as used
    ev.used_at = datetime.now(UTC)

    # Mark user as verified
    user = db.query(User).filter(User.id == ev.user_id).first()
    user.is_verified = True

    db.commit()
    db.refresh(user)
    return user
```

---

## 4. Feature 7: Resend Verification Email

The user may not have received the first email, or it expired. Allow them to request a new one.

```python
# In src/learn_auth/app/services/auth.py

from learn_auth.app.core.email import build_verification_email, send_email_sync


def resend_verification_email(db: Session, email: str) -> None:
    """
    Resend a verification email. Always returns 200 regardless of whether
    the email exists — prevents email enumeration.
    """
    user = db.query(User).filter(User.email == email).first()

    # Silently do nothing if user not found or already verified
    if not user or user.is_verified:
        return

    raw_token = create_email_verification_token(db, user)
    subject, body = build_verification_email(user.email, raw_token)
    send_email_sync(user.email, subject, body)
```

**Why return 200 silently even when the email isn't found?**

If you return `404` for unknown emails, an attacker can probe which emails have accounts. Always return the same generic response: "If an account exists, an email has been sent."

---

## 5. Feature 8: Forgot Password

The user provides their email → server generates a reset token → server sends email with link.

```python
# In src/learn_auth/app/services/auth.py

from learn_auth.app.core.email import build_password_reset_email
from learn_auth.app.models.auth import PasswordReset

PASSWORD_RESET_EXPIRE_HOURS = 1  # shorter than email verification


def request_password_reset(db: Session, email: str) -> None:
    """
    Send a password reset email. Silently succeeds even if email not found.
    """
    user = db.query(User).filter(User.email == email).first()

    if not user or user.deleted_at is not None:
        return  # Silent — no enumeration

    # Invalidate any existing unused tokens
    db.query(PasswordReset).filter(
        PasswordReset.user_id == user.id,
        PasswordReset.used_at.is_(None),
    ).delete()

    raw_token = generate_urlsafe_token()
    pr = PasswordReset(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=PASSWORD_RESET_EXPIRE_HOURS),
    )
    db.add(pr)
    db.commit()

    subject, body = build_password_reset_email(user.email, raw_token)
    send_email_sync(user.email, subject, body)
```

---

## 6. Feature 9: Reset Password

User clicks the link from email → frontend extracts the token → sends it to API with new password.

```python
# In src/learn_auth/app/services/auth.py


def reset_password(db: Session, raw_token: str, new_password: str) -> None:
    """
    Set a new password using a valid reset token.
    Also revokes all refresh tokens (forces re-login everywhere).
    """
    token_hash = hash_token(raw_token)

    pr = db.query(PasswordReset).filter(
        PasswordReset.token_hash == token_hash,
    ).first()

    if pr is None or pr.used_at is not None:
        raise HTTPException(status_code=400, detail="Invalid or already used reset link")

    if pr.expires_at < datetime.now(UTC):
        raise HTTPException(status_code=400, detail="Reset link expired")

    user = db.query(User).filter(User.id == pr.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # Mark token as used FIRST (prevent double-use even if later steps fail)
    pr.used_at = datetime.now(UTC)

    # Set new password
    user.hashed_password = get_password_hash(new_password)

    # Revoke all sessions — the password changed, all old sessions are suspect
    logout_all_devices(db, user.id)

    db.commit()
```

### Why Revoke All Sessions After Password Reset?

If an attacker had access to the account and initiated a password reset (to lock out the real user), they would also have active refresh tokens. Revoking all sessions ensures the attacker is also logged out even if they had tokens.

---

## 7. Putting It Together — Endpoints

Add to `src/learn_auth/app/api/v1/endpoints/auth.py`:

```python
from pydantic import BaseModel, EmailStr


class EmailRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        import re
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v


@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Activate a user account via the link from the verification email.
    token comes as a query param: GET /auth/verify-email?token=abc...
    """
    auth_service.verify_email(db, token)
    return {"message": "Email verified successfully"}


@router.post("/resend-verification")
def resend_verification(data: EmailRequest, db: Session = Depends(get_db)):
    """
    Resend the verification email.
    Always returns 200 regardless of whether the email exists.
    """
    auth_service.resend_verification_email(db, data.email)
    return {"message": "If an account exists, a verification email has been sent"}


@router.post("/forgot-password")
def forgot_password(data: EmailRequest, db: Session = Depends(get_db)):
    """
    Request a password reset email.
    Always returns 200 regardless of whether the email exists.
    """
    auth_service.request_password_reset(db, data.email)
    return {"message": "If an account exists, a password reset email has been sent"}


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Set a new password using the token from the reset email.
    Revokes all existing sessions after reset.
    """
    auth_service.reset_password(db, data.token, data.new_password)
    return {"message": "Password reset successfully. Please log in with your new password."}
```

---

## 8. Security Considerations

### Why Must Reset Links Expire?

A password reset link sent in an email is a "credential" — whoever has it can change the password. If it never expired, a leaked email (from email forwarding logs, spam folders, data breaches) from months ago would still be exploitable. 1-hour TTL keeps the window small.

### Invalidating Old Tokens on New Request

```python
# Before creating a new token, delete old unused ones:
db.query(PasswordReset).filter(
    PasswordReset.user_id == user.id,
    PasswordReset.used_at.is_(None),
).delete()
```

This prevents a user from having 50 valid reset links from repeatedly clicking "Forgot Password." Only the most recent link works.

### Same Response for Found/Not Found

```python
# Always return this — never 404 or any user-specific message:
return {"message": "If an account exists, a password reset email has been sent"}
```

---

## 9. Local Development (No Real Email)

Use **MailHog** — a fake SMTP server that shows emails in a web UI:

```yaml
# Add to docker-compose.yml
  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI
```

Then in `.envrc`:
```bash
export MAIL_SERVER="localhost"
export MAIL_PORT="1025"
export MAIL_USERNAME=""
export MAIL_PASSWORD=""
```

Open `http://localhost:8025` to see all emails that your app "sent." You'll see the verification links and reset links there — click them to test the full flow without needing a real email provider.

---

## What's Next

**Part 5** covers the authenticated user endpoints — `/me`, profile viewing, profile update, changing password, and soft-deleting your own account (Features 10–14). All of these require a valid access token.
