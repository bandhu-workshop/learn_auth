# JWT Authentication System Guide

A complete, in-depth guide to building a production-grade JWT authentication system using **FastAPI · SQLAlchemy · PostgreSQL · Alembic**.

## How To Read This Guide

Read the parts in order — each part builds on the previous.

| Part | File | Topics Covered | Features |
|---|---|---|---|
| 1 | [part_1_jwt_fundamentals.md](part_1_jwt_fundamentals.md) | JWT structure, access vs refresh tokens, security risks, best practices | Theory / Concepts |
| 2 | [part_2_models_and_alembic.md](part_2_models_and_alembic.md) | User/RefreshToken/EmailVerification/PasswordReset models, Alembic workflow | DB Foundation |
| 3 | [part_3_core_auth.md](part_3_core_auth.md) | security.py JWT functions, Register, Login, Logout, Refresh, Logout-All | #1–5 |
| 4 | [part_4_email_features.md](part_4_email_features.md) | Email sending setup, Verify Email, Resend Verification, Forgot/Reset Password | #6–9 |
| 5 | [part_5_authenticated_user.md](part_5_authenticated_user.md) | /me, Profile, Update Profile, Change Password, Delete Account (soft) | #10–14 |
| 6 | [part_6_session_management.md](part_6_session_management.md) | List Active Sessions, Revoke Specific Session | #15–16 |
| 7 | [part_7_admin.md](part_7_admin.md) | Admin: get any user, lock/unlock, deactivate/reactivate, list users, force logout, assign roles | #17–25 |
| 8 | [part_8_security_hardening.md](part_8_security_hardening.md) | Brute force lockout, timing-safe login, token rotation, family revocation, password strength | #26–30 |
| 9 | [part_9_integration_guide.md](part_9_integration_guide.md) | Protecting existing endpoints, full request/response cycle, frontend patterns, industry standards | Integration |

## Quick Feature Reference

### Core Auth (Part 3)
- `POST /api/v1/auth/register` — Create account
- `POST /api/v1/auth/login` — Get access + refresh token
- `POST /api/v1/auth/logout` — Revoke current session
- `POST /api/v1/auth/refresh` — Get new access token (rotates refresh)
- `POST /api/v1/auth/logout-all` — Revoke all sessions

### Email (Part 4)
- `GET  /api/v1/auth/verify-email?token=...` — Confirm email
- `POST /api/v1/auth/resend-verification` — Re-send verification link
- `POST /api/v1/auth/forgot-password` — Send reset link
- `POST /api/v1/auth/reset-password` — Set new password via token

### Authenticated User (Part 5)
- `GET    /api/v1/users/me` — Full current user data
- `GET    /api/v1/users/me/profile` — Public profile
- `PATCH  /api/v1/users/me/profile` — Update name, avatar, bio
- `PUT    /api/v1/users/me/password` — Change password
- `DELETE /api/v1/users/me` — Soft-delete account

### Session Management (Part 6)
- `GET    /api/v1/users/me/sessions` — List active devices
- `DELETE /api/v1/users/me/sessions/{id}` — Log out one device

### Admin (Part 7)
- `GET  /api/v1/admin/users` — List all users (filterable)
- `GET  /api/v1/admin/users/{id}` — Get any user
- `POST /api/v1/admin/users/{id}/lock` — Lock account
- `POST /api/v1/admin/users/{id}/unlock` — Unlock account
- `POST /api/v1/admin/users/{id}/deactivate` — Deactivate account
- `POST /api/v1/admin/users/{id}/reactivate` — Reactivate account
- `POST /api/v1/admin/users/{id}/restore` — Restore soft-deleted account
- `POST /api/v1/admin/users/{id}/logout` — Force logout user
- `PUT  /api/v1/admin/users/{id}/role` — Assign role

## Key Concepts Cheat Sheet

```
Access Token:  short-lived (15 min), no DB storage, sent in Authorization header
Refresh Token: long-lived (7 days), stored in DB (hashed), sent as HttpOnly cookie
Token Rotation: every refresh → revoke old token, issue new one
Family Revocation: token reuse detected → revoke all tokens in login chain
IDOR Protection: always scope DB queries to current_user.id
Timing Safety: always run bcrypt even when user not found (prevent email enumeration)
Soft Delete: never DELETE users, set deleted_at = now() instead
```

## Implementation Checklist

- [ ] Part 2: Create User, RefreshToken, EmailVerification, PasswordReset models
- [ ] Part 2: Generate and apply auth migration (`uv run alembic revision --autogenerate`)
- [ ] Part 2: Add JWT settings to config.py and .envrc
- [ ] Part 3: Implement JWT functions in security.py
- [ ] Part 3: Implement auth service (register, login, logout, refresh, logout-all)
- [ ] Part 3: Create auth endpoints and wire router
- [ ] Part 3: Update deps.py with get_current_user and get_current_admin
- [ ] Part 4: Set up email (MailHog locally, real SMTP in prod)
- [ ] Part 4: Implement email verification and password reset
- [ ] Part 5: Implement user profile endpoints
- [ ] Part 6: Implement session list and revocation
- [ ] Part 7: Implement admin endpoints
- [ ] Part 8: Verify all security features via testing
- [ ] Part 9: Add user_id to todos, scope all queries
- [ ] Part 9: Migrate todos table, update service and endpoints
