import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from learn_auth.app.core.config import settings

# Single shared instance — PasswordHash.recommended() uses Argon2id by default.
password_hash = PasswordHash.recommended()

# Custom — more memory, same time (better GPU resistance)
high_memory = PasswordHash(
    [
        Argon2Hasher(
            time_cost=2,
            memory_cost=131072,  # 128 MB instead of default 64 MB
            parallelism=2,
        )
    ]
)

# # Custom — more passes, less memory (better CPU resistance)
# high_time = PasswordHash(
#     [
#         Argon2Hasher(
#             time_cost=4,  # 4 passes instead of 2
#             memory_cost=65536,  # 64 MB
#             parallelism=1,
#         )
#     ]
# )


# Pre-computed dummy hash used for timing-safe login (see services/auth.py).
# Having a valid Argon2 hash means verify() always runs Argon2 work, making
# response time identical whether or not the supplied email exists in the DB.
_DUMMY_HASH: str = password_hash.hash("__timing_dummy__")


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored Argon2 hash."""
    return password_hash.verify(plain_password, hashed_password)


def verify_and_update_password(
    plain_password: str, hashed_password: str
) -> tuple[bool, str | None]:
    """
    Verify a password and transparently rehash if the algorithm parameters
    have changed (e.g. after a security upgrade).

    Returns:
        (is_valid, updated_hash)
        If is_valid is True and updated_hash is not None, persist the new hash.
    """
    return password_hash.verify_and_update(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with Argon2id."""
    return password_hash.hash(password)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def create_access_token(user_id: int, email: str, role: str) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),  # Subject: who the token is about
        "email": email,
        "role": role,
        "type": "access",  # Custom claim: distinguish from refresh
        "iat": now,  # Issued At
        "exp": expire,  # Expiry
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    user_id: int, family_id: str | None = None
) -> tuple[str, str, str]:
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
    raw_token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )
    return raw_token, jti, family_id


def decode_access_token(token: str) -> dict:
    """
    Decode and validate an access token.
    Raises JWTError on any problem (expired, invalid, wrong type).
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
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
            settings.JWT_SECRET_KEY.get_secret_value(),
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


if __name__ == "__main__":
    pw = "TestPassword1"
    h = get_password_hash(pw)
    print(f"Password : {pw}")
    print(f"Hash     : {h}")

    assert verify_password(pw, h), "verify_password failed"
    print("verify_password  ✓")

    valid, updated = verify_and_update_password(pw, h)
    assert valid, "verify_and_update_password failed"
    print(
        f"verify_and_update_password ✓  (updated_hash={'<same>' if updated is None else updated})"
    )
