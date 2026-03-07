from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

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
