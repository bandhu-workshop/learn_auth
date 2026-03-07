import pytest
from pwdlib import PasswordHash

from learn_auth.app.core.security import get_password_hash


@pytest.fixture
def password() -> str:
    return "SecurePassword1!"


def test_get_password_hash_returns_string(password: str) -> None:
    assert isinstance(get_password_hash(password), str)


def test_get_password_hash_argon2_prefix(password: str) -> None:
    assert get_password_hash(password).startswith("$argon2")


def test_get_password_hash_unique_salts(password: str) -> None:
    assert get_password_hash(password) != get_password_hash(password)


def test_get_password_hash_verifiable(password: str) -> None:
    ph = PasswordHash.recommended()
    assert ph.verify(password, get_password_hash(password))


def test_get_password_hash_wrong_password_fails(password: str) -> None:
    ph = PasswordHash.recommended()
    assert not ph.verify("WrongPassword9!", get_password_hash(password))
