"""Schema validation: no database, no network."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from riskreveal.domain.users.schemas import LoginRequest, UserCreate

GOOD_PW = "correct-horse-battery"


def test_email_is_trimmed_and_lowercased() -> None:
    user = UserCreate(email="  Alice@Example.COM ", password=GOOD_PW)
    assert user.email == "alice@example.com"


def test_short_password_is_rejected() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="a@example.com", password="short")


def test_overlong_password_is_rejected() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="a@example.com", password="x" * 129)


def test_overlong_email_is_rejected() -> None:
    too_long = ("a" * 250) + "@example.com"
    with pytest.raises(ValidationError):
        UserCreate(email=too_long, password=GOOD_PW)


def test_blank_full_name_becomes_none() -> None:
    assert UserCreate(email="a@example.com", password=GOOD_PW, full_name="   ").full_name is None


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        UserCreate.model_validate(
            {"email": "a@example.com", "password": GOOD_PW, "is_active": False}
        )


def test_login_does_not_enforce_password_policy() -> None:
    # Login must answer "wrong credentials", not reveal the password rules.
    assert LoginRequest(email="a@example.com", password="x").password == "x"
