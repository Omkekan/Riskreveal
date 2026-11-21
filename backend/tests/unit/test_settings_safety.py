"""Settings validation: the production-safety rules and the new switches (no database)."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.fernet import Fernet

from riskreveal.config import Environment, Settings

GOOD_DB = "postgresql+psycopg://riskreveal:s3cret-pass@db.internal:5432/riskreveal"


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "database_url": GOOD_DB,
        "jwt_secret_key": "j" * 48,
        "fernet_key": Fernet.generate_key().decode(),
        "environment": Environment.DEVELOPMENT,
        "debug": False,  # a developer's own DEBUG=true must not leak into these tests
        "cors_origins": ["https://app.example.com"],
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_a_sane_production_configuration_is_accepted() -> None:
    assert _settings(environment=Environment.PRODUCTION).is_production


def test_production_refuses_debug() -> None:
    with pytest.raises(ValueError, match="DEBUG"):
        _settings(environment=Environment.PRODUCTION, debug=True)


def test_production_refuses_wildcard_cors() -> None:
    with pytest.raises(ValueError, match="CORS_ORIGINS"):
        _settings(environment=Environment.PRODUCTION, cors_origins=["*"])


@pytest.mark.parametrize("password", ["CHANGE_ME", "change_me", "Change_Me"])
def test_production_refuses_the_example_database_password(password: str) -> None:
    url = f"postgresql+psycopg://riskreveal:{password}@localhost:5433/riskreveal"
    with pytest.raises(ValueError, match="CHANGE_ME"):
        _settings(environment=Environment.PRODUCTION, database_url=url)


def test_development_may_keep_the_example_password() -> None:
    url = "postgresql+psycopg://riskreveal:CHANGE_ME@localhost:5433/riskreveal"
    assert _settings(database_url=url).database_url == url


def test_registration_is_enabled_unless_switched_off() -> None:
    assert _settings().registration_enabled is True
    assert _settings(registration_enabled=False).registration_enabled is False


def test_a_short_jwt_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="32"):
        _settings(jwt_secret_key="short")


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_nvd_key_means_no_key(blank: str) -> None:
    assert _settings(nvd_api_key=blank).nvd_api_key is None


def test_a_real_nvd_key_is_kept_and_never_printed() -> None:
    settings = _settings(nvd_api_key="abc-123")
    assert settings.nvd_api_key is not None
    assert settings.nvd_api_key.get_secret_value() == "abc-123"
    assert "abc-123" not in repr(settings)


@pytest.mark.parametrize("hours", [0, -1, 721])
def test_the_cve_cache_lifetime_is_bounded(hours: int) -> None:
    with pytest.raises(ValueError, match="nvd_cache_hours"):
        _settings(nvd_cache_hours=hours)
