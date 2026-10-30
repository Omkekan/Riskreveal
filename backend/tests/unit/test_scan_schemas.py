"""ScanCreate: shape checks and the fixed profile list."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from riskreveal.domain.scanning.schemas import ScanCreate


def test_target_is_trimmed_and_profile_defaults() -> None:
    scan = ScanCreate(target="  8.8.8.8  ")
    assert scan.target == "8.8.8.8"
    assert scan.profile == "quick"


@pytest.mark.parametrize("target", ["", "   ", "x" * 256])
def test_blank_or_overlong_target_is_rejected(target: str) -> None:
    with pytest.raises(ValidationError):
        ScanCreate(target=target)


@pytest.mark.parametrize("profile", ["", "nope", "-sV", "quick --script vuln", "../standard"])
def test_unknown_profile_is_rejected(profile: str) -> None:
    with pytest.raises(ValidationError):
        ScanCreate(target="8.8.8.8", profile=profile)


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanCreate.model_validate({"target": "8.8.8.8", "nmap_args": "-sV"})
