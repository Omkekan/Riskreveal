"""Nmap's output is size-capped before it is parsed (pure Python; no real Nmap)."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from riskreveal.domain.scanning.profiles import get_profile
from riskreveal.domain.scanning.scope_policy import validate_target
from riskreveal.engines.base import EngineError
from riskreveal.engines.nmap_engine import run_nmap


def _target() -> Any:
    return validate_target("8.8.8.8", allow_private=False, resolver=lambda _h: [])


def _runner(stdout: bytes) -> Any:
    def run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    return run


def test_oversized_output_is_refused_before_parsing() -> None:
    with pytest.raises(EngineError, match="more output"):
        run_nmap(
            _target(),
            get_profile("quick"),
            nmap_path="nmap",
            runner=_runner(b"<nmaprun>" + b"x" * 500),
            max_output_bytes=100,
        )


def test_output_within_the_cap_reaches_the_parser() -> None:
    result = run_nmap(
        _target(),
        get_profile("quick"),
        nmap_path="nmap",
        runner=_runner(b"<nmaprun/>"),
        max_output_bytes=100,
    )
    assert list(result.hosts) == []  # parsed normally: an empty scan, not a size refusal
