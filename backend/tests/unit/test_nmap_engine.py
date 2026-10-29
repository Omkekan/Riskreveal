"""Command building and subprocess handling, with a fake runner (no Nmap)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from riskreveal.domain.scanning.profiles import PROFILES, UnknownProfileError, get_profile
from riskreveal.domain.scanning.scope_policy import validate_target
from riskreveal.engines.base import EngineError, EngineNotFoundError, EngineTimeoutError
from riskreveal.engines.nmap_engine import build_command, find_nmap, run_nmap

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_sample.xml"
QUICK = get_profile("quick")


def _target(raw: str, resolver_ips: tuple[str, ...] = ()):
    return validate_target(raw, allow_private=False, resolver=lambda _h: list(resolver_ips))


def test_command_is_an_argument_list_with_validated_targets_last() -> None:
    cmd = build_command("nmap", QUICK, _target("8.8.8.8"))
    assert isinstance(cmd, list)
    assert cmd[0] == "nmap"
    assert cmd[1:3] == ["-oX", "-"]
    assert cmd[-1] == "8.8.8.8"
    assert "--open" in cmd
    assert "-n" in cmd


def test_single_host_skips_ping_but_a_range_does_not() -> None:
    assert "-Pn" in build_command("nmap", QUICK, _target("8.8.8.8"))
    assert "-Pn" not in build_command("nmap", QUICK, _target("8.8.8.0/24"))


def test_ipv6_target_adds_dash_six() -> None:
    assert "-6" in build_command("nmap", QUICK, _target("2606:4700:4700::1111"))
    assert "-6" not in build_command("nmap", QUICK, _target("8.8.8.8"))


def test_hostname_target_scans_the_resolved_ip_not_the_name() -> None:
    cmd = build_command("nmap", QUICK, _target("scanme.nmap.org", ("45.33.32.156",)))
    assert cmd[-1] == "45.33.32.156"
    assert "scanme.nmap.org" not in cmd


def test_profiles_never_contain_script_or_output_file_flags() -> None:
    for profile in PROFILES.values():
        joined = " ".join(profile.nmap_args)
        for forbidden in ("--script", "-sC", "-oN", "-oG", "-oA", "--datadir", "--resume"):
            assert forbidden not in joined


def test_unknown_profile_raises() -> None:
    with pytest.raises(UnknownProfileError):
        get_profile("../../etc/passwd")


def test_find_nmap_uses_explicit_path_then_which() -> None:
    assert find_nmap("C:/tools/nmap.exe", which=lambda _n: None) == "C:/tools/nmap.exe"
    assert find_nmap(None, which=lambda n: f"/usr/bin/{n}") == "/usr/bin/nmap"


def test_find_nmap_missing_raises_helpful_error() -> None:
    with pytest.raises(EngineNotFoundError) as excinfo:
        find_nmap(None, which=lambda _n: None)
    assert "winget install" in str(excinfo.value)


def test_run_nmap_parses_stdout_and_passes_safe_subprocess_options() -> None:
    seen: dict[str, object] = {}

    def fake_runner(command, **kwargs):
        seen["command"] = command
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=FIXTURE.read_bytes(), stderr=b"")

    result = run_nmap(_target("8.8.8.8"), QUICK, nmap_path="nmap", runner=fake_runner)
    assert result.hosts[0].address == "45.33.32.156"
    assert seen["shell"] is False
    assert seen["timeout"] == QUICK.timeout_seconds
    assert seen["capture_output"] is True


def test_timeout_becomes_engine_timeout_error() -> None:
    def fake_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with pytest.raises(EngineTimeoutError):
        run_nmap(_target("8.8.8.8"), QUICK, nmap_path="nmap", runner=fake_runner)


def test_nonzero_exit_raises_with_truncated_stderr() -> None:
    def fake_runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"x" * 5000)

    with pytest.raises(EngineError) as excinfo:
        run_nmap(_target("8.8.8.8"), QUICK, nmap_path="nmap", runner=fake_runner)
    assert len(str(excinfo.value)) < 700


def test_oserror_becomes_engine_error() -> None:
    def fake_runner(_command, **_kwargs):
        raise PermissionError(13, "Permission denied")

    with pytest.raises(EngineError):
        run_nmap(_target("8.8.8.8"), QUICK, nmap_path="nmap", runner=fake_runner)
