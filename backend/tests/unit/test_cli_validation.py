"""CLI argument checks. Every case fails BEFORE any database or network access."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from riskreveal.cli.commands import app

runner = CliRunner()


def test_the_new_commands_are_registered() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("sync-cves", "match-scan", "load-kev", "load-epss", "feed-status"):
        assert name in result.output


@pytest.mark.parametrize("bad", ["garbage", "cpe:/a:apache:http_server", "", "cpe:/"])
def test_sync_cves_refuses_what_is_not_a_versioned_cpe(bad: str) -> None:
    result = runner.invoke(app, ["sync-cves", bad])
    assert result.exit_code == 1
    assert "not a CPE with a version" in result.output


def test_sync_cves_fails_loudly_for_a_cpe_the_nvd_cannot_be_asked_about() -> None:
    """A hardware CPE parses and has a version, but has no NVD name: exit 1, not 0."""
    result = runner.invoke(app, ["sync-cves", "cpe:/h:vendor:thing:1.0"])
    assert result.exit_code == 1
    assert "cannot be turned into an NVD name" in result.output


@pytest.mark.parametrize("bad", ["not-a-uuid", "123", "' OR 1=1 --"])
def test_match_scan_refuses_a_scan_id_that_is_not_a_uuid(bad: str) -> None:
    result = runner.invoke(app, ["match-scan", bad])
    assert result.exit_code == 1
    assert "must be a UUID" in result.output
