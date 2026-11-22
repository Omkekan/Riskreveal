"""Risk scoring. Pure Python."""

from __future__ import annotations

import pytest

from riskreveal.domain.findings.risk_scorer import RiskBand, _band_for, score
from riskreveal.domain.findings.schemas import VulnerabilityContext


def _context(**overrides: object) -> VulnerabilityContext:
    defaults: dict[str, object] = {"cve_id": "CVE-2099-0001"}
    defaults.update(overrides)
    return VulnerabilityContext(**defaults)


def test_no_cvss_and_not_in_kev_cannot_be_scored_honestly() -> None:
    assert score(_context()) is None


def test_no_cvss_but_an_epss_score_alone_still_cannot_be_scored() -> None:
    # EPSS without a severity signal (no CVSS, not in KEV) isn't enough --
    # "likely to be exploited" without "how bad if it is" isn't a score.
    assert score(_context(epss=0.9)) is None


def test_cvss_alone_produces_a_score() -> None:
    result = score(_context(cvss_score=9.8))
    assert result is not None
    assert result.severity_component == pytest.approx(0.98)
    assert result.threat_component == 0.0
    # severity is the base (not half of a blend): zero threat evidence
    # keeps 70% of it -- see the _BASE_SEVERITY_SHARE comment in
    # risk_scorer.py for why a plain 50/50 average was wrong here.
    assert result.value == round(0.98 * 100 * 0.7)
    assert any("CVSS 9.8" in r for r in result.reasons)


def test_a_critical_cvss_with_zero_threat_evidence_still_reads_as_high_priority() -> None:
    # The exact scenario that exposed the original 50/50-average flaw: a
    # CVSS 9.8 with no KEV/EPSS data must not be capped into Medium just
    # because nothing has been observed exploiting it yet -- patching
    # before exploitation is the point of a scanner.
    result = score(_context(cvss_score=9.8))
    assert result is not None
    assert result.band in (RiskBand.HIGH, RiskBand.CRITICAL)


def test_cvss_plus_epss_combines_both() -> None:
    result = score(_context(cvss_score=7.5, epss=0.4))
    assert result is not None
    assert result.threat_component == pytest.approx(0.4)
    assert result.value == round(0.75 * 100 * (0.7 + 0.3 * 0.4))
    assert any("EPSS 40%" in r for r in result.reasons)


def test_kev_without_cvss_uses_the_severity_floor() -> None:
    result = score(_context(in_kev=True))
    assert result is not None
    assert result.severity_component == 0.7
    assert result.threat_component == 1.0
    assert any("KEV listing alone" in r for r in result.reasons)


def test_kev_with_cvss_uses_the_real_cvss_not_the_floor() -> None:
    result = score(_context(cvss_score=5.0, in_kev=True))
    assert result is not None
    assert result.severity_component == 0.5
    assert result.threat_component == 1.0


def test_kev_ignores_epss_entirely_kev_is_the_stronger_signal() -> None:
    with_low_epss = score(_context(cvss_score=5.0, in_kev=True, epss=0.01))
    without_epss = score(_context(cvss_score=5.0, in_kev=True))
    assert with_low_epss is not None and without_epss is not None
    assert with_low_epss.threat_component == without_epss.threat_component == 1.0


def test_kev_plus_ransomware_floors_the_score_even_with_low_cvss() -> None:
    result = score(_context(cvss_score=0.1, in_kev=True, kev_ransomware_use=True))
    assert result is not None
    assert result.value >= 95
    assert any("ransomware" in r for r in result.reasons)


def test_kev_without_ransomware_does_not_trigger_the_ransomware_floor() -> None:
    result = score(_context(cvss_score=0.1, in_kev=True, kev_ransomware_use=False))
    assert result is not None
    assert result.value < 95
    assert not any("ransomware" in r for r in result.reasons)


def test_a_low_cvss_kev_entry_is_still_floored_above_what_cvss_alone_would_give() -> None:
    plain = score(_context(cvss_score=2.0))
    assert plain is not None
    kev_listed = score(_context(cvss_score=2.0, in_kev=True))
    assert kev_listed is not None
    assert kev_listed.value >= 50 > plain.value


@pytest.mark.parametrize(
    ("value", "expected_band"),
    [
        (100, RiskBand.CRITICAL),
        (85, RiskBand.CRITICAL),
        (84, RiskBand.HIGH),
        (65, RiskBand.HIGH),
        (64, RiskBand.MEDIUM),
        (40, RiskBand.MEDIUM),
        (39, RiskBand.LOW),
        (15, RiskBand.LOW),
        (14, RiskBand.INFO),
        (0, RiskBand.INFO),
    ],
)
def test_band_boundaries(value: int, expected_band: RiskBand) -> None:
    # Tested directly against the boundary helper rather than by reverse-
    # engineering a CVSS/EPSS combination that lands on each exact value:
    # the severity-is-the-base formula isn't linear enough (clamping, the
    # KEV floor) to invert cleanly, and that's not what this test is
    # actually checking -- it's checking the boundary table, not the
    # formula. The formula itself is covered by the scenario tests above.
    assert _band_for(value) is expected_band


def test_asset_criticality_scales_the_score_up() -> None:
    neutral = score(_context(cvss_score=6.0))
    critical_asset = score(_context(cvss_score=6.0), asset_criticality=1.5)
    assert neutral is not None and critical_asset is not None
    assert critical_asset.value > neutral.value
    assert critical_asset.value == min(100, round(neutral.value * 1.5))
    assert any("criticality weight" in r for r in critical_asset.reasons)


def test_default_asset_criticality_is_neutral_and_not_mentioned_in_reasons() -> None:
    result = score(_context(cvss_score=6.0))
    assert result is not None
    assert result.asset_criticality == 1.0
    assert not any("criticality" in r for r in result.reasons)


def test_score_never_exceeds_100_even_with_a_large_criticality_multiplier() -> None:
    result = score(_context(cvss_score=10.0, in_kev=True), asset_criticality=3.0)
    assert result is not None
    assert result.value == 100


def test_cvss_and_epss_are_clamped_defensively() -> None:
    # Upstream storage already validates these ranges; this is defense in
    # depth for a VulnerabilityContext built some other way, not a case
    # that should occur via the normal DB-backed path.
    result = score(_context(cvss_score=15.0, epss=1.5))
    assert result is not None
    assert result.severity_component == 1.0
    assert result.threat_component == 1.0


def test_result_is_immutable() -> None:
    result = score(_context(cvss_score=9.0))
    assert result is not None
    with pytest.raises(AttributeError):
        result.value = 0  # type: ignore[misc]
