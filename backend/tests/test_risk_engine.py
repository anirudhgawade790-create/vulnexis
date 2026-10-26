"""
Tests for RiskEngine: score calculation, multipliers, cap at 10.0.
"""

import pytest

from app.services.risk_engine import RiskEngine


# ── basic calculation ─────────────────────────────────────────────────────────

def test_risk_score_uses_cvss_v3():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 7.5, "severity": "high", "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    assert score == 7.5


def test_risk_score_uses_cvss_v2_when_no_v3():
    engine = RiskEngine()
    finding = {"cvss_v2_score": 6.8, "severity": "high", "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    assert score == 6.8


def test_risk_score_falls_back_to_severity_default():
    engine = RiskEngine()
    finding = {"severity": "medium", "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # medium default is 5.0, confidence confirmed=1.0, criticality medium=1.0
    assert score == 5.0


def test_risk_score_critical_severity_default():
    engine = RiskEngine()
    finding = {"severity": "critical", "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    assert score == 9.0


def test_risk_score_info_severity_default():
    engine = RiskEngine()
    finding = {"severity": "info", "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    assert score == 1.0


# ── KEV multiplier ────────────────────────────────────────────────────────────

def test_risk_score_kev_multiplier_applied():
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 7.0,
        "is_kev": True,
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 7.0 * 1.3 = 9.1
    assert abs(score - 9.1) < 0.01


def test_risk_score_no_kev_no_multiplier():
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 7.0,
        "is_kev": False,
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    assert score == 7.0


# ── exposure multiplier ───────────────────────────────────────────────────────

def test_risk_score_internet_exposed_multiplier():
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 5.0,
        "internet_exposed": True,
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 5.0 * 1.2 = 6.0
    assert abs(score - 6.0) < 0.01


def test_risk_score_network_exposure_type_treated_as_exposed():
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 5.0,
        "finding_type": "network_exposure",
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 5.0 * 1.2 = 6.0
    assert abs(score - 6.0) < 0.01


# ── criticality multiplier ────────────────────────────────────────────────────

def test_risk_score_critical_asset_multiplier():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 5.0, "confidence": "confirmed"}
    asset = {"business_criticality": "critical"}
    score = engine.calculate_risk_score(finding, asset)
    # 5.0 * 1.4 = 7.0
    assert abs(score - 7.0) < 0.01


def test_risk_score_low_criticality_reduces_score():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 5.0, "confidence": "confirmed"}
    asset = {"business_criticality": "low"}
    score = engine.calculate_risk_score(finding, asset)
    # 5.0 * 0.8 = 4.0
    assert abs(score - 4.0) < 0.01


def test_risk_score_high_criticality():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 5.0, "confidence": "confirmed"}
    asset = {"business_criticality": "high"}
    score = engine.calculate_risk_score(finding, asset)
    # 5.0 * 1.2 = 6.0
    assert abs(score - 6.0) < 0.01


# ── confidence factor ─────────────────────────────────────────────────────────

def test_risk_score_low_confidence_reduces_score():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 8.0, "confidence": "low"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 8.0 * 0.5 = 4.0
    assert abs(score - 4.0) < 0.01


def test_risk_score_medium_confidence():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 8.0, "confidence": "medium"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 8.0 * 0.7 = 5.6
    assert abs(score - 5.6) < 0.01


def test_risk_score_high_confidence():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 8.0, "confidence": "high"}
    asset = {"business_criticality": "medium"}
    score = engine.calculate_risk_score(finding, asset)
    # 8.0 * 0.9 = 7.2
    assert abs(score - 7.2) < 0.01


# ── cap at 10.0 ───────────────────────────────────────────────────────────────

def test_risk_score_capped_at_10():
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 9.0,
        "is_kev": True,
        "internet_exposed": True,
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "critical"}
    score = engine.calculate_risk_score(finding, asset)
    # 9.0 * 1.3 * 1.2 * 1.4 * 1.0 = 19.656 → capped at 10.0
    assert score == 10.0


def test_risk_score_never_exceeds_10():
    """Any combination of multipliers must never produce score > 10."""
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 10.0,
        "is_kev": True,
        "internet_exposed": True,
        "finding_type": "network_exposure",
        "confidence": "confirmed",
    }
    asset = {"business_criticality": "critical"}
    score = engine.calculate_risk_score(finding, asset)
    assert score <= 10.0


# ── complete scenario: KEV + critical + exposed ───────────────────────────────

def test_risk_score_kev_critical_exposed():
    """KEV finding on a critical asset with internet exposure."""
    engine = RiskEngine()
    finding = {
        "cvss_v3_score": 8.8,
        "is_kev": True,
        "internet_exposed": True,
        "confidence": "confirmed",
        "severity": "critical",
    }
    asset = {"business_criticality": "critical"}
    score = engine.calculate_risk_score(finding, asset)
    # 8.8 * 1.3 * 1.2 * 1.4 * 1.0 = 19.19 → capped at 10.0
    assert score == 10.0


# ── explanation ───────────────────────────────────────────────────────────────

def test_generate_risk_explanation_includes_kev():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 7.0, "is_kev": True, "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    explanation = engine.generate_risk_explanation(finding, asset)
    assert "KEV" in explanation or "kev" in explanation.lower()


def test_generate_risk_explanation_mentions_final_score():
    engine = RiskEngine()
    finding = {"cvss_v3_score": 5.0, "confidence": "confirmed"}
    asset = {"business_criticality": "medium"}
    explanation = engine.generate_risk_explanation(finding, asset)
    assert "5.0" in explanation


def test_generate_risk_explanation_returns_string():
    engine = RiskEngine()
    finding = {"severity": "low", "confidence": "low"}
    asset = {"business_criticality": "low"}
    explanation = engine.generate_risk_explanation(finding, asset)
    assert isinstance(explanation, str)
    assert len(explanation) > 0
