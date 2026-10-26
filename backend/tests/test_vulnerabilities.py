"""
Tests for VulnCorrelator: classification, confidence, and NVD API mock.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.scanners.vuln_correlator import (
    ConfidenceLevel,
    FindingType,
    VulnCorrelator,
)


# ── classify_finding_type ──────────────────────────────────────────────────────

def test_classify_confirmed_vulnerability():
    correlator = VulnCorrelator()
    evidence = {
        "exact_version_match": True,
        "cve_id": "CVE-2021-34527",
        "banner_only": False,
        "product_match": True,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.confirmed_vulnerability


def test_classify_potential_vulnerability_version_range():
    correlator = VulnCorrelator()
    evidence = {
        "exact_version_match": False,
        "cve_id": "CVE-2021-34527",
        "version": "6.1.1",
        "cpe": "cpe:2.3:a:microsoft:windows:*:*",
        "version_start": "6.0",
        "version_end": "6.2",
        "banner_only": False,
        "product_match": True,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.potential_vulnerability


def test_classify_potential_vulnerability_banner_only():
    """Banner-only evidence MUST NOT produce confirmed_vulnerability."""
    correlator = VulnCorrelator()
    evidence = {
        "banner_only": True,
        "exact_version_match": False,
        "cve_id": "CVE-2021-99999",
        "product_match": True,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.potential_vulnerability
    assert result != FindingType.confirmed_vulnerability


def test_classify_misconfiguration():
    correlator = VulnCorrelator()
    evidence = {
        "is_config_check": True,
        "banner_only": False,
        "exact_version_match": False,
        "cve_id": None,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.misconfiguration


def test_classify_network_exposure():
    correlator = VulnCorrelator()
    evidence = {
        "is_network": True,
        "banner_only": False,
        "exact_version_match": False,
        "is_config_check": False,
        "cve_id": None,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.network_exposure


def test_classify_informational_fallback():
    correlator = VulnCorrelator()
    evidence = {
        "banner_only": False,
        "exact_version_match": False,
        "cve_id": None,
        "product_match": False,
        "version_match": False,
        "is_config_check": False,
        "is_network": False,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.informational


def test_classify_product_match_no_version_is_potential():
    """Product match without version → potential, not confirmed."""
    correlator = VulnCorrelator()
    evidence = {
        "banner_only": False,
        "exact_version_match": False,
        "cve_id": "CVE-2021-12345",
        "product_match": True,
        "version_match": False,
        "version_range_match": False,
    }
    result = correlator.classify_finding_type(evidence)
    assert result == FindingType.potential_vulnerability


# ── calculate_confidence ───────────────────────────────────────────────────────

def test_confidence_confirmed():
    correlator = VulnCorrelator()
    evidence = {"exact_version_match": True, "product_match": True, "banner_only": False}
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.confirmed


def test_confidence_high_version_match():
    correlator = VulnCorrelator()
    evidence = {
        "exact_version_match": False,
        "version_match": True,
        "product_match": True,
        "banner_only": False,
    }
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.high


def test_confidence_high_version_range():
    correlator = VulnCorrelator()
    evidence = {
        "exact_version_match": False,
        "version_match": False,
        "version_range_match": True,
        "product_match": True,
        "banner_only": False,
    }
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.high


def test_confidence_medium_product_only():
    correlator = VulnCorrelator()
    evidence = {
        "exact_version_match": False,
        "version_match": False,
        "version_range_match": False,
        "product_match": True,
        "banner_only": False,
    }
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.medium


def test_confidence_low_banner_only():
    correlator = VulnCorrelator()
    evidence = {
        "banner_only": True,
        "product_match": False,
        "version_match": False,
        "exact_version_match": False,
    }
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.low


def test_confidence_low_no_evidence():
    correlator = VulnCorrelator()
    evidence = {
        "banner_only": False,
        "product_match": False,
        "version_match": False,
        "exact_version_match": False,
    }
    result = correlator.calculate_confidence(evidence)
    assert result == ConfidenceLevel.low


# ── fetch_nvd_cve ─────────────────────────────────────────────────────────────

def test_fetch_nvd_cve_success():
    """NVD API response is correctly parsed."""
    correlator = VulnCorrelator()

    mock_response_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-34527",
                    "published": "2021-07-01T00:00:00",
                    "lastModified": "2021-08-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": "Windows Print Spooler RCE"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 8.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://msrc.microsoft.com/update-guide"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:o:microsoft:windows_10:*",
                                            "versionStartIncluding": "1809",
                                            "versionEndExcluding": "10.0.17763.2029",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.json.return_value = mock_response_data
    mock_resp.raise_for_status = MagicMock()

    with patch("app.scanners.vuln_correlator.requests.get", return_value=mock_resp):
        result = correlator.fetch_nvd_cve("CVE-2021-34527")

    assert result is not None
    assert result["cve_id"] == "CVE-2021-34527"
    assert result["cvss_v3_score"] == 8.8
    assert "Windows Print Spooler" in result["description"]
    assert len(result["references"]) >= 1
    assert len(result["affected_products"]) >= 1


def test_fetch_nvd_cve_not_found():
    """Returns None when the CVE is not in the NVD response."""
    correlator = VulnCorrelator()

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"vulnerabilities": []}
    mock_resp.raise_for_status = MagicMock()

    with patch("app.scanners.vuln_correlator.requests.get", return_value=mock_resp):
        result = correlator.fetch_nvd_cve("CVE-0000-00000")

    assert result is None


def test_fetch_nvd_cve_request_error():
    """Returns None on network error."""
    import requests as req_lib

    correlator = VulnCorrelator()
    with patch(
        "app.scanners.vuln_correlator.requests.get",
        side_effect=req_lib.RequestException("timeout"),
    ):
        result = correlator.fetch_nvd_cve("CVE-2021-34527")

    assert result is None


# ── FindingType enum values ────────────────────────────────────────────────────

def test_finding_type_values():
    """All five FindingType values must be present."""
    values = {ft.value for ft in FindingType}
    assert "confirmed_vulnerability" in values
    assert "potential_vulnerability" in values
    assert "misconfiguration" in values
    assert "network_exposure" in values
    assert "informational" in values


def test_confidence_level_values():
    values = {cl.value for cl in ConfidenceLevel}
    assert "confirmed" in values
    assert "high" in values
    assert "medium" in values
    assert "low" in values
