"""
Risk engine: explainable risk score calculation for findings.
Score is internal and separate from CVSS.
"""

import logging

logger = logging.getLogger(__name__)

# Default severity base scores when no CVSS is available
_SEVERITY_DEFAULTS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

_CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "critical": 1.4,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.8,
}

_CONFIDENCE_FACTORS: dict[str, float] = {
    "confirmed": 1.0,
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}


class RiskEngine:
    """Calculates explainable risk scores for findings."""

    def calculate_risk_score(self, finding_dict: dict, asset_dict: dict) -> float:
        """
        Calculate risk score (0.0–10.0) using:
        - CVSS v3/v2 base score or severity default
        - KEV multiplier (1.3 if in CISA KEV)
        - Internet exposure multiplier (1.2 if exposed port)
        - Asset business criticality multiplier
        - Confidence factor

        The result is capped at 10.0.
        """
        # Base score
        cvss_v3 = finding_dict.get("cvss_v3_score")
        cvss_v2 = finding_dict.get("cvss_v2_score")
        severity = (finding_dict.get("severity") or "medium").lower()

        if cvss_v3 is not None:
            base = float(cvss_v3)
        elif cvss_v2 is not None:
            base = float(cvss_v2)
        else:
            base = _SEVERITY_DEFAULTS.get(severity, 5.0)

        # KEV multiplier
        is_kev = bool(finding_dict.get("is_kev", False))
        kev_multiplier = 1.3 if is_kev else 1.0

        # Exposure multiplier
        is_exposed = bool(finding_dict.get("internet_exposed", False))
        # Also treat network_exposure finding type as exposed
        if finding_dict.get("finding_type") == "network_exposure":
            is_exposed = True
        exposure_multiplier = 1.2 if is_exposed else 1.0

        # Business criticality multiplier
        criticality = (asset_dict.get("business_criticality") or "medium").lower()
        criticality_multiplier = _CRITICALITY_MULTIPLIERS.get(criticality, 1.0)

        # Confidence factor
        confidence = (finding_dict.get("confidence") or "medium").lower()
        confidence_factor = _CONFIDENCE_FACTORS.get(confidence, 0.7)

        raw_score = base * kev_multiplier * exposure_multiplier * criticality_multiplier * confidence_factor
        return round(min(raw_score, 10.0), 2)

    def generate_risk_explanation(self, finding: dict, asset: dict) -> str:
        """
        Generate a human-readable explanation of the risk score calculation.
        """
        parts: list[str] = []

        cvss_v3 = finding.get("cvss_v3_score")
        cvss_v2 = finding.get("cvss_v2_score")
        severity = (finding.get("severity") or "medium").lower()

        if cvss_v3 is not None:
            parts.append(f"Base score: CVSS v3 = {cvss_v3}")
        elif cvss_v2 is not None:
            parts.append(f"Base score: CVSS v2 = {cvss_v2}")
        else:
            default = _SEVERITY_DEFAULTS.get(severity, 5.0)
            parts.append(f"Base score: severity default for '{severity}' = {default}")

        if finding.get("is_kev"):
            parts.append("KEV multiplier applied (1.3×): this CVE is in the CISA Known Exploited Vulnerabilities catalog")

        finding_type = finding.get("finding_type", "")
        internet_exposed = finding.get("internet_exposed", False)
        if internet_exposed or finding_type == "network_exposure":
            parts.append("Exposure multiplier applied (1.2×): service is exposed / internet-accessible")

        criticality = (asset.get("business_criticality") or "medium").lower()
        mult = _CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
        if mult != 1.0:
            parts.append(f"Asset criticality multiplier applied ({mult}×): asset business criticality = {criticality}")

        confidence = (finding.get("confidence") or "medium").lower()
        factor = _CONFIDENCE_FACTORS.get(confidence, 0.7)
        if factor < 1.0:
            parts.append(f"Confidence factor applied ({factor}×): evidence confidence = {confidence}")

        final = self.calculate_risk_score(finding, asset)
        parts.append(f"Final risk score: {final} / 10.0")

        return ". ".join(parts) + "."
