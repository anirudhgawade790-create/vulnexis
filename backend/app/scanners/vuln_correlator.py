"""
Vulnerability correlator: NVD CVE lookup, CISA KEV sync, finding classification.
"""

import logging
from enum import Enum

import requests

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_REQUEST_TIMEOUT = 15  # seconds


class FindingType(str, Enum):
    confirmed_vulnerability = "confirmed_vulnerability"
    potential_vulnerability = "potential_vulnerability"
    misconfiguration = "misconfiguration"
    network_exposure = "network_exposure"
    informational = "informational"


class ConfidenceLevel(str, Enum):
    confirmed = "confirmed"
    high = "high"
    medium = "medium"
    low = "low"


class VulnCorrelator:
    """Correlates scan evidence with vulnerability intelligence."""

    # ── NVD ──────────────────────────────────────────────────────────────────

    def fetch_nvd_cve(self, cve_id: str, api_key: str = "") -> dict | None:
        """
        Fetch CVE details from NVD API 2.0.
        Returns parsed dict or None on failure.
        """
        params = {"cveId": cve_id}
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            resp = requests.get(
                NVD_CVE_URL, params=params, headers=headers, timeout=_REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("NVD API request failed for %s: %s", cve_id, exc)
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        # CVSS v3
        cvss_v3 = None
        cvss_v3_vector = None
        for entry in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
            cvss_data = entry.get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
            break

        # CVSS v2
        cvss_v2 = None
        for entry in metrics.get("cvssMetricV2", []):
            cvss_v2 = entry.get("cvssData", {}).get("baseScore")
            break

        descriptions = {
            d.get("lang"): d.get("value")
            for d in cve_data.get("descriptions", [])
        }

        references = [
            ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")
        ]

        affected_products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_products.append(
                            {
                                "cpe": cpe_match.get("criteria", ""),
                                "version_start": cpe_match.get("versionStartIncluding"),
                                "version_end": cpe_match.get("versionEndExcluding"),
                            }
                        )

        return {
            "cve_id": cve_id,
            "description": descriptions.get("en", ""),
            "cvss_v3_score": cvss_v3,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2,
            "references": references,
            "affected_products": affected_products,
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
        }

    # ── CISA KEV ──────────────────────────────────────────────────────────────

    def sync_kev_catalog(self, db_session) -> dict:
        """
        Download CISA KEV catalog and upsert entries into vulnerabilities table.
        Returns summary dict with counts.
        """
        from datetime import datetime, timezone

        from sqlalchemy import select

        from app.models.vulnerability import Vulnerability

        try:
            resp = requests.get(CISA_KEV_URL, timeout=_REQUEST_TIMEOUT)
            resp.raise_for_status()
            catalog = resp.json()
        except requests.RequestException as exc:
            logger.error("Failed to download CISA KEV catalog: %s", exc)
            return {"error": str(exc), "synced": 0}

        vulnerabilities = catalog.get("vulnerabilities", [])
        synced = 0
        created = 0

        for entry in vulnerabilities:
            cve_id = entry.get("cveID", "")
            if not cve_id:
                continue

            import asyncio

            # Handle both sync and async callers
            try:
                loop = asyncio.get_event_loop()
                existing = loop.run_until_complete(
                    db_session.execute(
                        select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                    )
                )
                existing = existing.scalar_one_or_none()
            except RuntimeError:
                # Sync session path (used in tests)
                result = db_session.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                )
                existing = result.scalar_one_or_none()

            kev_date = None
            kev_due = None
            try:
                date_str = entry.get("dateAdded", "")
                if date_str:
                    kev_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                due_str = entry.get("dueDate", "")
                if due_str:
                    kev_due = datetime.strptime(due_str, "%Y-%m-%d").date()
            except (ValueError, TypeError):
                pass

            if existing:
                existing.is_kev = True
                existing.kev_date_added = kev_date
                existing.kev_due_date = kev_due
            else:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    title=entry.get("shortDescription", cve_id)[:500],
                    description=entry.get("shortDescription", ""),
                    severity="high",  # KEV default; will be updated by fetch_nvd_cve
                    is_kev=True,
                    kev_date_added=kev_date,
                    kev_due_date=kev_due,
                    source="CISA_KEV",
                    fetched_at=datetime.now(timezone.utc),
                )
                db_session.add(vuln)
                created += 1

            synced += 1

        return {"synced": synced, "created": created}

    # ── correlation ───────────────────────────────────────────────────────────

    def correlate_asset(
        self, asset_dict: dict, software_list: list[dict], db_session
    ) -> list[dict]:
        """
        Query vulnerabilities table for entries matching asset's software.
        Returns list of potential finding dicts.
        """
        from sqlalchemy import select

        from app.models.vulnerability import Vulnerability

        findings = []

        for software in software_list:
            name = software.get("name", "").lower()
            version = software.get("version", "")

            try:
                import asyncio
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(
                    db_session.execute(select(Vulnerability))
                )
                vulns = result.scalars().all()
            except RuntimeError:
                result = db_session.execute(select(Vulnerability))
                vulns = result.scalars().all()

            for vuln in vulns:
                affected = vuln.affected_products or []
                for product in affected:
                    cpe = product.get("cpe", "").lower()
                    if name and name in cpe:
                        confidence = self.calculate_confidence(
                            {
                                "product_match": True,
                                "version_match": bool(version and version in cpe),
                                "version_range_match": bool(
                                    product.get("version_start") or product.get("version_end")
                                ),
                                "banner_only": False,
                            }
                        )
                        finding_type = self.classify_finding_type(
                            {
                                "version": version,
                                "cpe": cpe,
                                "version_start": product.get("version_start"),
                                "version_end": product.get("version_end"),
                                "cve_id": vuln.cve_id,
                            }
                        )
                        findings.append(
                            {
                                "cve_id": vuln.cve_id,
                                "vulnerability_id": vuln.id,
                                "asset_ip": asset_dict.get("ip_address", ""),
                                "title": vuln.title,
                                "finding_type": finding_type.value,
                                "severity": vuln.severity,
                                "confidence": confidence.value,
                                "evidence": f"Software '{software.get('name')}' version '{version}' matches {cpe}",
                                "is_kev": vuln.is_kev,
                                "cvss_v3_score": vuln.cvss_v3_score,
                            }
                        )

        return findings

    # ── classification helpers ────────────────────────────────────────────────

    def classify_finding_type(self, evidence_dict: dict) -> FindingType:
        """
        Classify finding type based on available evidence.
        Never confirms a vulnerability from banner/service name alone.
        """
        version = evidence_dict.get("version", "")
        cpe = evidence_dict.get("cpe", "")
        version_start = evidence_dict.get("version_start")
        version_end = evidence_dict.get("version_end")
        cve_id = evidence_dict.get("cve_id")
        banner_only = evidence_dict.get("banner_only", False)
        product_match = evidence_dict.get("product_match", False)
        exact_version_match = evidence_dict.get("exact_version_match", False)

        # Banner/service-name only → never confirm
        if banner_only:
            return FindingType.potential_vulnerability

        # Exact version + CVE = confirmed
        if exact_version_match and cve_id:
            return FindingType.confirmed_vulnerability

        # Version in range
        if version and cpe and (version_start or version_end):
            return FindingType.potential_vulnerability

        # Product match without specific version = potential
        if product_match and cve_id:
            return FindingType.potential_vulnerability

        # Configuration check result
        if evidence_dict.get("is_config_check"):
            return FindingType.misconfiguration

        # Network-level observation
        if evidence_dict.get("is_network"):
            return FindingType.network_exposure

        return FindingType.informational

    def calculate_confidence(self, evidence_dict: dict) -> ConfidenceLevel:
        """
        Calculate confidence level based on available evidence quality.
        confirmed = exact version match with CVE
        high = version range match
        medium = product match, no version
        low = banner/service guess only
        """
        banner_only = evidence_dict.get("banner_only", False)
        product_match = evidence_dict.get("product_match", False)
        version_match = evidence_dict.get("version_match", False)
        version_range_match = evidence_dict.get("version_range_match", False)
        exact_version_match = evidence_dict.get("exact_version_match", False)

        if banner_only and not product_match:
            return ConfidenceLevel.low

        if exact_version_match:
            return ConfidenceLevel.confirmed

        if version_match or version_range_match:
            return ConfidenceLevel.high

        if product_match:
            return ConfidenceLevel.medium

        return ConfidenceLevel.low
