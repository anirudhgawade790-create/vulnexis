"""
Insights engine: rule-based security insight generation.
Falls back to deterministic rules when no AI service is configured.
"""

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class InsightsEngine:
    """
    Deterministic, rule-based security insights engine.
    Each rule is a method that returns an InsightItem dict or None.
    """

    async def generate_insights(self, db_session) -> list[dict]:
        """
        Run all rules against the current DB state.
        Returns top 10 non-None results ordered by severity.
        """
        rules = [
            self.rule_risk_increased,
            self.rule_critical_kev,
            self.rule_unpatched_critical_assets,
            self.rule_new_exposures,
            self.rule_top_remediation,
            self.rule_unsupported_os,
            self.rule_defender_disabled,
        ]

        results: list[dict] = []
        for rule in rules:
            try:
                item = await rule(db_session)
                if item is not None:
                    results.append(item)
            except Exception as exc:
                logger.warning("Insight rule %s failed: %s", rule.__name__, exc)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 99))

        return results[:10]

    def _make_insight(
        self,
        title: str,
        detail: str,
        severity: str,
        category: str,
        evidence_tags: list[str] | None = None,
    ) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "title": title,
            "detail": detail,
            "severity": severity,
            "category": category,
            "evidence_tags": evidence_tags or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    async def rule_risk_increased(self, db_session) -> dict | None:
        """Compare latest vs previous scan total risk_score sum."""
        from sqlalchemy import desc, func, select

        from app.models.finding import Finding
        from app.models.scan_job import ScanJob

        # Get two most recent completed scans
        result = await db_session.execute(
            select(ScanJob.id)
            .where(ScanJob.status == "completed")
            .order_by(desc(ScanJob.completed_at))
            .limit(2)
        )
        scan_ids = [row[0] for row in result.fetchall()]
        if len(scan_ids) < 2:
            return None

        latest_id, prev_id = scan_ids[0], scan_ids[1]

        async def _risk_sum(sid: str) -> float:
            r = await db_session.execute(
                select(func.sum(Finding.risk_score)).where(Finding.scan_job_id == sid)
            )
            return float(r.scalar_one() or 0.0)

        latest_risk = await _risk_sum(latest_id)
        prev_risk = await _risk_sum(prev_id)

        if prev_risk == 0:
            return None

        delta_pct = ((latest_risk - prev_risk) / prev_risk) * 100

        if delta_pct > 10:
            return self._make_insight(
                title="Overall risk has increased",
                detail=f"Total risk score increased by {delta_pct:.1f}% compared to the previous scan. Investigate new findings in the latest scan.",
                severity="high",
                category="risk_trend",
                evidence_tags=[f"scan:{latest_id}", f"scan:{prev_id}"],
            )
        elif delta_pct < -10:
            return self._make_insight(
                title="Overall risk has decreased",
                detail=f"Total risk score decreased by {abs(delta_pct):.1f}% since the previous scan. Remediation efforts are showing results.",
                severity="low",
                category="risk_trend",
                evidence_tags=[f"scan:{latest_id}", f"scan:{prev_id}"],
            )
        return None

    async def rule_critical_kev(self, db_session) -> dict | None:
        """Any open finding with is_kev=True and severity=critical."""
        from sqlalchemy import select

        from app.models.finding import Finding
        from app.models.vulnerability import Vulnerability

        result = await db_session.execute(
            select(Finding)
            .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id, isouter=True)
            .where(
                Finding.status == "open",
                Finding.severity == "critical",
                Vulnerability.is_kev == True,  # noqa: E712
            )
            .limit(5)
        )
        findings = result.scalars().all()
        if not findings:
            return None

        return self._make_insight(
            title=f"{len(findings)} critical KEV finding(s) require immediate action",
            detail=f"There are {len(findings)} open critical finding(s) linked to CISA Known Exploited Vulnerabilities. These have active exploits in the wild and must be prioritized.",
            severity="critical",
            category="kev_alert",
            evidence_tags=[f"finding:{f.id}" for f in findings],
        )

    async def rule_unpatched_critical_assets(self, db_session) -> dict | None:
        """Assets with criticality=critical and open patch findings."""
        from sqlalchemy import select

        from app.models.asset import Asset
        from app.models.finding import Finding

        result = await db_session.execute(
            select(Asset)
            .join(Finding, Finding.asset_id == Asset.id)
            .where(
                Asset.business_criticality == "critical",
                Finding.status == "open",
                Finding.check_name.like("missing_patch%"),
            )
            .distinct()
            .limit(5)
        )
        assets = result.scalars().all()
        if not assets:
            return None

        return self._make_insight(
            title=f"{len(assets)} critical asset(s) have unpatched vulnerabilities",
            detail=f"{len(assets)} business-critical asset(s) have open patch findings. Unpatched critical assets represent the highest remediation priority.",
            severity="critical",
            category="patch_management",
            evidence_tags=[f"asset:{a.id}" for a in assets],
        )

    async def rule_new_exposures(self, db_session) -> dict | None:
        """Newly open network exposure findings since last scan."""
        from sqlalchemy import desc, select

        from app.models.finding import Finding
        from app.models.scan_job import ScanJob

        result = await db_session.execute(
            select(ScanJob.id)
            .where(ScanJob.status == "completed")
            .order_by(desc(ScanJob.completed_at))
            .limit(2)
        )
        scan_ids = [row[0] for row in result.fetchall()]
        if len(scan_ids) < 2:
            return None

        latest_id, prev_id = scan_ids[0], scan_ids[1]

        # Exposure findings in latest scan
        latest_result = await db_session.execute(
            select(Finding.check_name)
            .where(
                Finding.scan_job_id == latest_id,
                Finding.finding_type == "network_exposure",
                Finding.status == "open",
            )
        )
        latest_checks = {row[0] for row in latest_result.fetchall()}

        # Exposure findings in previous scan
        prev_result = await db_session.execute(
            select(Finding.check_name)
            .where(
                Finding.scan_job_id == prev_id,
                Finding.finding_type == "network_exposure",
            )
        )
        prev_checks = {row[0] for row in prev_result.fetchall()}

        new_exposures = latest_checks - prev_checks
        if not new_exposures:
            return None

        return self._make_insight(
            title=f"{len(new_exposures)} new network exposure(s) detected",
            detail=f"The latest scan found {len(new_exposures)} network exposure(s) not present in the previous scan: {', '.join(list(new_exposures)[:3])}.",
            severity="high",
            category="network_exposure",
            evidence_tags=list(new_exposures)[:5],
        )

    async def rule_top_remediation(self, db_session) -> dict | None:
        """Finding with highest risk_score that has remediation_steps."""
        from sqlalchemy import desc, select

        from app.models.finding import Finding

        result = await db_session.execute(
            select(Finding)
            .where(
                Finding.status == "open",
                Finding.remediation_steps.is_not(None),
            )
            .order_by(desc(Finding.risk_score))
            .limit(1)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        return self._make_insight(
            title=f"Top priority: {finding.title}",
            detail=f"Highest-risk open finding with available remediation steps. Risk score: {finding.risk_score:.1f}/10. Address this finding first for maximum risk reduction.",
            severity=finding.severity,
            category="remediation_priority",
            evidence_tags=[f"finding:{finding.id}"],
        )

    async def rule_unsupported_os(self, db_session) -> dict | None:
        """Assets with is_supported_os=False."""
        from sqlalchemy import select

        from app.models.asset import Asset

        result = await db_session.execute(
            select(Asset).where(Asset.is_supported_os == False).limit(10)  # noqa: E712
        )
        assets = result.scalars().all()
        if not assets:
            return None

        return self._make_insight(
            title=f"{len(assets)} asset(s) running unsupported operating systems",
            detail=f"{len(assets)} asset(s) appear to be running operating systems that are no longer receiving security updates. These systems cannot be patched against new vulnerabilities.",
            severity="critical",
            category="eol_software",
            evidence_tags=[f"asset:{a.id}" for a in assets],
        )

    async def rule_defender_disabled(self, db_session) -> dict | None:
        """Windows assets with defender_status finding indicating disabled."""
        from sqlalchemy import select

        from app.models.finding import Finding

        result = await db_session.execute(
            select(Finding)
            .where(
                Finding.check_name == "defender_status",
                Finding.status == "open",
            )
            .limit(10)
        )
        findings = result.scalars().all()
        disabled = [f for f in findings if "disabled" in (f.evidence or "").lower() or f.finding_type == "misconfiguration"]
        if not disabled:
            return None

        return self._make_insight(
            title=f"Windows Defender disabled on {len(disabled)} asset(s)",
            detail=f"Windows Defender is disabled or partially disabled on {len(disabled)} asset(s). These hosts have reduced malware protection.",
            severity="high",
            category="antivirus",
            evidence_tags=[f"finding:{f.id}" for f in disabled],
        )
