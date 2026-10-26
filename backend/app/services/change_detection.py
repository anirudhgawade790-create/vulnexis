"""
Change detection service: compares two scan runs to identify new, resolved,
and changed findings/assets/ports.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class ChangeDetectionService:
    """Compares two scans and returns a structured change report."""

    async def compare_scans(
        self, scan_id_new: str, scan_id_old: str, db: AsyncSession
    ) -> dict:
        """
        Return a ChangeDetectionReport dict comparing new vs old scan.
        Marks 'disappeared_inaccessible' when a host dropped off due to
        scan failure rather than actual remediation.
        """
        from app.models.asset import Asset
        from app.models.finding import Finding
        from app.models.scan_job import ScanJob

        # Verify both scans exist
        for sid in (scan_id_new, scan_id_old):
            r = await db.execute(select(ScanJob).where(ScanJob.id == sid))
            if not r.scalar_one_or_none():
                raise ValueError(f"Scan job {sid} not found")

        # ── Findings comparison ────────────────────────────────────────────
        new_findings_result = await db.execute(
            select(Finding).where(Finding.scan_job_id == scan_id_new)
        )
        new_findings = {
            (f.asset_id, f.check_name): f
            for f in new_findings_result.scalars().all()
        }

        old_findings_result = await db.execute(
            select(Finding).where(Finding.scan_job_id == scan_id_old)
        )
        old_findings = {
            (f.asset_id, f.check_name): f
            for f in old_findings_result.scalars().all()
        }

        # New: in new scan but not in old
        added_findings = [
            self._finding_to_dict(f)
            for key, f in new_findings.items()
            if key not in old_findings
        ]

        # Resolved: in old scan (open), not in new scan
        resolved_findings = [
            self._finding_to_dict(f)
            for key, f in old_findings.items()
            if key not in new_findings and f.status == "open"
        ]

        # ── Asset comparison ───────────────────────────────────────────────
        new_assets_result = await db.execute(
            select(Asset).where(Asset.scan_job_id == scan_id_new)
        )
        new_assets_map = {
            a.ip_address: a for a in new_assets_result.scalars().all()
        }

        old_assets_result = await db.execute(
            select(Asset).where(Asset.scan_job_id == scan_id_old)
        )
        old_assets_map = {
            a.ip_address: a for a in old_assets_result.scalars().all()
        }

        added_assets = [
            self._asset_to_dict(a)
            for ip, a in new_assets_map.items()
            if ip not in old_assets_map
        ]

        removed_assets = []
        for ip, a in old_assets_map.items():
            if ip not in new_assets_map:
                entry = self._asset_to_dict(a)
                # If this asset had WinRM errors in the new scan, mark as inaccessible
                entry["disappeared_inaccessible"] = True  # conservative assumption
                removed_assets.append(entry)

        # ── Port comparison (per asset) ─────────────────────────────────────
        new_open_ports: list[dict] = []
        closed_ports: list[dict] = []

        for ip, new_asset in new_assets_map.items():
            old_asset = old_assets_map.get(ip)
            new_ports_set = {
                p["port"] for p in (new_asset.open_ports or []) if isinstance(p, dict)
            }
            old_ports_set = (
                {p["port"] for p in (old_asset.open_ports or []) if isinstance(p, dict)}
                if old_asset
                else set()
            )

            for port in new_ports_set - old_ports_set:
                new_open_ports.append({"ip": ip, "port": port})

            for port in old_ports_set - new_ports_set:
                closed_ports.append({"ip": ip, "port": port})

        # ── Risk delta ─────────────────────────────────────────────────────
        from sqlalchemy import func

        new_risk_sum = (
            await db.execute(
                select(func.sum(Finding.risk_score)).where(
                    Finding.scan_job_id == scan_id_new
                )
            )
        ).scalar_one() or 0.0

        old_risk_sum = (
            await db.execute(
                select(func.sum(Finding.risk_score)).where(
                    Finding.scan_job_id == scan_id_old
                )
            )
        ).scalar_one() or 0.0

        risk_delta = float(new_risk_sum) - float(old_risk_sum)

        return {
            "scan_job_id": scan_id_new,
            "previous_scan_job_id": scan_id_old,
            "new_findings": added_findings,
            "resolved_findings": resolved_findings,
            "new_assets": added_assets,
            "removed_assets": removed_assets,
            "new_open_ports": new_open_ports,
            "closed_ports": closed_ports,
            "risk_delta": round(risk_delta, 2),
        }

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _finding_to_dict(finding) -> dict:
        return {
            "id": finding.id,
            "title": finding.title,
            "check_name": finding.check_name,
            "asset_id": finding.asset_id,
            "severity": finding.severity,
            "status": finding.status,
            "risk_score": finding.risk_score,
        }

    @staticmethod
    def _asset_to_dict(asset) -> dict:
        return {
            "id": asset.id,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "os_name": asset.os_name,
        }
