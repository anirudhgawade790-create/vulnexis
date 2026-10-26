"""
Scan orchestrator: coordinates NetworkScanner, WindowsScanner, VulnCorrelator.
Persists assets and findings, publishes progress to Redis.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.scanners.base import ScanConfig, ScanProgressEvent
from app.scanners.network_scanner import NetworkScanner
from app.scanners.vuln_correlator import VulnCorrelator
from app.scanners.windows_scanner import WindowsScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Coordinates the full scan pipeline:
    1. Network discovery + port scan
    2. Windows deep assessment (if applicable)
    3. Vulnerability correlation
    """

    def __init__(self) -> None:
        self._cancel_flags: dict[str, bool] = {}

    # ── public entry points ───────────────────────────────────────────────────

    async def start_scan(self, scan_job_id: str, db: AsyncSession) -> None:
        """Load the scan job and run all phases. Updates job status throughout."""
        from app.models.scan_job import ScanJob
        from app.models.target import Target

        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        scan_job = result.scalar_one_or_none()
        if not scan_job:
            logger.error("Scan job %s not found", scan_job_id)
            return

        # Mark running
        scan_job.status = "running"
        scan_job.started_at = datetime.now(timezone.utc)
        scan_job.progress = 0
        await db.commit()

        try:
            target_result = await db.execute(
                select(Target).where(Target.id == scan_job.target_id)
            )
            target = target_result.scalar_one_or_none()
            if not target:
                raise ValueError(f"Target {scan_job.target_id} not found")

            target_ips = self._expand_scope(target.scope_value, target.scope_type)
            options = scan_job.options or {}
            options["scan_job_id"] = scan_job_id

            config = ScanConfig(target_ips=target_ips, options=options)
            discovered_assets: list[dict] = []

            # ── Phase 1: Network scan ──────────────────────────────────────
            network_assets = await self._run_network_phase(
                scan_job_id, config, db, scan_job
            )
            discovered_assets.extend(network_assets)

            # ── Phase 2: Windows scan (if applicable) ─────────────────────
            if scan_job.scan_type in ("windows", "full"):
                windows_assets = [a for a in network_assets if a.get("is_windows", False)]
                if windows_assets or scan_job.scan_type == "windows":
                    await self._run_windows_phase(
                        scan_job_id, config, windows_assets, db, scan_job
                    )

            # ── Phase 3: Vulnerability correlation ────────────────────────
            await self._run_correlation_phase(scan_job_id, db)

            # ── Complete ───────────────────────────────────────────────────
            scan_job.status = "completed"
            scan_job.progress = 100
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()

            await self._publish_progress(
                scan_job_id,
                ScanProgressEvent(
                    scan_job_id=scan_job_id,
                    progress=100,
                    phase="completed",
                    message="Scan completed successfully",
                ),
            )

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_job_id, exc)
            scan_job.status = "failed"
            scan_job.error_message = str(exc)
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await self._publish_progress(
                scan_job_id,
                ScanProgressEvent(
                    scan_job_id=scan_job_id,
                    progress=scan_job.progress,
                    phase="failed",
                    message=str(exc),
                ),
            )

    async def cancel_scan(self, scan_job_id: str, db: AsyncSession) -> None:
        """Mark scan as cancelled and set flag for in-progress loops."""
        from app.models.scan_job import ScanJob

        self._cancel_flags[scan_job_id] = True
        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        scan_job = result.scalar_one_or_none()
        if scan_job and scan_job.status in ("queued", "running"):
            scan_job.status = "cancelled"
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()

    # ── phases ─────────────────────────────────────────────────────────────────

    async def _run_network_phase(
        self,
        scan_job_id: str,
        config: ScanConfig,
        db: AsyncSession,
        scan_job,
    ) -> list[dict]:
        """Run network scanner and persist discovered assets."""
        from app.models.asset import Asset

        scanner = NetworkScanner()
        persisted: list[dict] = []

        async for event in scanner.scan(config):
            if self._cancel_flags.get(scan_job_id):
                break
            await self._publish_progress(scan_job_id, event)
            scan_job.progress = min(event.progress, 60)
            await db.commit()

        results = await scanner.get_results()
        for asset_data in results.assets:
            asset = Asset(
                id=str(uuid.uuid4()),
                scan_job_id=scan_job_id,
                target_id=scan_job.target_id,
                ip_address=asset_data.get("ip", ""),
                hostname=asset_data.get("hostname"),
                is_windows=self._looks_like_windows(asset_data),
                open_ports=asset_data.get("open_ports", []),
                os_name=asset_data.get("os_guess"),
            )
            db.add(asset)
            await db.flush()
            asset_data["db_id"] = asset.id
            persisted.append(asset_data)

        await db.commit()
        return persisted

    async def _run_windows_phase(
        self,
        scan_job_id: str,
        config: ScanConfig,
        windows_assets: list[dict],
        db: AsyncSession,
        scan_job,
    ) -> None:
        """Run Windows scanner against discovered Windows hosts."""
        from app.models.finding import Finding

        # Use the same IPs as the config if no windows_assets prefiltered
        target_ips = (
            [a.get("ip", "") for a in windows_assets]
            if windows_assets
            else config.target_ips
        )
        win_config = ScanConfig(target_ips=target_ips, options=config.options)

        scanner = WindowsScanner()
        async for event in scanner.scan(win_config):
            if self._cancel_flags.get(scan_job_id):
                break
            await self._publish_progress(scan_job_id, event)
            scan_job.progress = 60 + min(event.progress // 3, 30)
            await db.commit()

        results = await scanner.get_results()

        # Persist findings
        for finding_data in results.findings:
            asset_ip = finding_data.get("asset_ip", "")
            asset_id = await self._get_asset_id(scan_job_id, asset_ip, db)
            if not asset_id:
                continue
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_job_id=scan_job_id,
                asset_id=asset_id,
                title=finding_data.get("title", finding_data.get("check_name", "Unknown")),
                finding_type=finding_data.get("finding_type", "informational"),
                severity=finding_data.get("severity", "info"),
                check_name=finding_data.get("check_name", "unknown"),
                evidence=finding_data.get("evidence", ""),
                detection_method=finding_data.get("detection_method", "winrm_powershell"),
                confidence=finding_data.get("confidence", "low"),
                risk_score=0.0,
                status="open",
            )
            db.add(finding)

        await db.commit()

    async def _run_correlation_phase(self, scan_job_id: str, db: AsyncSession) -> None:
        """Run vulnerability correlation for all assets in this scan."""
        from sqlalchemy import select

        from app.models.asset import Asset
        from app.models.finding import Finding

        correlator = VulnCorrelator()
        result = await db.execute(
            select(Asset).where(Asset.scan_job_id == scan_job_id)
        )
        assets = result.scalars().all()

        for asset in assets:
            software_list = []
            if asset.windows_details:
                software_list = asset.windows_details.get("software", [])

            corr_findings = correlator.correlate_asset(
                {"ip_address": asset.ip_address}, software_list, db
            )
            for fd in corr_findings:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_job_id=scan_job_id,
                    asset_id=asset.id,
                    vulnerability_id=fd.get("vulnerability_id"),
                    title=fd.get("title", fd.get("cve_id", "Unknown")),
                    finding_type=fd.get("finding_type", "potential_vulnerability"),
                    severity=fd.get("severity", "medium"),
                    check_name=f"correlation_{fd.get('cve_id', 'unknown')}",
                    evidence=fd.get("evidence", ""),
                    detection_method="vuln_correlation",
                    confidence=fd.get("confidence", "medium"),
                    risk_score=0.0,
                    status="open",
                )
                db.add(finding)

        await db.commit()

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _publish_progress(self, scan_job_id: str, event: ScanProgressEvent) -> None:
        """Publish progress event to Redis pub/sub."""
        try:
            import redis.asyncio as aioredis

            from app.config import get_settings

            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            payload = json.dumps(
                {
                    "scan_job_id": event.scan_job_id,
                    "progress": event.progress,
                    "phase": event.phase,
                    "message": event.message,
                    "current_host": event.current_host,
                }
            )
            await r.publish(f"scan:{scan_job_id}:progress", payload)
            await r.aclose()
        except Exception as exc:
            logger.warning("Failed to publish progress for %s: %s", scan_job_id, exc)

    async def _get_asset_id(
        self, scan_job_id: str, ip_address: str, db: AsyncSession
    ) -> str | None:
        from app.models.asset import Asset

        result = await db.execute(
            select(Asset).where(
                Asset.scan_job_id == scan_job_id,
                Asset.ip_address == ip_address,
            )
        )
        asset = result.scalar_one_or_none()
        return asset.id if asset else None

    @staticmethod
    def _expand_scope(scope_value: str, scope_type: str) -> list[str]:
        """Convert a scope value to a list of IP strings."""
        import ipaddress

        if scope_type == "cidr":
            try:
                net = ipaddress.ip_network(scope_value, strict=False)
                return [str(ip) for ip in net.hosts()] or [scope_value]
            except ValueError:
                return [scope_value]
        elif scope_type == "range":
            # Simple "start-end" range
            parts = scope_value.split("-")
            if len(parts) == 2:
                try:
                    start = int(ipaddress.ip_address(parts[0].strip()))
                    end = int(ipaddress.ip_address(parts[1].strip()))
                    return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
                except (ValueError, TypeError):
                    return [scope_value]
        return [scope_value]

    @staticmethod
    def _looks_like_windows(asset_data: dict) -> bool:
        os_guess = (asset_data.get("os_guess") or "").lower()
        return "windows" in os_guess
