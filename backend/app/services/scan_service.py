"""
Scan service: business logic for creating, listing, and managing scan jobs.
"""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _get_run_scan():
    """
    Return the run_scan Celery task.
    Imported lazily so the module can load without a live Celery broker
    and so tests can patch it via app.workers.scan_tasks.run_scan.
    """
    from app.workers.scan_tasks import run_scan as _run_scan
    return _run_scan


class ScanService:
    """Service layer for scan job management."""

    async def create_scan(self, scan_create, user, db: AsyncSession):
        """
        Validate target, create ScanJob, dispatch Celery task.
        scan_create is a ScanJobCreate pydantic model.
        """
        from app.models.scan_job import ScanJob
        from app.models.target import Target

        # Validate target exists and is active
        target_result = await db.execute(
            select(Target).where(
                Target.id == scan_create.target_id,
                Target.is_active == True,  # noqa: E712
            )
        )
        target = target_result.scalar_one_or_none()
        if not target:
            raise ValueError(f"Target {scan_create.target_id} not found or inactive")

        scan_job = ScanJob(
            id=str(uuid.uuid4()),
            target_id=scan_create.target_id,
            scan_type=scan_create.scan_type,
            options=scan_create.options,
            started_by=user.id,
            status="queued",
        )
        db.add(scan_job)
        await db.flush()

        # Dispatch Celery task
        try:
            import app.workers.scan_tasks as _tasks
            task = _tasks.run_scan.delay(scan_job.id)
            scan_job.celery_task_id = task.id
        except Exception as exc:
            logger.warning("Failed to dispatch Celery task for scan %s: %s", scan_job.id, exc)

        await db.commit()
        await db.refresh(scan_job)
        return scan_job

    async def list_scans(self, filters: dict, db: AsyncSession) -> list:
        """List scan jobs with optional status/target filters."""
        from app.models.scan_job import ScanJob

        query = select(ScanJob)
        if filters.get("status"):
            query = query.where(ScanJob.status == filters["status"])
        if filters.get("target_id"):
            query = query.where(ScanJob.target_id == filters["target_id"])

        page = filters.get("page", 1)
        size = filters.get("size", 50)
        query = query.order_by(ScanJob.created_at.desc()).offset((page - 1) * size).limit(size)

        result = await db.execute(query)
        return result.scalars().all()

    async def get_scan(self, scan_id: str, db: AsyncSession):
        """Get a single scan job by ID."""
        from app.models.scan_job import ScanJob

        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        return result.scalar_one_or_none()

    async def cancel_scan(self, scan_id: str, db: AsyncSession):
        """Cancel a queued or running scan."""
        from app.scanners.scan_orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator()
        await orchestrator.cancel_scan(scan_id, db)

    async def get_scan_results(self, scan_id: str, db: AsyncSession) -> dict:
        """Return a ScanResultsSummary dict for a completed scan."""
        from sqlalchemy import func

        from app.models.asset import Asset
        from app.models.finding import Finding
        from app.models.scan_job import ScanJob

        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return {}

        assets_count = (
            await db.execute(
                select(func.count(Asset.id)).where(Asset.scan_job_id == scan_id)
            )
        ).scalar_one()

        windows_count = (
            await db.execute(
                select(func.count(Asset.id)).where(
                    Asset.scan_job_id == scan_id,
                    Asset.is_windows == True,  # noqa: E712
                )
            )
        ).scalar_one()

        findings_result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_job_id == scan_id)
            .group_by(Finding.severity)
        )
        findings_by_severity = {row[0]: row[1] for row in findings_result}

        type_result = await db.execute(
            select(Finding.finding_type, func.count(Finding.id))
            .where(Finding.scan_job_id == scan_id)
            .group_by(Finding.finding_type)
        )
        findings_by_type = {row[0]: row[1] for row in type_result}

        duration = None
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()

        return {
            "scan_job_id": scan_id,
            "assets_found": assets_count,
            "windows_assets": windows_count,
            "total_open_ports": 0,
            "findings_by_severity": findings_by_severity,
            "findings_by_type": findings_by_type,
            "scan_duration_seconds": duration,
            "errors": [],
        }
