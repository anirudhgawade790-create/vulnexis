import asyncio
import logging

from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="scan_tasks.run_scan")
def run_scan(self, scan_job_id: str) -> dict:
    """
    Celery task: execute a scan job via ScanOrchestrator.
    Sets scan_job.status=failed on unhandled exceptions.
    """
    logger.info("Starting scan task for job %s", scan_job_id)
    self.update_state(state="PROGRESS", meta={"progress": 0, "phase": "initializing"})

    try:
        asyncio.run(_run_scan_async(scan_job_id))
        return {"scan_job_id": scan_job_id, "status": "completed"}
    except Exception as exc:
        logger.exception("Scan task %s failed: %s", scan_job_id, exc)
        asyncio.run(_mark_failed(scan_job_id, str(exc)))
        return {"scan_job_id": scan_job_id, "status": "failed", "error": str(exc)}


async def _run_scan_async(scan_job_id: str) -> None:
    """Run orchestrator inside an async context."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.config import get_settings
    from app.scanners.scan_orchestrator import ScanOrchestrator

    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as db:
        orchestrator = ScanOrchestrator()
        await orchestrator.start_scan(scan_job_id, db)

    await engine.dispose()


async def _mark_failed(scan_job_id: str, error_msg: str) -> None:
    """Mark a scan job as failed in the database."""
    from datetime import datetime, timezone

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.config import get_settings
    from app.models.scan_job import ScanJob

    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=False)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as db:
        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        scan_job = result.scalar_one_or_none()
        if scan_job:
            scan_job.status = "failed"
            scan_job.error_message = error_msg[:1000]
            scan_job.completed_at = datetime.now(timezone.utc)
            await db.commit()

    await engine.dispose()
