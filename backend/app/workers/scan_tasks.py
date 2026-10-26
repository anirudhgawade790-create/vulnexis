import logging

from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="scan_tasks.run_scan")
def run_scan(self, scan_job_id: str) -> dict:
    """
    Celery task that executes a scan job.
    Dispatches to ScanOrchestrator (implemented in FEAT-002).
    """
    import asyncio

    logger.info("Starting scan task for job %s", scan_job_id)
    self.update_state(state="PROGRESS", meta={"progress": 0, "phase": "initializing"})

    # Orchestration logic lives in app.scanners.scan_orchestrator (FEAT-002)
    # Placeholder: update status to failed with informative message
    logger.warning(
        "Scan orchestrator not yet implemented (FEAT-002). Job %s will remain queued.",
        scan_job_id,
    )
    return {"scan_job_id": scan_job_id, "status": "queued"}
