from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sih1684",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
    broker_connection_retry=False,
    broker_connection_retry_on_startup=False,
    task_publish_retry=False,
    broker_transport_options={
        "socket_connect_timeout": 3,
        "socket_timeout": 3,
        "retry_on_timeout": False,
    },
)
