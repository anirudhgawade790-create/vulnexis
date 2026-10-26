"""
Tests for scan endpoints: create, list, SSE progress, cancel, compare.
Celery tasks are mocked so no broker is needed.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def target_id(db_session, admin_user):
    from app.models.target import Target

    target = Target(
        id=str(uuid.uuid4()),
        name="Test Target",
        scope_type="ip",
        scope_value="192.168.1.1",
        is_active=True,
        business_criticality="medium",
        created_by=admin_user.id,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target.id


@pytest.fixture
def scan_job_id(db_session, admin_user, target_id):
    from app.models.scan_job import ScanJob

    scan = ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="network",
        status="queued",
        started_by=admin_user.id,
        progress=0,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan.id


@pytest.fixture
def running_scan_id(db_session, admin_user, target_id):
    from app.models.scan_job import ScanJob

    scan = ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="network",
        status="running",
        started_by=admin_user.id,
        progress=50,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan.id


# ── POST /api/v1/scans ─────────────────────────────────────────────────────────

def test_create_scan_success(client: TestClient, admin_token, target_id):
    """Creating a scan dispatches a Celery task and returns 201."""
    mock_task = MagicMock()
    mock_task.id = "fake-celery-task-id"

    with patch("app.workers.scan_tasks.run_scan") as mock_run_scan:
        mock_run_scan.delay.return_value = mock_task

        response = client.post(
            "/api/v1/scans/",
            json={"target_id": target_id, "scan_type": "network"},
            headers=auth_headers(admin_token),
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "queued"
    assert data["scan_type"] == "network"
    assert data["target_id"] == target_id


def test_create_scan_analyst_allowed(client: TestClient, analyst_token, target_id):
    """Analysts can create scans."""
    mock_task = MagicMock()
    mock_task.id = "fake-celery-task-2"

    with patch("app.workers.scan_tasks.run_scan") as mock_run_scan:
        mock_run_scan.delay.return_value = mock_task

        response = client.post(
            "/api/v1/scans/",
            json={"target_id": target_id, "scan_type": "windows"},
            headers=auth_headers(analyst_token),
        )

    assert response.status_code == 201


def test_create_scan_viewer_forbidden(client: TestClient, db_session, target_id):
    """Viewers cannot create scans."""
    from app.models.user import User
    from app.services.auth_service import create_access_token, hash_password

    viewer = User(
        id=str(uuid.uuid4()),
        username="vieweruser",
        email="viewer@test.local",
        hashed_password=hash_password("Viewer@1234"),
        role="viewer",
        is_active=True,
    )
    db_session.add(viewer)
    db_session.commit()
    viewer_token = create_access_token({"sub": viewer.id, "role": "viewer"})

    response = client.post(
        "/api/v1/scans/",
        json={"target_id": target_id, "scan_type": "network"},
        headers=auth_headers(viewer_token),
    )
    assert response.status_code == 403


def test_create_scan_invalid_target(client: TestClient, admin_token):
    """Creating a scan with a nonexistent target returns 400."""
    with patch("app.workers.scan_tasks.run_scan") as mock_run_scan:
        mock_task = MagicMock()
        mock_task.id = "fake-id"
        mock_run_scan.delay.return_value = mock_task

        response = client.post(
            "/api/v1/scans/",
            json={"target_id": "nonexistent-target-id", "scan_type": "network"},
            headers=auth_headers(admin_token),
        )

    assert response.status_code == 400


def test_create_scan_celery_failure_still_creates_job(client: TestClient, admin_token, target_id):
    """If Celery dispatch fails, the scan job is still created (queued)."""
    with patch("app.workers.scan_tasks.run_scan") as mock_run_scan:
        mock_run_scan.delay.side_effect = Exception("broker unavailable")

        response = client.post(
            "/api/v1/scans/",
            json={"target_id": target_id, "scan_type": "network"},
            headers=auth_headers(admin_token),
        )

    assert response.status_code == 201
    assert response.json()["status"] == "queued"


# ── GET /api/v1/scans ─────────────────────────────────────────────────────────

def test_list_scans(client: TestClient, admin_token, scan_job_id):
    response = client.get("/api/v1/scans/", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    ids = [s["id"] for s in data]
    assert scan_job_id in ids


def test_list_scans_unauthenticated(client: TestClient):
    response = client.get("/api/v1/scans/")
    assert response.status_code == 401


# ── GET /api/v1/scans/{id} ────────────────────────────────────────────────────

def test_get_scan(client: TestClient, admin_token, scan_job_id):
    response = client.get(f"/api/v1/scans/{scan_job_id}", headers=auth_headers(admin_token))
    assert response.status_code == 200
    assert response.json()["id"] == scan_job_id


def test_get_scan_not_found(client: TestClient, admin_token):
    response = client.get("/api/v1/scans/nonexistent-id", headers=auth_headers(admin_token))
    assert response.status_code == 404


# ── DELETE /api/v1/scans/{id}/cancel ─────────────────────────────────────────

def test_cancel_scan_queued(client: TestClient, admin_token, scan_job_id):
    response = client.delete(
        f"/api/v1/scans/{scan_job_id}/cancel",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert "cancelled" in response.json()["message"]


def test_cancel_running_scan(client: TestClient, admin_token, running_scan_id):
    response = client.delete(
        f"/api/v1/scans/{running_scan_id}/cancel",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200


def test_cancel_scan_not_found(client: TestClient, admin_token):
    response = client.delete(
        "/api/v1/scans/nonexistent-scan/cancel",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 404


def test_cancel_completed_scan_fails(client: TestClient, db_session, admin_user, admin_token, target_id):
    """Cancelling an already-completed scan should return 400."""
    from app.models.scan_job import ScanJob

    completed = ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="network",
        status="completed",
        started_by=admin_user.id,
        progress=100,
    )
    db_session.add(completed)
    db_session.commit()

    response = client.delete(
        f"/api/v1/scans/{completed.id}/cancel",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 400


# ── GET /api/v1/scans/{id}/progress (SSE) ────────────────────────────────────

def test_sse_endpoint_returns_event_stream_content_type(client: TestClient, admin_token, scan_job_id):
    """
    The progress endpoint must return text/event-stream content type.
    We verify headers only using a HEAD-like approach via the TestClient
    with a short-circuit mock on Redis.
    """
    # Patch redis at the module level used inside the SSE route
    mock_pubsub = MagicMock()
    mock_redis = MagicMock()

    # Make pubsub.listen() an async generator that immediately yields a done event
    async def _fake_listen():
        yield {"type": "message", "data": '{"progress": 100, "phase": "completed"}'}

    mock_pubsub.listen = _fake_listen
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.close = AsyncMock()
    mock_redis.pubsub.return_value = mock_pubsub
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        response = client.get(
            f"/api/v1/scans/{scan_job_id}/progress",
            headers=auth_headers(admin_token),
        )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")


def test_sse_endpoint_requires_auth(client: TestClient, scan_job_id):
    """Unauthenticated SSE requests should be rejected."""
    response = client.get(f"/api/v1/scans/{scan_job_id}/progress")
    assert response.status_code == 401


# ── GET /api/v1/scans/{id}/compare/{prev_id} ─────────────────────────────────

def test_compare_scans_same_target(client: TestClient, db_session, admin_user, admin_token, target_id):
    """Compare two scans on the same target."""
    from app.models.scan_job import ScanJob

    scan1 = ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="network",
        status="completed",
        started_by=admin_user.id,
        progress=100,
    )
    scan2 = ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="network",
        status="completed",
        started_by=admin_user.id,
        progress=100,
    )
    db_session.add(scan1)
    db_session.add(scan2)
    db_session.commit()

    response = client.get(
        f"/api/v1/scans/{scan1.id}/compare/{scan2.id}",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_job_id"] == scan1.id
    assert data["previous_scan_job_id"] == scan2.id
    assert "new_findings" in data
    assert "resolved_findings" in data
    assert "risk_delta" in data


def test_compare_scans_nonexistent(client: TestClient, admin_token, scan_job_id):
    """Comparing with a nonexistent scan returns 404."""
    response = client.get(
        f"/api/v1/scans/{scan_job_id}/compare/nonexistent-id",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 404
