"""Tests for asset endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.models.asset import Asset
from app.models.scan_job import ScanJob
from app.models.target import Target
from tests.conftest import auth_headers


@pytest.fixture
def sample_target(db_session, admin_user):
    target = Target(
        id="target-000000000000000000001",
        name="Test Target",
        scope_type="cidr",
        scope_value="192.168.1.0/24",
        created_by=admin_user.id,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


@pytest.fixture
def sample_scan(db_session, sample_target, admin_user):
    scan = ScanJob(
        id="scan-0000000000000000000001",
        target_id=sample_target.id,
        scan_type="network",
        status="completed",
        progress=100,
        started_by=admin_user.id,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


@pytest.fixture
def sample_asset(db_session, sample_scan, sample_target):
    asset = Asset(
        id="asset-000000000000000000001",
        scan_job_id=sample_scan.id,
        target_id=sample_target.id,
        ip_address="192.168.1.10",
        hostname="test-host.local",
        is_windows=True,
        asset_type="server",
        business_criticality="high",
        risk_score=7.5,
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)
    return asset


def test_list_assets(client: TestClient, sample_asset, admin_token):
    response = client.get("/api/v1/assets/", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_list_assets_filter_windows(client: TestClient, sample_asset, admin_token):
    response = client.get("/api/v1/assets/?is_windows=true", headers=auth_headers(admin_token))
    assert response.status_code == 200
    for asset in response.json():
        assert asset["is_windows"] is True


def test_get_asset(client: TestClient, sample_asset, admin_token):
    response = client.get(f"/api/v1/assets/{sample_asset.id}", headers=auth_headers(admin_token))
    assert response.status_code == 200
    assert response.json()["ip_address"] == "192.168.1.10"


def test_get_asset_not_found(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/assets/nonexistent-id", headers=auth_headers(admin_token))
    assert response.status_code == 404


def test_update_asset_criticality(client: TestClient, sample_asset, admin_token):
    response = client.patch(
        f"/api/v1/assets/{sample_asset.id}",
        json={"business_criticality": "critical"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["business_criticality"] == "critical"


def test_get_asset_findings(client: TestClient, sample_asset, admin_token):
    response = client.get(
        f"/api/v1/assets/{sample_asset.id}/findings",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_asset_history(client: TestClient, sample_asset, admin_token):
    response = client.get(
        f"/api/v1/assets/{sample_asset.id}/history",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_assets_require_auth(client: TestClient):
    response = client.get("/api/v1/assets/")
    assert response.status_code == 401
