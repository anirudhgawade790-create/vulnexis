"""Tests for findings endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.target import Target
from tests.conftest import auth_headers


@pytest.fixture
def setup_finding(db_session, admin_user):
    target = Target(
        id="target-find-00000000000000001",
        name="Finding Target",
        scope_type="ip",
        scope_value="10.0.0.1",
        created_by=admin_user.id,
    )
    db_session.add(target)

    scan = ScanJob(
        id="scan-find-000000000000000001",
        target_id=target.id,
        scan_type="network",
        status="completed",
        progress=100,
        started_by=admin_user.id,
    )
    db_session.add(scan)

    asset = Asset(
        id="asset-find-0000000000000001",
        scan_job_id=scan.id,
        target_id=target.id,
        ip_address="10.0.0.1",
        is_windows=True,
        asset_type="server",
        business_criticality="high",
        risk_score=9.0,
    )
    db_session.add(asset)

    finding = Finding(
        id="find-00000000000000000001",
        scan_job_id=scan.id,
        asset_id=asset.id,
        title="SMBv1 Enabled",
        finding_type="confirmed_vulnerability",
        severity="critical",
        status="open",
        check_name="smb_version_check",
        evidence="SMBv1 detected on port 445.",
        detection_method="network_scan",
        confidence="confirmed",
        risk_score=9.5,
        remediation_steps=[
            {
                "step": "Disable SMBv1",
                "command": "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                "requires_admin": True,
            }
        ],
    )
    db_session.add(finding)
    db_session.commit()
    return finding


def test_list_findings(client: TestClient, setup_finding, admin_token):
    response = client.get("/api/v1/findings/", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_list_findings_filter_severity(client: TestClient, setup_finding, admin_token):
    response = client.get("/api/v1/findings/?severity=critical", headers=auth_headers(admin_token))
    assert response.status_code == 200
    for f in response.json():
        assert f["severity"] == "critical"


def test_get_finding(client: TestClient, setup_finding, admin_token):
    response = client.get(
        f"/api/v1/findings/{setup_finding.id}",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["title"] == "SMBv1 Enabled"


def test_get_finding_not_found(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/findings/nonexistent", headers=auth_headers(admin_token))
    assert response.status_code == 404


def test_update_finding_status(client: TestClient, setup_finding, admin_token):
    response = client.patch(
        f"/api/v1/findings/{setup_finding.id}/status",
        json={"status": "acknowledged", "resolution_notes": "Being reviewed"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_get_finding_remediation(client: TestClient, setup_finding, admin_token):
    response = client.get(
        f"/api/v1/findings/{setup_finding.id}/remediation",
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    data = response.json()
    assert "finding_id" in data
    assert "recommended_fix" in data
    assert "estimated_effort" in data


def test_assign_finding(client: TestClient, setup_finding, admin_user, admin_token):
    response = client.post(
        f"/api/v1/findings/{setup_finding.id}/assign",
        json={"user_id": admin_user.id},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["assigned_to"] == admin_user.id


def test_findings_require_auth(client: TestClient):
    response = client.get("/api/v1/findings/")
    assert response.status_code == 401
