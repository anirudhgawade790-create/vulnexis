from fastapi.testclient import TestClient

from tests.conftest import auth_headers


def test_analyst_cannot_create_or_update_target(client: TestClient, analyst_token):
    headers = auth_headers(analyst_token)
    target_data = {
        "name": "Authorized scope",
        "scope_type": "ip",
        "scope_value": "192.0.2.10",
        "business_criticality": "medium",
        "is_active": True,
    }
    assert client.post("/api/v1/targets/", json=target_data, headers=headers).status_code == 403
    assert client.put("/api/v1/targets/target-id", json={"name": "Changed"}, headers=headers).status_code == 403


def test_viewer_cannot_access_admin_overview_or_audit(client: TestClient, viewer_token):
    headers = auth_headers(viewer_token)
    assert client.get("/api/v1/admin/overview", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/audit-logs", headers=headers).status_code == 403


def test_admin_can_access_admin_overview_and_audit(client: TestClient, admin_user, admin_token):
    headers = auth_headers(admin_token)
    overview = client.get("/api/v1/admin/overview", headers=headers)
    assert overview.status_code == 200
    assert overview.json()["total_users"] == 1
    assert client.get("/api/v1/admin/audit-logs", headers=headers).status_code == 200


def test_admin_cannot_demote_last_active_admin(client: TestClient, admin_user, admin_token):
    response = client.put(
        f"/api/v1/users/{admin_user.id}",
        json={"role": "viewer"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 400


def test_admin_cannot_disable_last_active_admin(client: TestClient, admin_user, admin_token):
    response = client.put(
        f"/api/v1/users/{admin_user.id}",
        json={"is_active": False},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 400

