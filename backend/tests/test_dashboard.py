"""Tests for dashboard endpoints."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers


def test_dashboard_summary(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/dashboard/summary", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert "total_assets" in data
    assert "total_vulnerabilities" in data
    assert "overall_posture_score" in data
    assert "findings_by_severity" in data


def test_dashboard_trends(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/dashboard/trends", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert "period_days" in data
    assert "data_points" in data


def test_dashboard_insights(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/dashboard/insights", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    for item in data:
        assert "id" in item
        assert "title" in item
        assert "severity" in item


def test_dashboard_top_risks(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/dashboard/top-risks", headers=auth_headers(admin_token))
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_dashboard_exposure_map(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/dashboard/exposure-map", headers=auth_headers(admin_token))
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "total_exposed_ports" in data
    assert "generated_at" in data


def test_dashboard_requires_auth(client: TestClient):
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 401
