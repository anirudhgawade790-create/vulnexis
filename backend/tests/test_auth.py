"""Tests for authentication endpoints."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers


def test_login_success(client: TestClient, admin_user):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testadmin", "password": "Admin@1234"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "testadmin"
    assert data["user"]["role"] == "admin"


def test_login_wrong_password(client: TestClient, admin_user):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testadmin", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_login_unknown_user(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nobody", "password": "irrelevant"},
    )
    assert response.status_code == 401


def test_me_authenticated(client: TestClient, admin_user, admin_token):
    response = client.get("/api/v1/auth/me", headers=auth_headers(admin_token))
    assert response.status_code == 200
    assert response.json()["username"] == "testadmin"


def test_me_unauthenticated(client: TestClient):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_me_invalid_token(client: TestClient):
    response = client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"}
    )
    assert response.status_code == 401


def test_role_enforcement_admin_only(client: TestClient, analyst_user, analyst_token):
    """Analyst should not be able to list all users (admin-only)."""
    response = client.get("/api/v1/users/", headers=auth_headers(analyst_token))
    assert response.status_code == 403


def test_logout(client: TestClient, admin_user, admin_token):
    response = client.post("/api/v1/auth/logout", headers=auth_headers(admin_token))
    assert response.status_code == 200
    assert "message" in response.json()


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
