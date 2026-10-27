"""Tests for the Flask app, using Flask's test client (no real server)."""

import pytest

from ctfc.config import Config
from ctfc.web.app import create_app


@pytest.fixture
def client():
    app = create_app(Config(max_upload_mb=1))
    app.testing = True
    return app.test_client()


def test_index_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"ctfc" in response.data


def test_health(client):
    assert client.get("/api/health").get_json()["ok"] is True


def test_path_traversal_is_refused(client):
    assert client.get("/../../etc/passwd").status_code == 404
    assert client.get("/%2e%2e/%2e%2e/etc/passwd").status_code == 404
