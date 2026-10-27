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


def test_api_auto(client):
    answer = client.post("/api/auto", json={"input": "Q1lCTnt3ZWJ9", "format": "auto"}).get_json()
    assert answer["candidates"][0]["data_text"] == "CYBN{web}"
    assert answer["candidates"][0]["label"] == "base64"


def test_api_detect_upload(client, fixture_bytes):
    import base64

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("png_with_zip.png")).decode(),
        "name": "x",
    }
    report = client.post("/api/detect", json=payload).get_json()["report"]
    assert report["guesses"][0]["rule"] == "magic.png"


def test_api_never_reads_server_files(client):
    for path in ("/etc/passwd", "/etc/hostname", "pyproject.toml"):
        answer = client.post("/api/parse", json={"input": path}).get_json()
        assert not answer["input"]["source"].startswith("file"), path
        assert answer["input"]["length"] == len(path)


def test_api_errors_are_json(client):
    response = client.post("/api/detect", json={"input": "zz", "format": "hex"})
    assert response.status_code == 400
    assert "hex" in response.get_json()["error"]


def test_upload_cap(client):
    response = client.post("/api/detect", json={"data_b64": "A" * (2 * 1024 * 1024)})
    assert response.status_code == 413


def test_strings_endpoint(client):
    strings = client.get("/api/strings").get_json()
    assert strings["web_run"] == "Run"
