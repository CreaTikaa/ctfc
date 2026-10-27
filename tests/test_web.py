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


def test_api_xor_with_options(client):
    import base64

    from ctfc.core.xor import xor_with_key

    data = xor_with_key(b"Hello there, the flag is CYBN{web_xor} have fun", b"k3y")
    payload = {
        "input": base64.b64encode(data).decode(),
        "format": "b64",
        "options": {"key": "text:k3y"},
    }
    answer = client.post("/api/xor", json=payload).get_json()
    assert "CYBN{web_xor}" in answer["candidates"][0]["data_text"]


def test_jobs_run_and_finish(client, fixture_bytes):
    import base64
    import time

    payload = {"data_b64": base64.b64encode(fixture_bytes("xor_repeating.bin")).decode()}
    job = client.post("/api/jobs/xor", json=payload).get_json()["job"]
    for _ in range(100):
        status = client.get(f"/api/jobs/{job}").get_json()
        if status["state"] != "running":
            break
        time.sleep(0.05)
    assert status["state"] == "done"
    assert "CYBN{fixture_xor_repeating}" in status["result"]["candidates"][0]["data_text"]


def test_job_cancel(client):
    from ctfc.core.budget import Budget
    from ctfc.web.jobs import JobManager

    manager = JobManager()

    def slow(budget: Budget) -> dict:
        while budget.spend():
            pass
        return {"stopped": budget.stopped_reason}

    job = manager.start("test", slow, Budget(max_attempts=10**12, max_seconds=30))
    manager.cancel(job.id)
    for _ in range(100):
        if job.state != "running":
            break
        import time

        time.sleep(0.02)
    assert job.state == "cancelled"
    assert job.result == {"stopped": "cancelled"}


def test_unknown_job_kind(client):
    response = client.post("/api/jobs/nope", json={"input": "x"})
    assert response.status_code == 400
