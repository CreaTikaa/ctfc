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


def test_api_sym_with_blob(client, fixture_bytes):
    """The Symmetric tab: ciphertext as the input, blob as an option."""
    import base64

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("aes_cbc_keyiv_blob.bin")).decode(),
        "name": "ct.bin",
        "options": {"blob": fixture_bytes("key_iv_blob.b64").decode().strip()},
    }
    answer = client.post("/api/sym", json=payload).get_json()
    assert "CYBN{fixture_key_iv_blob}" in answer["candidates"][0]["data_text"]
    assert answer["candidates"][0]["params"]["mode"] == "cbc"


def test_api_sym_openssl_file_notes_the_header(client, fixture_bytes):
    """Without a password we must still explain what the file is."""
    import base64

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("openssl_salted_md5.bin")).decode(),
        "options": {},
    }
    answer = client.post("/api/sym", json=payload).get_json()
    assert any("Salted__" in note for note in answer["notes"])
    assert any("--pass" in note for note in answer["notes"])


def test_api_sym_passphrase(client, fixture_bytes):
    import base64

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("openssl_salted_md5.bin")).decode(),
        "options": {"passphrase": "password123", "seconds": 20},
    }
    answer = client.post("/api/sym", json=payload).get_json()
    assert "CYBN{fixture_openssl_md5}" in answer["candidates"][0]["data_text"]


def test_api_sym_job(client, fixture_bytes):
    """The browser runs Symmetric as a background job (progress + cancel)."""
    import base64
    import time

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("aes_gcm_nonce_ct_tag.bin")).decode(),
        "options": {"key": fixture_bytes("aes_cbc_iv_prefix.key").decode().strip()},
    }
    job = client.post("/api/jobs/sym", json=payload).get_json()["job"]
    for _ in range(200):
        status = client.get(f"/api/jobs/{job}").get_json()
        if status["state"] != "running":
            break
        time.sleep(0.05)
    assert status["state"] == "done", status
    assert "CYBN{fixture_gcm_nonce_ct_tag}" in status["result"]["candidates"][0]["data_text"]


def test_api_blob_needs_a_ciphertext(client):
    response = client.post("/api/jobs/blob", json={"input": "00" * 48, "options": {}})
    assert response.status_code == 400
    assert "ciphertext" in response.get_json()["error"]


def test_api_lens_python(client, fixture_bytes):
    """The Code Lens tab: a pasted script, analysed statically."""
    payload = {"input": fixture_bytes("lens_layers.py").decode(), "format": "text", "name": "x.py"}
    answer = client.post("/api/lens", json=payload).get_json()
    assert answer["language"] == "python"
    assert [operation["kind"] for operation in answer["operations"]] == ["base64", "zlib", "xor"]
    assert answer["recovery"]["complete"] is True
    assert "zlib.decompress" in answer["recovery"]["python"]


def test_api_lens_uploaded_powershell(client, fixture_bytes):
    import base64

    payload = {
        "data_b64": base64.b64encode(fixture_bytes("lens_dropper.ps1")).decode(),
        "name": "dropper.ps1",
    }
    answer = client.post("/api/lens", json=payload).get_json()
    assert answer["language"] == "powershell"
    assert any(behaviour["kind"] == "network" for behaviour in answer["behaviours"])
    assert any(artifact["kind"] == "url" for artifact in answer["artifacts"])


def test_api_lens_keeps_a_script_as_text(client):
    """A script that happens to look like base64 must not be decoded first."""
    answer = client.post("/api/lens", json={"input": "YWJjZGVmZ2g=", "format": "auto"}).get_json()
    assert answer["input"]["length"] == len("YWJjZGVmZ2g=")


def test_api_rsa_job_with_attack(client, fixture_bytes):
    """The RSA tab runs as a job, because an attack can take seconds."""
    import time

    payload = {
        "input": fixture_bytes("rsa_fermat.bin").hex(),
        "format": "hex",
        "options": {
            "key": fixture_bytes("rsa_fermat.pub.pem").decode(),
            "attack": True,
            "seconds": 20,
        },
    }
    job = client.post("/api/jobs/rsa", json=payload).get_json()["job"]
    for _ in range(400):
        status = client.get(f"/api/jobs/{job}").get_json()
        if status["state"] != "running":
            break
        time.sleep(0.05)
    assert status["state"] == "done", status
    answer = status["result"]
    assert "CYBN{fixture_rsa_fermat}" in answer["candidates"][0]["data_text"]
    assert answer["attacks"]["factorisation"]["method"].startswith("Fermat")


def test_api_rsa_sync_with_numbers(client, fixture_bytes):
    from Crypto.PublicKey import RSA

    key = RSA.import_key(fixture_bytes("rsa_small_e.pub.pem"))
    payload = {
        "input": fixture_bytes("rsa_small_e.bin").hex(),
        "format": "hex",
        "options": {"n": str(key.n), "e": "3"},
    }
    answer = client.post("/api/rsa", json=payload).get_json()
    assert "CYBN{fixture_rsa_small_e}" in answer["candidates"][0]["data_text"]


def test_api_rsa_bad_key_is_json_400(client):
    response = client.post("/api/rsa", json={"input": "00", "options": {"key": "not a key"}})
    assert response.status_code == 400
    assert "RSA key" in response.get_json()["error"]


def test_api_hash(client):
    import hashlib

    digest = hashlib.sha1(b"letmein").hexdigest()
    answer = client.post("/api/hash", json={"input": digest}).get_json()
    assert answer["matches"][0]["id"] == "sha1"
    assert answer["matches"][0]["cracked"] == "letmein"
    assert "hashcat -m 100" in answer["matches"][0]["hashcat"]


def test_api_hash_without_the_password_list(client):
    import hashlib

    digest = hashlib.sha1(b"letmein").hexdigest()
    answer = client.post(
        "/api/hash", json={"input": digest, "options": {"no_passwords": True}}
    ).get_json()
    assert answer["matches"][0]["cracked"] is None


# --- M6: recipes, CyberChef links, suggested tools -------------------------


def b64_payload(fixture_bytes, name: str) -> dict:
    import base64

    return {"data_b64": base64.b64encode(fixture_bytes(name)).decode(), "name": name}


def test_pipeline_tab_is_enabled(client):
    page = client.get("/").data.decode()
    assert 'data-tab="pipeline" data-milestone' not in page
    assert 'id="options-pipeline"' in page
    assert 'id="suggested"' in page


def test_api_recipe_runs_step_by_step(client, fixture_bytes):
    payload = b64_payload(fixture_bytes, "layers_b64_zlib_xor.txt")
    payload["options"] = {
        "recipe": '{"name": "t", "steps": ["base64", "zlib", '
        '{"op": "xor", "args": {"key": "4b337921"}}]}'
    }
    answer = client.post("/api/recipe", json=payload).get_json()
    assert answer["ok"] is True
    assert len(answer["steps"]) == 3
    assert "CYBN{" in answer["output_text"]
    assert answer["cyberchef"].startswith("From_Base64(")
    assert '"op": "xor"' in answer["recipe_json"]


def test_api_recipe_does_not_decode_the_input_first(client):
    """The recipe says "base64": the pasted base64 must reach that step untouched."""
    payload = {"input": "Q1lCTnt3ZWJ9", "format": "auto", "options": {"recipe": '["base64"]'}}
    answer = client.post("/api/recipe", json=payload).get_json()
    assert answer["output_text"] == "CYBN{web}"


def test_api_recipe_failing_step(client):
    payload = {
        "input": "Q1lCTnt3ZWJ9",
        "format": "text",
        "options": {"recipe": '["base64", "zlib"]'},
    }
    answer = client.post("/api/recipe", json=payload).get_json()
    assert answer["ok"] is False
    assert answer["steps"][1]["error"]
    assert answer["output_text"] == "CYBN{web}"


@pytest.mark.parametrize("recipe", ["{nope", "", '{"steps": "x"}', '["rot1000"]'])
def test_api_recipe_bad_recipe_is_json_400(client, recipe):
    payload = {"input": "abc", "format": "text", "options": {"recipe": recipe}}
    response = client.post("/api/recipe", json=payload)
    assert response.status_code == 400
    assert response.get_json()["error"]


def test_cyberchef_link_prefers_the_embedded_copy(client, monkeypatch):
    from ctfc.core import tools

    monkeypatch.setattr(tools, "embedded_cyberchef_installed", lambda: True)
    payload = {"input": "A", "format": "text", "options": {"recipe": "From_Hex('Auto')"}}
    link = client.post("/api/cyberchef", json=payload).get_json()
    assert link["url"] == "/vendor/cyberchef/index.html#recipe=From_Hex('Auto')&input=QQ%3D%3D"
    assert link["public"] is False


def test_cyberchef_link_falls_back_to_public_with_a_warning(client, monkeypatch):
    from ctfc.core import tools

    monkeypatch.setattr(tools, "embedded_cyberchef_installed", lambda: False)
    payload = {"input": "A", "format": "text", "options": {"recipe": "From_Hex('Auto')"}}
    link = client.post("/api/cyberchef", json=payload).get_json()
    assert link["url"].startswith("https://gchq.github.io/CyberChef/#recipe=")
    assert link["public"] is True
    assert "third party" in link["note"]


def test_cyberchef_link_offline_without_embedded_copy_is_refused(monkeypatch):
    from ctfc.core import tools

    monkeypatch.setattr(tools, "embedded_cyberchef_installed", lambda: False)
    app = create_app(Config(offline=True))
    payload = {"input": "A", "format": "text", "options": {"recipe": "From_Hex('Auto')"}}
    link = app.test_client().post("/api/cyberchef", json=payload).get_json()
    assert link["url"] == ""
    assert "offline" in link["note"]


def test_api_tools_suggests_hashcat_for_md5(client):
    payload = {"input": "482c811da5d5b4bc6d497ffa98491e38", "format": "text"}
    answer = client.post("/api/tools", json=payload).get_json()
    assert answer["suggestions"][0]["id"] == "hashcat"
    assert answer["suggestions"][0]["command"][:3] == ["hashcat", "-m", "0"]


def test_api_tools_is_empty_when_nothing_fires(client):
    answer = client.post("/api/tools", json={"input": "hello there", "format": "text"}).get_json()
    assert answer["suggestions"] == []


@pytest.mark.skipif(__import__("shutil").which("openssl") is None, reason="no openssl")
def test_api_tools_run_openssl(client, fixture_bytes):
    payload = b64_payload(fixture_bytes, "openssl_salted_md5.bin")
    payload["options"] = {"tool": "openssl", "password": "password123"}
    result = client.post("/api/tools/run", json=payload).get_json()
    assert result["returncode"] == 0, result
    assert "CYBN{fixture_openssl_md5}" in result["stdout"]


def test_api_tools_run_refuses_online_and_unknown_tools(client):
    for tool in ("factordb", "cyberchef_public", "nc"):
        payload = {"input": "abc", "format": "text", "options": {"tool": tool}}
        assert client.post("/api/tools/run", json=payload).status_code == 400


def test_api_tools_run_checks_the_wordlist(client):
    payload = {
        "input": "482c811da5d5b4bc6d497ffa98491e38",
        "format": "text",
        "options": {"tool": "hashcat", "wordlist": "/nonexistent/rockyou.txt"},
    }
    response = client.post("/api/tools/run", json=payload)
    assert response.status_code == 400
    assert "wordlist not found" in response.get_json()["error"]
