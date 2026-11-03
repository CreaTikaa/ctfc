"""Tests for the Files, CRC32 and Classical tabs of the web UI.

The terminal has a command per file format; the browser gets **one** tab, because
the page starts from "something was dropped in the box" rather than from knowing
what it is. `ctfc/web/formats.py` is what makes that one tab enough: it sniffs
the reader, runs it, and returns every report in the same display shape.

So these tests check two different things. That each reader is reachable and
answers with its own content - and that the *shape* holds, because one JSON
contract is the whole reason a reader added later needs no JavaScript.
"""

from __future__ import annotations

import base64
import time
import zlib

import pytest

from ctfc.config import Config
from ctfc.web import formats
from ctfc.web.app import create_app


@pytest.fixture
def client():
    app = create_app(Config(max_upload_mb=8))
    app.testing = True
    return app.test_client()


def send(client, data: bytes, reader: str = "") -> dict:
    payload = {
        "input": "b64:" + base64.b64encode(data).decode(),
        "format": "auto",
        "options": {"reader": reader},
    }
    return client.post("/api/file", json=payload).get_json()


# ---------------------------------------------------------------------------
# Every reader is reachable from the browser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "reader"),
    [
        ("archive_lzma.7z", "archive"),
        ("archive_docker_image.tar", "archive"),
        ("archive_mszip.cab", "archive"),
        ("archive_rar5_stored.rar", "archive"),
        ("audit_zipcrypto.zip", "zip"),
        ("audit_macro.doc", "office"),
        ("audit_macro.docm", "office"),
        ("compound_message.msg", "msg"),
        ("compound_installer.msi", "msi"),
        ("audit_malicious.pdf", "pdf"),
        ("audit_lsb.png", "stego"),
        ("audit_security.evtx", "evtx"),
        ("audit_notes.sqlite", "sqlite"),
        ("capture.pcap", "pcap"),
        ("winartifact_dropper.lnk", "winartifact"),
        ("winartifact_powershell.pf", "winartifact"),
        ("executable_dropper.elf", "exe"),
        ("executable_secret.jar", "exe"),
        ("executable_app.dex", "exe"),
    ],
)
def test_every_reader_is_reachable_and_sniffed_correctly(client, fixture_bytes, fixture, reader):
    answer = send(client, fixture_bytes(fixture))
    assert answer.get("reader") == reader, answer
    assert answer["sniffed"] is True
    assert answer["sections"], f"{fixture} produced no section"


def test_the_shape_is_the_same_for_every_reader(client, fixture_bytes):
    """One JSON contract: that is why one renderer covers every format."""
    for fixture in ("archive_lzma.7z", "compound_message.msg", "winartifact_dropper.lnk"):
        answer = send(client, fixture_bytes(fixture))
        assert set(answer) >= {
            "reader",
            "label",
            "command",
            "sniffed",
            "sections",
            "flags",
            "notes",
            "commands",
            "input",
        }
        for section in answer["sections"]:
            assert section["kind"] in ("facts", "table", "text")
            if section["kind"] == "facts":
                assert all(len(row) == 2 for row in section["rows"])
            elif section["kind"] == "table":
                assert all(len(row) == len(section["columns"]) for row in section["rows"])
            else:
                assert isinstance(section["text"], str)


# ---------------------------------------------------------------------------
# The answers themselves
# ---------------------------------------------------------------------------


def test_a_docker_image_shows_its_layers_and_the_deleted_file(client, fixture_bytes):
    answer = send(client, fixture_bytes("archive_docker_image.tar"))
    titles = [section["title"] for section in answer["sections"]]
    assert "Docker image" in titles
    assert any("layer" in title for title in titles)
    assert "CYBN{docker_whiteout}" in answer["flags"]
    hidden = next(s for s in answer["sections"] if "hides" in s["title"])
    assert hidden["rows"][0][0] == "app/secret.txt"


def test_a_shortcut_shows_its_decoded_command(client, fixture_bytes):
    answer = send(client, fixture_bytes("winartifact_dropper.lnk"))
    assert "CYBN{lnk_encoded_command}" in answer["flags"]
    assert any("decoded PowerShell" in section["title"] for section in answer["sections"])


def test_a_jar_is_read_as_java_not_as_a_zip(client, fixture_bytes):
    """A .jar *is* a ZIP; the useful reader is the one that reads its constant pool."""
    answer = send(client, fixture_bytes("executable_secret.jar"))
    assert answer["reader"] == "exe"
    assert "CYBN{java_literal}" in answer["flags"]


def test_a_docm_goes_to_office_and_a_plain_zip_to_zip(client, fixture_bytes):
    assert send(client, fixture_bytes("audit_macro.docm"))["reader"] == "office"
    assert send(client, fixture_bytes("audit_zipcrypto.zip"))["reader"] == "zip"


def test_the_compound_formats_do_not_claim_each_other(client, fixture_bytes):
    """A .doc, a .msg, an .msi and a jump list are one container, four readers."""
    assert send(client, fixture_bytes("compound_message.msg"))["reader"] == "msg"
    assert send(client, fixture_bytes("compound_installer.msi"))["reader"] == "msi"
    assert send(client, fixture_bytes("compound_embedded.doc"))["reader"] == "office"
    jump = send(client, fixture_bytes("winartifact_jumplist.automaticDestinations-ms"))
    assert jump["reader"] == "winartifact"


def test_a_reader_can_be_forced(client, fixture_bytes):
    """`repair` and `time` are only reachable this way: they sniff nothing."""
    answer = send(client, fixture_bytes("audit_pixel_rehab.fun"), reader="repair")
    assert answer["reader"] == "repair"
    assert answer["sniffed"] is False
    timed = send(client, bytes.fromhex("0080fc5ec4d1d901"), reader="time")
    assert timed["reader"] == "time"
    assert timed["sections"]


def test_something_unknown_is_a_400_that_says_what_to_do(client):
    answer = client.post("/api/file", json={"input": "text:just a sentence, nothing more"})
    assert answer.status_code == 400
    assert "Detect tab" in answer.get_json()["error"]


def test_a_reader_refusing_the_file_is_a_400_with_its_own_reason(client, fixture_bytes):
    answer = client.post(
        "/api/file",
        json={
            "input": "b64:" + base64.b64encode(fixture_bytes("audit_lsb.png")).decode(),
            "options": {"reader": "msg"},
        },
    )
    assert answer.status_code == 400
    assert "Outlook" in answer.get_json()["error"]


def test_an_unknown_reader_name_lists_the_real_ones(client):
    answer = client.post("/api/file", json={"input": "text:x", "options": {"reader": "nonsense"}})
    assert answer.status_code == 400
    assert "archive" in answer.get_json()["error"]


# ---------------------------------------------------------------------------
# The catalogue the dropdown is built from
# ---------------------------------------------------------------------------


def test_the_reader_catalogue(client):
    readers = client.get("/api/file/readers").get_json()["readers"]
    names = [reader["name"] for reader in readers]
    assert "archive" in names and "winartifact" in names and "exe" in names
    for reader in readers:
        assert reader["command"].startswith("ctfc ")
        assert reader["label"]


def test_every_cli_format_command_has_a_reader():
    """The promise of the tab: what the terminal reads, the browser reads too."""
    commands = {reader.command for reader in formats.READERS}
    for command in (
        "ctfc archive",
        "ctfc zip",
        "ctfc office",
        "ctfc msg",
        "ctfc msi",
        "ctfc pdf",
        "ctfc stego",
        "ctfc pe",
        "ctfc exe",
        "ctfc winartifact",
        "ctfc evtx",
        "ctfc hive",
        "ctfc sqlite",
        "ctfc pcap",
        "ctfc repair",
        "ctfc time",
    ):
        assert command in commands


# ---------------------------------------------------------------------------
# CRC32
# ---------------------------------------------------------------------------


def test_api_crc_finds_the_word(client):
    answer = client.post("/api/crc", json={"input": f"{zlib.crc32(b'dragon'):08x}"}).get_json()
    assert answer["results"][0]["text"] == "dragon"
    assert answer["results"][0]["exact"] is True


def test_api_crc_accepts_a_pattern(client):
    answer = client.post(
        "/api/crc",
        json={
            "input": f"0x{zlib.crc32(b'CYBN{ab}'):08x}",
            "options": {"pattern": "CYBN{??}"},
        },
    ).get_json()
    assert answer["results"][0]["text"] == "CYBN{ab}"


def test_api_crc_solve_is_opt_in(client):
    quiet = client.post(
        "/api/crc", json={"input": "deadbeef", "options": {"length": "12"}}
    ).get_json()
    assert quiet["results"] == []
    solved = client.post(
        "/api/crc", json={"input": "deadbeef", "options": {"length": "12", "solve": True}}
    ).get_json()
    assert solved["results"][0]["method"] == "solved"
    assert solved["results"][0]["exact"] is False


def test_api_crc_refuses_rubbish(client):
    answer = client.post("/api/crc", json={"input": "not-a-number"})
    assert answer.status_code == 400
    assert "not a CRC32" in answer.get_json()["error"]


# ---------------------------------------------------------------------------
# Classical
# ---------------------------------------------------------------------------


def test_api_classical_solves_beaufort_blind(client, fixture_bytes):
    text = fixture_bytes("classical_beaufort.txt").decode()
    answer = client.post("/api/classical", json={"input": "text:" + text}).get_json()
    assert answer["candidates"][0]["label"] == "beaufort(key='lemon')"
    assert "CYBN{beaufort_subtracts}" in answer["candidates"][0]["data_text"]
    assert answer["notes"]


def test_api_classical_with_the_key_given(client, fixture_bytes):
    text = fixture_bytes("classical_beaufort.txt").decode()
    answer = client.post(
        "/api/classical",
        json={"input": "text:" + text, "options": {"cipher": "beaufort", "key": "lemon"}},
    ).get_json()
    assert "universally acknowledged" in answer["candidates"][0]["data_text"]


def test_api_classical_rejects_a_key_it_cannot_read(client):
    answer = client.post(
        "/api/classical",
        json={"input": "text:abcdefghij", "options": {"cipher": "caesar", "key": "lemon"}},
    )
    assert answer.status_code == 400


def test_classical_runs_as_a_job_too(client, fixture_bytes):
    """The Classical tab is a job tab: it must start and finish through /api/jobs."""
    text = fixture_bytes("classical_beaufort.txt").decode()
    started = client.post("/api/jobs/classical", json={"input": "text:" + text}).get_json()
    assert started["job"]
    for _ in range(400):
        status = client.get(f"/api/jobs/{started['job']}").get_json()
        if status["state"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert status["state"] == "done", status
    assert status["result"]["candidates"][0]["label"] == "beaufort(key='lemon')"
