"""Tests for sessions (core/session.py), the write-up (core/report.py) and their CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ctfc.core import session as sessions
from ctfc.core.report import build_report, fence
from ctfc.core.session import Session, SessionError
from ctfc.core.types import Candidate

ROOT = Path(__file__).resolve().parent.parent


def candidate(score: float = 0.95, data: bytes = b"the flag is CYBN{session_test}") -> Candidate:
    return Candidate(
        label="base64 -> xor(key='k')",
        data=data,
        score=score,
        reasons=["decoded with 2 layer(s)", "matches flag pattern: CYBN{session_test}"],
        python='print("hello")\n',
        cyberchef="From_Base64('A-Za-z0-9+/=',true,false)",
    )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["../etc", "a/b", "", "x" * 65, "with space", ".hidden"])
def test_bad_names_are_refused(tmp_path, name):
    with pytest.raises(SessionError):
        Session.open(name, tmp_path)


def test_open_creates_the_folder_and_meta(tmp_path):
    session = Session.open("cave-expedition", tmp_path)
    assert (tmp_path / "cave-expedition" / "inputs").is_dir()
    assert session.meta().display_title() == "Cave Expedition"
    session.update_meta(title="Cave Expedition!", ctf="Cyber Apocalypse", flag=None)
    assert session.meta().title == "Cave Expedition!"
    assert session.meta().ctf == "Cyber Apocalypse"


def test_open_without_create(tmp_path):
    with pytest.raises(SessionError, match="no session"):
        Session.open("missing", tmp_path, create=False)


def test_steps_and_notes_in_order(tmp_path):
    session = Session.open("demo", tmp_path)
    session.add_note("first, the logs")
    session.add_step("auto", "ctfc auto x.bin", b"abc", "x.bin", [candidate()])
    entries = session.entries()
    assert [entry.kind for entry in entries] == ["note", "step"]
    step = entries[1]
    assert step.result["label"] == "base64 -> xor(key='k')"
    assert step.result["flags"] == ["CYBN{session_test}"]
    assert step.input["saved_as"].startswith("inputs/")
    assert (session.folder / step.input["saved_as"]).read_bytes() == b"abc"


def test_huge_inputs_are_referenced_not_copied(tmp_path, monkeypatch):
    monkeypatch.setattr(sessions, "INPUT_COPY_LIMIT", 10)
    session = Session.open("demo", tmp_path)
    entry = session.add_step("keys", "ctfc keys dump.raw", b"x" * 100, "dump.raw")
    assert "saved_as" not in entry.input
    assert entry.input["size"] == 100 and len(entry.input["sha256"]) == 64


def test_a_damaged_line_does_not_lose_the_rest(tmp_path):
    session = Session.open("demo", tmp_path)
    session.add_note("one")
    with session.steps_path.open("a") as handle:
        handle.write('{"kind": "step", "ti\n')  # a crash in the middle of a write
    session.add_note("two")
    assert [entry.text for entry in session.entries()] == ["one", "two"]


def test_current_session(tmp_path):
    assert sessions.current_session(tmp_path) is None
    sessions.use_session("demo", tmp_path)
    assert sessions.current_session(tmp_path) == "demo"
    sessions.use_session(None, tmp_path)
    assert sessions.current_session(tmp_path) is None


def test_flags_meta_first(tmp_path):
    session = Session.open("demo", tmp_path)
    session.add_step("auto", "ctfc auto x", b"x", "x", [candidate()])
    assert session.flags() == ["CYBN{session_test}"]
    session.update_meta(flag="CYBN{typed_by_hand}")
    assert session.flags()[0] == "CYBN{typed_by_hand}"


# ---------------------------------------------------------------------------
# The write-up
# ---------------------------------------------------------------------------


def demo_session(tmp_path) -> Session:
    session = Session.open("cave-expedition", tmp_path)
    session.update_meta(
        title="Cave Expedition",
        ctf="Cyber Apocalypse CTF 2025",
        category="Forensics",
        description="A map was encrypted.",
    )
    session.add_note("The only non-empty .evtx holds a script.")
    session.add_step(
        "detect", "ctfc detect map.pdf.secured", b"x", "m", summary=["base64 text (0.85)"]
    )
    session.add_step("auto", "ctfc auto nothing.bin", b"y", "n", [candidate(score=0.1)])
    session.add_step(
        "lens", "ctfc lens ransom.ps1 --against map.pdf.secured", b"z", "r", [candidate()]
    )
    return session


def test_report_layout_follows_the_write_ups(tmp_path):
    text = build_report(demo_session(tmp_path))
    assert text.startswith("# Cave Expedition\n\n### A map was encrypted.")
    assert "**CTF:** Cyber Apocalypse CTF 2025 · **Category:** Forensics" in text
    assert text.index("The only non-empty .evtx") < text.index("## Step 1: Recon")
    assert "## Step 2: Reading the script" in text  # the dead end is skipped
    assert "```bash\nctfc lens ransom.ps1 --against map.pdf.secured\n```" in text
    assert "To redo it by hand:" in text and '```python\nprint("hello")\n```' in text
    assert "Or in CyberChef:" in text
    assert "## Flag\n\n**Flag:** `CYBN{session_test}`" in text
    assert "GGs !" in text


def test_report_in_french(tmp_path):
    text = build_report(demo_session(tmp_path), lang="fr")
    assert "## Étape 1: Reco" in text
    assert "**Catégorie :** Forensics" in text
    assert "Pour le refaire à la main :" in text


def test_report_all_keeps_the_dead_ends(tmp_path):
    text = build_report(demo_session(tmp_path), include_all=True)
    assert "ctfc auto nothing.bin" in text
    assert "## Step 3: Reading the script" in text


def test_a_retry_appears_once(tmp_path):
    session = Session.open("demo", tmp_path)
    session.add_step("auto", "ctfc auto x", b"x", "x", [candidate(data=b"first try CYBN{a_1234}")])
    session.add_step("auto", "ctfc auto x", b"x", "x", [candidate(data=b"second try CYBN{b_1234}")])
    text = build_report(session)
    assert text.count("ctfc auto x") == 1
    assert "second try" in text


def test_fence_cannot_be_closed_by_the_output():
    text = "evil ``` output\n````"
    block = fence(text, "text")
    assert block.startswith("`````text\n") and block.endswith("\n`````")


def test_binary_output_is_not_dumped(tmp_path):
    session = Session.open("demo", tmp_path)
    session.add_step("lens", "ctfc lens x", b"x", "x", [candidate(data=bytes(range(256)) * 4)])
    text = build_report(session)
    assert "binary output, 1024 bytes" in text


# ---------------------------------------------------------------------------
# CLI, end to end (a private sessions folder through --config)
# ---------------------------------------------------------------------------


def run_ctfc(tmp_path, *args: str) -> subprocess.CompletedProcess:
    config = tmp_path / "config.toml"
    if not config.exists():
        config.write_text(f'sessions_dir = "{tmp_path / "sessions"}"\n')
    return subprocess.run(
        [sys.executable, "-m", "ctfc", *args, "--config", str(config)],
        cwd=ROOT,
        capture_output=True,
        timeout=120,
    )


def test_cli_session_then_report(tmp_path):
    done = run_ctfc(tmp_path, "session", "new", "layers", "--title", "Layers", "--category", "Misc")
    assert done.returncode == 0, done.stderr.decode()
    assert (
        run_ctfc(tmp_path, "session", "note", "a", "base64", "blob", "in", "a", "mail").returncode
        == 0
    )
    done = run_ctfc(tmp_path, "auto", "tests/fixtures/layers_b64_zlib_xor.txt")
    assert done.returncode == 0, done.stderr.decode()
    assert "recorded in session layers" in done.stderr.decode()
    out = tmp_path / "writeup.md"
    done = run_ctfc(tmp_path, "report", "--lang", "fr", "--out", str(out))
    assert done.returncode == 0, done.stderr.decode()
    text = out.read_text()
    assert text.startswith("# Layers")
    assert "a base64 blob in a mail" in text
    assert "ctfc auto tests/fixtures/layers_b64_zlib_xor.txt\n" in text  # no --config in it
    assert "CYBN{fixture_multi_layer}" in text


def test_cli_without_session_records_nothing(tmp_path):
    done = run_ctfc(tmp_path, "auto", "text:Q1lCTnt4eHh4fQ==")
    assert done.returncode == 0
    assert "recorded" not in done.stderr.decode()
    assert not (tmp_path / "sessions").exists()


def test_cli_session_option_and_list_json_free(tmp_path):
    done = run_ctfc(
        tmp_path, "detect", "tests/fixtures/xor_repeating.bin", "--session", "xor-chall", "--json"
    )
    assert done.returncode == 0, done.stderr.decode()
    json.loads(done.stdout)  # --json output stays pure JSON (the notice goes to stderr)
    listing = run_ctfc(tmp_path, "session", "list").stdout.decode()
    assert "xor-chall" in listing and "1 steps" in listing


def test_cli_bad_session_name(tmp_path):
    done = run_ctfc(tmp_path, "session", "new", "../../etc")
    assert done.returncode == 2
    assert "bad session name" in done.stderr.decode()
