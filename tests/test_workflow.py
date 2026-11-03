"""Tests for the workflow polish (ideas.md 3.4): `ctfc watch` and `ctfc replay`.

The real test of a replay script is not what it looks like: it is that **it
runs**. `test_the_generated_script_actually_runs` executes the generated file
in a subprocess and checks the flag comes out of it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctfc.core import session as sessions
from ctfc.core.replay import build_script
from ctfc.core.watch import MAX_SIZE, Watcher, triage

FIXTURES = Path(__file__).parent / "fixtures"
LAYERED = FIXTURES / "layers_b64_zlib_hex.txt"

# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------


def test_triage_finds_the_flag_through_a_decoding_chain():
    finding = triage(LAYERED)
    assert finding.kind == "base64 text"
    assert finding.chain == "base64 -> zlib -> hex"
    assert finding.flags == ["CYBN{fixture_layers_b64_zlib_hex}"]


def test_triage_names_the_file_type_and_the_next_command(tmp_path):
    target = tmp_path / "x.7z"
    target.write_bytes((FIXTURES / "archive_lzma.7z").read_bytes())
    finding = triage(target)
    assert "7-Zip" in finding.kind
    assert "ctfc archive" in finding.next_command


def test_triage_skips_an_empty_file(tmp_path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    finding = triage(target)
    assert finding.skipped == "empty"
    assert finding.flags == []


def test_triage_refuses_to_read_something_huge(tmp_path, monkeypatch):
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 2048)
    monkeypatch.setattr("ctfc.core.watch.MAX_SIZE", 1024)
    finding = triage(target)
    assert finding.skipped
    assert "ctfc detect" in finding.next_command
    assert MAX_SIZE > 1024  # the real limit is not what the test moved it to


def test_catch_up_triages_what_is_already_there(tmp_path):
    (tmp_path / "a.txt").write_bytes(LAYERED.read_bytes())
    (tmp_path / "b.bin").write_bytes(bytes(range(256)))
    findings = Watcher(tmp_path).catch_up()
    assert sorted(str(finding.path) for finding in findings) == ["a.txt", "b.bin"]


def test_a_file_is_only_read_once_it_has_stopped_growing(tmp_path):
    """Triaging half a downloaded file is worse than not triaging it."""
    watcher = Watcher(tmp_path)
    assert watcher.pass_once() == []
    target = tmp_path / "growing.txt"
    target.write_bytes(b"CYBN")
    # First sight: recorded, not read - it may still be being written.
    assert watcher.pass_once() == []
    # It grew, so still not read.
    target.write_bytes(LAYERED.read_bytes())
    assert watcher.pass_once() == []
    # Now it has settled.
    findings = watcher.pass_once()
    assert [str(finding.path) for finding in findings] == ["growing.txt"]
    assert findings[0].flags == ["CYBN{fixture_layers_b64_zlib_hex}"]


def test_a_file_is_reported_once_and_not_again(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hello world, this is a sentence\n")
    watcher = Watcher(tmp_path)
    assert len(watcher.catch_up()) == 1
    assert watcher.pass_once() == []
    assert watcher.pass_once() == []


def test_sub_folders_are_watched_unless_told_otherwise(tmp_path):
    (tmp_path / "deep").mkdir()
    (tmp_path / "deep" / "a.txt").write_bytes(b"a sentence in a sub-folder\n")
    assert len(Watcher(tmp_path).catch_up()) == 1
    assert Watcher(tmp_path, recursive=False).catch_up() == []


def test_run_stops_after_the_passes_it_was_given(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"a sentence to triage\n")
    watcher = Watcher(tmp_path)
    started = time.monotonic()
    findings = list(watcher.run(seconds=0.01, passes=3))
    assert [str(finding.path) for finding in findings] == ["a.txt"]
    assert time.monotonic() - started < 5


def test_watching_something_that_is_not_a_folder(tmp_path):
    target = tmp_path / "a.txt"
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="is not a folder"):
        Watcher(target)


def test_finding_to_dict(tmp_path):
    (tmp_path / "a.txt").write_bytes(LAYERED.read_bytes())
    payload = json.loads(json.dumps([f.to_dict() for f in Watcher(tmp_path).catch_up()]))
    assert payload[0]["flags"] == ["CYBN{fixture_layers_b64_zlib_hex}"]


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def make_session(tmp_path, *commands: list[str]) -> Path:
    """Run some ctfc commands with a session active, and return the session base."""
    base = tmp_path / "sessions"
    environment = {"CTFC_SESSIONS_DIR": str(base)}
    root = Path(__file__).resolve().parent.parent
    import os

    env = {**os.environ, **environment}
    subprocess.run(
        [sys.executable, "-m", "ctfc", "session", "new", "demo", "--title", "Demo"],
        cwd=root,
        env=env,
        capture_output=True,
        timeout=120,
        check=True,
    )
    for command in commands:
        subprocess.run(
            [sys.executable, "-m", "ctfc", *command],
            cwd=root,
            env=env,
            capture_output=True,
            timeout=300,
            check=True,
        )
    return base


def test_an_empty_session_says_so(tmp_path):
    base = tmp_path / "sessions"
    session = sessions.Session.open("empty", base, create=True)
    script = build_script(session)
    assert "no step with a reproduce snippet" in script


def test_the_script_has_one_block_per_step(tmp_path):
    base = make_session(
        tmp_path,
        ["auto", "tests/fixtures/layers_b64_zlib_hex.txt"],
        ["xor", "tests/fixtures/xor_two_layers.bin"],
    )
    session = sessions.Session.open("demo", base, create=False)
    script = build_script(session)
    assert script.count("# --- step ") == 2
    assert "# $ ctfc auto tests/fixtures/layers_b64_zlib_hex.txt" in script
    assert "# result: base64 -> zlib -> hex" in script
    assert "CYBN{fixture_layers_b64_zlib_hex}" in script


def test_the_generated_script_actually_runs(tmp_path):
    """The point of the whole feature: the file runs with no editing."""
    base = make_session(
        tmp_path,
        ["auto", "tests/fixtures/layers_b64_zlib_hex.txt"],
        ["xor", "tests/fixtures/xor_two_layers.bin"],
    )
    session = sessions.Session.open("demo", base, create=False)
    script = tmp_path / "solve.py"
    script.write_text(build_script(session), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", str(script)], capture_output=True, timeout=300, cwd=tmp_path
    )
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "CYBN{fixture_layers_b64_zlib_hex}" in out
    assert "CYBN{fixture_xor_repeating}" in out


def test_the_same_snippet_is_not_replayed_twice(tmp_path):
    base = make_session(
        tmp_path,
        ["auto", "tests/fixtures/layers_b64_zlib_hex.txt"],
        ["auto", "tests/fixtures/layers_b64_zlib_hex.txt"],
    )
    session = sessions.Session.open("demo", base, create=False)
    assert build_script(session).count("# --- step ") == 1


def test_cli_replay_writes_a_file(tmp_path):
    base = make_session(tmp_path, ["auto", "tests/fixtures/layers_b64_zlib_hex.txt"])
    out = tmp_path / "solve.py"
    import os

    result = subprocess.run(
        [sys.executable, "-m", "ctfc", "replay", "demo", "--out", str(out)],
        cwd=Path(__file__).resolve().parent.parent,
        env={**os.environ, "CTFC_SESSIONS_DIR": str(base)},
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0
    assert b"replay script written" in result.stderr
    assert "CYBN{fixture_layers_b64_zlib_hex}" in out.read_text()


def test_cli_watch_once(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    (tmp_path / "a.txt").write_bytes(LAYERED.read_bytes())
    result = run_ctfc("watch", str(tmp_path), "--once", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload[0]["flags"] == ["CYBN{fixture_layers_b64_zlib_hex}"]
