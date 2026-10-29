"""auto_decode(): peel layers and find the flag."""

import base64
import subprocess
import sys

import pytest

from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget

CASES = [
    ("layers_b64_zlib_hex.txt", "base64 -> zlib -> hex", b"CYBN{fixture_layers_b64_zlib_hex}"),
    ("reversed_b64.txt", "reverse -> base64", b"CYBN{fixture_reversed}"),
    # One `psenc` step now beats the old extract_base64 -> utf16le chain: it finds
    # the -EncodedCommand itself, so it also works when the line sits in a binary.
    ("powershell_encoded.txt", "psenc", b"CYBN{fixture_encodedcommand}"),
    ("zero_width.txt", "zero_width_a", b"CYBN{zero_width}"),
]


@pytest.mark.parametrize("name,chain,flag", CASES)
def test_fixture_chains(fixture_bytes, name, chain, flag):
    best = auto_decode(fixture_bytes(name))[0]
    assert best.label == chain
    assert flag in best.data
    assert best.score >= 0.9
    assert best.reasons


@pytest.mark.parametrize("name,chain,flag", CASES)
def test_generated_python_reproduces_result(fixture_bytes, tmp_path, name, chain, flag):
    """The snippet must really work: run it and compare its output."""
    best = auto_decode(fixture_bytes(name))[0]
    script = tmp_path / "reproduce.py"
    script.write_text(best.python)
    (tmp_path / "input.bin").write_bytes(fixture_bytes(name))
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stderr.decode()
    assert flag in result.stdout


def test_nothing_better_than_input_gives_no_result(fixture_bytes):
    assert auto_decode(fixture_bytes("key_iv_blob.b64")) == []


def test_budget_is_respected():
    budget = Budget(max_attempts=3)
    layered = base64.b64encode(b"nothing to see here, " * 4).hex().encode()
    auto_decode(layered, budget=budget)
    assert budget.stopped_reason == "attempts"


def test_cancel():
    budget = Budget()
    budget.cancel()
    assert auto_decode(b"SGVsbG8gd29ybGQ=", budget=budget) == []


def test_input_that_is_already_the_answer():
    best = auto_decode(b"the flag is CYBN{already_here}")[0]
    assert best.label == "(input as given)"


def test_evtx_dropper_command_is_decoded_from_a_binary_log(fixture_bytes):
    """Cave Expedition's first step: the command line is UTF-16LE inside the .evtx."""
    best = auto_decode(fixture_bytes("audit_evtx_dropper.evtx"))[0]
    assert best.label.startswith("psenc")
    assert b"CYBN{fixture_evtx_dropper}" in best.data
    assert best.score >= 0.9
