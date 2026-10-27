"""End-to-end tests of the command line (run as a real subprocess)."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_ctfc(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    """Run `python -m ctfc ...` from the repo root, without installation."""
    return subprocess.run(
        [sys.executable, "-m", "ctfc", *args],
        cwd=ROOT,
        input=stdin,
        capture_output=True,
        timeout=60,
    )


def test_help_lists_commands():
    result = run_ctfc("--help")
    assert result.returncode == 0
    out = result.stdout.decode()
    for command in ("detect", "auto", "xor", "sym", "serve"):
        assert command in out


def test_command_help_has_example():
    result = run_ctfc("xor", "--help")
    assert result.returncode == 0
    assert "example:" in result.stdout.decode()


def test_planned_command_says_which_milestone():
    result = run_ctfc("rsa")
    assert result.returncode == 1
    assert "M5" in result.stderr.decode()


def test_detect_json(tmp_path):
    import json

    result = run_ctfc("detect", "tests/fixtures/openssl_salted_md5.bin", "--json")
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)["report"]
    assert report["guesses"][0]["rule"] == "magic.enc"


def test_auto_finds_flag_and_shows_code():
    result = run_ctfc("auto", "tests/fixtures/layers_b64_zlib_hex.txt", "--show-code")
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "CYBN{fixture_layers_b64_zlib_hex}" in out
    assert "zlib.decompress" in out


def test_auto_from_stdin():
    result = run_ctfc("auto", "-", "--json", stdin=b"Q1lCTntzdGRpbn0=")
    assert b"CYBN{stdin}" in result.stdout


def test_bad_input_is_a_clear_error():
    result = run_ctfc("detect", "hex:zz")
    assert result.returncode == 2
    assert "invalid hex" in result.stderr.decode()
