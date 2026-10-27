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
