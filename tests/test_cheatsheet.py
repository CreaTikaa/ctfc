"""The cheat sheet must stay true: every command it tells you to run must exist."""

import re
import subprocess
import sys
from pathlib import Path

from ctfc.cli import build_parser
from ctfc.core.datafiles import load_cheatsheet

ROOT = Path(__file__).resolve().parent.parent


def test_every_ctfc_command_in_the_cheatsheet_exists():
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices  # noqa: SLF001 - argparse internals
    mentioned = set(re.findall(r"`ctfc ([a-z]+)", load_cheatsheet()))
    assert mentioned, "the cheat sheet mentions no command?"
    assert mentioned <= set(commands), f"unknown commands: {mentioned - set(commands)}"


def test_every_option_in_the_cheatsheet_exists():
    """`ctfc xor <file> --keylen N`: --keylen must be an option of `xor`."""
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices  # noqa: SLF001
    for command, rest in re.findall(r"`ctfc ([a-z]+)([^`]*)`", load_cheatsheet()):
        known = {flag for action in commands[command]._actions for flag in action.option_strings}  # noqa: SLF001
        for option in re.findall(r"(--[a-z][a-z-]*)", rest):
            assert option in known, f"ctfc {command} has no option {option}"


def test_cli_cheatsheet_renders_and_raw():
    raw = subprocess.run(
        [sys.executable, "-m", "ctfc", "cheatsheet", "--raw"],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert raw.returncode == 0
    assert raw.stdout.decode() == load_cheatsheet()
    rendered = subprocess.run(
        [sys.executable, "-m", "ctfc", "cheatsheet"], cwd=ROOT, capture_output=True, timeout=30
    )
    assert rendered.returncode == 0
    assert "cheat sheet" in rendered.stdout.decode()
    assert "## " not in rendered.stdout.decode()  # rendered, not raw Markdown


def test_docs_point_to_the_packaged_cheatsheet():
    assert "ctfc/data/cheatsheet.md" in (ROOT / "docs" / "cheatsheet.md").read_text()
