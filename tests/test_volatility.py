"""The Volatility cheat sheet is reference data: check it stays consistent.

ctfc never runs Volatility (CLAUDE.md: external tools are only ever suggested),
so what matters is that every command shown is correct, pasteable and written
with the user's aliases.
"""

from __future__ import annotations

import re

import pytest

from ctfc.core.datafiles import load_volatility

ENGINES = {"vol3": "vol ", "vol2": "vol2 "}
PLACEHOLDERS = {
    "<image>",
    "<PID>",
    "<offset>",
    "<profile>",
    "<LinuxProfile>",
    "<SYSTEM_offset>",
    "<SAM_offset>",
    "<hive>",
    "<hive_offset>",
}


@pytest.fixture(scope="module")
def sheet():
    return load_volatility()


def steps(sheet):
    for section in sheet["section"]:
        for step in section["step"]:
            yield section, step


def test_there_is_a_filetype_triage(sheet):
    """The page must answer "what do I have?" before any command."""
    assert len(sheet["filetype"]) >= 5
    for item in sheet["filetype"]:
        for field in ("name", "how", "what"):
            assert item[field].strip(), item


def test_both_engines_are_covered(sheet):
    engines = {section["engine"] for section in sheet["section"]}
    assert engines == {"vol3", "vol2"}


def test_every_command_uses_the_users_alias(sheet):
    """vol = volatility3 -f, vol2 = volatility2.4 -f: never spell the binary out."""
    for section, step in steps(sheet):
        prefix = ENGINES[section["engine"]]
        assert step["cmd"].startswith(prefix), f"{step['cmd']!r} should start with {prefix!r}"
        assert "volatility" not in step["cmd"], f"{step['cmd']!r} spells the binary out"
        # The alias already carries -f, so no command may repeat it.
        assert " -f " not in step["cmd"], f"{step['cmd']!r} repeats -f"


def test_the_image_comes_right_after_the_alias(sheet):
    """`vol <image> plugin`: the alias ends in -f, so the dump is the next word."""
    for _section, step in steps(sheet):
        words = step["cmd"].split()
        assert words[1] == "<image>", step["cmd"]


def test_vol2_commands_carry_a_profile(sheet):
    """Volatility 2 does nothing without --profile, except the plugins that find it."""
    finders = ("imageinfo", "kdbgscan")
    for section, step in steps(sheet):
        if section["engine"] != "vol2":
            continue
        if any(name in step["cmd"] for name in finders):
            continue
        assert "--profile=" in step["cmd"], f"{step['cmd']!r} is missing --profile"


def test_vol3_commands_name_a_plugin_namespace(sheet):
    """vol3 plugins are namespaced: windows.* , linux.* , banners.* , frameworkinfo.*"""
    allowed = ("windows.", "linux.", "mac.", "banners.", "frameworkinfo.")
    for section, step in steps(sheet):
        if section["engine"] != "vol3":
            continue
        assert any(name in step["cmd"] for name in allowed), step["cmd"]


def test_no_unknown_placeholder_is_left_in_a_command(sheet):
    """A placeholder the web page does not fill in would be pasted as-is."""
    for _, step in steps(sheet):
        for found in re.findall(r"<[A-Za-z_]+>", step["cmd"]):
            assert found in PLACEHOLDERS, f"{found} in {step['cmd']!r} is not a known placeholder"


def test_every_step_explains_itself(sheet):
    """CLAUDE.md section 6: every result is explainable."""
    for _, step in steps(sheet):
        assert len(step["desc"].strip()) > 20, step
        if "tip" in step:
            assert step["tip"].strip(), step


def test_sections_are_well_formed(sheet):
    for section in sheet["section"]:
        assert section["os"] in ("any", "windows", "linux", "mac"), section["os"]
        assert section["title"].strip() and section["group"].strip()
        assert section["step"], f"{section['title']} has no command"


def test_it_hands_back_to_ctfc(sheet):
    """The sheet should say what to do with a dumped file, not stop at Volatility."""
    tips = " ".join(step.get("tip", "") + step["desc"] for _, step in steps(sheet))
    assert "ctfc detect" in tips
    assert "ctfc hash" in tips or "Hash tab" in tips
