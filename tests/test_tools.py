"""Tests for the external tool bridge (core/tools.py + data/tools.toml)."""

import fnmatch
import shutil
import subprocess

import pytest

from ctfc.core import tools
from ctfc.core.datafiles import load_toml
from ctfc.core.hashes import load_formats
from ctfc.core.magic import load_prefix_rules, load_signatures
from ctfc.core.tools import Signal, fill, gather, load_tools, run_tool, suggest, tool_by_id

SHELL_CHARACTERS = ("|", ";", "&&", "$(", "`", ">", "<")


def known_rule_ids() -> set[str]:
    """Every rule id that detect / the hash identifier can produce today."""
    ids = {
        "flag",
        "polyglot.trailing",
        "embedded",
        "stego.zero_width",
        "base64.custom_alphabet",
        "entropy.high",
        "entropy.mixed",
        "xor.simple",
        "xor.repeating",
        "aes.ecb",
        "block8.ecb",
        "length.key16",
        "length.key24",
        "length.key32",
        "classical.flag_shift",
        "classical.transposition",
        "classical.monoalphabetic",
        "classical.vigenere",
    }
    ids |= {f"magic.{sig.ext}" for sig in load_signatures()}
    ids |= {rule.id for rule in load_prefix_rules()}
    ids |= {f"hash.{fmt.id}" for fmt in load_formats()}
    ids |= {
        f"const.{row['algo'].split()[0].lower()}" for row in load_toml("constants.toml")["const"]
    }
    return ids


@pytest.fixture
def no_embedded_copy(monkeypatch):
    monkeypatch.setattr(tools, "embedded_cyberchef_installed", lambda: False)


@pytest.fixture
def embedded_copy(monkeypatch):
    monkeypatch.setattr(tools, "embedded_cyberchef_installed", lambda: True)


# ---------------------------------------------------------------------------
# The registry itself
# ---------------------------------------------------------------------------


def test_every_tool_is_well_formed():
    ids = [tool.id for tool in load_tools()]
    assert len(ids) == len(set(ids)), "duplicate tool id"
    for tool in load_tools():
        assert tool.kind in ("online", "local", "embedded"), tool.id
        assert tool.suggest_when, f"{tool.id} never fires"
        if tool.kind == "local":
            assert tool.command_template, f"{tool.id}: a local tool needs a command"
            assert tool.install, f"{tool.id}: say how to install it"
        if tool.kind == "online":
            assert not tool.offline_safe, f"{tool.id}: an online tool cannot be offline_safe"
        for other in tool.prefer_over:
            tool_by_id(other)  # raises on a typo


def test_no_command_is_ever_a_shell_string():
    """Hard rule 4: argument lists only, and no shell syntax hiding in an argument."""
    for row in load_toml("tools.toml")["tool"]:
        template = row.get("command_template")
        if template is None:
            continue
        assert isinstance(template, list), f"{row['id']}: command_template must be a list"
        assert all(isinstance(arg, str) for arg in template)
        assert " " not in template[0], f"{row['id']}: program name with a space"
        for arg in template:
            for char in SHELL_CHARACTERS:
                assert char not in arg, f"{row['id']}: shell syntax {char!r} in {arg!r}"


def test_every_suggest_when_pattern_can_fire():
    """A typo in a rule id ("magic.tiff") would make a tool silently never appear."""
    known = known_rule_ids()
    for tool in load_tools():
        for pattern in tool.suggest_when:
            assert any(fnmatch.fnmatch(rule, pattern) for rule in known), (
                f"{tool.id}: {pattern!r} matches no rule id detect can produce"
            )


# ---------------------------------------------------------------------------
# Suggestions
# ---------------------------------------------------------------------------


def test_below_the_threshold_nothing_is_suggested(no_embedded_copy):
    assert suggest([Signal("xor.repeating", 0.5)], threshold=0.7) == []


def test_a_confident_rule_suggests_its_tool(no_embedded_copy):
    found = suggest([Signal("xor.repeating", 0.8, "period 6")], {"input": "a.bin", "keylen": 6})
    by_id = {item.tool.id: item for item in found}
    assert by_id["xortool"].command == ["xortool", "-l", "6", "a.bin"]
    assert by_id["xortool"].reason == "period 6 (confidence 0.80)"
    assert by_id["xortool"].placeholders == []


def test_suggestions_are_capped(no_embedded_copy):
    signals = [Signal("magic.png", 0.95), Signal("hash.md5", 0.9), Signal("magic.pcap", 0.9)]
    assert len(suggest(signals, limit=3)) == 3
    assert len(suggest(signals, limit=1)) == 1


def test_most_confident_signal_first(no_embedded_copy):
    found = suggest([Signal("magic.pcap", 0.75), Signal("hash.md5", 0.95)], limit=1)
    assert found[0].tool.id == "hashcat"


def test_each_tool_once(no_embedded_copy):
    found = suggest([Signal("hash.md5", 0.9), Signal("hash.ntlm", 0.8)], limit=10)
    ids = [item.tool.id for item in found]
    assert len(ids) == len(set(ids))


def test_offline_hides_third_party_tools(no_embedded_copy):
    online = suggest([Signal("pem", 0.9)], limit=10)
    assert "factordb" in {item.tool.id for item in online}
    assert next(item for item in online if item.tool.id == "factordb").warning
    offline = suggest([Signal("pem", 0.9)], offline=True, limit=10)
    assert all(item.tool.offline_safe for item in offline)
    assert "factordb" not in {item.tool.id for item in offline}


def test_embedded_cyberchef_replaces_the_public_one(embedded_copy):
    values = {
        "cyberchef_url": "/vendor/cyberchef/index.html",
        "cyberchef_recipe": "From_Hex('Auto')",
    }
    ids = [item.tool.id for item in suggest([Signal("xor.repeating", 0.9)], values, limit=10)]
    assert "cyberchef_local" in ids
    assert "cyberchef_public" not in ids


def test_without_the_embedded_copy_no_dead_link(no_embedded_copy):
    ids = [item.tool.id for item in suggest([Signal("xor.repeating", 0.9)], limit=10)]
    assert "cyberchef_local" not in ids
    assert "cyberchef_public" in ids


def test_cyberchef_link_is_a_real_deep_link(embedded_copy):
    values = {
        "cyberchef_url": "/vendor/cyberchef/index.html",
        "cyberchef_recipe": "From_Hex('Auto')",
        "cyberchef_data": b"A",
    }
    found = suggest([Signal("xor.repeating", 0.9)], values, limit=10)
    local = next(item for item in found if item.tool.id == "cyberchef_local")
    assert local.url == "/vendor/cyberchef/index.html#recipe=From_Hex('Auto')&input=QQ%3D%3D"


def test_missing_placeholders_are_reported(no_embedded_copy):
    found = suggest([Signal("hash.md5", 0.9)], {"hashcat_mode": 0}, limit=10)
    hashcat = next(item for item in found if item.tool.id == "hashcat")
    assert hashcat.placeholders == ["{input}", "{wordlist}"]


def test_fill_keeps_arguments_separate():
    """A path with spaces stays one argument: nothing is ever split by a shell."""
    filled, missing = fill(
        ("xortool", "-l", "{keylen}", "{input}"), {"keylen": 6, "input": "my file; rm -rf"}
    )
    assert filled == ["xortool", "-l", "6", "my file; rm -rf"]
    assert missing == []


# ---------------------------------------------------------------------------
# Working out the signals for an input
# ---------------------------------------------------------------------------


def test_a_bare_md5_is_confidently_a_hash():
    """MD5 vs NTLM is a coin toss, but "this is a hash, use hashcat" is not."""
    signals, values = gather(b"482c811da5d5b4bc6d497ffa98491e38\n", None)
    hash_signal = next(signal for signal in signals if signal.rule.startswith("hash."))
    assert hash_signal.confidence >= 0.7
    assert "MD5" in hash_signal.why
    assert values["hashcat_mode"] == 0
    assert "input" not in values  # pasted data: no file to hand to a tool


def test_gather_on_a_file(fixture_bytes):
    path = "tests/fixtures/xor_repeating.bin"
    signals, values = gather(fixture_bytes("xor_repeating.bin"), path)
    assert values["input"] == path
    assert values["keylen"] == 6
    assert any(signal.rule == "xor.repeating" for signal in signals)
    assert values["cyberchef_recipe"].startswith("XOR(")


def test_cyberchef_base_for_the_terminal_is_a_file_url():
    assert (
        tools.cyberchef_base("/vendor/cyberchef/index.html", for_web=True)
        == "/vendor/cyberchef/index.html"
    )
    assert tools.cyberchef_base("/vendor/cyberchef/index.html", for_web=False).startswith("file://")
    custom = "http://127.0.0.1:9000/"
    assert tools.cyberchef_base(custom, for_web=False) == custom


# ---------------------------------------------------------------------------
# Running a tool
# ---------------------------------------------------------------------------


def test_run_tool_uses_an_argument_list_and_no_stdin(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, b"ok", b"")

    monkeypatch.setattr(tools.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    result = run_tool(tool_by_id("xortool"), {"keylen": 4, "input": "a b.bin"})
    assert result.stdout == "ok"
    assert seen["command"] == ["/usr/bin/xortool", "-l", "4", "a b.bin"]
    assert not seen["kwargs"].get("shell", False)
    # openssl without -pass would otherwise wait for a password on the keyboard
    assert seen["kwargs"]["stdin"] is subprocess.DEVNULL


def test_run_tool_refuses_online_tools():
    result = run_tool(tool_by_id("factordb"), {"modulus": "15"})
    assert result.returncode == -1
    assert "not a local program" in result.error


def test_run_tool_refuses_missing_placeholders():
    result = run_tool(tool_by_id("hashcat"), {"input": "h.txt"})
    assert result.returncode == -1
    assert "{hashcat_mode}" in result.error and "{wordlist}" in result.error


def test_run_tool_on_a_missing_program(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    result = run_tool(tool_by_id("zsteg"), {"input": "a.png"})
    assert "not installed" in result.error
    assert "gem install zsteg" in result.error


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_run_real_openssl_on_the_fixture():
    values = {"input": "tests/fixtures/openssl_salted_md5.bin", "password": "password123"}
    result = run_tool(tool_by_id("openssl"), values)
    assert result.returncode == 0, result.stderr
    assert "CYBN{fixture_openssl_md5}" in result.stdout


def test_a_value_starting_with_a_dash_is_refused(monkeypatch):
    """`--outfile=~/.bashrc` given as a wordlist must not become a hashcat option."""
    monkeypatch.setattr(tools.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(tools.subprocess, "run", lambda *a, **k: pytest.fail("must not run"))
    values = {"hashcat_mode": 0, "input": "h.txt", "wordlist": "--outfile=/tmp/x"}
    result = run_tool(tool_by_id("hashcat"), values)
    assert "starts with '-'" in result.error


def test_john_extractors_fire_on_their_file_magic(no_embedded_copy):
    """Each *2john / oletools entry is suggested by the matching file signature."""
    cases = {
        "magic.zip": "zip2john",
        "magic.rar": "rar2john",
        "magic.7z": "sevenz2john",
        "magic.pdf": "pdf2john",
        "magic.kdbx": "keepass2john",
        "magic.doc": "office2john",  # olevba/oleid also fire, but office2john is in the list
    }
    for rule, tool_id in cases.items():
        found = suggest([Signal(rule, 0.95)], {"input": "f.bin"}, limit=10)
        ids = {item.tool.id for item in found}
        assert tool_id in ids, f"{rule} should suggest {tool_id}, got {ids}"
