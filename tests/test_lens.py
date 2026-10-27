"""Code Lens tests: one script per language, plus the parts that are easy to get wrong.

Each fixture hides a flag. The real check is not "did we print something pretty"
but **does the generated recovery script actually recover the payload** - so most
tests run the generated snippet and look for the flag in its output.

Nothing here ever executes a fixture script. They are read as data.
"""

import subprocess
import sys

import pytest

from ctfc.core.lens import analyse, detect_language
from ctfc.core.lens_python import Folder, analyse_python, dotted_name
from ctfc.core.lens_rules import load_rules, read_capture, rules_for


def run_recovery(tmp_path, report) -> bytes:
    """Run the generated recovery script in isolation and return its output."""
    assert report.recovery is not None, f"no recovery script; notes: {report.notes}"
    script = tmp_path / "recover.py"
    script.write_text(report.recovery.python)
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=60
    )
    assert result.returncode == 0, report.recovery.python + "\n" + result.stderr.decode()
    return result.stdout


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("x.py", "python"),
        ("x.ps1", "powershell"),
        ("x.js", "javascript"),
        ("x.sh", "bash"),
        ("x.vbs", "vbs"),
    ],
)
def test_language_from_extension(filename, expected):
    assert detect_language("whatever", filename)[0] == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import base64\nprint(base64.b64decode('eA=='))\n", "python"),
        ("$x = [Convert]::FromBase64String($y)\nWrite-Host $x\n", "powershell"),
        ("var a = atob('eA==');\nfunction f(){}\n", "javascript"),
        ("#!/bin/bash\necho hi | base64 -d\n", "bash"),
        ('Dim a\nSet o = CreateObject("WScript.Shell")\n', "vbs"),
    ],
)
def test_language_from_content(source, expected):
    """Without a file name (a pasted snippet), markers decide."""
    language, why = detect_language(source)
    assert language == expected, why


def test_unknown_language_is_said_so():
    language, why = detect_language("lorem ipsum dolor sit amet")
    assert language == "unknown" and "no marker" in why


# ---------------------------------------------------------------------------
# Constant folding (the part that replaces `eval`)
# ---------------------------------------------------------------------------


def fold_expression(source: str):
    """Fold a Python expression the way the analyser does."""
    import ast

    return Folder().fold(ast.parse(source, mode="eval").body)


@pytest.mark.parametrize(
    "source,expected",
    [
        ('"ab" + "cd"', "abcd"),
        ('b"ab" + b"cd"', b"abcd"),
        ('"ab" * 3', "ababab"),
        ('"hello"[::-1]', "olleh"),
        ("bytes([0x41, 0x42, 67])", b"ABC"),
        ("bytes(range(3))", None),  # range() is not folded: we do not guess
        ('"abc".encode()', b"abc"),
        ('b"abc".decode()', "abc"),
        ('bytes.fromhex("414243")', b"ABC"),
        ('base64.b64decode("QUJD")', b"ABC"),
        ('"".join(["a", "b", "c"])', "abc"),
        ("chr(65)", "A"),
        ('ord("A")', 65),
        ('"a-b".replace("-", "")', "ab"),
        ("0x41 ^ 0x01", 0x40),
        ("open('x').read()", None),  # never folded: that would mean reading a file
        ("some_function()", None),
    ],
)
def test_folding(source, expected):
    assert fold_expression(source) == expected


def test_folding_follows_variables():
    report = type("R", (), {"artifacts": [], "operations": [], "behaviours": [], "notes": []})()
    source = 'PART = "QUJD"\nDATA = PART + "="\n'
    analyse_python(source, report)  # fills nothing, but the folder tracked both names
    assert fold_expression('"a" + "b"') == "ab"


def test_folding_caps_repetition():
    """A huge repetition must not blow up memory while folding."""
    value = fold_expression('"a" * 100000')
    assert value is not None and len(value) <= 4096
    # An exponent is not folded at all, so it cannot be used to blow it up either.
    assert fold_expression('"a" * 10**9') is None


def test_dotted_name():
    import ast

    assert dotted_name(ast.parse("base64.b64decode", mode="eval").body) == "base64.b64decode"
    assert dotted_name(ast.parse("AES.new(k).decrypt", mode="eval").body) == "<call>.decrypt"


# ---------------------------------------------------------------------------
# Python: the two droppers
# ---------------------------------------------------------------------------


def test_python_aes_dropper(tmp_path, fixture_bytes):
    report = analyse(fixture_bytes("lens_dropper.py"), "lens_dropper.py")
    assert report.language == "python"
    assert [operation.kind for operation in report.operations] == ["base64", "cipher"]
    cipher = report.operations[1]
    assert cipher.params["cipher"] == "aes" and cipher.params["mode"] == "cbc"
    assert len(cipher.params["key"]) == 32 and len(cipher.params["iv"]) == 16

    kinds = {artifact.kind for artifact in report.artifacts}
    assert {"key", "iv", "blob", "url"} <= kinds
    assert report.artifacts_of("url")[0].value == b"http://invoice.example.invalid/report.php"
    assert any(behaviour.kind == "execute" for behaviour in report.behaviours)

    assert b"CYBN{fixture_lens_python_aes}" in run_recovery(tmp_path, report)
    assert report.recovery.complete


def test_python_key_setup_is_not_a_data_step(fixture_bytes):
    """`KEY = bytes.fromhex(...)` must not show up as "decode hex" in the data path."""
    report = analyse(fixture_bytes("lens_dropper.py"), "lens_dropper.py")
    assert "hex" not in [operation.kind for operation in report.operations]


def test_python_layers(tmp_path, fixture_bytes):
    report = analyse(fixture_bytes("lens_layers.py"), "lens_layers.py")
    assert [operation.kind for operation in report.operations] == ["base64", "zlib", "xor"]
    assert report.operations[2].params["key"] == b"L4y3rs!"
    assert b"CYBN{fixture_lens_python_layers}" in run_recovery(tmp_path, report)


def test_python_operation_order_is_execution_order():
    """Nested calls run innermost first, and the report must say so."""
    source = (
        "import base64, zlib\n"
        'BLOB = "eJwrSS0uUSguSSwCAB2YBF4="\n'
        "print(zlib.decompress(base64.b64decode(BLOB)))\n"
    )
    report = analyse(source, "x.py")
    assert [operation.kind for operation in report.operations] == ["base64", "zlib"]


def test_python_fernet_key_is_a_key_not_a_blob(fixture_bytes):
    """A 44-char base64 string called FERNET_KEY is a key, not the payload."""
    report = analyse(fixture_bytes("lens_fernet.py"), "lens_fernet.py")
    keys = report.artifacts_of("key")
    assert keys and keys[0].name == "FERNET_KEY"
    assert any("Fernet" in operation.label for operation in report.operations)


def test_python_fernet_recovery_uses_the_token():
    """A Fernet token plus its key gets the snippet symmetric.py writes."""
    import base64

    from ctfc.core.symmetric import fernet_candidates

    key = base64.urlsafe_b64encode(bytes(range(32))).decode()
    # Build a real token with ctfc's own Fernet code path, then analyse a script
    # that carries both the key and the token.
    from tests.make_fixtures import fernet_token

    token = fernet_token(bytes(range(32)), b"CYBN{lens_fernet_live}", 1700000000).decode()
    source = f'FERNET_KEY = "{key}"\nTOKEN = "{token}"\nprint(Fernet(FERNET_KEY).decrypt(TOKEN))\n'
    report = analyse(source, "x.py")
    assert report.recovery is not None, report.notes
    assert "Fernet" in report.recovery.label
    candidates = fernet_candidates(token.encode(), [key.encode()], None)
    assert candidates[0].data == b"CYBN{lens_fernet_live}"


def test_python_that_does_not_parse_falls_back_to_rules():
    """Decompiled or truncated Python still has to give something."""
    source = 'import base64\nBLOB = "' + "QUJD" * 20 + '"\nprint(base64.b64decode(BLOB)\n'
    report = analyse(source, "broken.py")
    assert any("does not parse" in note for note in report.notes)
    assert report.artifacts_of("blob")


def test_python_encrypting_script_is_inverted():
    """A script that *encodes* must give a chain that decodes, in reverse order."""
    source = (
        "import base64, zlib\n"
        'DATA = b"hello world, this is the plaintext"\n'
        "out = base64.b64encode(zlib.compress(DATA))\n"
        'open("out.bin", "wb").write(out)\n'
    )
    report = analyse(source, "encrypt.py")
    assert [operation.direction for operation in report.operations] == ["encode", "encode"]
    # zlib then base64 when encoding -> base64 then zlib to undo it
    assert [step.name for step in report.recovery.steps] == ["base64", "zlib"]


# ---------------------------------------------------------------------------
# The rule-based languages
# ---------------------------------------------------------------------------


def test_powershell_dropper(tmp_path, fixture_bytes):
    report = analyse(fixture_bytes("lens_dropper.ps1"), "lens_dropper.ps1")
    assert report.language == "powershell"
    kinds = [operation.kind for operation in report.operations]
    assert kinds[:2] == ["base64", "xor"]
    # The XOR key lives in a variable: a regex alone cannot find it.
    assert report.operations[1].params["key"] == b"\x3b"
    assert any("from the variable k" in operation.label for operation in report.operations)
    behaviours = {behaviour.kind for behaviour in report.behaviours}
    assert {"network", "execute", "persistence"} <= behaviours
    assert report.artifacts_of("url")[0].value.startswith(b"http://update.example.invalid")
    assert b"CYBN{fixture_lens_powershell}" in run_recovery(tmp_path, report)


def test_powershell_guessed_key_stops_the_chain(fixture_bytes):
    """The AES object in that script is a separate path: its key was matched by
    size, so the recovery must stop before it and say why."""
    report = analyse(fixture_bytes("lens_dropper.ps1"), "lens_dropper.ps1")
    assert not report.recovery.complete
    assert any("matched by size" in note for note in report.notes)
    assert [step.name for step in report.recovery.steps] == ["base64", "xor"]


def test_javascript_cryptojs(tmp_path, fixture_bytes):
    report = analyse(fixture_bytes("lens_cryptojs.js"), "lens_cryptojs.js")
    assert report.language == "javascript"
    assert report.operations[0].kind == "base64"
    assert report.operations[1].params["key"] == b"\x17"
    passwords = report.artifacts_of("password")
    assert passwords and passwords[0].value == b"s3cr3tpassphrase"
    assert b"CYBN{fixture_lens_javascript}" in run_recovery(tmp_path, report)


def test_bash_openssl_hands_over_to_sym(fixture_bytes):
    """A password-based cipher cannot give a key: Code Lens must point to `ctfc sym`."""
    report = analyse(fixture_bytes("lens_openssl.sh"), "lens_openssl.sh")
    assert report.language == "bash"
    assert report.artifacts_of("password")[0].value == b"bashpass"
    commands = [artifact.value.decode() for artifact in report.artifacts_of("command")]
    assert any("openssl enc -d -aes-256-cbc" in command for command in commands)
    assert any("ctfc sym" in note and "bashpass" in note for note in report.notes)


def test_bash_handover_really_works(fixture_bytes):
    """Follow the advice Code Lens gives and check it finds the flag."""
    import base64

    from ctfc.core.symmetric import solve_symmetric

    report = analyse(fixture_bytes("lens_openssl.sh"), "lens_openssl.sh")
    blob = base64.b64decode(report.artifacts_of("blob")[0].value)
    password = report.artifacts_of("password")[0].value
    result = solve_symmetric(blob, passphrase=password)
    assert b"CYBN{fixture_lens_bash}" in result.candidates[0].data


def test_vbs_dropper(tmp_path, fixture_bytes):
    report = analyse(fixture_bytes("lens_dropper.vbs"), "lens_dropper.vbs")
    assert report.language == "vbs"
    assert [operation.kind for operation in report.operations] == ["hex", "xor"]
    assert report.operations[1].params["key"] == b"\x2a"
    assert b"CYBN{fixture_lens_vbs}" in run_recovery(tmp_path, report)


def test_hex_blob_is_not_also_reported_as_base64(fixture_bytes):
    """Hex digits are valid base64 characters: the same string must be reported once."""
    report = analyse(fixture_bytes("lens_dropper.vbs"), "lens_dropper.vbs")
    assert len(report.artifacts_of("blob")) == 1
    assert report.artifacts_of("blob")[0].how.startswith("text")


# ---------------------------------------------------------------------------
# The rule table itself
# ---------------------------------------------------------------------------


def test_every_rule_is_well_formed():
    """A broken rule must fail here, not in the middle of a CTF."""
    seen = set()
    for rule in load_rules():
        assert rule.id not in seen, f"duplicate rule id {rule.id}"
        seen.add(rule.id)
        assert rule.explain, rule.id
        assert rule.direction in ("decode", "encode", "both"), rule.id
        assert rule.capture_as in ("text", "hex", "base64", "number", "charcodes", "utf16le_b64")
        if rule.capture:
            assert rule.regex.groups >= 1, f"{rule.id} captures but has no group"
        if rule.cipher:
            from ctfc.core.symmetric import CIPHERS

            assert rule.cipher in CIPHERS, rule.id


def test_each_language_has_rules():
    for language in ("powershell", "javascript", "bash", "vbs"):
        assert len(rules_for(language)) >= 8, language


@pytest.mark.parametrize(
    "text,how,expected",
    [
        ("414243", "hex", b"ABC"),
        ("QUJD", "base64", b"ABC"),
        ("0x5a", "number", b"\x5a"),
        ("90", "number", b"\x5a"),
        ("&H5A", "number", b"\x5a"),
        ("0x41, 0x42, 67", "charcodes", b"ABC"),
        ("65 66 67", "charcodes", b"ABC"),
        ("hello", "text", b"hello"),
        ("zz", "hex", None),
    ],
)
def test_read_capture(text, how, expected):
    assert read_capture(text, how) == expected


# ---------------------------------------------------------------------------
# Safety: nothing is ever executed
# ---------------------------------------------------------------------------


def test_analysis_never_executes_the_script(tmp_path):
    """A script whose side effect would be visible must leave no trace."""
    witness = tmp_path / "witness.txt"
    source = (
        "import os\n"
        f'open({str(witness)!r}, "w").write("executed")\n'
        f'os.system("touch {witness}")\n'
        'exec("print(1)")\n'
    )
    report = analyse(source, "evil.py")
    assert not witness.exists(), "the analysed script was executed!"
    kinds = {behaviour.kind for behaviour in report.behaviours}
    assert {"execute", "process", "filesystem"} & kinds


def test_lens_module_never_calls_eval_or_exec():
    """Guard the hard rule, by parsing our own code the way Code Lens parses others.

    A plain text search would trip over the *words* "exec()" in the explanations we
    print, so we look for real Call nodes instead.
    """
    import ast
    from pathlib import Path

    import ctfc.core.lens as lens_module

    forbidden = {"eval", "exec", "compile", "__import__"}
    folder = Path(lens_module.__file__).parent
    for name in ("lens.py", "lens_python.py", "lens_rules.py"):
        tree = ast.parse((folder / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden, f"{name}:{node.lineno} calls {node.func.id}"
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in node.names] + [getattr(node, "module", "") or ""]
                assert not any("pickle" in entry for entry in names), name


# ---------------------------------------------------------------------------
# Peeling the layers: the chain applied to every blob, statically
# ---------------------------------------------------------------------------


def test_peeling_finds_the_flag_in_the_m2_dropper(fixture_bytes):
    """The M2 PowerShell fixture was not written for Code Lens: a good robustness check.

    It hides two strings as arrays of byte values, XORed with 0x5A. Peeling must
    reveal both, with the flag ranked first because scoring recognises it.
    """
    from ctfc.core.auto import auto_decode

    recovered = auto_decode(fixture_bytes("powershell_xor.b64"))[0].data
    report = analyse(recovered, "recovered.ps1")
    assert report.peeled, report.notes
    assert report.peeled[0].data == b"CYBN{fixture_powershell_layers}"
    assert report.peeled[0].score > 0.9
    outputs = [peeled.data for peeled in report.peeled]
    assert b"http://update.example.invalid/payload.exe" in outputs


def test_peeling_is_reported_for_each_language(fixture_bytes):
    expected = {
        "lens_dropper.py": b"CYBN{fixture_lens_python_aes}",
        "lens_layers.py": b"CYBN{fixture_lens_python_layers}",
        "lens_dropper.ps1": b"CYBN{fixture_lens_powershell}",
        "lens_cryptojs.js": b"CYBN{fixture_lens_javascript}",
        "lens_dropper.vbs": b"CYBN{fixture_lens_vbs}",
    }
    for name, flag in expected.items():
        report = analyse(fixture_bytes(name), name)
        assert report.peeled, f"{name}: nothing peeled ({report.notes})"
        assert flag in report.peeled[0].data, f"{name}: {report.peeled[0].data!r}"


def test_peeling_stops_cleanly_on_a_broken_chain():
    """A chain that cannot apply must give no peeled result, not a wrong one."""
    from ctfc.core.codegen import Step
    from ctfc.core.lens import apply_chain

    assert apply_chain(b"not base64 at all !!", [Step("base64"), Step("zlib")]) is None
    assert apply_chain(b"QUJD", [Step("base64")]) == b"ABC"


def test_peeling_scores_against_the_user_flag_formats():
    """A custom flag format must be recognised in the peeled output."""
    import base64

    from ctfc.core.flags import build_flagset

    payload = b"BZHCTF{custom_format}"
    blob = base64.b64encode(bytes(byte ^ 0x41 for byte in payload)).decode()
    source = f'K = 0x41\nD = "{blob}"\nimport base64\n'
    source += "raw = base64.b64decode(D)\nout = bytes(b ^ 0x41 for b in raw)\nexec(out)\n"
    flagset = build_flagset([r"BZHCTF\{[^}\n]*\}"], ["BZHCTF{"])
    report = analyse(source, "x.py", flagset=flagset)
    assert report.peeled[0].data == payload
    assert any("flag" in reason for reason in report.peeled[0].reasons)
