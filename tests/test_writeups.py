"""The shapes of the user's own past challenges (github.com/CreaTikaa/CTFs-Writeups).

Each fixture is rebuilt by tests/make_fixtures.py with new keys and a fake flag;
the real flags are never in this repository. These tests are the "would ctfc
have solved it?" check, end to end, the way it would be used during the CTF.
"""

import subprocess
import sys

from ctfc.core.lens import analyse
from ctfc.core.lens_against import collect_material, mirror_against
from ctfc.core.symmetric import solve_symmetric


def run_script(tmp_path, source: str, input_data: bytes) -> subprocess.CompletedProcess:
    script = tmp_path / "reproduce.py"
    script.write_text(source)
    (tmp_path / "input.bin").write_bytes(input_data)
    return subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=60
    )


def test_cave_expedition_two_xor_keys_need_the_encrypted_file(fixture_bytes, tmp_path):
    """PowerShell ransomware: obfuscated names, two base64 keys, XOR with both, base64.

    Static analysis alone cannot know which literal is which key; with the
    encrypted file, the script's literals are tried as its own XOR keys.
    """
    source = fixture_bytes("writeup_cave_ransom.ps1")
    encrypted = fixture_bytes("writeup_cave_map.pdf.secured")
    report = analyse(source, "ransom.ps1")
    best = mirror_against(source, report, encrypted)[0]
    assert best.data.startswith(b"%PDF-1.4")
    assert b"CYBN{fixture_two_xor_keys}" in best.data
    assert best.label.startswith("base64 -> xor(")
    assert best.label.count("xor(") == 2
    # The reasons name the literals (line + obfuscated variable) used as keys.
    assert any("a53Va" in reason for reason in best.reasons)
    assert any("b64Vb" in reason for reason in best.reasons)
    # The generated script writes the PDF back to disk.
    done = run_script(tmp_path, best.python, encrypted)
    assert done.returncode == 0, done.stderr.decode()
    assert (tmp_path / "output.pdf").read_bytes() == best.data


def test_cave_expedition_literals_are_read_as_base64(fixture_bytes):
    source = fixture_bytes("writeup_cave_ransom.ps1").decode()
    report = analyse(source, "ransom.ps1")
    readings = {(m.name, m.reading) for m in collect_material(source, report)}
    assert ("a53Va", "base64") in readings
    assert ("b64Vb", "base64") in readings


def test_new_hire_python_stager_is_peeled_statically(fixture_bytes, tmp_path):
    """base64 key, base64 blob, XOR, zlib, exec: everything is in the script."""
    source = fixture_bytes("writeup_newhire_client.py")
    report = analyse(source, "client.py")
    assert report.recovery.label == "base64 -> xor(key='CYBN{fixture_stager_key}') -> zlib"
    assert b"CYBN{fixture_new_hire}" in report.peeled[0].data
    # The recovery script starts from the *encoded* literal: it must not decode twice.
    done = run_script(tmp_path, report.recovery.python, b"")
    assert done.returncode == 0, done.stderr.decode()
    assert "CYBN{fixture_new_hire}" in done.stdout.decode()


def test_ghost_loader_dotnet_aes_key_and_iv_from_variables(fixture_bytes):
    """[Aes]::Create(), .Key = $k, .IV = $v, $k = [Convert]::FromBase64String(...)."""
    report = analyse(fixture_bytes("writeup_ghost_loader.ps1"), "loader.ps1")
    keys = report.artifacts_of("key")
    ivs = report.artifacts_of("iv")
    assert len(keys) == 1 and len(keys[0].value) == 32 and keys[0].name == "k"
    assert len(ivs) == 1 and len(ivs[0].value) == 16 and ivs[0].name == "v"
    assert not report.artifacts_of("blob")  # the key literals are not payloads
    cipher = [op for op in report.operations if op.kind == "cipher"]
    assert cipher and cipher[0].params["key"] == keys[0].value
    assert cipher[0].params["mode"] == "cbc"
    # The decode of the key is key setup, not a data step.
    assert [op.kind for op in report.operations] == ["cipher"]


def test_ghost_loader_decrypts_the_payload_against(fixture_bytes, tmp_path):
    source = fixture_bytes("writeup_ghost_loader.ps1")
    encrypted = fixture_bytes("writeup_ghost_payload.enc")
    best = mirror_against(source, analyse(source, "loader.ps1"), encrypted)[0]
    assert best.label.startswith("AES-256-CBC")
    assert b"CYBN{fixture_ghost_loader}" in best.data
    done = run_script(tmp_path, best.python, encrypted)
    assert done.returncode == 0, done.stderr.decode()
    assert "CYBN{fixture_ghost_loader}" in done.stdout.decode()


def test_silent_trap_rc4_over_base64(fixture_bytes, tmp_path):
    """C2 commands in mails: RC4 then base64. The solver decodes the text first."""
    data = fixture_bytes("writeup_silent_rc4.b64")
    key = bytes.fromhex(fixture_bytes("writeup_silent_rc4.key").decode().strip())
    report = solve_symmetric(data, cipher="rc4", key=key)
    best = report.candidates[0]
    assert b"CYBN{fixture_rc4_mail}" in best.data
    assert any("base64 text: decoded first" in note for note in report.notes)
    assert best.cyberchef.startswith("From_Base64(")
    done = run_script(tmp_path, best.python, data)
    assert done.returncode == 0, done.stderr.decode()
    assert "CYBN{fixture_rc4_mail}" in done.stdout.decode()


def test_against_says_so_when_nothing_works(fixture_bytes):
    import os

    source = fixture_bytes("writeup_cave_ransom.ps1")
    report = analyse(source, "ransom.ps1")
    assert mirror_against(source, report, os.urandom(300)) == []
    assert any("no combination" in note for note in report.notes)
