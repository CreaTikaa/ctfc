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
    """Commands that are not built yet must say which milestone brings them."""
    result = run_ctfc("keys", "somedump.bin")
    assert result.returncode == 1
    assert "M7" in result.stderr.decode()


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


def test_xor_command():
    import json

    result = run_ctfc("xor", "tests/fixtures/xor_repeating.bin", "--json")
    assert result.returncode == 0, result.stderr.decode()
    payload = json.loads(result.stdout)
    assert payload["key_lengths"][0]["length"] == 6
    assert "CYBN{fixture_xor_repeating}" in payload["candidates"][0]["data_text"]


def test_xor_with_key_and_crib_options():
    import json

    result = run_ctfc("xor", "tests/fixtures/xor_short_crib.bin", "--crib", "CYBN{", "--json")
    assert "CYBN{crib_dragging_works}" in json.loads(result.stdout)["candidates"][0]["data_text"]
    result = run_ctfc("xor", "tests/fixtures/xor_repeating.bin", "--key", "text:x0rK3y", "--json")
    assert "CYBN{fixture_xor_repeating}" in json.loads(result.stdout)["candidates"][0]["data_text"]


def test_blob_command_finds_the_split():
    result = run_ctfc(
        "blob",
        "tests/fixtures/key_iv_blob.b64",
        "--against",
        "tests/fixtures/aes_cbc_keyiv_blob.bin",
    )
    assert result.returncode == 0, result.stderr.decode()
    assert "CYBN{fixture_key_iv_blob}" in result.stdout.decode()


def test_sym_openssl_json_and_code():
    import json

    result = run_ctfc(
        "sym",
        "tests/fixtures/openssl_salted_pbkdf2.bin",
        "--pass",
        "infected",
        "--json",
    )
    assert result.returncode == 0, result.stderr.decode()
    answer = json.loads(result.stdout)
    best = answer["candidates"][0]
    assert "CYBN{fixture_openssl_pbkdf2}" in best["data_text"]
    assert "pbkdf2" in best["params"]["kdf"]
    assert "pbkdf2_hmac" in best["python"]


def test_sym_unknown_cipher_is_an_error():
    result = run_ctfc(
        "sym", "tests/fixtures/aes_cbc_cts.bin", "--cipher", "nope", "--key", "text:x"
    )
    assert result.returncode == 2
    assert "unknown cipher" in result.stderr.decode()


def test_sym_without_material_explains():
    result = run_ctfc("sym", "tests/fixtures/aes_cbc_keyiv_blob.bin")
    assert result.returncode == 1
    assert "no key material" in result.stdout.decode()


def test_lens_command_on_the_powershell_dropper():
    result = run_ctfc("lens", "tests/fixtures/lens_dropper.ps1", "--show-code")
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "powershell" in out
    assert "base64" in out and "XOR" in out
    assert "Recovery" in out or "recovery" in out


def test_lens_command_json():
    import json

    result = run_ctfc("lens", "tests/fixtures/lens_dropper.py", "--json")
    assert result.returncode == 0, result.stderr.decode()
    answer = json.loads(result.stdout)
    assert answer["language"] == "python"
    assert answer["recovery"]["complete"] is True
    kinds = [operation["kind"] for operation in answer["operations"]]
    assert kinds == ["base64", "cipher"]


def test_lens_from_stdin():
    script = b"import base64\nprint(base64.b64decode('Q1lCTntzdGRpbl9sZW5zfQ=='))\n"
    result = run_ctfc("lens", "-", "--json", stdin=script)
    assert result.returncode == 0, result.stderr.decode()
    assert b'"base64"' in result.stdout


def test_rsa_command_attacks_and_decrypts():
    result = run_ctfc(
        "rsa",
        "--key",
        "tests/fixtures/rsa_fermat.pub.pem",
        "--decrypt",
        "tests/fixtures/rsa_fermat.bin",
        "--attack",
    )
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "CYBN{fixture_rsa_fermat}" in out
    assert "Fermat" in out


def test_rsa_command_from_raw_numbers():
    """--n and --e instead of a key file, with a small exponent."""
    import json

    from Crypto.PublicKey import RSA

    key = RSA.import_key(open("tests/fixtures/rsa_small_e.pub.pem", "rb").read())
    result = run_ctfc(
        "rsa",
        "--n",
        str(key.n),
        "--e",
        "3",
        "--decrypt",
        "tests/fixtures/rsa_small_e.bin",
        "--json",
    )
    assert result.returncode == 0, result.stderr.decode()
    answer = json.loads(result.stdout)
    assert "CYBN{fixture_rsa_small_e}" in answer["candidates"][0]["data_text"]


def test_rsa_check_pairs_keys():
    ok = run_ctfc(
        "rsa", "--key", "tests/fixtures/rsa_private.pem", "--check", "tests/fixtures/rsa_public.pem"
    )
    assert ok.returncode == 0 and b"MATCH" in ok.stdout
    bad = run_ctfc(
        "rsa",
        "--key",
        "tests/fixtures/rsa_private.pem",
        "--check",
        "tests/fixtures/rsa_fermat.pub.pem",
    )
    assert bad.returncode == 1 and b"NO MATCH" in bad.stdout


def test_rsa_shared_prime_with_other():
    result = run_ctfc(
        "rsa",
        "--key",
        "tests/fixtures/rsa_shared_a.pub.pem",
        "--decrypt",
        "tests/fixtures/rsa_shared_a.bin",
        "--attack",
        "--other",
        "tests/fixtures/rsa_shared_b.pub.pem",
    )
    assert result.returncode == 0, result.stderr.decode()
    assert b"CYBN{fixture_rsa_shared}" in result.stdout


def test_rsa_bad_number_is_an_error():
    result = run_ctfc("rsa", "--n", "not-a-number", "--e", "3")
    assert result.returncode == 2
    assert b"not a number" in result.stderr


def test_hash_command_identifies_and_cracks():
    result = run_ctfc("hash", "482c811da5d5b4bc6d497ffa98491e38")
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "MD5" in out and "hashcat -m 0" in out
    assert "password123" in out


def test_hash_command_json_with_prefix_format():
    import json

    value = open("tests/fixtures/mysqlna_hash.txt").read().strip()
    result = run_ctfc("hash", value, "--json")
    assert result.returncode == 0, result.stderr.decode()
    answer = json.loads(result.stdout)
    assert answer["matches"][0]["id"] == "mysqlna"
    assert answer["matches"][0]["hashcat_mode"] == 11200


def test_hash_command_unknown_returns_one():
    result = run_ctfc("hash", "definitely not a hash")
    assert result.returncode == 1


def test_scan_command_ranks_a_folder(tmp_path):
    import shutil

    (tmp_path / "noise.bin").write_bytes(bytes(32))
    shutil.copy("tests/fixtures/layers_b64_zlib_hex.txt", tmp_path / "payload.txt")
    result = run_ctfc("scan", str(tmp_path))
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "payload.txt" in out and "files scanned" in out


def test_scan_command_json_is_sorted(tmp_path):
    import json
    import shutil

    shutil.copy("tests/fixtures/xor_repeating.bin", tmp_path / "a.bin")
    (tmp_path / "b.txt").write_bytes(b"nothing\n")
    result = run_ctfc("scan", str(tmp_path), "--json")
    answer = json.loads(result.stdout)
    scores = [entry["interest"] for entry in answer["files"]]
    assert scores == sorted(scores, reverse=True)


def test_pcap_command_finds_every_flag():
    result = run_ctfc("pcap", "tests/fixtures/capture.pcap")
    assert result.returncode == 0, result.stderr.decode()
    out = result.stdout.decode()
    assert "dns-exfil" in out and "http-body" in out


def test_pcap_command_extracts_to_a_folder(tmp_path):
    result = run_ctfc("pcap", "tests/fixtures/capture.pcap", "--extract", str(tmp_path))
    assert result.returncode == 0, result.stderr.decode()
    written = sorted(path.name for path in tmp_path.iterdir())
    assert len(written) == 4, written
    # And the hand-off works: scan picks the flags out of what was written.
    scanned = run_ctfc("scan", str(tmp_path), "--json")
    assert b"CYBN{fixture_pcap_dns}" in scanned.stdout


def test_pcap_command_rejects_a_non_capture():
    result = run_ctfc("pcap", "tests/fixtures/rsa_public.pem")
    assert result.returncode == 2
    assert b"not a pcap" in result.stderr
