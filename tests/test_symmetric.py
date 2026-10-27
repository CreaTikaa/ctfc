"""Symmetric cipher tests: the ciphers themselves, then the unknown-layout solver.

Every fixture was built with a known key (see make_fixtures.py), and the flag it
hides says which case it covers. The solver is only ever given what a player
would have: the ciphertext plus a key, a blob or a password.
"""

import base64
import subprocess
import sys

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ctfc.core.blockmodes import cbc_cts_decrypt, cbc_decrypt, ecb_decrypt
from ctfc.core.budget import Budget
from ctfc.core.kdf import evp_bytes_to_key, openssl_derive
from ctfc.core.symmetric import (
    CIPHERS,
    CryptoError,
    decrypt_raw,
    key_forms,
    modes_to_try,
    parse_openssl_enc,
    solve_symmetric,
    strip_padding,
)
from ctfc.core.tea import (
    tea_decrypt_block,
    tea_encrypt_block,
    xtea_decrypt_block,
    xtea_encrypt_block,
)

FILLER = b" The rest of this message is only here so the text scores well. " * 2


def best(report):
    assert report.candidates, f"no candidate; notes: {report.notes}"
    return report.candidates[0]


# ---------------------------------------------------------------------------
# The ciphers and modes we implement ourselves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endian", ["big", "little"])
@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(tea_encrypt_block, tea_decrypt_block), (xtea_encrypt_block, xtea_decrypt_block)],
)
def test_tea_round_trip(encrypt, decrypt, endian):
    key = bytes(range(16))
    assert decrypt(encrypt(b"12345678", key, endian), key, endian) == b"12345678"


def test_tea_published_vectors():
    """TEA and XTEA of an all-zero block with an all-zero key (big-endian words)."""
    assert tea_encrypt_block(bytes(8), bytes(16), "big").hex() == "41ea3a0a94baa940"
    assert xtea_encrypt_block(bytes(8), bytes(16), "big").hex() == "dee9d4d8f7131ed9"


def test_hand_written_modes_match_pycryptodome():
    key, iv = bytes(range(16)), bytes(range(16, 32))
    plain = pad(b"sixteen byte msg" * 3, 16)
    block = AES.new(key, AES.MODE_ECB)

    def block_decrypt(chunk, _key, _endian="big"):
        return block.decrypt(chunk)

    ecb_ct = AES.new(key, AES.MODE_ECB).encrypt(plain)
    assert ecb_decrypt(ecb_ct, key, block_decrypt, 16) == plain
    cbc_ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plain)
    assert cbc_decrypt(cbc_ct, key, iv, block_decrypt, 16) == plain
    # With a whole number of blocks, CTS is plain CBC.
    assert cbc_cts_decrypt(cbc_ct, key, iv, block_decrypt, 16) == plain


def test_cts_matches_openssl_cs1():
    """Vector produced by `openssl enc -aes-128-cbc-cts` (OpenSSL 3 uses CS1)."""
    key = bytes.fromhex("636869636b656e207465726979616b69")
    ciphertext = bytes.fromhex("97687268ff57a6d3eff5a80900a018fd5ad6e1de")

    def block_decrypt(chunk, _key, _endian="big"):
        return AES.new(key, AES.MODE_ECB).decrypt(chunk)

    plain = cbc_cts_decrypt(ciphertext, key, bytes(16), block_decrypt, 16, swapped=False)
    assert plain == b"I would like the Gen"


def test_evp_bytes_to_key_matches_openssl():
    """Vector printed by the real openssl binary:

    openssl enc -aes-256-cbc -md md5 -P -S 0102030405060708 -pass pass:password123
    """
    key, iv = evp_bytes_to_key(b"password123", bytes.fromhex("0102030405060708"), 32, 16, "md5")
    assert key.hex() == "31cc9139806998b2aac366cf401b49dc0d37bd5c2252c7cb4401c65d44c1da61"
    assert iv.hex() == "3d72c90048ea450c9b3bb01c304fa3a4"


def test_decrypt_raw_explains_bad_length():
    with pytest.raises(CryptoError, match="not a multiple of 16"):
        decrypt_raw(CIPHERS["aes"], "cbc", bytes(16), bytes(16), b"too short")


def test_modes_to_try_follows_the_length():
    aes = CIPHERS["aes"]
    aligned = modes_to_try(aes, None, 32)
    assert "cbc" in aligned and "cts" not in aligned
    ragged = modes_to_try(aes, None, 37)
    assert "cbc" not in ragged and "cts" in ragged and "ctr" in ragged
    with pytest.raises(CryptoError, match="no mode"):
        modes_to_try(aes, "nope", 32)


def test_strip_padding():
    assert strip_padding(b"hi" + bytes([14]) * 14, 16) == (b"hi", "pkcs7")
    assert strip_padding(b"hi" + bytes(6), 1) == (b"hi", "zero")
    assert strip_padding(b"nopadding", 16) == (b"nopadding", None)


def test_key_forms_tries_hex_and_padding():
    reasons = [form.reason for form in key_forms(b"41" * 16, 16)]
    assert any("hex-decoded" in reason for reason in reasons)
    assert any("as given" in reason or "cut to" in reason for reason in reasons)
    # A short key gets zero-padded (what CryptoJS does) and hashed.
    reasons = [form.reason for form in key_forms(b"short", 16)]
    assert any("zero-padded" in reason for reason in reasons)
    assert any("md5" in reason for reason in reasons)


# ---------------------------------------------------------------------------
# The solver, on the fixtures
# ---------------------------------------------------------------------------


def test_blob_key_iv_split(fixture_bytes):
    """48-byte blob = 32-byte key || 16-byte IV, AES-256-CBC."""
    blob = base64.b64decode(fixture_bytes("key_iv_blob.b64"))
    candidate = best(solve_symmetric(fixture_bytes("aes_cbc_keyiv_blob.bin"), blob=blob))
    assert b"CYBN{fixture_key_iv_blob}" in candidate.data
    assert candidate.params["cipher"] == "aes" and candidate.params["mode"] == "cbc"
    assert "key = blob[:32]" in candidate.label and "iv = blob[32:]" in candidate.label
    assert any("PKCS7" in reason for reason in candidate.reasons)


def test_blob_given_as_base64_text(fixture_bytes):
    """The blob is pasted as base64: the solver must try the decoded form."""
    report = solve_symmetric(
        fixture_bytes("aes_cbc_keyiv_blob.bin"), blob=fixture_bytes("key_iv_blob.b64").strip()
    )
    assert b"CYBN{fixture_key_iv_blob}" in best(report).data
    assert any("base64-decoded" in reason for reason in best(report).reasons)


def test_iv_prepended_to_ciphertext(fixture_bytes):
    key = fixture_bytes("aes_cbc_iv_prefix.key").strip()
    candidate = best(solve_symmetric(fixture_bytes("aes_cbc_iv_prefix.bin"), key=key))
    assert b"CYBN{fixture_iv_prefixed}" in candidate.data
    assert "first 16 bytes of the ciphertext" in candidate.label


def test_gcm_nonce_ct_tag(fixture_bytes):
    """nonce || ciphertext || tag, and the tag proves the key."""
    key = fixture_bytes("aes_cbc_iv_prefix.key").strip()
    candidate = best(solve_symmetric(fixture_bytes("aes_gcm_nonce_ct_tag.bin"), key=key))
    assert candidate.data == b"CYBN{fixture_gcm_nonce_ct_tag}"
    assert any("tag verifies" in reason for reason in candidate.reasons)


def test_cbc_cts_non_aligned(fixture_bytes):
    key = fixture_bytes("aes_cbc_cts.key").strip()
    candidate = best(solve_symmetric(fixture_bytes("aes_cbc_cts.bin"), key=key))
    assert b"CYBN{fixture_cts_mode}" in candidate.data
    assert "CTS" in candidate.label


def test_openssl_enc_md5(fixture_bytes):
    report = solve_symmetric(fixture_bytes("openssl_salted_md5.bin"), passphrase=b"password123")
    candidate = best(report)
    assert b"CYBN{fixture_openssl_md5}" in candidate.data
    assert any("Salted__" in note for note in report.notes)
    assert any("openssl enc -d -aes-256-cbc -md md5" in reason for reason in candidate.reasons)


def test_openssl_enc_base64_form(fixture_bytes):
    """The same file, base64 encoded, as `openssl enc -a` writes it."""
    report = solve_symmetric(fixture_bytes("openssl_salted_md5.b64"), passphrase=b"password123")
    assert b"CYBN{fixture_openssl_md5}" in best(report).data
    assert any("-a " in reason for reason in best(report).reasons)


def test_openssl_enc_pbkdf2(fixture_bytes):
    report = solve_symmetric(fixture_bytes("openssl_salted_pbkdf2.bin"), passphrase=b"infected")
    candidate = best(report)
    assert b"CYBN{fixture_openssl_pbkdf2}" in candidate.data
    assert "pbkdf2" in candidate.params["kdf"]


def test_openssl_enc_with_embedded_password_list(fixture_bytes):
    """No password given: the embedded list must find "password123"."""
    report = solve_symmetric(
        fixture_bytes("openssl_salted_md5.bin"),
        try_passwords=True,
        budget=Budget(max_attempts=10**7, max_seconds=60),
    )
    candidate = best(report)
    assert b"CYBN{fixture_openssl_md5}" in candidate.data
    assert candidate.params["password"] == "password123"


def test_fernet_token(fixture_bytes):
    key = fixture_bytes("fernet_key.b64").strip()
    candidate = best(solve_symmetric(fixture_bytes("fernet_token.txt"), key=key))
    assert candidate.data == b"CYBN{fixture_fernet}"
    assert candidate.params["verified"] is True


def test_fernet_wrong_key_is_reported(fixture_bytes):
    """A wrong Fernet key must be called out, not quietly presented as plaintext."""
    report = solve_symmetric(fixture_bytes("fernet_token.txt"), key=base64.b64encode(bytes(32)))
    fernet = [c for c in report.candidates if c.params.get("cipher") == "fernet"]
    assert fernet, f"no Fernet candidate; got {[c.label for c in report.candidates]}"
    assert any("does NOT verify" in reason for reason in fernet[0].reasons)
    assert fernet[0].params["verified"] is False


def test_chacha20_nonce_prefix(fixture_bytes):
    key = fixture_bytes("chacha20_nonce_prefix.key").strip()
    candidate = best(solve_symmetric(fixture_bytes("chacha20_nonce_prefix.bin"), key=key))
    assert b"CYBN{fixture_chacha20}" in candidate.data
    assert candidate.params["cipher"] == "chacha20"


def test_xtea_cbc_from_passphrase(fixture_bytes):
    """XTEA-CBC, 16-byte key = md5(passphrase), IV in front of the ciphertext."""
    candidate = best(
        solve_symmetric(fixture_bytes("xtea_cbc.bin"), passphrase=b"tiny", cipher="xtea")
    )
    assert b"CYBN{fixture_xtea_cbc}" in candidate.data
    assert candidate.params["endian"] == "big"


def test_ecb_with_known_key():
    key = b"0123456789abcdef"
    data = AES.new(key, AES.MODE_ECB).encrypt(pad(b"CYBN{ecb}" + FILLER, 16))
    candidate = best(solve_symmetric(data, key=key))
    assert b"CYBN{ecb}" in candidate.data
    assert candidate.params["mode"] == "ecb"


def test_des3_cbc_with_blob():
    """3DES, 24-byte key || 8-byte IV in one 32-byte blob."""
    from Crypto.Cipher import DES3

    key, iv = bytes(range(1, 25)), bytes(range(8))
    data = DES3.new(key, DES3.MODE_CBC, iv).encrypt(pad(b"CYBN{des3}" + FILLER, 8))
    candidate = best(solve_symmetric(data, blob=key + iv))
    assert b"CYBN{des3}" in candidate.data
    assert candidate.params["cipher"] == "3des"


def test_no_key_material_says_what_to_do():
    report = solve_symmetric(b"\x00" * 32)
    assert not report.candidates
    assert any("no key material" in note for note in report.notes)


def test_unknown_cipher_is_explained():
    with pytest.raises(CryptoError, match="unknown cipher"):
        solve_symmetric(b"x" * 16, cipher="rot13", key=bytes(16))


def test_budget_stops_the_search(fixture_bytes):
    """A tiny budget must stop cleanly and say so, not raise.

    The password is wrong on purpose: with the right one the search stops because
    it succeeded, which is a different (also tested) path.
    """
    report = solve_symmetric(
        fixture_bytes("openssl_salted_md5.bin"),
        passphrase=b"not-the-password",
        budget=Budget(max_attempts=5, max_seconds=30),
    )
    assert any("stopped early" in note for note in report.notes)
    assert "attempt budget reached" in report.budget_summary


def test_search_stops_once_it_is_sure(fixture_bytes):
    """Finding a flag must end the search instead of burning the whole budget."""
    report = solve_symmetric(
        fixture_bytes("openssl_salted_md5.bin"),
        try_passwords=True,
        budget=Budget(max_attempts=10**7, max_seconds=60),
    )
    assert any("stopped as soon as a convincing result" in note for note in report.notes)
    assert "search finished" in report.budget_summary


def test_wrong_key_scores_low():
    """A wrong key must not be presented as an answer."""
    data = AES.new(bytes(range(16)), AES.MODE_CBC, bytes(16)).encrypt(pad(b"hello" + FILLER, 16))
    report = solve_symmetric(data, key=bytes(range(32, 48)), cipher="aes", mode="cbc")
    assert report.candidates[0].score < 0.3
    assert any("least-bad" in note for note in report.notes)


def test_openssl_command_is_reproducible(fixture_bytes, tmp_path):
    """The `openssl enc -d ...` line we print must really work."""
    import re
    import shutil

    if not shutil.which("openssl"):
        pytest.skip("openssl is not installed")
    report = solve_symmetric(fixture_bytes("openssl_salted_pbkdf2.bin"), passphrase=b"infected")
    line = next(
        reason.split("openssl enc", 1)[1]
        for reason in best(report).reasons
        if "openssl enc -d" in reason
    )
    path = tmp_path / "secret.enc"
    path.write_bytes(fixture_bytes("openssl_salted_pbkdf2.bin"))
    arguments = re.sub(r"<file>", str(path), "openssl enc" + line).split()
    result = subprocess.run(arguments, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode()
    assert b"CYBN{fixture_openssl_pbkdf2}" in result.stdout


# ---------------------------------------------------------------------------
# Generated code: every snippet must really reproduce the plaintext
# ---------------------------------------------------------------------------


def run_snippet(tmp_path, candidate, data: bytes) -> bytes:
    """Write the candidate's Python snippet to a file and run it in isolation."""
    script = tmp_path / "reproduce.py"
    script.write_text(candidate.python)
    (tmp_path / "input.bin").write_bytes(data)
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=60
    )
    assert result.returncode == 0, candidate.python + "\n" + result.stderr.decode()
    return result.stdout


@pytest.mark.parametrize(
    "fixture,flag,kwargs",
    [
        ("aes_cbc_keyiv_blob.bin", b"CYBN{fixture_key_iv_blob}", {"blob_file": "key_iv_blob.b64"}),
        (
            "aes_cbc_iv_prefix.bin",
            b"CYBN{fixture_iv_prefixed}",
            {"key_file": "aes_cbc_iv_prefix.key"},
        ),
        ("aes_gcm_nonce_ct_tag.bin", b"CYBN{fixture_gcm", {"key_file": "aes_cbc_iv_prefix.key"}),
        ("aes_cbc_cts.bin", b"CYBN{fixture_cts_mode}", {"key_file": "aes_cbc_cts.key"}),
        ("openssl_salted_md5.bin", b"CYBN{fixture_openssl_md5}", {"passphrase": b"password123"}),
        ("openssl_salted_pbkdf2.bin", b"CYBN{fixture_openssl_pbkdf2}", {"passphrase": b"infected"}),
        ("fernet_token.txt", b"CYBN{fixture_fernet}", {"key_file": "fernet_key.b64"}),
        (
            "chacha20_nonce_prefix.bin",
            b"CYBN{fixture_chacha20}",
            {"key_file": "chacha20_nonce_prefix.key"},
        ),
        ("xtea_cbc.bin", b"CYBN{fixture_xtea_cbc}", {"passphrase": b"tiny", "cipher": "xtea"}),
    ],
)
def test_generated_snippet_reproduces(tmp_path, fixture_bytes, fixture, flag, kwargs):
    options = dict(kwargs)
    if "key_file" in options:
        options["key"] = fixture_bytes(options.pop("key_file")).strip()
    if "blob_file" in options:
        options["blob"] = base64.b64decode(fixture_bytes(options.pop("blob_file")))
    data = fixture_bytes(fixture)
    candidate = best(solve_symmetric(data, **options))
    assert flag in run_snippet(tmp_path, candidate, data)


def test_openssl_derive_layouts_differ():
    """Two different KDF layouts must not give the same key (sanity check)."""
    salt = bytes(range(8))
    legacy = openssl_derive(b"pass", salt, 32, 16, "md5", 0)
    modern = openssl_derive(b"pass", salt, 32, 16, "sha256", 10000)
    assert legacy.key != modern.key
    assert legacy.openssl_flags == "-md md5"
    assert modern.openssl_flags == "-pbkdf2 -md sha256 -iter 10000"


def test_parse_openssl_enc_rejects_other_data():
    assert parse_openssl_enc(b"Salted__") is None  # header but no body
    assert parse_openssl_enc(b"not an openssl file at all") is None
    parsed = parse_openssl_enc(b"Salted__" + bytes(range(8)) + b"x" * 16)
    assert parsed is not None and parsed.salt == bytes(range(8))


@pytest.mark.parametrize(
    "mode,openssl_mode",
    [("cfb", "cfb"), ("ctr", "ctr"), ("ofb", "ofb"), ("cbc", "cbc")],
)
def test_modes_match_the_openssl_binary(tmp_path, mode, openssl_mode):
    """Our mode conventions must be the ones `openssl enc` uses.

    This is the check CLAUDE.md asks for: compare against a real implementation,
    not against ourselves. CFB especially: openssl does one segment per block,
    while pycryptodome defaults to one per byte (that is our separate "cfb8").
    """
    import shutil

    if not shutil.which("openssl"):
        pytest.skip("openssl is not installed")
    key, iv = bytes(range(32)), bytes(range(16))
    # Exactly 4 AES blocks, so that CBC can run with -nopad.
    plain = b"The quick brown fox jumps over the lazy dog".ljust(64, b".")
    source = tmp_path / "pt.bin"
    source.write_bytes(plain)
    arguments = [
        "openssl", "enc", f"-aes-256-{openssl_mode}", "-K", key.hex(), "-iv", iv.hex(),
        "-nopad" if openssl_mode == "cbc" else "-nosalt", "-in", str(source),
    ]  # fmt: skip
    result = subprocess.run(arguments, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode()
    assert decrypt_raw(CIPHERS["aes"], mode, key, iv, result.stdout) == plain
