"""detect() on fixtures that mirror real challenge shapes."""

from ctfc.core.detect import detect


def rules(data: bytes) -> list[str]:
    return [guess.rule for guess in detect(data).guesses]


def top_rule(data: bytes) -> str:
    return detect(data).guesses[0].rule


def test_ecb(fixture_bytes):
    found = rules(fixture_bytes("aes_ecb_repeated.bin"))
    assert found[0] == "aes.ecb"
    assert "xor.repeating" not in found  # ECB explains the repeats


def test_openssl_salted(fixture_bytes):
    assert top_rule(fixture_bytes("openssl_salted_md5.bin")) == "magic.enc"
    found = rules(fixture_bytes("openssl_salted_md5.b64"))
    assert "openssl.salted_b64" in found
    assert "magic.enc" in found  # seen after base64 decoding


def test_polyglot(fixture_bytes):
    report = detect(fixture_bytes("png_with_zip.png"))
    found = [guess.rule for guess in report.guesses]
    assert found[0] == "magic.png"
    trailing = next(guess for guess in report.guesses if guess.rule == "polyglot.trailing")
    assert "ZIP" in trailing.label


def test_zero_width(fixture_bytes):
    found = rules(fixture_bytes("zero_width.txt"))
    assert found[0] == "stego.zero_width"
    assert "xor.simple" not in found


def test_crypto_constants(fixture_bytes):
    found = rules(fixture_bytes("crypto_constants.bin"))
    assert "const.tea/xtea" in found
    assert "const.aes" in found


def test_constant_written_in_source_code():
    script = b"uint32_t delta = 0x9E3779B9; for (i = 0; i < 32; i++) sum += delta;"
    assert "const.tea/xtea" in rules(script)


def test_repeating_xor_period(fixture_bytes):
    report = detect(fixture_bytes("xor_repeating.bin"))
    guess = next(guess for guess in report.guesses if guess.rule == "xor.repeating")
    assert "period 6" in guess.label


def test_key_iv_blob(fixture_bytes):
    found = rules(fixture_bytes("key_iv_blob.b64"))
    assert found[0] == "encoding.base64"
    assert "length.key48" in found


def test_text_formats(fixture_bytes):
    assert top_rule(fixture_bytes("jwt.txt")) == "jwt"
    assert top_rule(fixture_bytes("mysqlna_hash.txt")) == "hash.mysqlna"
    assert "powershell.encodedcommand" in rules(fixture_bytes("powershell_encoded.txt"))


def test_flag_in_clear():
    assert top_rule(b"blah CYBN{v1s1bl3} blah") == "flag"


def test_custom_base64_alphabet():
    alphabet = b"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    assert "base64.custom_alphabet" in rules(b'table = "' + alphabet + b'"')


def test_report_is_json_friendly(fixture_bytes):
    import json

    json.dumps(detect(fixture_bytes("crypto_constants.bin")).to_dict())
