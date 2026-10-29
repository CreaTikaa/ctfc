"""detect() on fixtures that mirror real challenge shapes."""

import re
from pathlib import Path

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


# ---------------------------------------------------------------------------
# "Apply" actions: which tab solves this guess (improvement idea 1)
# ---------------------------------------------------------------------------


def applies(report) -> dict:
    """{rule: apply} for every guess that knows where to go next."""
    return {guess.rule: guess.apply for guess in report.guesses if guess.apply}


def test_repeating_xor_offers_the_xor_tab_with_the_key_length(fixture_bytes):
    actions = applies(detect(fixture_bytes("xor_repeating.bin")))
    assert actions["xor.repeating"] == {"tab": "xor", "options": {"keylen": 6}}


def test_openssl_file_offers_the_symmetric_tab_with_the_word_list(fixture_bytes):
    actions = applies(detect(fixture_bytes("openssl_salted_md5.bin")))
    assert actions["magic.enc"] == {"tab": "sym", "options": {"passwords": True}}


def test_ecb_offers_the_symmetric_tab_in_ecb_mode(fixture_bytes):
    actions = applies(detect(fixture_bytes("aes_ecb_repeated.bin")))
    assert actions["aes.ecb"] == {"tab": "sym", "options": {"mode": "ecb"}}


def test_a_hash_offers_the_hash_tab(fixture_bytes):
    actions = applies(detect(fixture_bytes("mysqlna_hash.txt")))
    assert actions["hash.mysqlna"] == {"tab": "hash", "options": {}}


def test_a_pem_key_offers_the_rsa_tab(fixture_bytes):
    actions = applies(detect(fixture_bytes("rsa_private.pem")))
    assert actions["pem"] == {"tab": "rsa", "options": {}}


def test_a_key_sized_blob_offers_the_symmetric_tab(fixture_bytes):
    actions = applies(detect(fixture_bytes("key_iv_blob.b64")))
    assert actions["length.key48"]["tab"] == "sym"


def test_every_apply_names_a_real_tab_and_options():
    """A typo in an apply action would make a dead button in the UI."""
    from ctfc.core.detect import PREFIX_APPLY, SIG_APPLY

    # Read the tabs out of the page rather than listing them here, so this check
    # cannot drift as tabs are added.
    page = (Path(__file__).parent.parent / "ctfc/web/static/index.html").read_text()
    tabs = set(re.findall(r'data-tab="([a-z]+)"', page))
    assert "auto" in tabs, "the tab list could not be read from index.html"
    for table in (PREFIX_APPLY, SIG_APPLY):
        for rule, action in table.items():
            assert action["tab"] in tabs, f"{rule}: unknown tab {action['tab']}"
            assert isinstance(action["options"], dict), rule


def test_apply_survives_the_json_round_trip(fixture_bytes):
    """The web UI reads this field from JSON, so it must be serialisable."""
    import json

    report = detect(fixture_bytes("xor_repeating.bin"))
    payload = json.loads(json.dumps(report.to_dict()))
    actions = [guess["apply"] for guess in payload["guesses"] if guess["apply"]]
    assert {"tab": "xor", "options": {"keylen": 6}} in actions


def test_detect_spots_a_column_of_generator_output():
    """624 big integers are not a ciphertext: they are MT19937's state."""
    import random

    rng = random.Random(5)
    text = "\n".join(str(rng.getrandbits(32)) for _ in range(624)).encode()
    report = detect(text)
    guess = next(g for g in report.guesses if g.rule == "prng.mt19937")
    assert guess.apply == {"tab": "prng", "options": {}}
    assert guess.next_step == "ctfc prng <input>"


def test_detect_does_not_call_prose_with_numbers_a_capture():
    body = b"The report was filed in 2024 after 1200 hours of work, costing 350000 euros. " * 6
    report = detect(body)
    assert not [g for g in report.guesses if g.rule.startswith("prng.")]
