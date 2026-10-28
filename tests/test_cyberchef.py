"""Tests for the CyberChef deep links and recipe strings.

The expected strings below were checked against the real CyberChef source
(v11.5.0) and against `encodeURIFragment` run in node. They are pinned here so a
"small cleanup" cannot silently change an argument order: a CyberChef recipe with
its arguments in the wrong place still runs, and gives a wrong answer.
"""

from ctfc.core.codegen import Step, chain_cyberchef, cipher_cyberchef
from ctfc.core.cyberchef import PUBLIC_URL, deep_link, encode_uri_fragment, is_public

KEY16 = "00" * 16
IV16 = "11" * 16


def test_fragment_encoding_matches_cyberchef():
    """& + = stay percent-encoded (they would break base64 input); @ / ? ' do not."""
    assert encode_uri_fragment("a+b=c&d@e/f ?'x'") == "a%2Bb%3Dc%26d@e/f%20?'x'"


def test_fragment_encoding_of_unicode():
    assert encode_uri_fragment("é") == "%C3%A9"


def test_full_deep_link():
    url = deep_link("From_Base64('A-Za-z0-9+/=',true,false)", b"\xfb\xff hi")
    assert url == (
        "https://gchq.github.io/CyberChef/"
        "#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)"
        "&input=%2B/8gaGk%3D"
    )


def test_deep_link_without_anything_is_the_bare_url():
    assert deep_link("", None) == PUBLIC_URL


def test_deep_link_on_the_embedded_copy():
    url = deep_link("From_Hex('Auto')", b"A", "/vendor/cyberchef/index.html")
    assert url == "/vendor/cyberchef/index.html#recipe=From_Hex('Auto')&input=QQ%3D%3D"


def test_deep_link_adds_the_missing_slash():
    assert deep_link("To_Hex('Space',0)", None, "http://127.0.0.1:9000").startswith(
        "http://127.0.0.1:9000/#recipe="
    )


def test_is_public():
    assert is_public(PUBLIC_URL)
    assert not is_public("/vendor/cyberchef/index.html")
    assert not is_public("http://127.0.0.1:8137/vendor/cyberchef/index.html")
    assert not is_public("http://localhost:8137/vendor/cyberchef/index.html")


def test_aes_decrypt_has_nine_arguments():
    """The bug M6 found: ctfc used to emit 6 arguments, so the mode landed in "IV Length"."""
    recipe = cipher_cyberchef(
        {"cipher": "aes", "mode": "cbc", "key": KEY16, "iv": IV16, "unpad": "pkcs7"}
    )
    assert recipe == (
        "AES_Decrypt("
        "{'option':'Hex','string':'00000000000000000000000000000000'},"
        "{'option':'Hex','string':'11111111111111111111111111111111'},"
        "16,'CBC','Raw','Raw',"
        "{'option':'Hex','string':''},{'option':'Hex','string':''},'Off')"
    )


def test_aes_without_unpad_keeps_the_padding():
    recipe = cipher_cyberchef({"cipher": "aes", "mode": "cbc", "key": KEY16, "iv": IV16})
    assert "'CBC/NoPadding'" in recipe


def test_aes_gcm_carries_the_tag_and_iv_length():
    recipe = cipher_cyberchef(
        {"cipher": "aes", "mode": "gcm", "key": KEY16, "iv": "11" * 12, "tag": "22" * 16}
    )
    assert ",12,'GCM','Raw','Raw'," in recipe
    assert "{'option':'Hex','string':'" + "22" * 16 + "'}" in recipe


def test_des_has_five_arguments():
    recipe = cipher_cyberchef({"cipher": "des", "mode": "cbc", "key": "00" * 8, "iv": "11" * 8})
    assert recipe == (
        "DES_Decrypt({'option':'Hex','string':'0000000000000000'},"
        "{'option':'Hex','string':'1111111111111111'},'CBC/NoPadding','Raw','Raw')"
    )


def test_rc4_has_three_arguments():
    recipe = cipher_cyberchef({"cipher": "rc4", "mode": "stream", "key": "6b6579"})
    assert recipe == "RC4({'option':'Hex','string':'6b6579'},'Latin1','Latin1')"


def test_iv_read_from_the_data_has_no_recipe():
    """A recipe cannot say "take the first 16 bytes as IV": better nothing than a wrong one."""
    params = {"cipher": "aes", "mode": "cbc", "key": KEY16, "iv_from": "prefix"}
    assert cipher_cyberchef(params) is None


def test_decoder_chain():
    steps = [Step("base64", {}), Step("zlib", {}), Step("xor", {"key": "4b337921"})]
    assert chain_cyberchef(steps) == (
        "From_Base64('A-Za-z0-9+/=',true,false)"
        "Zlib_Inflate(0,0,'Adaptive',false,false)"
        "XOR({'option':'Hex','string':'4b337921'},'Standard',false)"
    )


def test_chain_with_an_inexpressible_step_is_none():
    steps = [
        Step("base64", {}),
        Step(
            "cipher",
            {"cipher": "aes", "mode": "cbc", "key": KEY16, "iv_from": "prefix", "iv_size": 16},
        ),
    ]
    assert chain_cyberchef(steps) is None
