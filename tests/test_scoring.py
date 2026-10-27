"""Scoring must rank: flag > file > natural text > encoded text > random bytes."""

import base64
import random

from ctfc.core.flags import base64_forms, build_flagset, find_flags
from ctfc.core.scoring import has_valid_pkcs7, score, shannon_entropy

RANDOM = random.Random(42).randbytes(256)
ENGLISH = b"The meeting is moved to Friday night, bring the usual equipment and be on time."
FRENCH = b"Le rendez-vous est deplace a vendredi soir, apporte le materiel habituel."
B64 = base64.b64encode(RANDOM[:60])


def s(data, **kwargs):
    return score(data, **kwargs)[0]


def test_ranking():
    assert s(b"here: CYBN{r4nk1ng}") > s(b"\x89PNG\r\n\x1a\n" + RANDOM)
    assert s(b"\x89PNG\r\n\x1a\n" + RANDOM) > s(ENGLISH)
    assert s(ENGLISH) > s(B64) > s(RANDOM)


def test_french_counts_as_text():
    assert s(FRENCH) > 0.6
    assert any("French" in reason for reason in score(FRENCH)[1])


def test_reasons_are_never_empty():
    for data in (b"", RANDOM, ENGLISH, b"\x00"):
        assert score(data)[1]


def test_pkcs7_bonus():
    padded = ENGLISH[: 16 * 4 - 4] + b"\x04" * 4
    assert has_valid_pkcs7(padded)
    assert s(padded, check_padding=True) > s(padded)
    assert not has_valid_pkcs7(b"A" * 15 + b"\x00")


def test_entropy():
    assert shannon_entropy(b"aaaa") == 0
    assert shannon_entropy(bytes(range(256))) == 8


def test_base64_forms_of_prefix():
    assert base64_forms(b"CYBN{")[0] == "Q1lCTn"
    assert len(base64_forms(b"CYBN{")) == 3


def test_base64_flag_found_at_every_alignment():
    for prefix in (b"", b"a", b"ab", b"some text "):
        encoded = base64.b64encode(prefix + b"CYBN{al1gn3d}")
        hits = find_flags(encoded)
        assert any(hit.text == "CYBN{al1gn3d}" and hit.how == "base64" for hit in hits)


def test_user_flag_format():
    flagset = build_flagset([r"BZHCTF\{[^}]+\}"], ["BZHCTF{"])
    assert find_flags(b"BZHCTF{yes}", flagset)[0].text == "BZHCTF{yes}"
    assert find_flags(base64.b64encode(b"BZHCTF{b64}"), flagset)[0].text == "BZHCTF{b64}"
