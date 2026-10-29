"""Tests for reading and attacking a JWT (core/jwt.py)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from ctfc.core import jwt


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def dump(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def make(header: dict, payload: dict, secret: bytes | None = None, signature: str = "") -> str:
    head, body = b64(dump(header)), b64(dump(payload))
    if secret is not None:
        digest = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
        return f"{head}.{body}.{b64(digest)}"
    return f"{head}.{body}.{signature}"


def rules(report) -> list[str]:
    return [finding.rule for finding in report.findings]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_the_parts_are_decoded_without_any_key():
    token = make({"alg": "HS256", "typ": "JWT"}, {"user": "bob", "admin": False}, secret=b"x")
    parsed = jwt.parse(token)
    assert parsed.header == {"alg": "HS256", "typ": "JWT"}
    assert parsed.payload == {"user": "bob", "admin": False}
    assert parsed.algorithm == "HS256"


def test_base64url_without_padding_is_handled():
    assert jwt.b64url_decode(jwt.b64url_encode(b"\xfb\xff\xfe")) == b"\xfb\xff\xfe"


def test_a_token_with_the_wrong_number_of_parts_is_refused():
    with pytest.raises(jwt.JwtError, match="three dot-separated parts"):
        jwt.parse("only.two")


def test_a_jwe_is_named_rather_than_mangled():
    with pytest.raises(jwt.JwtError, match="JWE"):
        jwt.parse("a.b.c.d.e")


def test_parts_that_are_not_json_are_refused():
    with pytest.raises(jwt.JwtError, match="not JSON"):
        jwt.parse("aaaa.bbbb.cccc")


def test_a_payload_that_is_not_an_object_is_refused():
    token = f"{b64(dump({'alg': 'none'}))}.{b64(b'[1,2,3]')}."
    with pytest.raises(jwt.JwtError, match="JSON objects"):
        jwt.parse(token)


def test_looks_like_jwt_is_strict_enough():
    assert jwt.looks_like_jwt(make({"alg": "none"}, {"a": 1}))
    assert not jwt.looks_like_jwt("hello world")
    assert not jwt.looks_like_jwt("a.b")


# ---------------------------------------------------------------------------
# alg=none
# ---------------------------------------------------------------------------


def test_alg_none_is_reported_as_high_and_a_token_is_offered():
    report = jwt.analyse(make({"alg": "none"}, {"user": "bob"}))
    assert "jwt.alg_none" in rules(report)
    assert report.findings[0].severity == "high"
    forged = jwt.parse(report.forged)
    assert forged.payload["admin"] is True
    assert forged.signature == b""


def test_an_empty_signature_counts_as_unsigned_whatever_alg_says():
    report = jwt.analyse(make({"alg": "HS256"}, {"user": "bob"}), try_secrets=False)
    assert "jwt.alg_none" in rules(report)


# ---------------------------------------------------------------------------
# HMAC secrets
# ---------------------------------------------------------------------------


def test_a_weak_secret_is_found_and_the_hit_is_certain():
    """Cracking is a verification: the recomputed HMAC matches or it does not."""
    token = make({"alg": "HS256"}, {"user": "bob"}, secret=b"secret")
    report = jwt.analyse(token)
    assert report.secret == b"secret"
    assert "jwt.weak_secret" in rules(report)


def test_the_forged_token_really_verifies_with_the_found_secret():
    token = make({"alg": "HS256"}, {"user": "bob", "role": "user"}, secret=b"secret")
    report = jwt.analyse(token)
    forged = jwt.parse(report.forged)
    expected = jwt.sign(forged.signing_input, report.secret, "HS256")
    assert hmac.compare_digest(expected, forged.signature)
    assert forged.payload["admin"] is True
    assert forged.payload["role"] == "user"  # the rest of the payload is kept


def test_a_strong_secret_is_not_found_and_nothing_is_forged():
    token = make({"alg": "HS256"}, {"user": "bob"}, secret=b"8f3a!xQ27-notInAnyList")
    report = jwt.analyse(token)
    assert report.secret is None
    assert "jwt.weak_secret" not in rules(report)
    assert report.forged == ""


def test_only_the_given_secret_is_tried_when_one_is_passed():
    token = make({"alg": "HS256"}, {"user": "bob"}, secret=b"secret")
    assert jwt.analyse(token, secrets=[b"wrong"]).secret is None
    assert jwt.analyse(token, secrets=[b"secret"]).secret == b"secret"


def test_no_secrets_skips_the_search_entirely():
    token = make({"alg": "HS256"}, {"user": "bob"}, secret=b"secret")
    assert jwt.analyse(token, try_secrets=False).secret is None


@pytest.mark.parametrize("algorithm,digest", [("HS384", hashlib.sha384), ("HS512", hashlib.sha512)])
def test_the_other_hmac_sizes_work_too(algorithm, digest):
    head, body = b64(dump({"alg": algorithm})), b64(dump({"u": 1}))
    signature = hmac.new(b"secret", f"{head}.{body}".encode(), digest).digest()
    report = jwt.analyse(f"{head}.{body}.{b64(signature)}")
    assert report.secret == b"secret"


# ---------------------------------------------------------------------------
# Headers that choose the key
# ---------------------------------------------------------------------------


def test_a_jwk_in_the_header_is_reported():
    token = make({"alg": "RS256", "jwk": {"kty": "RSA"}}, {"u": 1}, signature="AAAA")
    assert "jwt.jwk_in_header" in rules(jwt.analyse(token))


@pytest.mark.parametrize("field", ["jku", "x5u"])
def test_a_url_in_the_header_is_reported(field):
    token = make({"alg": "RS256", field: "https://x.invalid/k.json"}, {"u": 1}, signature="AAAA")
    assert f"jwt.{field}" in rules(jwt.analyse(token))


def test_a_kid_that_looks_like_a_path_is_reported():
    token = make({"alg": "HS256", "kid": "../../dev/null"}, {"u": 1}, signature="AAAA")
    assert "jwt.kid_path" in rules(jwt.analyse(token, try_secrets=False))


def test_an_ordinary_kid_is_not_reported():
    token = make({"alg": "HS256", "kid": "key-2024"}, {"u": 1}, signature="AAAA")
    assert "jwt.kid_path" not in rules(jwt.analyse(token, try_secrets=False))


def test_rs256_suggests_the_hs256_confusion():
    report = jwt.analyse(make({"alg": "RS256"}, {"u": 1}, signature="AAAA"))
    finding = next(f for f in report.findings if f.rule == "jwt.asymmetric")
    assert "HS256" in finding.next_step
    assert "PUBLIC key" in finding.next_step


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------


def test_time_claims_are_read_as_dates():
    report = jwt.analyse(make({"alg": "none"}, {"exp": 1700000000, "iat": 1699999000}))
    joined = " ".join(report.times)
    assert "2023-11-14" in joined
    assert "expires at" in joined and "issued at" in joined


def test_an_expired_token_is_pointed_out():
    report = jwt.analyse(make({"alg": "none"}, {"exp": 1000000000}))
    assert "jwt.expired" in rules(report)


def test_a_valid_token_is_not_called_expired():
    future = int(time.time()) + 86400
    report = jwt.analyse(make({"alg": "none"}, {"exp": future}))
    assert "jwt.expired" not in rules(report)


def test_a_non_timestamp_number_is_not_read_as_a_date():
    """A small `iat` is a counter or a mistake, not seconds since the epoch."""
    report = jwt.analyse(make({"alg": "none"}, {"iat": 5}))
    assert report.times == []


def test_a_flag_in_the_payload_is_found():
    report = jwt.analyse(make({"alg": "none"}, {"note": "CYBN{jwt_payload}"}))
    assert report.flags == ["CYBN{jwt_payload}"]


# ---------------------------------------------------------------------------
# The teaching layer
# ---------------------------------------------------------------------------


def test_the_snippet_for_a_cracked_secret_produces_a_valid_token():
    token = make({"alg": "HS256"}, {"user": "bob"}, secret=b"secret")
    report = jwt.analyse(token)
    printed: list[str] = []
    namespace = {"print": printed.append}
    exec(report.python, namespace)  # noqa: S102 - our own generated code
    produced = jwt.parse(printed[0])
    assert produced.payload["admin"] is True
    assert hmac.compare_digest(
        jwt.sign(produced.signing_input, b"secret", "HS256"), produced.signature
    )


def test_the_snippet_for_alg_none_produces_an_unsigned_token():
    report = jwt.analyse(make({"alg": "none"}, {"user": "bob"}))
    printed: list[str] = []
    namespace = {"print": printed.append}
    exec(report.python, namespace)  # noqa: S102 - our own generated code
    produced = jwt.parse(printed[0])
    assert produced.header["alg"] == "none"
    assert produced.signature == b""
