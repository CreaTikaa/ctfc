"""Tests for core/secrets.py: credentials written in clear in a config / script."""

import base64

import pytest

from ctfc.core.auto import auto_decode
from ctfc.core.detect import detect
from ctfc.core.secrets import find_secrets


def names(data: bytes) -> dict:
    return {s.name.lower(): s.value for s in find_secrets(data)}


def test_assignment_shapes():
    config = (
        b"# settings\n"
        b"DB_HOST = localhost\n"
        b'DB_PASSWORD="hunter2!"\n'
        b"api_key: 4f2ad91c8b\n"
        b"AWS_SECRET_KEY = wJalrXUtnFEMI\n"
        b"PORT = 8080\n"
    )
    got = names(config)
    assert got["db_password"] == "hunter2!"
    assert got["api_key"] == "4f2ad91c8b"
    assert got["aws_secret_key"] == "wJalrXUtnFEMI"
    assert "db_host" not in got  # name is not credential-like
    assert "port" not in got  # digits only


def test_xml_and_json():
    assert names(b"<config><secret>Y3t4plBar</secret></config>")["secret"] == "Y3t4plBar"
    got = names(b'{"host": "x", "client_secret": "abc123def", "timeout": 30}')
    assert got["client_secret"] == "abc123def"
    assert "timeout" not in got


def test_placeholders_and_short_values_are_ignored():
    assert find_secrets(b"password = changeme\nsecret = \nAPI_KEY = xxx\npass = 12") == []


def test_rotation_hint_adds_rot13():
    text = b"<radius>\n<!-- rotation policy -->\n<secret>Y3t4plBar</secret>\n</radius>"
    secret = find_secrets(text)[0]
    assert secret.value == "Y3t4plBar"
    assert secret.rot13 == "L3g4cyOne"  # Y3t4plBar rot13'd


def test_no_rotation_no_rot13():
    secret = find_secrets(b"password = Y3t4plBar")[0]
    assert secret.rot13 == ""


def test_binary_and_plain_prose_are_ignored():
    assert find_secrets(bytes(range(256))) == []
    assert find_secrets(b"Just a sentence that happens to mention a password somewhere.") == []


def test_duplicates_collapse():
    assert len(find_secrets(b"password = same\npassword = same\n")) == 1


def test_line_numbers():
    secret = find_secrets(b"a = 1\nb = 2\ntoken = deadbeefcafe\n")[0]
    assert secret.line == 3


# --- integration: the pfSense fixture, through auto and detect ---------------


@pytest.fixture
def pfsense(fixture_bytes) -> bytes:
    return fixture_bytes("audit_pfsense_gateway.bak")


def test_auto_surfaces_the_rotated_secret(pfsense):
    best = auto_decode(pfsense)[0]
    rot = [r for r in best.reasons if "ROT13 'L3g4cyOne!sn3o'" in r]
    assert rot, best.reasons


def test_detect_reports_the_credential_and_points_to_classical(pfsense):
    creds = [g for g in detect(pfsense).guesses if g.rule == "creds.found"]
    assert creds
    assert any("L3g4cyOne!sn3o" in r for g in creds for r in g.reasons)
    assert "ctfc classical" in creds[0].next_step


def test_the_decoded_xml_really_holds_it(pfsense):
    xml = base64.b64decode(pfsense)
    assert find_secrets(xml)[0].value == "Y3t4plBar!fa3b"
