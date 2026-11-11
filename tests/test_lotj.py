"""Lot J: the readers the 2026-11-12 public-challenge audit found missing.

Group Policy Preferences passwords, gzip/bzip2/xz streams, InfoVista 5View
captures, DNS names written as literal text, and USB keystrokes recorded the
way a real keyboard sends them (held keys, not one report per character).

Each has an external ground truth, named in its test: Microsoft's published
MS-GPPREF vector, the stdlib's own gzip, Wireshark's editcap for 5View, and
tshark's usbhid.data for USB (checked by hand against the challenge files, as
the handoff records; the fixtures keep the shape with fake flags).
"""

from __future__ import annotations

import bz2
import gzip
import lzma
from pathlib import Path

import pytest

from ctfc.core import gpp, readers
from ctfc.core.budget import Budget
from ctfc.core.flags import find_flags
from ctfc.core.solve import solve
from ctfc.core.zipinfo import analyse, crack_with_wordlist

FIXTURES = Path(__file__).parent / "fixtures"


def solved(name: str) -> list[str]:
    report = solve((FIXTURES / name).read_bytes(), path=f"tests/fixtures/{name}")
    return [flag.text for flag in report.flags]


# --- Group Policy Preferences (MS-GPPREF) --------------------------------------


def test_gpp_published_vector():
    # The canonical public GPP test vector (used by gpp-decrypt): this exact
    # cpassword decrypts to this password with Microsoft's published key.
    cpassword = (
        "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
    )
    assert gpp.decrypt_cpassword(cpassword) == "GPPstillStandingStrong2k18"


def test_gpp_cpassword_decrypts_and_names_the_account():
    data = (FIXTURES / "gpp_groups.xml").read_bytes()
    entries = gpp.find_cpasswords(data)
    assert len(entries) == 1
    assert entries[0].password == "CYBN{gpp_pub1ished_k3y}"
    assert entries[0].user == "Backup"
    assert entries[0].error == ""


def test_gpp_detect_guess_is_strong():
    from ctfc.core.detect import detect

    report = detect((FIXTURES / "gpp_groups.xml").read_bytes())
    gpp_guesses = [g for g in report.guesses if g.rule == "creds.gpp"]
    assert gpp_guesses and gpp_guesses[0].confidence >= 0.9


def test_gpp_bad_value_reports_why_not_crash():
    # A value in the base64 charset but not a whole number of AES blocks.
    entry = gpp.find_cpasswords(b'<User cpassword="AAAABBBBCCCC"/>')
    assert entry and entry[0].password == "" and entry[0].error


@pytest.mark.parametrize("name", ["gpp_groups.xml", "gpp_groups.zip"])
def test_solve_gets_the_gpp_password(name):
    assert any("CYBN{gpp" in flag for flag in solved(name))


# --- compressed streams: gzip / bzip2 / xz -------------------------------------


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
def test_compressed_stream_is_opened_and_searched(compress):
    blob = compress(b"look inside: CYBN{compressed_payload}")
    assert readers.sniff(blob) == "compressed"
    opened = readers.open_with("compressed", blob, None, "x")
    assert opened.children
    assert any(find_flags(child.data) for child in opened.children)


def test_compressed_decompression_is_capped():
    bomb = gzip.compress(b"\x00" * 50_000_000)
    _content, note = readers.decompress_stream(bomb, limit=4096)
    assert "stopped at 4096" in note


def test_truncated_gzip_gives_what_it_can():
    content, note = readers.decompress_stream(gzip.compress(b"abc" * 100000)[:-20])
    assert b"abc" in content and "truncated" in note


def test_solve_gets_the_flag_in_a_tar_gz():
    assert solved("compressed_flag.tar.gz") == ["CYBN{flag_in_a_tar_gz}"]


def test_solve_gets_the_flag_in_a_bz2():
    assert solved("compressed_flag.bz2") == ["CYBN{bzip2_stream}"]


# --- InfoVista 5View capture ----------------------------------------------------


def test_fiveview_frames_parse_as_ethernet():
    frames, link_type, kind = readers.pcap.read_packets(
        (FIXTURES / "fiveview_http.pcap").read_bytes()
    )
    assert kind == "5view"
    assert len(frames) == 2
    assert all(frame[12:14] == b"\x08\x00" for frame in frames)  # IPv4 ethertype


def test_solve_reads_a_5view_capture():
    assert solved("fiveview_http.pcap") == ["CYBN{fiveview_capture}"]


# --- a DNS name written as literal text (a forged query) -----------------------


def test_literal_dns_name_is_read():
    from ctfc.core.pcap import parse_dns_question

    # The name after the one real length byte is plain text, not length-prefixed.
    query = (
        b"\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06remote.ABCDEFGH.example.invalid\x00\x00\x01\x00\x01"
    )
    assert parse_dns_question(query) == "remote.ABCDEFGH.example.invalid"


def test_solve_reads_literal_dns_exfiltration():
    assert solved("dns_literal.pcap") == ["CYBN{literal_dns_name}"]


# --- USB keystrokes, recorded the realistic way --------------------------------


def test_held_key_is_not_retyped():
    from ctfc.core.usb import decode_reports

    def report(code: int, modifier: int = 0) -> bytes:
        return bytes([modifier, 0, code, 0, 0, 0, 0, 0])

    # "a" held across two reports is one "a"; a release then "a" again is two.
    reports = [report(0x04), report(0x04), bytes(8), report(0x04)]
    text, _notes = decode_reports(reports)
    assert text == "aa"


def test_ctrl_backspace_deletes_a_word():
    from ctfc.core.usb import decode_reports

    def press(code: int, modifier: int = 0) -> bytes:
        return bytes([modifier, 0, code, 0, 0, 0, 0, 0])

    # type "ab cd", then Ctrl+Backspace -> "ab "
    reports = [
        press(0x04),
        press(0x05),
        press(0x2C),  # space
        press(0x06),
        press(0x07),
        press(0x2A, 0x01),  # Ctrl+Backspace
    ]
    text, _notes = decode_reports(reports)
    assert text == "ab "


def test_solve_reads_the_usb_keyboard():
    assert solved("usb_typed.pcap") == ["CYBN{ll_held_keys}"]


# --- the ZIP wordlist path -----------------------------------------------------


def test_zip_wordlist_finds_the_password():
    data = (FIXTURES / "zipcrypto_wordlist.zip").read_bytes()
    report = analyse(data, "x", Budget(max_attempts=100, max_seconds=5))
    wordlist = (b"123456", b"password", b"dragon", b"letmein")
    crack_with_wordlist(data, report, wordlist, Budget(max_attempts=100, max_seconds=5))
    assert report.password == "dragon"
    assert report.opened_entry == "flag.txt"


def test_zip_wordlist_reports_miss():
    data = (FIXTURES / "gpp_groups.zip").read_bytes()  # not encrypted
    report = analyse(data, "x", Budget(max_attempts=10, max_seconds=5))
    crack_with_wordlist(data, report, (b"a", b"b"), Budget(max_attempts=10, max_seconds=5))
    assert report.password == ""  # nothing to crack: no encrypted entry
