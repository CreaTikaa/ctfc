"""Tenth audit (2026-11-14): the 787 in-scope challenges of the big corpus.

What the salvo taught, each rebuilt here as a fixture with a fake CYBN flag:
- a placeholder flag shipped in a challenge's source (corctf{test_flag},
  CCSC{fake_dummy_flag_1}, actf{REDACTED}) is not the answer: it is a lead, and
  the walk goes on to find the real one;
- a flag shape that only appears after a GUESSED key (xor brute force, affine,
  rail fence, Vigenère with a crib) is chance unless its body reads as words;
- a USB Rubber Ducky payload (inject.bin) is decoded back into the keystrokes
  it types (CCSC 2024 "HIDden").
"""

from __future__ import annotations

from ctfc.core import flags
from ctfc.core.encodings import ducky_decode, ducky_ok
from ctfc.core.solve import guessed_key, solve
from ctfc.core.usb import KEYMAP, decode_ducky, looks_like_ducky

FLAG = "CYBN{ducky_typ3s_th3_fl4g}"


# ---------------------------------------------------------------- placeholders


def test_placeholder_flags_are_recognised():
    for stand_in in (
        "corctf{test_flag}",
        "corctf{t3st_fl4g}",
        "CCSC{fake_dummy_flag_1}",
        "actf{REDACTED}",
        "HTB{example-flag}",
        "flag{this_is_not_the_flag1}",
        "flag{xxxxxxxxxxxxxxxx}",
        "CYBN{FAKE_FLAG}",
    ):
        assert flags.is_placeholder(stand_in), stand_in


def test_real_flags_are_not_placeholders():
    for real in (
        "CYBN{fixture_vba_macro}",
        "HTB{w1ll_y0u_St4nd_y0uR_Gr0uNd!!}",
        "bctf{docx_is_zip}",
        "flag{fugly_cats_need_luv_2}",
        "DUCTF{test_your_luck_4ever}",
    ):
        assert not flags.is_placeholder(real), real


def test_solve_keeps_walking_past_a_placeholder():
    # A source file with the stand-in, and the real flag base64-encoded further on.
    import base64

    data = (
        b'FLAG = os.environ.get("FLAG", "CYBN{fake_flag_for_testing}")\n'
        b"blob = '" + base64.b64encode(FLAG.encode()) + b"'\n"
    )
    report = solve(data, "server.py")
    texts = [found.text for found in report.flags]
    assert FLAG in texts
    assert "CYBN{fake_flag_for_testing}" not in texts


def test_a_lone_placeholder_is_a_lead_not_a_flag():
    report = solve(b'print("corctf{test_flag}")\n', "chall.py")
    # The stand-in is never returned as the answer (and neither is a blind rot/
    # caesar scramble of it): a lone placeholder yields no flag.
    assert not report.flags
    assert "corctf{test_flag}" not in {flag.text for flag in report.flags}


# ---------------------------------------------------------------- guessed keys


def test_guessed_key_chains_are_recognised():
    assert guessed_key("decoded: rot47 -> url -> xor(key='TUTIUR') -> xor(0x40)")
    assert guessed_key("decoded: railfence(rails=7, offset=2)")
    assert guessed_key("decoded: vigenere(key='paer')")
    assert not guessed_key("decoded: base64 -> zlib")
    assert not guessed_key("ZIP member")


def test_wordy_body_separates_flags_from_chance():
    for chance in (
        "LD{4D_usa1}",
        "flag{vho_veehs_bwljvhns_eher_yow_kyxd_aroumintu}",
        "SWWOI{eLlDtWORIKNIrEeRiN}",
        "CYBN{ramlcpno}",
        "NK{OG2MEFT0hG_e0AtPuIRO}",
    ):
        assert not flags.wordy_body(chance), chance
    for real in (
        "CYBN{fixture_vba_macro}",
        "HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}",
        "CCSC{Dis4bling_USBs_D03s_n0t_Dis4ble_HID}",
        "flag{d316759c281bf925d600be698a4973d5}",  # a hash body
    ):
        assert flags.wordy_body(real), real


def test_short_underscored_generic_hit_is_weak():
    # "LD{4D_usa1}" used to pass for a flag because of its underscore.
    assert flags.rate("LD{4D_usa1}") <= flags.WEAK_GENERIC_STRENGTH
    assert flags.rate("HTB{w1ll_y0u_St4nd}") > flags.WEAK_GENERIC_STRENGTH


# ---------------------------------------------------------------- Rubber Ducky

_CHAR_TO_KEY = {}
for _code, (_low, _high) in KEYMAP.items():
    if _code >= 0x54:  # keypad: keep the main keys
        continue
    _CHAR_TO_KEY.setdefault(_low, (_code, 0))
    _CHAR_TO_KEY.setdefault(_high, (_code, 0x02))


def _ducky_encode(text: str) -> bytes:
    """What Duck Encoder writes for STRING <text>: (keycode, modifier) pairs."""
    out = bytearray(b"\x00\xff\x00\xff")  # DELAY 510 at the start, as the encoder does
    out += bytes([0x15, 0x08])  # GUI r
    out += bytes([0x00, 0x64])  # DELAY 100
    for ch in text:
        if ch == "\n":
            out += bytes([0x28, 0x00])
            continue
        code, mod = _CHAR_TO_KEY[ch]
        out += bytes([code, mod])
    return bytes(out)


def test_ducky_payload_decodes_to_the_typed_text():
    payload = _ducky_encode(f"cmd /c echo {FLAG}\n")
    assert looks_like_ducky(payload)
    text, notes = decode_ducky(payload)
    assert FLAG in text
    assert "cmd /c echo" in text
    assert any("shortcut" in note for note in notes)


def test_ducky_decoder_is_in_the_auto_chain():
    payload = _ducky_encode(f"echo {FLAG}\n")
    assert ducky_ok(payload)
    assert FLAG.encode() in ducky_decode(payload)
    report = solve(payload, "inject.bin")
    assert [found.text for found in report.flags] == [FLAG]


def test_ducky_sniff_leaves_text_and_zeros_alone():
    assert not looks_like_ducky(b"1 " * 200)
    assert not looks_like_ducky(bytes(400))
    assert not looks_like_ducky(b"hello world, this is a plain text line\n" * 5)


# ---------------------------------------------------------------- pcap: ICMP + ranges

import io  # noqa: E402
import struct  # noqa: E402
import zipfile  # noqa: E402

from ctfc.core import pcap  # noqa: E402
from tests.make_fixtures import ethernet_ipv4, pcap_packet, tcp_segment  # noqa: E402


def _capture(frames: list[bytes]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(pcap_packet(frame, 1700000000 + i) for i, frame in enumerate(frames))


def _echo(data: bytes, seq: int, request: bool = True) -> bytes:
    icmp = struct.pack(">BBHHH", 8 if request else 0, 0, 0, 0x1234, seq) + data
    source, destination = ("10.0.3.15", "176.28.50.165")
    if not request:
        source, destination = destination, source
    return ethernet_ipv4(source, destination, 1, icmp)


def _zip_with_flag() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("flag.txt", f"well done: {FLAG}\n" + "padding line\n" * 40)
    return buffer.getvalue()


def test_icmp_echo_data_is_extracted_in_order():
    secret = _zip_with_flag()
    chunks = [secret[i : i + 48] for i in range(0, len(secret), 48)]
    frames = []
    for seq, chunk in enumerate(chunks):
        frames += [_echo(chunk, seq), _echo(chunk, seq, request=False)]
    report = pcap.analyse(_capture(frames))
    requests = [o for o in report.objects if o.kind == "icmp-payload" and "request" in o.name]
    assert requests and requests[0].data == secret
    # the reply echoes the same bytes: it is not handed over twice
    assert sum(o.kind == "icmp-payload" for o in report.objects) == 1
    assert [f.text for f in solve(_capture(frames), "pings.pcap").flags] == [FLAG]


def test_stock_ping_filler_is_ignored_and_one_byte_per_packet_is_read():
    linux = struct.pack("<Q", 1700000000) + bytes(range(0x10, 0x38))
    frames = [_echo(linux, seq) for seq in range(5)]
    frames += [_echo(bytes([ch]) * 32, 100 + i) for i, ch in enumerate(FLAG.encode())]
    report = pcap.analyse(_capture(frames))
    letters = [o for o in report.objects if o.name.endswith("one-byte-per-packet.bin")]
    assert letters and letters[0].data == FLAG.encode()
    assert not any(linux in o.data for o in report.objects)


def _response_206(body: bytes, first: int, total: int) -> bytes:
    last = first + len(body) - 1
    head = (
        "HTTP/1.1 206 Partial Content\r\nContent-Type: application/zip\r\n"
        f"Content-Range: bytes {first}-{last}/{total}\r\nContent-Length: {len(body)}\r\n\r\n"
    )
    return head.encode() + body


def test_http_206_ranges_are_put_back_together():
    secret = _zip_with_flag()
    size = 100
    pieces = [(i, secret[i : i + size]) for i in range(0, len(secret), size)]
    pieces.reverse()  # downloaded out of order, one connection per piece
    frames = []
    for port, (first, body) in enumerate(pieces, start=40000):
        segment = tcp_segment(80, port, 1000, _response_206(body, first, len(secret)))
        frames.append(ethernet_ipv4("192.168.4.10", "192.168.3.102", 6, segment))
    report = pcap.analyse(_capture(frames))
    rebuilt = [o for o in report.objects if o.kind == "http-ranges"]
    assert rebuilt and rebuilt[0].data == secret
    assert [f.text for f in solve(_capture(frames), "splitted.pcap").flags] == [FLAG]


# ---------------------------------------------------------------- media: name the stego tool

def test_a_flagless_image_names_the_stego_tools():
    """A PNG with no readable payload must still point at zsteg/stegsolve, not stop silent."""
    import struct
    import zlib as _zlib

    def _chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(
            ">I", _zlib.crc32(kind + body) & 0xFFFFFFFF
        )

    raw = b"".join(b"\x00" + b"\x00\x00\x00" * 8 for _ in range(8))  # 8x8 black, filter byte
    data = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", _zlib.compress(raw))
        + _chunk(b"IEND", b"")
    )
    report = solve(data, "stego.png")
    assert not report.flags
    blob = repr(report.to_dict() if hasattr(report, "to_dict") else report.__dict__)
    assert "zsteg" in blob or "stegsolve" in blob, blob[:400]
