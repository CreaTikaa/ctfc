"""Ninth public audit (2026-11-13): ImaginaryCTF 2023 and LA CTF.

Two in-scope wins found and built:
- a one-byte-per-packet UDP exfiltration split by the IP "evil bit" (RFC 3514),
  LA CTF 2023 "EBE";
- an ASCII flag read at the wrong UTF-16 endianness (shown as CJK), LA CTF 2026
  "endians".
"""

from __future__ import annotations

import struct

from ctfc.core import pcap
from ctfc.core.encodings import utf16_byteswap_decode, utf16_byteswap_ok
from ctfc.core.solve import solve
from tests.make_fixtures import ethernet_ipv4, pcap_packet, udp_datagram

FLAG = b"CYBN{ev1l_b1t_3xf1l}"


def _udp_frame(payload: bytes, evil: bool) -> bytes:
    """An Ethernet/IPv4/UDP frame, with the IP reserved (evil) flag optionally set."""
    frame = bytearray(ethernet_ipv4("10.0.1.10", "10.0.1.5", 17, udp_datagram(4444, 9999, payload)))
    if evil:
        frame[20] |= 0x80  # IP flags byte = ethernet(14) + IP header offset 6
    return bytes(frame)


def _pcap(frames: list[bytes]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # link type 1
    return header + b"".join(pcap_packet(frame, 1700000000 + i) for i, frame in enumerate(frames))


# ---------------------------------------------------------------- evil bit


def test_evil_bit_splits_a_one_byte_per_packet_channel():
    # The flag goes one byte per clean packet; decoy bytes ride on evil packets.
    decoys = b"XQZ9kLmPpWvT!?aA#" * 2
    frames = []
    flag_iter = iter(FLAG)
    decoy_iter = iter(decoys)
    for want_flag in [True, False, True, False] * 20:
        try:
            byte = bytes([next(flag_iter)]) if want_flag else bytes([next(decoy_iter)])
        except StopIteration:
            continue
        frames.append(_udp_frame(byte, evil=not want_flag))
    report = pcap.analyse(_pcap(frames))
    clean = next(o for o in report.objects if "no-evil-bit" in o.name)
    assert clean.data == FLAG


def test_solve_reads_the_evil_bit_flag():
    frames = []
    flag_iter = iter(FLAG)
    for want_flag in [True, False] * 60:
        if want_flag:
            try:
                frames.append(_udp_frame(bytes([next(flag_iter)]), evil=False))
            except StopIteration:
                pass
        else:
            frames.append(_udp_frame(b"Z", evil=True))
    report = solve(_pcap(frames), "ebe.pcap")
    assert any(f.text == FLAG.decode() for f in report.flags)


def test_a_flow_without_evil_packets_gets_no_split():
    frames = [_udp_frame(bytes([b]), evil=False) for b in FLAG]
    report = pcap.analyse(_pcap(frames))
    assert not any("evil-bit" in o.name for o in report.objects)


# ---------------------------------------------------------------- UTF-16 endian swap


def _mangle(flag: bytes) -> bytes:
    """ASCII read the wrong way round: bytes -> UTF-16BE code units -> UTF-8 (CJK)."""
    return flag.decode("ascii").encode("utf-16-le").decode("utf-16-be").encode("utf-8")


def test_utf16_byteswap_recovers_ascii():
    mangled = _mangle(FLAG)
    assert utf16_byteswap_ok(mangled)
    assert utf16_byteswap_decode(mangled) == FLAG


def test_utf16_byteswap_leaves_real_text_alone():
    # The gate (applicable) is what keeps the decoder off ordinary text: plain
    # ASCII, real CJK and Latin-1 all fail it, so decode is never tried on them.
    assert not utf16_byteswap_ok("こんにちは世界、これはテスト".encode())
    assert not utf16_byteswap_ok(b"hello world, this is plain ascii")
    assert not utf16_byteswap_ok(b"cafe resume decode")


def test_solve_reads_the_endian_swapped_flag():
    report = solve(_mangle(FLAG), "chall.txt")
    assert any(f.text == FLAG.decode() for f in report.flags)
