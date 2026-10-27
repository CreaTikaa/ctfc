"""Packet capture tests.

The fixture `capture.pcap` is built by hand in make_fixtures (classic pcap,
Ethernet/IPv4) and hides three things: a flag in an HTTP response body, a base64
upload in a POST, and a base32 exfiltration in DNS subdomains. The TCP payload is
deliberately split across two packets so the reassembly is exercised.

The important tests are the ones that compare against **tshark**, when it is
installed: a parser checked only against itself proves nothing.
"""

import shutil
import struct
import subprocess

import pytest

from ctfc.core.pcap import (
    PcapError,
    analyse,
    analyse_file,
    extract_dns,
    parse_dns_question,
    parse_packet,
    read_packets,
    reassemble_tcp,
    solve,
    strip_link_layer,
)
from tests.make_fixtures import dns_query, ethernet_ipv4, pcap_packet, tcp_segment, udp_datagram

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
TSHARK = shutil.which("tshark")


def build_capture(frames: list[bytes]) -> bytes:
    return PCAP_HEADER + b"".join(pcap_packet(frame, 1700000000) for frame in frames)


# ---------------------------------------------------------------------------
# The file formats
# ---------------------------------------------------------------------------


def test_reads_the_classic_pcap_fixture(fixture_bytes):
    frames, link_type, kind = read_packets(fixture_bytes("capture.pcap"))
    assert kind == "pcap" and link_type == 1
    assert len(frames) == 10


def test_reads_pcapng():
    """A minimal pcapng built here: section header, interface, one packet."""
    frame = ethernet_ipv4("10.0.0.1", "10.0.0.2", 17, udp_datagram(1234, 53, dns_query("a.b.c")))
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    idb = struct.pack("<IIHHI", 0x00000001, 20, 1, 0, 65535) + struct.pack("<I", 20)
    padded = frame + b"\x00" * (-len(frame) % 4)
    epb_length = 32 + len(padded)
    epb = (
        struct.pack("<IIIIIII", 0x00000006, epb_length, 0, 0, 0, len(frame), len(frame))
        + padded
        + struct.pack("<I", epb_length)
    )
    frames, link_type, kind = read_packets(shb + idb + epb)
    assert kind == "pcapng" and link_type == 1 and len(frames) == 1
    assert frames[0] == frame


def test_rejects_something_that_is_not_a_capture():
    with pytest.raises(PcapError, match="unknown magic"):
        read_packets(b"this is not a capture at all, just bytes")
    with pytest.raises(PcapError, match="too short"):
        read_packets(b"ab")


def test_truncated_file_keeps_what_it_can():
    """A capture cut in the middle must not raise: forensics data is often partial."""
    full = build_capture([ethernet_ipv4("1.2.3.4", "5.6.7.8", 6, tcp_segment(1, 80, 1, b"hello"))])
    frames, _link, _kind = read_packets(full[:-3])
    assert len(frames) == 1 and frames[0]


# ---------------------------------------------------------------------------
# The protocol stack
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "link_type,header_size",
    [(1, 14), (101, 0), (0, 4), (113, 16), (276, 20)],
)
def test_strip_link_layer_sizes(link_type, header_size):
    payload = b"\x45" + b"\x00" * 40
    frame = b"\x00" * header_size + payload
    if link_type == 1:  # Ethernet needs a real ethertype
        frame = b"\x00" * 12 + b"\x08\x00" + payload
    assert strip_link_layer(frame, link_type) == payload


def test_unknown_ethertype_is_skipped():
    assert strip_link_layer(b"\x00" * 12 + b"\x08\x06" + b"x" * 20, 1) is None  # ARP


def test_parses_tcp_and_udp():
    tcp = ethernet_ipv4("10.0.0.1", "10.0.0.2", 6, tcp_segment(1111, 80, 42, b"body"))
    packet = parse_packet(tcp, 1, 1)
    assert packet.protocol == "tcp" and packet.payload == b"body"
    assert packet.source == "10.0.0.1:1111" and packet.destination == "10.0.0.2:80"
    assert packet.sequence == 42

    udp = ethernet_ipv4("10.0.0.1", "8.8.8.8", 17, udp_datagram(5353, 53, b"query"))
    packet = parse_packet(udp, 1, 2)
    assert packet.protocol == "udp" and packet.payload == b"query"
    assert packet.destination.endswith(":53")


def test_parses_ipv6():
    body = tcp_segment(2222, 443, 7, b"hi")
    header = struct.pack(">IHBB", 6 << 28, len(body), 6, 64) + bytes(range(16)) + bytes(range(16))
    frame = b"\x00" * 12 + b"\x86\xdd" + header + body
    packet = parse_packet(frame, 1, 1)
    assert packet is not None and packet.protocol == "tcp"
    assert packet.payload == b"hi" and ":" in packet.source


def test_reassembles_out_of_order_segments():
    """The segments arrive in the wrong order: the stream must still be right."""
    pieces = [(100, b"world!"), (0, b"hello "), (6, b"brave new ")]
    packets = [
        parse_packet(
            ethernet_ipv4("1.1.1.1", "2.2.2.2", 6, tcp_segment(1, 80, 1000 + offset, payload)),
            1,
            number,
        )
        for number, (offset, payload) in enumerate(pieces)
    ]
    stream = reassemble_tcp(packets)[0]
    assert stream.data.startswith(b"hello brave new ")
    assert stream.gaps is True, "the hole between offset 16 and 100 must be reported"


def test_retransmission_is_not_written_twice():
    segment = tcp_segment(1, 80, 1000, b"abcdef")
    frame = ethernet_ipv4("1.1.1.1", "2.2.2.2", 6, segment)
    packets = [parse_packet(frame, 1, 1), parse_packet(frame, 1, 2)]
    stream = reassemble_tcp(packets)[0]
    assert stream.data == b"abcdef"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_parse_dns_question():
    assert parse_dns_question(dns_query("chunk.exfil.example.com")) == "chunk.exfil.example.com"
    assert parse_dns_question(b"too short") is None


def test_dns_exfiltration_is_joined_in_order():
    names = ["AAAAAAAA", "BBBBBBBB", "CCCCCCCC", "DDDD"]
    packets = [
        parse_packet(
            ethernet_ipv4(
                "10.0.0.5",
                "8.8.8.8",
                17,
                udp_datagram(40000 + index, 53, dns_query(f"{name}.exfil.example.com")),
            ),
            1,
            index,
        )
        for index, name in enumerate(names)
    ]
    found = extract_dns(packets)
    assert len(found) == 1
    assert found[0].data == b"AAAAAAAABBBBBBBBCCCCCCCCDDDD"


def test_a_couple_of_lookups_is_not_an_exfiltration():
    """Two ordinary queries must not be reported: that would be noise."""
    packets = [
        parse_packet(
            ethernet_ipv4("10.0.0.5", "8.8.8.8", 17, udp_datagram(40000, 53, dns_query(name))),
            1,
            index,
        )
        for index, name in enumerate(["www.example.com", "cdn.example.com"])
    ]
    assert extract_dns(packets) == []


# ---------------------------------------------------------------------------
# End to end on the fixture
# ---------------------------------------------------------------------------


def test_extracts_the_three_payloads(fixture_bytes):
    report = analyse(fixture_bytes("capture.pcap"), "capture.pcap")
    assert report.format == "pcap" and report.packets == 10
    kinds = [item.kind for item in report.objects]
    assert kinds.count("http-body") == 1
    assert kinds.count("http-request") == 2
    assert kinds.count("dns-exfil") == 1

    body = next(item for item in report.objects if item.kind == "http-body")
    assert b"CYBN{fixture_pcap_http}" in body.data, "the body was split over two packets"
    assert "status 200" in body.details


def test_solve_decodes_every_payload(fixture_bytes):
    """The point of the command: the flags come out without any manual step."""
    _report, findings = solve(fixture_bytes("capture.pcap"), "capture.pcap")
    decoded = []
    for finding in findings:
        decoded.append(finding.best.data if finding.best is not None else finding.extracted.data)
    joined = b" ".join(decoded)
    assert b"CYBN{fixture_pcap_http}" in joined
    assert b"CYBN{fixture_pcap_upload}" in joined, "the base64 POST body must be decoded"
    assert b"CYBN{fixture_pcap_dns}" in joined, "the base32 DNS exfiltration must be decoded"
    # The DNS exfiltration is the strongest finding: a decoded flag beats plain HTML.
    assert findings[0].extracted.kind == "dns-exfil"


def test_a_capture_with_nothing_in_it_says_so():
    """Only a handshake: no payload. The honest answer is "nothing to extract"."""
    syn = ethernet_ipv4("1.1.1.1", "2.2.2.2", 6, tcp_segment(1234, 443, 1, b""))
    report = analyse(build_capture([syn, syn]))
    assert not report.objects
    assert any("no payload to extract" in note for note in report.notes)


def test_gzip_response_body_is_decompressed():
    import gzip

    body = gzip.compress(b"CYBN{gzipped_body} and some filler text to go with it.")
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    frame = ethernet_ipv4("2.2.2.2", "1.1.1.1", 6, tcp_segment(80, 1234, 1, response))
    report = analyse(build_capture([frame]))
    extracted = next(item for item in report.objects if item.kind == "http-body")
    assert b"CYBN{gzipped_body}" in extracted.data
    assert any("gzip-decompressed" in detail for detail in extracted.details)


def test_chunked_response_body_is_rebuilt():
    body = b"5\r\nCYBN{\r\n9\r\nchunked}\r\n0\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
    frame = ethernet_ipv4("2.2.2.2", "1.1.1.1", 6, tcp_segment(80, 1234, 1, response))
    report = analyse(build_capture([frame]))
    extracted = next(item for item in report.objects if item.kind == "http-body")
    assert extracted.data.startswith(b"CYBN{chunked")
    assert any("chunked" in detail for detail in extracted.details)


def test_non_http_stream_is_handed_over_raw():
    payload = bytes(range(256)) * 2
    frame = ethernet_ipv4("1.1.1.1", "2.2.2.2", 6, tcp_segment(5555, 6666, 1, payload))
    report = analyse(build_capture([frame]))
    assert report.objects[0].kind == "tcp-stream"
    assert "custom protocol" in report.objects[0].details[0]


def test_analyse_file(fixture_bytes, tmp_path):
    target = tmp_path / "copy.pcap"
    target.write_bytes(fixture_bytes("capture.pcap"))
    assert analyse_file(target).packets == 10


# ---------------------------------------------------------------------------
# Against tshark, the reference implementation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")
def test_packet_count_matches_tshark(fixture_bytes, tmp_path):
    target = tmp_path / "c.pcap"
    target.write_bytes(fixture_bytes("capture.pcap"))
    result = subprocess.run(
        [TSHARK, "-r", str(target), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    counted = len([line for line in result.stdout.split(b"\n") if line.strip()])
    assert counted == analyse(fixture_bytes("capture.pcap")).packets


@pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")
def test_dns_names_match_tshark(fixture_bytes, tmp_path):
    target = tmp_path / "c.pcap"
    target.write_bytes(fixture_bytes("capture.pcap"))
    result = subprocess.run(
        [TSHARK, "-r", str(target), "-T", "fields", "-e", "dns.qry.name"],
        capture_output=True,
        timeout=60,
    )
    reference = [line.decode() for line in result.stdout.split(b"\n") if line.strip()]
    frames, link_type, _kind = read_packets(fixture_bytes("capture.pcap"))
    ours = []
    for number, frame in enumerate(frames, start=1):
        packet = parse_packet(frame, link_type, number)
        if packet is not None and packet.protocol == "udp" and packet.destination.endswith(":53"):
            name = parse_dns_question(packet.payload)
            if name:
                ours.append(name)
    assert ours == reference


@pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")
def test_http_objects_match_tshark(fixture_bytes, tmp_path):
    """Byte-for-byte: our extracted HTTP objects must equal tshark's export."""
    import hashlib

    target = tmp_path / "c.pcap"
    target.write_bytes(fixture_bytes("capture.pcap"))
    export = tmp_path / "objects"
    export.mkdir()
    result = subprocess.run(
        [TSHARK, "-r", str(target), "--export-objects", f"http,{export}", "-q"],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    reference = {
        hashlib.md5(path.read_bytes()).hexdigest() for path in export.iterdir() if path.is_file()
    }
    assert reference, "tshark exported nothing: the fixture would be wrong"
    report = analyse(fixture_bytes("capture.pcap"))
    ours = {
        hashlib.md5(item.data).hexdigest()
        for item in report.objects
        if item.kind in ("http-body", "http-request")
    }
    assert reference <= ours, "tshark found an object we missed"
