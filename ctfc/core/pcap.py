"""Read a packet capture with the standard library only, and pull the payloads out.

Why this exists: in a forensics CTF the flag is very often *inside* a capture -
an HTTP response body, a file posted to a server, or a DNS exfiltration where
each query carries a few base32 characters of the secret. Wireshark can export
those by hand; this does it in one command and then hands everything to the rest
of ctfc (`detect`, `auto`, `scan`), which is where the decoding happens.

No dependency: both capture formats are simple enough to parse directly.

    classic pcap: a 24-byte global header, then (16-byte header + bytes) per packet
    pcapng:       a chain of blocks (type, length, body, length again)

Then the usual stack is walked by hand: Ethernet -> IP(v4/v6) -> TCP/UDP. TCP
streams are reassembled by sequence number, which is what makes an HTTP body
readable again when it was split across packets.

What it does *not* do: no decryption of TLS, no IP defragmentation, no retransmit
heuristics beyond "lowest sequence number wins". It is a payload extractor, not
Wireshark, and it says so when a stream looks incomplete.
"""

from __future__ import annotations

import gzip
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core import usb

# Capture file magics.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanoseconds
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006

# Link types we know how to strip (https://www.tcpdump.org/linktypes.html).
LINK_ETHERNET = 1
LINK_NULL = 0
LINK_RAW_IP = 101
LINK_LINUX_SLL = 113
LINK_LINUX_SLL2 = 276

MAX_OBJECT = 8 * 1024 * 1024  # a single extracted object is capped
HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE")


class PcapError(ValueError):
    """Raised when the file is not a capture we can read. The message says why."""


@dataclass
class Packet:
    """One captured packet, already stripped down to its transport payload."""

    number: int
    protocol: str  # "tcp" | "udp" | "other"
    source: str  # "10.0.0.1:1234"
    destination: str
    payload: bytes
    sequence: int = 0  # TCP only

    @property
    def flow(self) -> tuple[str, str]:
        return (self.source, self.destination)


@dataclass
class Stream:
    """One direction of one TCP conversation, reassembled."""

    source: str
    destination: str
    data: bytes
    packets: int
    gaps: bool = False  # True when sequence numbers were not contiguous


@dataclass
class Extracted:
    """One payload worth looking at, with where it came from."""

    kind: str  # "http-body", "http-request", "dns-exfil", "tcp-stream", "udp-payload"
    name: str  # a file name to save it under
    data: bytes
    description: str
    source: str = ""
    destination: str = ""
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "length": len(self.data),
            "description": self.description,
            "source": self.source,
            "destination": self.destination,
            "details": list(self.details),
            "preview": self.data[:200].decode("utf-8", errors="replace"),
        }


@dataclass
class PcapReport:
    """Everything we pulled out of one capture."""

    path: str = ""
    format: str = ""
    link_type: int = 0
    packets: int = 0
    objects: list[Extracted] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "link_type": self.link_type,
            "packets": self.packets,
            "objects": [item.to_dict() for item in self.objects],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# The two file formats
# ---------------------------------------------------------------------------


def read_packets(data: bytes) -> tuple[list[bytes], int, str]:
    """Return (raw link-layer frames, link type, format name)."""
    if len(data) < 4:
        raise PcapError("file too short to be a capture")
    magic = data[:4]
    if magic in PCAP_MAGICS:
        return _read_pcap(data, *PCAP_MAGICS[magic])
    if struct.unpack("<I", magic)[0] == PCAPNG_SHB or struct.unpack(">I", magic)[0] == PCAPNG_SHB:
        return _read_pcapng(data)
    raise PcapError(
        f"unknown magic {magic.hex()}: not a pcap or pcapng file "
        "(a .pcap from tcpdump/Wireshark starts with d4c3b2a1 or 0a0d0d0a)"
    )


def _read_pcap(data: bytes, endian: str, _resolution: int) -> tuple[list[bytes], int, str]:
    """Classic libpcap: one global header, then a header per packet."""
    if len(data) < 24:
        raise PcapError("truncated pcap global header")
    link_type = struct.unpack(endian + "I", data[20:24])[0]
    frames = []
    offset = 24
    while offset + 16 <= len(data):
        _ts_sec, _ts_frac, captured, _original = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if captured > len(data) - offset:
            captured = len(data) - offset  # truncated file: keep what is there
        frames.append(data[offset : offset + captured])
        offset += captured
    return frames, link_type, "pcap"


def _read_pcapng(data: bytes) -> tuple[list[bytes], int, str]:
    """pcapng: a chain of blocks. We only need the interface and packet blocks."""
    endian = "<"
    if struct.unpack(">I", data[:4])[0] == PCAPNG_SHB:
        # The byte-order magic inside the section header block decides.
        if struct.unpack(">I", data[8:12])[0] == 0x1A2B3C4D:
            endian = ">"
    frames: list[bytes] = []
    link_type = LINK_ETHERNET
    offset = 0
    while offset + 8 <= len(data):
        block_type, block_length = struct.unpack(endian + "II", data[offset : offset + 8])
        if block_length < 12 or offset + block_length > len(data):
            break  # truncated or nonsense: stop cleanly with what we have
        body = data[offset + 8 : offset + block_length - 4]
        if block_type == PCAPNG_SHB and len(body) >= 4:
            if struct.unpack(">I", body[:4])[0] == 0x1A2B3C4D:
                endian = ">"
            elif struct.unpack("<I", body[:4])[0] == 0x1A2B3C4D:
                endian = "<"
        elif block_type == PCAPNG_IDB and len(body) >= 2:
            link_type = struct.unpack(endian + "H", body[:2])[0]
        elif block_type == PCAPNG_EPB and len(body) >= 20:
            captured = struct.unpack(endian + "I", body[12:16])[0]
            frames.append(body[20 : 20 + captured])
        elif block_type == PCAPNG_SPB and len(body) >= 4:
            frames.append(body[4:])
        offset += block_length
    return frames, link_type, "pcapng"


# ---------------------------------------------------------------------------
# The protocol stack, walked by hand
# ---------------------------------------------------------------------------


def strip_link_layer(frame: bytes, link_type: int) -> bytes | None:
    """Remove the link-layer header and return the IP packet, or None."""
    if link_type == LINK_ETHERNET:
        if len(frame) < 14:
            return None
        ether_type = struct.unpack(">H", frame[12:14])[0]
        if ether_type == 0x8100 and len(frame) >= 18:  # 802.1Q VLAN tag
            return frame[18:]
        if ether_type in (0x0800, 0x86DD):
            return frame[14:]
        return None
    if link_type == LINK_RAW_IP:
        return frame
    if link_type == LINK_NULL:
        return frame[4:] if len(frame) > 4 else None
    if link_type == LINK_LINUX_SLL:
        return frame[16:] if len(frame) > 16 else None
    if link_type == LINK_LINUX_SLL2:
        return frame[20:] if len(frame) > 20 else None
    return None


def _ipv4_address(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw)


def _ipv6_address(raw: bytes) -> str:
    groups = [raw[index : index + 2].hex() for index in range(0, 16, 2)]
    return ":".join(group.lstrip("0") or "0" for group in groups)


def parse_packet(frame: bytes, link_type: int, number: int) -> Packet | None:
    """Ethernet -> IP -> TCP/UDP, returning the transport payload."""
    packet = strip_link_layer(frame, link_type)
    if not packet:
        return None

    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            return None
        header_length = (packet[0] & 0x0F) * 4
        if header_length < 20 or len(packet) < header_length:
            return None
        protocol_number = packet[9]
        source_ip = _ipv4_address(packet[12:16])
        destination_ip = _ipv4_address(packet[16:20])
        body = packet[header_length:]
    elif version == 6:
        if len(packet) < 40:
            return None
        protocol_number = packet[6]
        source_ip = _ipv6_address(packet[8:24])
        destination_ip = _ipv6_address(packet[24:40])
        body = packet[40:]
    else:
        return None

    if protocol_number == 6 and len(body) >= 20:  # TCP
        source_port, destination_port, sequence = struct.unpack(">HHI", body[:8])
        data_offset = (body[12] >> 4) * 4
        if data_offset < 20 or len(body) < data_offset:
            return None
        return Packet(
            number=number,
            protocol="tcp",
            source=f"{source_ip}:{source_port}",
            destination=f"{destination_ip}:{destination_port}",
            payload=body[data_offset:],
            sequence=sequence,
        )
    if protocol_number == 17 and len(body) >= 8:  # UDP
        source_port, destination_port = struct.unpack(">HH", body[:4])
        return Packet(
            number=number,
            protocol="udp",
            source=f"{source_ip}:{source_port}",
            destination=f"{destination_ip}:{destination_port}",
            payload=body[8:],
        )
    return Packet(
        number=number,
        protocol="other",
        source=source_ip,
        destination=destination_ip,
        payload=body,
    )


def reassemble_tcp(packets: list[Packet]) -> list[Stream]:
    """Rebuild each direction of each TCP conversation, ordered by sequence number.

    Retransmissions and overlaps are resolved the simple way: a byte range already
    seen is not written twice. A hole in the sequence numbers is reported (`gaps`)
    rather than silently glued over, because a glued-over hole gives a corrupted
    file and an hour of confusion.
    """
    flows: dict[tuple[str, str], list[Packet]] = {}
    for packet in packets:
        if packet.protocol != "tcp" or not packet.payload:
            continue
        flows.setdefault(packet.flow, []).append(packet)

    streams = []
    for (source, destination), flow_packets in flows.items():
        flow_packets.sort(key=lambda item: (item.sequence, item.number))
        base = flow_packets[0].sequence
        chunks: dict[int, bytes] = {}
        for packet in flow_packets:
            offset = packet.sequence - base
            if offset < 0:  # sequence wrapped or a stray packet: skip it
                continue
            chunks.setdefault(offset, packet.payload)
        out = bytearray()
        gaps = False
        for offset in sorted(chunks):
            if offset > len(out):
                gaps = True
                out.extend(b"\x00" * (offset - len(out)))
            piece = chunks[offset]
            out[offset : offset + len(piece)] = piece
            if len(out) > MAX_OBJECT:
                break
        streams.append(
            Stream(
                source=source,
                destination=destination,
                data=bytes(out),
                packets=len(flow_packets),
                gaps=gaps,
            )
        )
    return streams


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

HEADER_END = re.compile(rb"\r?\n\r?\n")


def _split_headers(data: bytes) -> tuple[bytes, bytes] | None:
    match = HEADER_END.search(data)
    if match is None:
        return None
    return data[: match.start()], data[match.end() :]


def _header_value(headers: bytes, name: bytes) -> bytes:
    for line in headers.split(b"\n"):
        if line.lower().startswith(name.lower() + b":"):
            return line.split(b":", 1)[1].strip()
    return b""


def _dechunk(body: bytes) -> tuple[bytes, bool]:
    """Undo HTTP chunked transfer encoding. Returns (body, was_chunked)."""
    out = bytearray()
    rest = body
    while True:
        line_end = rest.find(b"\n")
        if line_end == -1:
            break
        try:
            size = int(rest[:line_end].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(body), False
        rest = rest[line_end + 1 :]
        if size == 0:
            return bytes(out), True
        out += rest[:size]
        rest = rest[size:].lstrip(b"\r\n")
    return bytes(out) if out else bytes(body), bool(out)


def _decompress_body(body: bytes, encoding: bytes) -> tuple[bytes, str]:
    """Undo Content-Encoding, so the body is the actual file."""
    lowered = encoding.lower()
    try:
        if b"gzip" in lowered:
            return gzip.decompress(body), "gzip-decompressed"
        if b"deflate" in lowered:
            try:
                return zlib.decompress(body), "deflate-decompressed"
            except zlib.error:
                return zlib.decompress(body, -15), "raw-deflate-decompressed"
    except (OSError, zlib.error, EOFError):
        return body, f"{lowered.decode('ascii', 'replace')} body, but it failed to decompress"
    return body, ""


def extract_http(stream: Stream) -> list[Extracted]:
    """Pull requests and response bodies out of one reassembled TCP stream."""
    data = stream.data
    objects: list[Extracted] = []

    # Responses: one or more "HTTP/1.x <code>" blocks.
    for match in re.finditer(rb"HTTP/1\.[01] (\d{3})", data):
        start = match.start()
        split = _split_headers(data[start:])
        if split is None:
            continue
        headers, body = split
        status = match.group(1).decode()
        length = _header_value(headers, b"content-length")
        if length.isdigit():
            body = body[: int(length)]
        else:
            # Until the next response in the same stream, if any.
            following = re.search(rb"HTTP/1\.[01] \d{3}", data[start + len(headers) :])
            if following is not None:
                body = body[: following.start()]
        details = [f"status {status}"]
        content_type = _header_value(headers, b"content-type")
        if content_type:
            details.append("content-type " + content_type.decode("ascii", "replace")[:60])

        encoding = _header_value(headers, b"transfer-encoding")
        if b"chunked" in encoding.lower():
            body, was_chunked = _dechunk(body)
            if was_chunked:
                details.append("chunked transfer-encoding undone")
        body, note = _decompress_body(body, _header_value(headers, b"content-encoding"))
        if note:
            details.append(note)
        if not body:
            continue
        objects.append(
            Extracted(
                kind="http-body",
                name=f"http_{stream.source.replace(':', '_')}_{len(objects)}.bin",
                data=body[:MAX_OBJECT],
                description=f"HTTP {status} response body ({len(body)} bytes)",
                source=stream.source,
                destination=stream.destination,
                details=details,
            )
        )

    # Requests: the interesting part is usually a POST body (an upload).
    for method in HTTP_METHODS:
        for match in re.finditer(re.escape(method) + rb" (\S+) HTTP/1\.[01]", data):
            start = match.start()
            split = _split_headers(data[start:])
            if split is None:
                continue
            headers, body = split
            path = match.group(1).decode("ascii", "replace")
            host = _header_value(headers, b"host").decode("ascii", "replace")
            length = _header_value(headers, b"content-length")
            if length.isdigit():
                body = body[: int(length)]
            elif method != b"POST":
                body = b""
            details = [f"{method.decode()} {path}"]
            if host:
                details.append(f"host {host}")
            payload = body if body else headers
            objects.append(
                Extracted(
                    kind="http-request",
                    name=f"request_{method.decode().lower()}_{len(objects)}.bin",
                    data=payload[:MAX_OBJECT],
                    description=(
                        f"{method.decode()} {path}"
                        + (f" with a {len(body)}-byte body" if body else " (headers only)")
                    ),
                    source=stream.source,
                    destination=stream.destination,
                    details=details,
                )
            )
    return objects


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def parse_dns_question(payload: bytes) -> str | None:
    """The queried name of a DNS message, as dotted text."""
    if len(payload) < 13:
        return None
    questions = struct.unpack(">H", payload[4:6])[0]
    if questions < 1:
        return None
    labels = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        if length & 0xC0:  # a compression pointer has no place in a question
            return None
        offset += 1
        label = payload[offset : offset + length]
        if len(label) < length:
            return None
        labels.append(label.decode("latin-1"))
        offset += length
    return ".".join(labels) if labels else None


def extract_dns(packets: list[Packet]) -> list[Extracted]:
    """Rebuild a DNS exfiltration: the payload travels in the subdomain labels.

    Tunnelling tools differ in the details, so the queries are read in the most
    general way and the likely variants are all offered:

        MFRGGZDF.exfil.example.com                       one label per query
        s001x.89504e470d0a1a0a.0000000d49.data.lab       several labels, a counter

    1. queries are grouped by their last two labels (the domain the attacker
       controls) and kept in capture order, exact repeats (retries) dropped;
    2. labels that are the SAME in every query ("exfil", "data") carry nothing:
       they are dropped, at both ends;
    3. what is left is joined, query after query. When the first remaining label
       changes every time but is short and regular (s001x, s002x...), it is a
       sequence counter: a second variant without it is offered too;
    4. a variant that decodes (hex, base32, base64) to bytes holding a known file
       signature is ALSO given as that file, cut at the signature - junk before a
       PNG's magic is what the challenge writers like to add.

    `auto` then reads each text variant like any other input.
    """
    groups: dict[str, list[list[str]]] = {}
    for packet in packets:
        if packet.protocol != "udp" or not packet.destination.endswith(":53"):
            continue
        name = parse_dns_question(packet.payload)
        if not name:
            continue
        labels = name.split(".")
        if len(labels) < 3:
            continue  # nothing in front of the domain
        rows = groups.setdefault(".".join(labels[-2:]), [])
        payload = labels[:-2]
        if not rows or rows[-1] != payload:  # an exact repeat is a DNS retry
            rows.append(payload)

    objects = []
    for domain, rows in groups.items():
        if len(rows) < 3:
            continue  # three queries is the minimum that looks deliberate
        rows = _drop_constant_labels(rows)
        if not any(rows):
            continue
        variants = [("", rows, "all the labels in front of the domain")]
        if _first_label_is_a_counter(rows):
            variants.append(
                (
                    "_nocounter",
                    [row[1:] for row in rows],
                    f"without the first label ({rows[0][0]}, {rows[1][0]}, ...), "
                    "a sequence counter",
                )
            )
        for suffix, chosen, how in variants:
            joined = "".join("".join(row) for row in chosen)
            if len(joined) < 8:
                continue
            base = f"dns_{domain.replace('.', '_')}{suffix}"
            objects.append(
                Extracted(
                    kind="dns-exfil",
                    name=f"{base}.txt",
                    data=joined.encode(),
                    description=f"{len(rows)} DNS queries under {domain}: {how}, concatenated",
                    details=[
                        "first queries: " + ", ".join(".".join(row) for row in rows[:3]),
                        f"{len(joined)} characters in total",
                        "feed it to `ctfc auto`: hex, base32 and base64 are the usual encodings",
                    ],
                )
            )
            hidden = _file_in_stream(joined)
            if hidden is not None:
                encoding, offset, item = hidden
                objects.append(
                    Extracted(
                        kind="dns-exfil",
                        name=f"{base}.{item.ext}",
                        data=item.data,
                        description=(
                            f"the {encoding} stream of {domain} holds a {item.name}: cut at its "
                            f"signature, {offset} junk byte(s) before it dropped"
                        ),
                        details=[
                            f"{len(item.data)} bytes, decoded from {encoding}",
                            "this is the exfiltrated file itself: open it, or ctfc detect it",
                        ],
                    )
                )
    return objects


def _drop_constant_labels(rows: list[list[str]]) -> list[list[str]]:
    """Remove the labels that are identical in every query, at the front and the back."""
    while all(len(row) > 1 for row in rows) and len({row[-1] for row in rows}) == 1:
        rows = [row[:-1] for row in rows]
    while all(len(row) > 1 for row in rows) and len({row[0] for row in rows}) == 1:
        rows = [row[1:] for row in rows]
    return rows


def _first_label_is_a_counter(rows: list[list[str]]) -> bool:
    """s001x, s002x, ...: short, the same length everywhere, different every time."""
    if not all(len(row) >= 2 for row in rows):
        return False
    firsts = [row[0] for row in rows]
    return (
        len({len(label) for label in firsts}) == 1
        and len(firsts[0]) <= 12
        and len(set(firsts)) == len(firsts)
        and any(char.isdigit() for char in firsts[0])
    )


def _file_in_stream(text: str):
    """(encoding, junk bytes skipped, the carved file) if the decoded stream holds a file."""
    from ctfc.core.magic import match_signature
    from ctfc.core.repair import Carved, carve

    for encoding, decoder in (
        ("hex", _from_hex),
        ("base32", _from_base32),
        ("base64", _from_base64),
    ):
        raw = decoder(text)
        if raw is None or len(raw) < 16:
            continue
        sig = match_signature(raw)
        if sig is not None and not sig.weak:
            return encoding, 0, Carved(0, sig.name, sig.ext, raw)
        found = carve(raw)
        if found:
            return encoding, found[0].offset, found[0]
    return None


def _from_hex(text: str) -> bytes | None:
    try:
        return bytes.fromhex(text) if len(text) % 2 == 0 else None
    except ValueError:
        return None


def _from_base32(text: str) -> bytes | None:
    import base64
    import binascii

    cleaned = text.upper().rstrip("=")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (binascii.Error, ValueError):
        return None


def _from_base64(text: str) -> bytes | None:
    import base64
    import binascii

    cleaned = text.replace("-", "+").replace("_", "/").rstrip("=")
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


# ---------------------------------------------------------------------------
# USB
# ---------------------------------------------------------------------------


def extract_usb(frames: list[bytes], link_type: int) -> list[Extracted]:
    """Decode what was typed on each USB keyboard in the capture (see core/usb.py)."""
    objects = []
    for typed in usb.extract_keystrokes(frames, link_type):
        objects.append(
            Extracted(
                kind="usb-keystrokes",
                name=f"usb_{typed.device.replace('.', '_')}_typed.txt",
                data=typed.text.encode(),
                description=(
                    f"USB keyboard {typed.device}: {typed.reports} report(s) decoded into "
                    f"{len(typed.text)} character(s)"
                ),
                source=f"usb {typed.device}",
                details=[
                    "HID boot-protocol reports, decoded with the usage table (page 0x07)",
                    "Backspace was applied as a real deletion",
                    *typed.notes,
                ],
            )
        )
    return objects


# ---------------------------------------------------------------------------
# RADIUS PAP
# ---------------------------------------------------------------------------


def _port(endpoint: str) -> int:
    """The port number of a "host:port" string, or -1 if there is none."""
    _, _, port = endpoint.rpartition(":")
    return int(port) if port.isdigit() else -1


def extract_radius(packets: list[Packet]) -> tuple[list[Extracted], set[bytes]]:
    """Find RADIUS Access-Requests and recover the PAP password in each.

    Returns the extracted objects and the raw payloads consumed (so the generic
    UDP dump does not repeat them). The shared secret is brute-forced from the
    common list + the embedded passwords, so a capture alone yields the password.
    """
    from ctfc.core import radius

    objects: list[Extracted] = []
    consumed: set[bytes] = set()
    for packet in packets:
        if packet.protocol != "udp" or not packet.payload:
            continue
        if _port(packet.destination) not in radius.AUTH_PORTS:
            continue
        request = radius.parse_access_request(packet.payload)
        if request is None:
            continue
        consumed.add(packet.payload)
        user = request.user_name.decode("utf-8", "replace") or "?"
        found = radius.recover(request.user_password, request.authenticator)
        if found:
            best = found[0]
            objects.append(
                Extracted(
                    kind="radius-pap",
                    name=f"radius_{user}_password.txt",
                    data=best.password,
                    description=(
                        f"RADIUS PAP password for {user!r}, recovered with the shared "
                        f"secret {best.secret.decode('utf-8', 'replace')!r}"
                    ),
                    source=packet.source,
                    destination=packet.destination,
                    details=[
                        f"user {user}",
                        f"shared secret {best.secret.decode('utf-8', 'replace')!r} "
                        "(guessed from the common list)",
                        "RFC 2865 section 5.2: password XOR MD5(secret + authenticator)",
                    ],
                )
            )
        else:
            objects.append(
                Extracted(
                    kind="radius-pap",
                    name=f"radius_{user}_encrypted.bin",
                    data=request.user_password,
                    description=(
                        f"RADIUS Access-Request for {user!r}: the password is hidden and "
                        "the shared secret was not in the list"
                    ),
                    source=packet.source,
                    destination=packet.destination,
                    details=[
                        f"authenticator {request.authenticator.hex()}",
                        "try your own secret: ctfc radius "
                        f"hex:{request.user_password.hex()} "
                        f"--authenticator hex:{request.authenticator.hex()} --secret <secret>",
                    ],
                )
            )
    return objects, consumed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyse(data: bytes, path: str = "") -> PcapReport:
    """Read a capture and return everything worth looking at."""
    report = PcapReport(path=path)
    frames, link_type, kind = read_packets(data)
    report.format = kind
    report.link_type = link_type
    report.notes.append(f"{kind} file, link type {link_type}, {len(frames)} frame(s)")

    # A USB capture holds no network traffic at all: the payloads are HID reports,
    # so the whole IP/TCP walk below would find nothing.
    if link_type in usb.USB_LINK_TYPES:
        report.objects += extract_usb(frames, link_type)
        if not report.objects:
            report.notes.append(
                "USB capture, but no keyboard report was found: it may be a mouse, a "
                "storage device or bulk traffic. `ctfc scan` the payloads instead."
            )
        return report

    packets = []
    for number, frame in enumerate(frames, start=1):
        packet = parse_packet(frame, link_type, number)
        if packet is not None:
            packets.append(packet)
    report.packets = len(packets)
    if not packets:
        report.notes.append(
            "no IPv4/IPv6 packet could be parsed: unsupported link type, or the "
            "capture holds something else entirely"
        )
        return report

    streams = reassemble_tcp(packets)
    report.notes.append(f"{len(streams)} TCP stream direction(s), {report.packets} packets parsed")

    seen: set[bytes] = set()
    for stream in streams:
        http_objects = extract_http(stream)
        for item in http_objects:
            if item.data in seen:
                continue
            seen.add(item.data)
            if stream.gaps:
                item.details.append("the stream had sequence gaps: this may be incomplete")
            report.objects.append(item)
        if not http_objects and len(stream.data) >= 16:
            # Not HTTP: hand over the raw stream, it may be a custom protocol.
            if stream.data in seen:
                continue
            seen.add(stream.data)
            report.objects.append(
                Extracted(
                    kind="tcp-stream",
                    name=f"stream_{stream.source.replace(':', '_')}"
                    f"-{stream.destination.replace(':', '_')}.bin",
                    data=stream.data[:MAX_OBJECT],
                    description=(
                        f"raw TCP stream {stream.source} -> {stream.destination} "
                        f"({len(stream.data)} bytes, {stream.packets} packets)"
                    ),
                    source=stream.source,
                    destination=stream.destination,
                    details=["not HTTP: a custom protocol, or TLS"]
                    + (["sequence gaps: incomplete"] if stream.gaps else []),
                )
            )

    report.objects += extract_dns(packets)

    radius_objects, radius_payloads = extract_radius(packets)
    report.objects += radius_objects
    seen |= radius_payloads

    # UDP payloads that are not DNS, grouped per flow.
    udp: dict[tuple[str, str], bytearray] = {}
    for packet in packets:
        if packet.protocol != "udp" or packet.destination.endswith(":53") or not packet.payload:
            continue
        if packet.payload in radius_payloads:
            continue  # already handled as a RADIUS Access-Request
        udp.setdefault(packet.flow, bytearray()).extend(packet.payload)
    for (source, destination), blob in udp.items():
        if len(blob) < 16 or bytes(blob) in seen:
            continue
        report.objects.append(
            Extracted(
                kind="udp-payload",
                name=f"udp_{source.replace(':', '_')}-{destination.replace(':', '_')}.bin",
                data=bytes(blob[:MAX_OBJECT]),
                description=f"UDP payloads {source} -> {destination} ({len(blob)} bytes)",
                source=source,
                destination=destination,
            )
        )

    if not report.objects:
        report.notes.append(
            "no payload to extract: the capture may be only handshakes, or encrypted "
            "(TLS cannot be opened without the keys)"
        )
    return report


def analyse_file(path: str | Path) -> PcapReport:
    """Read a capture from disk."""
    file_path = Path(path)
    return analyse(file_path.read_bytes(), str(file_path))


# ---------------------------------------------------------------------------
# Decoding what was extracted
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One extracted object, plus what `auto` made of it."""

    extracted: Extracted
    score: float
    best: object | None = None  # a Candidate, when a decoding chain worked

    def to_dict(self) -> dict:
        return {
            **self.extracted.to_dict(),
            "score": round(self.score, 3),
            "best": self.best.to_dict() if self.best is not None else None,
        }


def solve(
    data: bytes, path: str = "", flagset=None, budget=None
) -> tuple[PcapReport, list[Finding]]:
    """Extract everything, then run the decoding chains on each object and rank them.

    This is the whole point of the command: the payloads come out of the capture
    and go straight into the machinery that already knows how to read base32,
    base64, zlib and XOR.
    """
    from ctfc.core.auto import auto_decode
    from ctfc.core.budget import Budget
    from ctfc.core.scoring import score as score_bytes

    report = analyse(data, path)
    budget = budget or Budget(max_attempts=20000, max_seconds=30)
    findings = []
    for item in report.objects:
        own_score, _reasons = score_bytes(item.data, flagset)
        slice_budget = Budget(
            max_attempts=2000,
            max_seconds=max(0.5, (budget.max_seconds - budget.elapsed()) / 4),
            cancel_event=budget.cancel_event,
        )
        candidates = auto_decode(item.data, flagset=flagset, budget=slice_budget, top_n=1)
        budget.attempts += slice_budget.attempts
        best = candidates[0] if candidates else None
        findings.append(
            Finding(
                extracted=item,
                score=max(own_score, best.score if best else 0.0),
                best=best,
            )
        )
    findings.sort(key=lambda finding: -finding.score)
    return report, findings
