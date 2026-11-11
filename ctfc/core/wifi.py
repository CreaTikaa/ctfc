"""Read an IEEE 802.11 (Wi-Fi) capture: open traffic, and the WPA handshake.

A whole family of forensics challenges hands over a `.pcap`/`.cap` that holds no
Ethernet at all - it is a raw Wi-Fi capture (link type 105, or 127 with a
radiotap header in front). Wireshark shows the frames; the usual answers are
"crack it with aircrack" or "strip the headers with a script". This module does
the two things that matter without either:

1. **Open traffic.** An unprotected data frame carries, after the 802.11 MAC
   header and an LLC/SNAP shim, an ordinary IP packet. Stripped to that, the
   capture flows through the same IP/TCP/HTTP/DNS walk as any Ethernet capture -
   so an open-network capture is read end to end.

2. **The WPA handshake.** A protected network cannot be decrypted without the
   passphrase, but the 4-way EAPOL handshake in the capture is exactly what
   hashcat cracks. This finds it, names the network (SSID) and the two MAC
   addresses, and prints the `hcxpcapngtool` + `hashcat -m 22000` commands. It
   does not forge the hash line itself: there is no tool on this machine to
   check that against, so it points at the one that makes it (ground-truth rule).

Everything is pure functions on bytes; nothing is executed or cracked here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Link types of a Wi-Fi capture (https://www.tcpdump.org/linktypes.html).
LINK_IEEE80211 = 105  # the 802.11 MAC frame, nothing in front
LINK_IEEE80211_RADIOTAP = 127  # a radiotap header, then the MAC frame
LINK_IEEE80211_AVS = 163  # an AVS header, then the MAC frame
LINK_PPI = 192  # a PPI header, then the MAC frame
WIFI_LINK_TYPES = (LINK_IEEE80211, LINK_IEEE80211_RADIOTAP, LINK_IEEE80211_AVS, LINK_PPI)

# Frame Control: the three frame types and the subtypes we care about.
TYPE_MANAGEMENT = 0
TYPE_DATA = 2
SUBTYPE_BEACON = 8
SUBTYPE_PROBE_RESPONSE = 5
SUBTYPE_QOS_DATA = 8  # the QoS bit of a data subtype (0x08..0x0F carry QoS control)

# LLC/SNAP shim that sits between the MAC header and the network packet.
SNAP_HEADER = b"\xaa\xaa\x03\x00\x00\x00"
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_EAPOL = 0x888E  # the 802.1X / WPA handshake


def dot11_frame(frame: bytes, link_type: int) -> bytes | None:
    """Strip whatever precedes the 802.11 MAC frame (radiotap, AVS, PPI)."""
    if link_type == LINK_IEEE80211:
        return frame
    if link_type == LINK_IEEE80211_RADIOTAP:
        # radiotap: version(1), pad(1), it_len(2, little-endian), then the frame.
        if len(frame) < 4:
            return None
        it_len = struct.unpack("<H", frame[2:4])[0]
        return frame[it_len:] if it_len <= len(frame) else None
    if link_type == LINK_IEEE80211_AVS:
        return frame[64:] if len(frame) > 64 else None  # AVS header is 64 bytes
    if link_type == LINK_PPI:
        if len(frame) < 8:
            return None
        ppi_len = struct.unpack("<H", frame[2:4])[0]
        return frame[ppi_len:] if ppi_len <= len(frame) else None
    return None


@dataclass
class Dot11:
    """The parts of an 802.11 MAC header a reader needs."""

    ftype: int
    subtype: int
    protected: bool
    header_len: int
    addr1: bytes  # receiver
    addr2: bytes  # transmitter
    addr3: bytes  # BSSID, usually
    body: bytes


def parse_dot11(frame: bytes) -> Dot11 | None:
    """Parse an 802.11 MAC header and return it plus the frame body."""
    if len(frame) < 24:
        return None
    fc0, fc1 = frame[0], frame[1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xF
    to_ds = fc1 & 0x1
    from_ds = (fc1 >> 1) & 0x1
    protected = bool((fc1 >> 6) & 0x1)
    header_len = 24
    if to_ds and from_ds:
        header_len += 6  # a fourth address (WDS)
    if ftype == TYPE_DATA and (subtype & 0x08):
        header_len += 2  # QoS control field
    if len(frame) < header_len:
        return None
    return Dot11(
        ftype=ftype,
        subtype=subtype,
        protected=protected,
        header_len=header_len,
        addr1=frame[4:10],
        addr2=frame[10:16],
        addr3=frame[16:22],
        body=frame[header_len:],
    )


def _snap_ethertype(body: bytes) -> tuple[int, bytes] | None:
    """If the body starts with an LLC/SNAP shim, return (ethertype, payload)."""
    if len(body) < 8 or body[:6] != SNAP_HEADER:
        return None
    ethertype = struct.unpack(">H", body[6:8])[0]
    return ethertype, body[8:]


def ip_payload(frame: bytes, link_type: int) -> bytes | None:
    """The IP packet inside an unprotected 802.11 data frame, or None.

    Used by the capture reader's link-layer stripping: an open-network data
    frame becomes an ordinary IP packet and flows through the normal walk.
    """
    mac = dot11_frame(frame, link_type)
    if mac is None:
        return None
    parsed = parse_dot11(mac)
    if parsed is None or parsed.ftype != TYPE_DATA or parsed.protected:
        return None
    snap = _snap_ethertype(parsed.body)
    if snap is None:
        return None
    ethertype, payload = snap
    return payload if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6) else None


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _ssids(frames: list[bytes], link_type: int) -> dict[str, str]:
    """BSSID -> network name, read from beacon and probe-response frames."""
    names: dict[str, str] = {}
    for frame in frames:
        mac = dot11_frame(frame, link_type)
        if mac is None:
            continue
        parsed = parse_dot11(mac)
        if parsed is None or parsed.ftype != TYPE_MANAGEMENT:
            continue
        if parsed.subtype not in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESPONSE):
            continue
        # After the 24-byte header come 12 fixed bytes, then tagged parameters.
        tags = parsed.body[12:]
        offset = 0
        while offset + 2 <= len(tags):
            tag_id, length = tags[offset], tags[offset + 1]
            value = tags[offset + 2 : offset + 2 + length]
            if tag_id == 0 and value:  # tag 0 = SSID
                try:
                    names.setdefault(_mac(parsed.addr3), value.decode("utf-8"))
                except UnicodeDecodeError:
                    names.setdefault(_mac(parsed.addr3), value.hex())
                break
            offset += 2 + length
    return names


@dataclass
class Handshake:
    """A WPA 4-way handshake between one access point and one client."""

    ap: str
    client: str
    ssid: str = ""
    messages: int = 0

    def to_dict(self) -> dict:
        return {"ap": self.ap, "client": self.client, "ssid": self.ssid, "messages": self.messages}


@dataclass
class WifiReport:
    """What a Wi-Fi capture holds besides its IP traffic."""

    handshakes: list[Handshake] = field(default_factory=list)
    ssids: dict[str, str] = field(default_factory=dict)
    data_frames: int = 0
    protected_frames: int = 0

    def to_dict(self) -> dict:
        return {
            "handshakes": [hs.to_dict() for hs in self.handshakes],
            "ssids": dict(self.ssids),
            "data_frames": self.data_frames,
            "protected_frames": self.protected_frames,
        }


def analyse_wifi(frames: list[bytes], link_type: int) -> WifiReport:
    """Find the WPA handshakes and the network names in a Wi-Fi capture."""
    report = WifiReport(ssids=_ssids(frames, link_type))
    # Count EAPOL messages per (access point, client) pair.
    pairs: dict[tuple[str, str], int] = {}
    for frame in frames:
        mac = dot11_frame(frame, link_type)
        if mac is None:
            continue
        parsed = parse_dot11(mac)
        if parsed is None or parsed.ftype != TYPE_DATA:
            continue
        report.data_frames += 1
        if parsed.protected:
            report.protected_frames += 1
            continue
        snap = _snap_ethertype(parsed.body)
        if snap is None or snap[0] != ETHERTYPE_EAPOL:
            continue
        # The two endpoints, ordered so the AP (also the BSSID) comes first.
        bssid = _mac(parsed.addr3)
        a, b = _mac(parsed.addr1), _mac(parsed.addr2)
        ap, client = (a, b) if a == bssid else (b, a)
        pairs[(ap, client)] = pairs.get((ap, client), 0) + 1
    for (ap, client), count in pairs.items():
        report.handshakes.append(
            Handshake(ap=ap, client=client, ssid=report.ssids.get(ap, ""), messages=count)
        )
    return report
