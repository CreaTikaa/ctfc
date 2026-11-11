"""Lot K: IEEE 802.11 (Wi-Fi) captures (core/wifi.py and its pcap integration).

Two shapes a Wi-Fi forensics challenge has: an open network whose data frames
carry ordinary IP traffic (read end to end), and a WPA network whose 4-way
handshake is in the capture (reported with the hashcat command). The fixtures
are checked against tshark where it is installed.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from ctfc.core import pcap, wifi
from ctfc.core.solve import solve

FIXTURES = Path(__file__).parent / "fixtures"
HAS_TSHARK = shutil.which("tshark") is not None


def test_open_network_data_frame_becomes_ip():
    data = (FIXTURES / "wifi_open.pcap").read_bytes()
    report = pcap.analyse(data, "wifi_open.pcap")
    assert report.packets >= 1  # the data frame was stripped to an IP packet
    kinds = {obj.kind for obj in report.objects}
    assert "udp-payload" in kinds


def test_open_network_flag_is_found_end_to_end():
    report = solve((FIXTURES / "wifi_open.pcap").read_bytes(), path="wifi_open.pcap")
    assert [flag.text for flag in report.flags] == ["CYBN{open_wifi_flag}"]


def test_wpa_handshake_is_reported_with_the_crack_command():
    data = (FIXTURES / "wifi_wpa.pcap").read_bytes()
    report = pcap.analyse(data, "wifi_wpa.pcap")
    notes = " ".join(report.notes)
    assert "WPA handshake" in notes
    assert "SecureNet" in notes
    assert "hashcat -m 22000" in notes


def test_ssid_is_extracted_as_a_searchable_object():
    data = (FIXTURES / "wifi_wpa.pcap").read_bytes()
    report = pcap.analyse(data, "wifi_wpa.pcap")
    ssid_objects = [obj for obj in report.objects if obj.kind == "wifi-ssid"]
    assert ssid_objects and b"SecureNet" in ssid_objects[0].data


def test_protected_frames_are_counted_not_read():
    data = (FIXTURES / "wifi_wpa.pcap").read_bytes()
    frames, link_type, _ = pcap.read_packets(data)
    result = wifi.analyse_wifi(frames, link_type)
    assert result.protected_frames == 5
    assert result.handshakes and result.handshakes[0].ssid == "SecureNet"


def test_radiotap_header_is_stripped():
    # A radiotap header (version 0, len 8) in front of the 802.11 frame.
    mac = b"\x08\x00\x00\x00" + b"\x02" * 18  # a short QoS-less data frame header
    radiotap = struct.pack("<BBH", 0, 0, 8) + b"\x00\x00\x00\x00" + mac
    assert wifi.dot11_frame(radiotap, wifi.LINK_IEEE80211_RADIOTAP) == mac


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
@pytest.mark.parametrize(
    "name, ssid",
    [("wifi_open.pcap", "CYBNet"), ("wifi_wpa.pcap", "SecureNet")],
)
def test_ssid_matches_tshark(name, ssid):
    out = subprocess.run(
        ["tshark", "-r", str(FIXTURES / name), "-T", "fields", "-e", "wlan.ssid"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    hexes = {line.strip() for line in out.stdout.splitlines() if line.strip()}
    assert ssid.encode().hex() in hexes  # tshark prints the SSID as hex
    frames, link_type, _ = pcap.read_packets((FIXTURES / name).read_bytes())
    assert ssid in wifi.analyse_wifi(frames, link_type).ssids.values()
