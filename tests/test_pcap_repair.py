"""Recovering a pcap whose magic (and per-record captured length) was smashed.

The shape of ImaginaryCTF 2023 "forensics": the global header keeps a valid
version, snaplen and link type, and each record keeps its original-length field
and its data. Ground truth: the recovered frames equal the clean capture's.
"""

from __future__ import annotations

from pathlib import Path

from ctfc.core import pcap, readers
from ctfc.core.solve import solve

FIXTURES = Path(__file__).parent / "fixtures"


def test_recovered_frames_equal_the_clean_capture():
    clean = pcap.read_packets((FIXTURES / "capture.pcap").read_bytes())
    recovered = pcap.read_packets((FIXTURES / "corrupt_magic.pcap").read_bytes())
    assert recovered[2] == "pcap (header recovered)"
    assert recovered[0] == clean[0]  # identical frames
    assert recovered[1] == clean[1]  # same link type


def test_the_reader_claims_a_recoverable_pcap():
    assert readers.sniff((FIXTURES / "corrupt_magic.pcap").read_bytes()) == "pcap"


def test_solve_reads_a_corrupted_capture():
    report = solve((FIXTURES / "corrupt_magic.pcap").read_bytes(), path="corrupt_magic.pcap")
    flags = {flag.text for flag in report.flags}
    assert "CYBN{fixture_pcap_http}" in flags


def test_header_check_is_cheap_and_not_fooled_by_noise():
    import random

    rng = random.Random(7)
    for _ in range(500):
        blob = bytes(rng.randrange(256) for _ in range(64))
        assert not pcap.looks_like_recoverable_pcap(blob)


def test_a_real_magic_is_not_treated_as_recoverable():
    # A normal pcap has its magic: the recovery path must leave it alone.
    assert not pcap.looks_like_recoverable_pcap((FIXTURES / "capture.pcap").read_bytes())
