"""Tests for USB keyboard decoding (core/usb.py) and its pcap integration."""

from __future__ import annotations

import struct
from pathlib import Path

from ctfc.core import usb
from ctfc.core.pcap import analyse
from ctfc.core.pcap import solve as solve_pcap

FIXTURES = Path(__file__).parent / "fixtures"


def report(code: int, shift: bool = False) -> bytes:
    return bytes([0x02 if shift else 0, 0, code, 0, 0, 0, 0, 0])


def test_letters_and_shift():
    # 0x04 = a, 0x05 = b
    text, _ = usb.decode_reports([report(0x04), report(0x05, shift=True)])
    assert text == "aB"


def test_digits_and_their_shifted_symbols():
    text, _ = usb.decode_reports([report(0x1E), report(0x1E, shift=True), report(0x27)])
    assert text == "1!0"


def test_backspace_really_deletes():
    text, _ = usb.decode_reports([report(0x04), report(0x05), report(0x2A), report(0x06)])
    assert text == "ac"  # a, b, backspace, c


def test_backspace_on_empty_text_is_harmless():
    text, _ = usb.decode_reports([report(0x2A), report(0x04)])
    assert text == "a"


def test_enter_and_tab_become_characters():
    text, _ = usb.decode_reports([report(0x04), report(0x28), report(0x2B), report(0x05)])
    assert text == "a\n\tb"


def test_capslock_toggles_letter_case_only():
    # Caps on, "a" -> "A", digit unaffected, caps off again.
    text, notes = usb.decode_reports(
        [report(0x39), report(0x04), report(0x1E), report(0x39), report(0x04)]
    )
    assert text == "A1a"
    assert not any("Caps Lock was left on" in note for note in notes)


def test_capslock_left_on_is_reported():
    _, notes = usb.decode_reports([report(0x39), report(0x04)])
    assert any("Caps Lock was left on" in note for note in notes)


def test_unprintable_keys_are_counted_not_dropped_silently():
    text, notes = usb.decode_reports([report(0x04), report(0x3A), report(0x05)])  # 0x3A = F1
    assert text == "ab"
    assert any("no printable character" in note for note in notes)


def test_a_mouse_report_is_not_mistaken_for_a_keyboard():
    assert not usb.looks_like_keyboard_report(b"\x00\x01\xff\xfe")  # too short
    assert not usb.looks_like_keyboard_report(bytes([0, 1, 4, 0, 0, 0, 0, 0]))  # byte 1 reserved
    assert not usb.looks_like_keyboard_report(bytes([0, 0, 0xFF, 0, 0, 0, 0, 0]))  # no such key
    assert usb.looks_like_keyboard_report(bytes([0, 0, 4, 0, 0, 0, 0, 0]))


def test_usbmon_payload_offsets():
    frame = bytes(64) + b"REPORT08"
    assert usb.usb_payload(frame, usb.LINK_USB_LINUX_MMAPPED) == b"REPORT08"
    frame48 = bytes(48) + b"REPORT08"
    assert usb.usb_payload(frame48, usb.LINK_USB_LINUX) == b"REPORT08"


def test_usbpcap_header_declares_its_own_length():
    """Windows USBPcap: the first two bytes are the header length."""
    body = report(0x04)
    header = (28).to_bytes(2, "little") + bytes(26)
    assert usb.usb_payload(header + body, usb.LINK_USBPCAP) == body
    # A nonsense length must not raise or return garbage.
    assert usb.usb_payload((9999).to_bytes(2, "little") + bytes(26), usb.LINK_USBPCAP) == b""


def test_usbpcap_capture_is_decoded_end_to_end():
    frames = []
    for code in (0x0B, 0x08, 0x0F, 0x0F, 0x12):  # h e l l o
        frames.append((28).to_bytes(2, "little") + bytes(26) + report(code))
    typed = usb.extract_keystrokes(frames, usb.LINK_USBPCAP)
    assert typed and typed[0].text == "hello"


def test_two_devices_stay_apart():
    """A keyboard and a second keyboard must not interleave into nonsense."""

    def usbmon(code: int, device: int) -> bytes:
        head = bytearray(64)
        head[11] = device
        head[12:14] = (1).to_bytes(2, "little")
        return bytes(head) + report(code)

    frames = [usbmon(0x04, 3), usbmon(0x05, 4), usbmon(0x06, 3)]
    typed = usb.extract_keystrokes(frames, usb.LINK_USB_LINUX_MMAPPED)
    texts = {item.device: item.text for item in typed}
    assert texts == {"1.3": "ac", "1.4": "b"}


def test_fixture_capture_recovers_the_typed_flag():
    data = (FIXTURES / "audit_usb_keyboard.pcap").read_bytes()
    _, findings = solve_pcap(data, "audit_usb_keyboard.pcap")
    assert findings, "nothing extracted from the USB capture"
    assert findings[0].extracted.kind == "usb-keystrokes"
    assert b"CYBN{usb_keystrokes}" in findings[0].extracted.data


def test_a_usb_capture_with_no_keyboard_says_so():
    """Mouse-only traffic: the report must explain itself, not stay silent."""
    mouse = bytes(64) + b"\x00\x01\xff"
    capture = (
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 220)
        + struct.pack("<IIII", 0, 0, len(mouse), len(mouse))
        + mouse
    )
    result = analyse(capture)
    assert not result.objects
    assert any("no keyboard report" in note for note in result.notes)
