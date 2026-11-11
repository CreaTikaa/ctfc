"""Read what was typed on a USB keyboard that someone captured.

A whole family of forensics challenges hands you a capture that holds no network
traffic at all: it is a recording of the USB bus (`tcpdump -i usbmon1` on Linux,
USBPcap on Windows) while the victim typed a password, a command or the flag.
Wireshark shows the packets but not the text, so the usual answer is a throwaway
script plus a scancode table copied off a blog. This does it in one command.

How a USB keyboard talks
------------------------

A standard ("boot protocol") keyboard sends an 8-byte report on an interrupt IN
endpoint every time the set of held keys changes:

    byte 0   modifiers, as bit flags (0x02 = left shift, 0x20 = right shift...)
    byte 1   reserved, always 0
    byte 2-7 up to six HID usage codes of the keys currently held down

A keycode is NOT ASCII: 0x04 is "a", 0x1E is "1", 0x28 is Enter. Releasing every
key sends a report of eight zero bytes, which is why a capture is half zeros.

So the text is recovered by walking the reports in order, turning each keycode
into a character through the HID usage table (page 0x07), with the shift flag
choosing between the two characters printed on the key. Backspace is applied as a
real deletion, which matters: challenge authors type a wrong character on purpose.

Where the bytes sit in the capture
----------------------------------

The capture frames are not Ethernet, so they carry a pseudo-header that has to be
stripped before the report is visible:

    usbmon (Linux, link type 189 / 220)   48- or 64-byte header, then the data
    USBPcap (Windows, link type 249)      header whose own length is its first field

Pure functions on bytes, nothing is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Link types of a USB capture (https://www.tcpdump.org/linktypes.html).
LINK_USB_LINUX = 189  # usbmon, 48-byte header
LINK_USB_LINUX_MMAPPED = 220  # usbmon, 64-byte header
LINK_USBPCAP = 249  # USBPcap on Windows, variable header
USB_LINK_TYPES = (LINK_USB_LINUX, LINK_USB_LINUX_MMAPPED, LINK_USBPCAP)

HID_REPORT_SIZE = 8  # a boot-protocol keyboard report
# Modifier bits of byte 0 that mean "shift is held" (left or right).
SHIFT_BITS = 0x22
# ... and "Ctrl is held" (left 0x01, right 0x10).
CTRL_BITS = 0x11
# Keycodes handled on their own rather than through the table below.
KEY_ENTER = 0x28
KEY_BACKSPACE = 0x2A
KEY_TAB = 0x2B
KEY_CAPSLOCK = 0x39
KEY_KEYPAD_ENTER = 0x58

# HID usage page 0x07: (unshifted, shifted) for every printable key.
# Built from the ranges first, then the punctuation, which is easier to check
# against the table in the HID spec than one long literal dict.
KEYMAP: dict[int, tuple[str, str]] = {}
for _code in range(0x04, 0x1E):  # 0x04..0x1D = a..z
    _letter = chr(ord("a") + _code - 0x04)
    KEYMAP[_code] = (_letter, _letter.upper())
for _code, _pair in enumerate(
    [
        ("1", "!"),
        ("2", "@"),
        ("3", "#"),
        ("4", "$"),
        ("5", "%"),
        ("6", "^"),
        ("7", "&"),
        ("8", "*"),
        ("9", "("),
        ("0", ")"),
    ],
    start=0x1E,  # 0x1E..0x27 = 1..9 then 0
):
    KEYMAP[_code] = _pair
KEYMAP.update(
    {
        0x2C: (" ", " "),
        0x2D: ("-", "_"),
        0x2E: ("=", "+"),
        0x2F: ("[", "{"),
        0x30: ("]", "}"),
        0x31: ("\\", "|"),
        0x32: ("#", "~"),  # non-US key next to Enter
        0x33: (";", ":"),
        0x34: ("'", '"'),
        0x35: ("`", "~"),
        0x36: (",", "<"),
        0x37: (".", ">"),
        0x38: ("/", "?"),
        # Keypad, which some authors use for digits.
        0x54: ("/", "/"),
        0x55: ("*", "*"),
        0x56: ("-", "-"),
        0x57: ("+", "+"),
        0x59: ("1", "1"),
        0x5A: ("2", "2"),
        0x5B: ("3", "3"),
        0x5C: ("4", "4"),
        0x5D: ("5", "5"),
        0x5E: ("6", "6"),
        0x5F: ("7", "7"),
        0x60: ("8", "8"),
        0x61: ("9", "9"),
        0x62: ("0", "0"),
        0x63: (".", "."),
    }
)


def usb_payload(frame: bytes, link_type: int) -> bytes:
    """Strip the capture's USB pseudo-header and return the transferred bytes."""
    if link_type == LINK_USB_LINUX:
        return frame[48:] if len(frame) > 48 else b""
    if link_type == LINK_USB_LINUX_MMAPPED:
        return frame[64:] if len(frame) > 64 else b""
    if link_type == LINK_USBPCAP:
        if len(frame) < 2:
            return b""
        header_length = int.from_bytes(frame[0:2], "little")
        # The header declares its own length; anything shorter is a broken frame.
        if not 27 <= header_length <= len(frame):
            return b""
        return frame[header_length:]
    return b""


def usb_device(frame: bytes, link_type: int) -> str:
    """Which device the frame belongs to ("bus.device"), so two keyboards stay apart."""
    if link_type in (LINK_USB_LINUX, LINK_USB_LINUX_MMAPPED) and len(frame) >= 14:
        device = frame[11]
        bus = int.from_bytes(frame[12:14], "little")
        return f"{bus}.{device}"
    if link_type == LINK_USBPCAP and len(frame) >= 21:
        bus = int.from_bytes(frame[17:19], "little")
        device = int.from_bytes(frame[19:21], "little")
        return f"{bus}.{device}"
    return "?"


def looks_like_keyboard_report(data: bytes) -> bool:
    """Is this 8-byte payload a boot-protocol keyboard report?

    Byte 1 is reserved and must be zero, and the six key slots must hold codes
    that exist. That is enough to tell a keyboard apart from a mouse (which sends
    3-5 bytes) or from bulk data that happens to be 8 bytes long.
    """
    if len(data) != HID_REPORT_SIZE or data[1] != 0:
        return False
    # 0x00 is "no key", 0x01-0x03 are error roll-over codes; above 0xA4 nothing
    # is a key a challenge would ever type.
    return all(code <= 0xA4 for code in data[2:])


@dataclass
class Keystrokes:
    """What one device typed, and how sure we are it was a keyboard."""

    device: str
    text: str
    reports: int  # non-empty reports decoded
    notes: list[str] = field(default_factory=list)


def _delete_word(out: list[str]) -> None:
    """Ctrl+Backspace: delete the word before the cursor, as a text field does.

    Trailing spaces go first, then either a run of word characters (letters,
    digits, underscore) or, if the cursor sits after punctuation, that one run
    of punctuation.
    """
    while out and out[-1] in " \t":
        out.pop()
    if not out:
        return
    is_word = out[-1].isalnum() or out[-1] == "_"
    while out and out[-1] not in " \t\n" and (out[-1].isalnum() or out[-1] == "_") == is_word:
        out.pop()


def decode_reports(reports: list[bytes]) -> tuple[str, list[str]]:
    """Turn a list of 8-byte keyboard reports into the text that was typed.

    A report lists every key HELD at that moment, not the keys just pressed: a
    fast typist's "t" then "r" arrives as [t], [t, r], [r], []. So a character
    is typed only for a key that was not already in the previous report - and
    the empty "all released" reports must stay in the list for that to work.

    Backspace deletes a character, Ctrl+Backspace a word, Enter and Tab become
    real characters, Caps Lock toggles the letter case. Keys with no printable
    character (F1, arrows, other Ctrl combinations) are skipped but counted, and
    the count is reported so nothing is silently lost.
    """
    out: list[str] = []
    notes: list[str] = []
    caps = False
    skipped = 0
    held: set[int] = set()
    for report in reports:
        modifiers = report[0]
        shift = bool(modifiers & SHIFT_BITS)
        ctrl = bool(modifiers & CTRL_BITS)
        now = {code for code in report[2:] if code > 3}  # 1-3: roll-over error codes
        pressed = [code for code in report[2:] if code > 3 and code not in held]
        held = now
        for code in pressed:
            if code == KEY_CAPSLOCK:
                caps = not caps
                continue
            if code == KEY_BACKSPACE:
                if ctrl:
                    _delete_word(out)
                elif out:
                    out.pop()
                continue
            if code in (KEY_ENTER, KEY_KEYPAD_ENTER):
                out.append("\n")
                continue
            if code == KEY_TAB:
                out.append("\t")
                continue
            pair = KEYMAP.get(code)
            if pair is None or ctrl:
                skipped += 1  # no character, or a shortcut (Ctrl+C, Ctrl+V...)
                continue
            character = pair[1] if shift else pair[0]
            # Caps Lock affects letters only, and flips what shift decided.
            if caps and character.isalpha():
                character = character.upper() if not shift else character.lower()
            out.append(character)
    if skipped:
        notes.append(f"{skipped} keypress(es) with no printable character were skipped")
    if caps:
        notes.append("Caps Lock was left on at the end of the capture")
    return "".join(out), notes


def extract_keystrokes(frames: list[bytes], link_type: int) -> list[Keystrokes]:
    """Find every USB keyboard in the capture and decode what each one typed.

    Reports are grouped per device so that a capture of a keyboard plus a mouse,
    or of two keyboards, does not end up interleaved into nonsense.
    """
    if link_type not in USB_LINK_TYPES:
        return []
    per_device: dict[str, list[bytes]] = {}
    for frame in frames:
        data = usb_payload(frame, link_type)
        if not looks_like_keyboard_report(data):
            continue
        # The "all released" reports are kept: they are what tells a second
        # press of the same key ("ll") apart from the key being held.
        per_device.setdefault(usb_device(frame, link_type), []).append(data)
    results = []
    for device, reports in per_device.items():
        text, notes = decode_reports(reports)
        if not text:
            continue
        typed = sum(1 for report in reports if any(report[2:]))
        results.append(Keystrokes(device=device, text=text, reports=typed, notes=notes))
    # The device that typed the most is almost always the interesting one.
    results.sort(key=lambda item: -len(item.text))
    return results


def snippet(link_type: int) -> str:
    """A standalone script that redoes the extraction (teaching layer)."""
    offsets = {LINK_USB_LINUX: 48, LINK_USB_LINUX_MMAPPED: 64}
    if link_type in offsets:
        strip = f"data = frame[{offsets[link_type]}:]  # strip the usbmon pseudo-header"
    else:
        strip = (
            "data = frame[int.from_bytes(frame[0:2], 'little'):]  "
            "# USBPcap: the header says its own length"
        )
    return (
        "# USB keyboard reports -> text. Needs only the standard library.\n"
        "from ctfc.core.pcap import read_packets\n"
        "from ctfc.core.usb import decode_reports, looks_like_keyboard_report\n"
        "\n"
        "frames, link_type, _ = read_packets(open('capture.pcap', 'rb').read())\n"
        "reports = []\n"
        "for frame in frames:\n"
        f"    {strip}\n"
        "    if looks_like_keyboard_report(data):  # keep the releases too\n"
        "        reports.append(data)\n"
        "print(decode_reports(reports)[0])\n"
    )
