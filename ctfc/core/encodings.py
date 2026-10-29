"""Decoders for common encodings and compression formats.

An *encoding* (hex, base64, ...) only changes how bytes are written: no key, anyone
can reverse it. *Compression* (zlib, gzip, ...) shrinks data; compressed data looks
random, like encrypted data, but starts with recognisable header bytes.

Every decoder is one `Decoder` entry in the `DECODERS` list below, with:
- `applicable(data)`: a cheap test, "is it worth trying?" (keeps `auto` fast)
- `decode(data)`: the real decoding; raises DecodeError if it fails
- `python`: the line(s) that do the same thing in a standalone script
- `cyberchef`: the matching CyberChef operation (checked against CyberChef in M6)

To add a decoder: write the two functions, then add a `Decoder(...)` to `DECODERS`.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import html
import lzma
import quopri
import re
import string
import urllib.parse
import zlib
from collections.abc import Callable
from dataclasses import dataclass

from ctfc.core.inputs import clean_hex, looks_like_hex

MAX_OUTPUT = 64 * 1024 * 1024  # decompression stops here (protects against zip bombs)
PRINTABLE = set(string.printable)

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B85_CHARS = set(string.digits + string.ascii_letters + "!#$%&()*+-;<=>?@^_`{|}~")
A85_CHARS = {chr(c) for c in range(33, 118)} | {"z"}

# Zero-width characters used to hide data inside normal-looking text.
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
}


class DecodeError(ValueError):
    """The data is not valid for this decoder."""


@dataclass(frozen=True)
class Decoder:
    name: str  # short id, used in chains: "base64", "zlib", ...
    label: str  # human-readable name
    decode: Callable[[bytes], bytes]
    applicable: Callable[[bytes], bool]
    imports: tuple[str, ...] = ()  # modules the python snippet needs
    python: str = ""  # code transforming the variable `data` (bytes -> bytes)
    helper: str = ""  # extra function(s) the snippet needs
    cyberchef: str | None = None


# ---------------------------------------------------------------------------
# Custom base64 alphabets
# ---------------------------------------------------------------------------

STANDARD_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# 64 distinct characters in a row, from the set alphabets are written with.
ALPHABET_RUN = re.compile(r"[A-Za-z0-9+/=_\-.!@#$%^&*(){}\[\]|~<>?,;:]{64,4096}")


def find_custom_alphabet(data: bytes, limit: int = 1_000_000) -> tuple[str, int] | None:
    """Find a (non-standard) base64 alphabet written inside the data.

    Obfuscators love shuffling the alphabet: the payload then looks like base64,
    decodes to nothing with the standard table, and the shuffled table is sitting
    right there in the same file. Returns (alphabet, offset) or None.
    """
    text = data[:limit].decode("latin-1")
    for match in ALPHABET_RUN.finditer(text):
        run = match.group(0)
        for start in range(len(run) - 63):
            window = run[start : start + 64]
            if len(set(window)) == 64 and window != STANDARD_B64_ALPHABET:
                return window, match.start() + start
    return None


def decode_custom_base64(data: bytes, alphabet: str) -> bytes:
    """Decode base64 written with `alphabet` instead of the standard table.

    The trick itself is a plain character translation to the standard alphabet,
    then a normal base64 decode. The fiddly part is finding *what* to decode: a
    custom alphabet contains most letters and digits, so "keep every character
    the alphabet knows" would swallow the whole script around the payload.

    So we work like the `extract_base64` decoder: drop the alphabet declaration
    itself (it is a 64-character run in its own alphabet), then take the longest
    remaining run of alphabet characters.
    """
    if len(set(alphabet)) != 64:
        raise DecodeError(f"an alphabet needs 64 distinct characters, got {len(set(alphabet))}")
    text = data.decode("latin-1")
    # The alphabet is usually declared right next to the payload: remove it, or it
    # would be the longest run and decode to nothing useful.
    text = text.replace(alphabet, " ")
    allowed = set(alphabet) | {"="}
    best = ""
    current: list[str] = []
    for char in text:
        if char in allowed:
            current.append(char)
            continue
        if len(current) > len(best):
            best = "".join(current)
        current = []
    if len(current) > len(best):
        best = "".join(current)
    if len(best) < 8:
        raise DecodeError("no run of 8+ characters of this alphabet to decode")

    translated = best.translate(str.maketrans(alphabet, STANDARD_B64_ALPHABET))
    translated = translated.rstrip("=")
    translated += "=" * (-len(translated) % 4)
    try:
        return base64.b64decode(translated, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def as_text(data: bytes, max_len: int = 4 * 1024 * 1024) -> str | None:
    """Return the data as stripped ASCII text, or None if it is not printable ASCII."""
    if not data or len(data) > max_len:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not set(text) <= PRINTABLE:
        return None
    return text.strip()


def _no_space(text: str) -> str:
    return re.sub(r"\s", "", text)


def _decompress(obj: zlib._Decompress | lzma.LZMADecompressor, data: bytes) -> bytes:
    """Decompress with an output cap, so a zip bomb cannot fill the memory."""
    try:
        out = obj.decompress(data, MAX_OUTPUT)
    except (zlib.error, lzma.LZMAError, EOFError, ValueError) as exc:
        raise DecodeError(str(exc)) from exc
    if not out:
        raise DecodeError("no output")
    return out


# ---------------------------------------------------------------------------
# Text encodings
# ---------------------------------------------------------------------------


def hex_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and looks_like_hex(text)


def hex_decode(data: bytes) -> bytes:
    try:
        return bytes.fromhex(clean_hex(data.decode("ascii")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecodeError(str(exc)) from exc


def base64_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None:
        return False
    text = _no_space(text)
    return (
        len(text) >= 4
        and len(text.rstrip("=")) % 4 != 1
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) is not None
    )


def base64_decode(data: bytes) -> bytes:
    text = _no_space(data.decode("ascii"))
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(str(exc)) from exc


def base64url_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None:
        return False
    text = _no_space(text)
    return (
        len(text) >= 4
        and re.search(r"[-_]", text) is not None
        and len(text.rstrip("=")) % 4 != 1
        and re.fullmatch(r"[A-Za-z0-9\-_]+={0,2}", text) is not None
    )


def base64url_decode(data: bytes) -> bytes:
    text = _no_space(data.decode("ascii"))
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(str(exc)) from exc


def base32_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None:
        return False
    text = _no_space(text).upper()
    return len(text) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", text) is not None


def base32_decode(data: bytes) -> bytes:
    text = _no_space(data.decode("ascii")).upper().rstrip("=")
    try:
        return base64.b32decode(text + "=" * (-len(text) % 8))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(str(exc)) from exc


def base58_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and len(text) >= 6 and set(text) <= set(B58_ALPHABET)


def base58_decode(data: bytes) -> bytes:
    """Base58 (Bitcoin alphabet): a big number written in base 58; '1' = leading zero byte."""
    text = data.decode("ascii").strip()
    number = 0
    for char in text:
        index = B58_ALPHABET.find(char)
        if index < 0:
            raise DecodeError(f"invalid base58 character {char!r}")
        number = number * 58 + index
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + raw


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = B58_ALPHABET[rest] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def base62_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None or len(text) < 8 or not text.isalnum() or not text.isascii():
        return False
    # Any word is valid base62, so ask for digits and both letter cases.
    return (
        any(c.isdigit() for c in text)
        and any(c.isupper() for c in text)
        and (any(c.islower() for c in text))
    )


def base62_decode(data: bytes) -> bytes:
    """Base62 (0-9A-Za-z), as in CyberChef: one big number written in base 62."""
    number = 0
    for char in data.decode("ascii").strip():
        index = B62_ALPHABET.find(char)
        if index < 0:
            raise DecodeError(f"invalid base62 character {char!r}")
        number = number * 62 + index
    if number == 0:
        raise DecodeError("empty base62 value")
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


def base62_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 62)
        out = B62_ALPHABET[rest] + out
    return out or "0"


def base85_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None or len(text) < 5:
        return False
    text = _no_space(text)
    # Needs some punctuation, otherwise it is more likely base64/base62.
    return set(text) <= B85_CHARS and any(not c.isalnum() for c in text)


def base85_decode(data: bytes) -> bytes:
    try:
        return base64.b85decode(_no_space(data.decode("ascii")))
    except (ValueError, binascii.Error) as exc:
        raise DecodeError(str(exc)) from exc


def ascii85_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None or len(text) < 5:
        return False
    if text.startswith("<~") and text.endswith("~>"):
        return True
    text = _no_space(text)
    return set(text) <= A85_CHARS and sum(not c.isalnum() for c in text) >= 2


def ascii85_decode(data: bytes) -> bytes:
    text = _no_space(data.decode("ascii"))
    adobe = text.startswith("<~")
    try:
        return base64.a85decode(text, adobe=adobe)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError(str(exc)) from exc


def url_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and re.search(r"%[0-9A-Fa-f]{2}", text) is not None


def url_decode(data: bytes) -> bytes:
    return urllib.parse.unquote_to_bytes(data.strip())


def html_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text) is not None


def html_decode(data: bytes) -> bytes:
    return html.unescape(data.decode("ascii")).encode("utf-8")


def qp_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and len(re.findall(r"=[0-9A-F]{2}", text)) >= 2


def qp_decode(data: bytes) -> bytes:
    return quopri.decodestring(data)


def rot13_ok(data: bytes) -> bool:
    """ROT13 is worth trying on sentence-like text (spaces or a flag-like '{')."""
    text = as_text(data)
    if text is None:
        return False
    letters = sum(c.isalpha() for c in text)
    visible = sum(not c.isspace() for c in text)
    has_shape = " " in text or "{" in text
    return letters >= 4 and letters >= 0.5 * visible and has_shape


def rot13_decode(data: bytes) -> bytes:
    return codecs.encode(data.decode("ascii"), "rot13").encode("ascii")


def rot47_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None or len(text) < 4:
        return False
    # ROT47 output of normal text is full of punctuation like ; : < = > ? @
    punctuation = set(text) & set("!\"#$%&'()*,-./:;<>?@[\\]^`|~")
    return len(punctuation) >= 3


def rot47_decode(data: bytes) -> bytes:
    """ROT47: rotate every printable ASCII character (33..126) by 47 positions."""
    out = bytearray()
    for byte in data:
        out.append(33 + (byte - 33 + 47) % 94 if 33 <= byte <= 126 else byte)
    return bytes(out)


def reverse_ok(data: bytes) -> bool:
    """Reversed strings are a classic obfuscation (e.g. '==gZ...' = reversed base64)."""
    text = as_text(data)
    if text is None or len(text) < 4:
        return False
    if text.startswith("=") and re.fullmatch(r"=+[A-Za-z0-9+/]+", text):
        return True
    # A reversed flag looks like "}....{FTC"
    return re.search(r"\}[^{}\n]{3,}\{[A-Za-z0-9_]{2,15}", text) is not None


def reverse_decode(data: bytes) -> bytes:
    return data.strip()[::-1]


def binary_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None:
        return False
    bits = _no_space(text)
    return len(bits) >= 8 and len(bits) % 8 == 0 and set(bits) <= {"0", "1"}


def binary_decode(data: bytes) -> bytes:
    bits = _no_space(data.decode("ascii"))
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def decimal_ok(data: bytes) -> bool:
    text = as_text(data)
    if text is None:
        return False
    numbers = re.split(r"[\s,;]+", text)
    return (
        len(numbers) >= 4
        and all(n.isdigit() for n in numbers)
        and all(int(n) <= 255 for n in numbers)
    )


def decimal_decode(data: bytes) -> bytes:
    return bytes(int(n) for n in re.split(r"[\s,;]+", data.decode("ascii").strip()))


# ---------------------------------------------------------------------------
# Encoded data embedded in a bigger text (script, command line, JSON...)
# ---------------------------------------------------------------------------

B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")


def _longest(regex: re.Pattern[str], text: str) -> str:
    runs = regex.findall(text)
    return max(runs, key=len) if runs else ""


def extract_base64_ok(data: bytes) -> bool:
    """Text that is not base64 as a whole, but contains a long base64 run."""
    text = as_text(data)
    if text is None or base64_ok(data):
        return False
    run = _longest(B64_RUN, text)
    return bool(run) and len(run.rstrip("=")) % 4 != 1


def extract_base64_decode(data: bytes) -> bytes:
    run = _longest(B64_RUN, data.decode("ascii"))
    return base64_decode(run.encode())


def extract_hex_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and not hex_ok(data) and bool(_longest(HEX_RUN, text))


def extract_hex_decode(data: bytes) -> bytes:
    return bytes.fromhex(_longest(HEX_RUN, data.decode("ascii")))


JWT_RE = re.compile(r"^(eyJ[A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]*)\.[A-Za-z0-9_\-]*$")


def jwt_ok(data: bytes) -> bool:
    text = as_text(data)
    return text is not None and JWT_RE.match(text) is not None


def jwt_decode(data: bytes) -> bytes:
    """A JWT is header.payload.signature, each part base64url without padding."""
    match = JWT_RE.match(data.decode("ascii").strip())
    if match is None:
        raise DecodeError("not a JWT")
    parts = []
    for part in match.groups():
        parts.append(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return b"\n".join(parts)


# ---------------------------------------------------------------------------
# Character sets and hidden text
# ---------------------------------------------------------------------------


def utf16le_ok(data: bytes) -> bool:
    """ASCII text stored as UTF-16LE has a zero byte after every character (PowerShell!)."""
    if len(data) < 4 or len(data) % 2:
        return False
    body = data[2:] if data[:2] == b"\xff\xfe" else data
    zeros = sum(1 for b in body[1::2] if b == 0)
    return zeros >= 0.8 * (len(body) // 2)


def utf16le_decode(data: bytes) -> bytes:
    try:
        return data.decode("utf-16-le").lstrip("﻿").encode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(str(exc)) from exc


# A PowerShell encoded command. `-EncodedCommand` may be shortened to any
# unambiguous prefix ("-e", "-enc", "-encodedcommand"), so the flag is matched
# loosely and the base64 that follows is what really decides.
PS_ENCODED = re.compile(r"-e[a-z]*[\s:]+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
PS_SEARCH_LIMIT = 4 * 1024 * 1024  # bytes of a dump we are willing to scan


def _text_views(data: bytes):
    """The data read as text, the three ways a command line hides in a binary.

    Once as raw bytes (an ASCII command line), then as UTF-16LE at both byte
    alignments - Windows writes its event logs and registry values in UTF-16LE,
    so the command sits there with a zero byte after every character.
    """
    window = data[:PS_SEARCH_LIMIT]
    yield window.decode("latin-1")
    for start in (0, 1):
        chunk = window[start:]
        if len(chunk) % 2:
            chunk = chunk[:-1]
        # errors="ignore" is deliberate: the surrounding binary noise is not text
        # and we only ever regex-search the result.
        yield chunk.decode("utf-16-le", errors="ignore")


def find_encoded_command(data: bytes) -> bytes | None:
    """The script behind a PowerShell `-EncodedCommand`, wherever it hides.

    PowerShell takes that argument as base64 of UTF-16LE source, which is why a
    dropper line looks like noise. Returns the decoded script, or None.
    """
    for view in _text_views(data):
        for match in PS_ENCODED.finditer(view):
            blob = match.group(1)
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(raw) < 8 or len(raw) % 2:
                continue
            try:
                script = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            # A real script is readable *ASCII*: random bytes also decode as
            # UTF-16LE, and land on printable Unicode letters often enough that
            # str.isprintable() alone would accept them.
            printable = sum(1 for char in script if " " <= char < "\x7f" or char in "\r\n\t")
            if printable >= 0.9 * len(script):
                return script.encode("utf-8")
    return None


def powershell_enc_ok(data: bytes) -> bool:
    """Is there a PowerShell encoded command hidden in here?"""
    return find_encoded_command(data) is not None


def powershell_enc_decode(data: bytes) -> bytes:
    script = find_encoded_command(data)
    if script is None:
        raise DecodeError("no PowerShell -EncodedCommand found")
    return script


def protobuf_ok(data: bytes) -> bool:
    """Is this a protobuf message? Strict, because the format decodes by accident."""
    from ctfc.core.protobuf import looks_like_protobuf

    return looks_like_protobuf(data)


def protobuf_decode(data: bytes) -> bytes:
    from ctfc.core.protobuf import ProtobufError, decode_to_text

    try:
        return decode_to_text(data)
    except ProtobufError as exc:
        raise DecodeError(str(exc)) from exc


def zero_width_chars(data: bytes) -> list[str]:
    """Return the zero-width characters of the text, in order."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [char for char in text if char in ZERO_WIDTH]


def zero_width_ok(data: bytes) -> bool:
    hidden = zero_width_chars(data)
    return len(hidden) >= 8 and len(set(hidden)) == 2


def _zero_width_bits(data: bytes, low_is_one: bool) -> bytes:
    """Two different invisible characters = bits 0 and 1, 8 bits per byte."""
    hidden = zero_width_chars(data)
    low = min(hidden)
    bits = ""
    for char in hidden:
        is_low = char == low
        bits += "1" if is_low == low_is_one else "0"
    bits = bits[: len(bits) - len(bits) % 8]
    if not bits:
        raise DecodeError("not enough zero-width characters")
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def zero_width_decode_a(data: bytes) -> bytes:
    return _zero_width_bits(data, low_is_one=False)


def zero_width_decode_b(data: bytes) -> bytes:
    return _zero_width_bits(data, low_is_one=True)


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------


def zlib_ok(data: bytes) -> bool:
    # zlib header: CMF=0x78 (deflate, 32K window) and (CMF*256 + FLG) % 31 == 0
    return len(data) > 2 and data[0] == 0x78 and (data[0] * 256 + data[1]) % 31 == 0


def zlib_decode(data: bytes) -> bytes:
    return _decompress(zlib.decompressobj(), data)


def deflate_ok(data: bytes) -> bool:
    """Raw deflate has no header: only tried on binary data without another signature."""
    return len(data) >= 8 and as_text(data) is None and not zlib_ok(data) and not gzip_ok(data)


def deflate_decode(data: bytes) -> bytes:
    obj = zlib.decompressobj(-15)
    out = _decompress(obj, data)
    if not obj.eof or len(obj.unused_data) > 8:
        raise DecodeError("not a complete raw deflate stream")
    return out


def gzip_ok(data: bytes) -> bool:
    return data[:2] == b"\x1f\x8b"


def gzip_decode(data: bytes) -> bytes:
    return _decompress(zlib.decompressobj(16 + zlib.MAX_WBITS), data)


def bz2_ok(data: bytes) -> bool:
    return data[:3] == b"BZh"


def bz2_decode(data: bytes) -> bytes:
    try:
        decompressor = bz2.BZ2Decompressor()
        out = decompressor.decompress(data, MAX_OUTPUT)
    except (OSError, ValueError, EOFError) as exc:
        raise DecodeError(str(exc)) from exc
    if not out:
        raise DecodeError("no output")
    return out


def lzma_ok(data: bytes) -> bool:
    return data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00"


def lzma_decode(data: bytes) -> bytes:
    return _decompress(lzma.LZMADecompressor(), data)


# ---------------------------------------------------------------------------
# Snippet helpers (copied into generated scripts when needed)
# ---------------------------------------------------------------------------

B58_HELPER = '''
def base58_decode(text):
    """Base58 = a big number in base 58 (Bitcoin alphabet); each leading '1' is a 0 byte."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for char in text:
        number = number * 58 + alphabet.index(char)
    zeros = len(text) - len(text.lstrip("1"))
    return b"\\x00" * zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")
'''

B62_HELPER = '''
def base62_decode(text):
    """Base62 = a big number in base 62 (0-9A-Za-z)."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    number = 0
    for char in text:
        number = number * 62 + alphabet.index(char)
    return number.to_bytes((number.bit_length() + 7) // 8, "big")
'''

ROT47_HELPER = '''
def rot47(data):
    """Rotate every printable ASCII character (33..126) by 47."""
    return bytes(33 + (b - 33 + 47) % 94 if 33 <= b <= 126 else b for b in data)
'''

ZW_HELPER = '''
ZERO_WIDTH = "\\u200b\\u200c\\u200d\\u2060\\u2061\\u2062\\u2063\\u2064\\ufeff\\u180e\\u200e\\u200f"

def zero_width_bits(data, low_is_one):
    """Keep only the invisible characters; the two kinds are the bits 0 and 1."""
    hidden = [c for c in data.decode("utf-8") if c in ZERO_WIDTH]
    low = min(hidden)
    bits = "".join(str(int((c == low) == low_is_one)) for c in hidden)
    bits = bits[: len(bits) - len(bits) % 8]
    return int(bits, 2).to_bytes(len(bits) // 8, "big")
'''

# ---------------------------------------------------------------------------
# The registry: order = order of trial in `auto` (cheap and common first)
# ---------------------------------------------------------------------------

DECODERS: list[Decoder] = [
    Decoder(
        name="hex",
        label="from hex",
        decode=hex_decode,
        applicable=hex_ok,
        imports=("re",),
        python=r'data = bytes.fromhex(re.sub(r"0x|\\x|[\s:,]", "", data.decode()))',
        cyberchef="From_Hex('Auto')",
    ),
    Decoder(
        name="base64",
        label="from base64",
        decode=base64_decode,
        applicable=base64_ok,
        imports=("base64",),
        python='data = b"".join(data.split())\n'
        'data = base64.b64decode(data + b"=" * (-len(data) % 4))',
        cyberchef="From_Base64('A-Za-z0-9+/=',true,false)",
    ),
    Decoder(
        name="base64url",
        label="from base64 (URL-safe alphabet -_)",
        decode=base64url_decode,
        applicable=base64url_ok,
        imports=("base64",),
        python='data = b"".join(data.split())\n'
        'data = base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))',
        cyberchef="From_Base64('A-Za-z0-9-_',true,false)",
    ),
    Decoder(
        name="base32",
        label="from base32",
        decode=base32_decode,
        applicable=base32_ok,
        imports=("base64",),
        python='data = b"".join(data.split()).upper().rstrip(b"=")\n'
        'data = base64.b32decode(data + b"=" * (-len(data) % 8))',
        cyberchef="From_Base32('A-Z2-7=',true)",
    ),
    Decoder(
        name="base58",
        label="from base58",
        decode=base58_decode,
        applicable=base58_ok,
        python="data = base58_decode(data.decode().strip())",
        helper=B58_HELPER,
        cyberchef="From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',true)",
    ),
    Decoder(
        name="base62",
        label="from base62",
        decode=base62_decode,
        applicable=base62_ok,
        python="data = base62_decode(data.decode().strip())",
        helper=B62_HELPER,
        cyberchef="From_Base62('0-9A-Za-z')",
    ),
    Decoder(
        name="base85",
        label="from base85 (RFC 1924 / Python b85)",
        decode=base85_decode,
        applicable=base85_ok,
        imports=("base64",),
        python='data = base64.b85decode(b"".join(data.split()))',
        cyberchef="From_Base85('0-9A-Za-z!#$%&()*+\\\\-;<=>?@^_`{|}~',true,'z')",
    ),
    Decoder(
        name="ascii85",
        label="from ascii85 (Adobe)",
        decode=ascii85_decode,
        applicable=ascii85_ok,
        imports=("base64",),
        python='data = b"".join(data.split())\n'
        'data = base64.a85decode(data, adobe=data.startswith(b"<~"))',
        cyberchef="From_Base85('!-u',true,'z')",
    ),
    Decoder(
        name="jwt",
        label="JWT: base64url-decode header and payload",
        decode=jwt_decode,
        applicable=jwt_ok,
        imports=("base64",),
        python='header, payload = data.decode().strip().split(".")[:2]\n'
        'data = b"\\n".join(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))'
        " for p in (header, payload))",
        cyberchef="JWT_Decode()",
    ),
    Decoder(
        name="extract_base64",
        label="extract the longest base64 run from the text, decode it",
        decode=extract_base64_decode,
        applicable=extract_base64_ok,
        imports=("base64", "re"),
        python='run = max(re.findall(rb"[A-Za-z0-9+/]{20,}={0,2}", data), key=len)\n'
        'data = base64.b64decode(run + b"=" * (-len(run) % 4))',
        cyberchef="Regular_expression('User defined','[A-Za-z0-9+/]{20,}={0,2}',true,true,"
        "false,false,false,false,'List matches')From_Base64('A-Za-z0-9+/=',true,false)",
    ),
    Decoder(
        name="extract_hex",
        label="extract the longest hex run from the text, decode it",
        decode=extract_hex_decode,
        applicable=extract_hex_ok,
        imports=("re",),
        python='run = max(re.findall(rb"(?:[0-9a-fA-F]{2}){16,}", data), key=len)\n'
        "data = bytes.fromhex(run.decode())",
        cyberchef="Regular_expression('User defined','(?:[0-9a-fA-F]{2}){16,}',true,true,"
        "false,false,false,false,'List matches')From_Hex('Auto')",
    ),
    Decoder(
        name="url",
        label="URL decode (%XX)",
        decode=url_decode,
        applicable=url_ok,
        imports=("urllib.parse",),
        python="data = urllib.parse.unquote_to_bytes(data.strip())",
        cyberchef="URL_Decode()",
    ),
    Decoder(
        name="html",
        label="HTML entities (&#65; &lt;)",
        decode=html_decode,
        applicable=html_ok,
        imports=("html",),
        python='data = html.unescape(data.decode()).encode("utf-8")',
        cyberchef="From_HTML_Entity()",
    ),
    Decoder(
        name="quoted_printable",
        label="quoted-printable (=XX)",
        decode=qp_decode,
        applicable=qp_ok,
        imports=("quopri",),
        python="data = quopri.decodestring(data)",
        cyberchef="From_Quoted_Printable()",
    ),
    Decoder(
        name="binary",
        label="from binary (01000001)",
        decode=binary_decode,
        applicable=binary_ok,
        python='bits = "".join(data.decode().split())\n'
        "data = int(bits, 2).to_bytes(len(bits) // 8, 'big')",
        cyberchef="From_Binary('Space',8)",
    ),
    Decoder(
        name="decimal",
        label="from decimal char codes (72 101 108)",
        decode=decimal_decode,
        applicable=decimal_ok,
        imports=("re",),
        python='data = bytes(int(n) for n in re.split(r"[\\s,;]+", data.decode().strip()))',
        cyberchef="From_Decimal('Space',false)",
    ),
    Decoder(
        name="reverse",
        label="reverse the string",
        decode=reverse_decode,
        applicable=reverse_ok,
        python="data = data.strip()[::-1]",
        cyberchef="Reverse('Character')",
    ),
    Decoder(
        name="rot13",
        label="ROT13 (letters shifted by 13)",
        decode=rot13_decode,
        applicable=rot13_ok,
        imports=("codecs",),
        python='data = codecs.encode(data.decode(), "rot13").encode()',
        cyberchef="ROT13(true,true,false,13)",
    ),
    Decoder(
        name="rot47",
        label="ROT47 (printable ASCII shifted by 47)",
        decode=rot47_decode,
        applicable=rot47_ok,
        python="data = rot47(data)",
        helper=ROT47_HELPER,
        cyberchef="ROT47(47)",
    ),
    Decoder(
        name="protobuf",
        label="protobuf message (decoded without a .proto, like protoc --decode_raw)",
        decode=protobuf_decode,
        applicable=protobuf_ok,
        helper="# see ctfc/core/protobuf.py, or run: protoc --decode_raw < message.bin",
        python="from ctfc.core.protobuf import decode_to_text\ndata = decode_to_text(data)",
    ),
    Decoder(
        name="psenc",
        label="PowerShell -EncodedCommand found in the data",
        decode=powershell_enc_decode,
        applicable=powershell_enc_ok,
        imports=("base64", "re"),
        python='match = re.search(rb"-e[a-z]*[\\s:]+([A-Za-z0-9+/=]{20,})", data, re.I)\n'
        'data = base64.b64decode(match.group(1)).decode("utf-16-le").encode()',
        helper="# the command may be UTF-16LE inside the dump: decode that view first",
    ),
    Decoder(
        name="utf16le",
        label="UTF-16LE text (PowerShell -EncodedCommand)",
        decode=utf16le_decode,
        applicable=utf16le_ok,
        python='data = data.decode("utf-16-le").encode("utf-8")',
        cyberchef="Decode_text('UTF-16LE (1200)')",
    ),
    Decoder(
        name="zero_width_a",
        label="zero-width characters as bits (lower code point = 0)",
        decode=zero_width_decode_a,
        applicable=zero_width_ok,
        python="data = zero_width_bits(data, low_is_one=False)",
        helper=ZW_HELPER,
    ),
    Decoder(
        name="zero_width_b",
        label="zero-width characters as bits (lower code point = 1)",
        decode=zero_width_decode_b,
        applicable=zero_width_ok,
        python="data = zero_width_bits(data, low_is_one=True)",
        helper=ZW_HELPER,
    ),
    Decoder(
        name="zlib",
        label="zlib decompress",
        decode=zlib_decode,
        applicable=zlib_ok,
        imports=("zlib",),
        python="data = zlib.decompress(data)",
        cyberchef="Zlib_Inflate(0,0,'Adaptive',false,false)",
    ),
    Decoder(
        name="gzip",
        label="gzip decompress",
        decode=gzip_decode,
        applicable=gzip_ok,
        imports=("gzip",),
        python="data = gzip.decompress(data)",
        cyberchef="Gunzip()",
    ),
    Decoder(
        name="bz2",
        label="bzip2 decompress",
        decode=bz2_decode,
        applicable=bz2_ok,
        imports=("bz2",),
        python="data = bz2.decompress(data)",
        cyberchef="Bzip2_Decompress(false)",
    ),
    Decoder(
        name="lzma",
        label="lzma / xz decompress",
        decode=lzma_decode,
        applicable=lzma_ok,
        imports=("lzma",),
        python="data = lzma.decompress(data)",
        cyberchef="LZMA_Decompress()",
    ),
    Decoder(
        name="deflate",
        label="raw deflate decompress (no header)",
        decode=deflate_decode,
        applicable=deflate_ok,
        imports=("zlib",),
        python="data = zlib.decompress(data, -15)",
        cyberchef="Raw_Inflate(0,0,'Adaptive',false,false)",
    ),
]

DECODERS_BY_NAME: dict[str, Decoder] = {decoder.name: decoder for decoder in DECODERS}
