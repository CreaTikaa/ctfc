"""Password candidates taken from the challenge's own files.

A protected ZIP is often opened by a word the challenge itself carries: a PNG
text chunk (`Title = panda_d02b3ab3`, tjctf "nothing to see"), an EXIF comment,
a line of a README, a string in the file the ZIP was glued to. That word is in
no wordlist, but it is in the handout. This module collects such strings,
cheaply and with a cap, so that `solve` and `workspace` can try them on a
ZipCrypto archive (one attempt is a 12-byte header check: thousands per
millisecond, so trying every string costs nothing).

Collected, in this order (the likeliest first):
1. the values of a PNG's tEXt / zTXt / iTXt chunks, and each word in them;
2. every printable string of 3 to 64 characters in the data (the part before
   an appended ZIP, when there is one), and its words;
3. each of those, base64- or hex-decoded, when that gives printable text
   (a hint is often written encoded: `iTXt Password = cGFuZGE=`).
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
import zlib

# Hard caps: this runs on every piece of a walk.
MAX_PER_PIECE = 3000
SCAN_BYTES = 2 * 1024 * 1024
MIN_LENGTH = 3
MAX_LENGTH = 64

_STRING = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_LENGTH, MAX_LENGTH))
_WORD = re.compile(r"[^\s\"'`<>()\[\]{},;]{3,64}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){3,32}")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_text_chunks(data: bytes) -> list[tuple[str, str]]:
    """(keyword, text) of every tEXt / zTXt / iTXt chunk of a PNG.

    PNG metadata lives in these chunks. tEXt is plain Latin-1, zTXt is
    zlib-compressed (so `strings` does not show it), iTXt is UTF-8 and may be
    compressed too.
    """
    found: list[tuple[str, str]] = []
    if not data.startswith(PNG_SIGNATURE):
        return found
    offset = 8
    while offset + 8 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        body = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        try:
            if kind == b"tEXt" and b"\x00" in body:
                keyword, text = body.split(b"\x00", 1)
                found.append((keyword.decode("latin-1"), text.decode("latin-1")))
            elif kind == b"zTXt" and b"\x00" in body:
                keyword, rest = body.split(b"\x00", 1)
                text = zlib.decompressobj().decompress(rest[1:], 65536)
                found.append((keyword.decode("latin-1"), text.decode("latin-1")))
            elif kind == b"iTXt" and b"\x00" in body:
                keyword, rest = body.split(b"\x00", 1)
                compressed, rest = rest[0], rest[2:]
                _language, _, rest = rest.partition(b"\x00")
                _translated, _, text = rest.partition(b"\x00")
                if compressed:
                    text = zlib.decompressobj().decompress(text, 65536)
                found.append((keyword.decode("latin-1"), text.decode("utf-8", "replace")))
        except (zlib.error, IndexError, UnicodeDecodeError):
            continue
        if kind == b"IEND":
            break
    return found


def _printable(raw: bytes) -> str | None:
    """The bytes as a short printable string, or None."""
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if MIN_LENGTH <= len(text) <= MAX_LENGTH and text.isprintable():
        return text
    return None


def decoded_forms(text: str) -> list[str]:
    """The base64 and hex readings of a string, when they are printable."""
    out: list[str] = []
    token = text.strip()
    if len(token) % 4 == 0 and _BASE64.fullmatch(token):
        try:
            value = _printable(base64.b64decode(token, validate=True))
        except (binascii.Error, ValueError):
            value = None
        if value:
            out.append(value)
    if _HEX.fullmatch(token):
        value = _printable(bytes.fromhex(token))
        if value:
            out.append(value)
    return out


def password_hints(data: bytes, name: str = "") -> list[bytes]:
    """Every string of this piece worth trying as a password, likeliest first."""
    out: list[bytes] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        text = text.strip()
        if not (MIN_LENGTH <= len(text) <= MAX_LENGTH) or text in seen:
            return
        if len(out) >= MAX_PER_PIECE:
            return
        seen.add(text)
        out.append(text.encode("utf-8"))
        for decoded in decoded_forms(text):
            if decoded not in seen:
                seen.add(decoded)
                out.append(decoded.encode("utf-8"))

    for _keyword, text in png_text_chunks(data):
        add(text)
        for word in _WORD.findall(text):
            add(word.strip(".:!?"))

    head = data[:SCAN_BYTES]
    glued = head.find(b"PK\x03\x04")
    if glued > 0:
        head = head[:glued]  # the ZIP's own bytes are not its password
    for match in _STRING.finditer(head):
        text = match.group().decode("ascii")
        add(text)
        if " " in text:
            for word in _WORD.findall(text):
                add(word.strip(".:!?"))

    stem = name.rsplit("/", 1)[-1].rsplit(">", 1)[-1].strip()
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    add(stem)
    return out
