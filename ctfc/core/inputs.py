"""Turn what the user typed into bytes.

Input convention (same for CLI and web):
    path/to/file   -> the raw bytes of the file
    -              -> read stdin
    hex:41424344   -> hex string
    b64:QUJDRA==   -> base64 string (standard or URL-safe, padding optional)
    text:hello     -> the UTF-8 bytes of the text
    anything else  -> if it looks like hex or base64 it is decoded (with a note),
                      otherwise it is used as plain text.
"""

from __future__ import annotations

import base64
import binascii
import re
import sys
from pathlib import Path
from typing import BinaryIO

from ctfc.core.types import Input

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")


class InputError(ValueError):
    """Raised when the input cannot be parsed. The message says how to fix it."""


def clean_hex(text: str) -> str:
    """Remove common hex decorations: spaces, newlines, '0x', '\\x', ':' and ','."""
    text = text.strip()
    text = text.replace("\\x", "").replace("0x", "").replace("0X", "")
    return re.sub(r"[\s:,]", "", text)


def looks_like_hex(text: str) -> bool:
    """True if `text` is an even-length run of hex digits (after cleaning)."""
    cleaned = clean_hex(text)
    return len(cleaned) >= 2 and len(cleaned) % 2 == 0 and bool(HEX_RE.match(cleaned))


def looks_like_base64(text: str) -> bool:
    """True if `text` is plausibly base64.

    Any word made of letters is valid base64, so we also require some evidence:
    a digit, '+', '/', '=' or a long length. Use `text:` to force plain text.
    """
    cleaned = re.sub(r"\s", "", text)
    if len(cleaned) < 8 or not BASE64_RE.match(cleaned):
        return False
    has_evidence = bool(re.search(r"[0-9+/=_\-]", cleaned)) or len(cleaned) >= 20
    if not has_evidence:
        return False
    try:
        decode_base64(cleaned)
    except InputError:
        return False
    return True


def decode_hex(text: str) -> bytes:
    """Decode a hex string, tolerating spaces, '0x', '\\x' and ':' separators."""
    cleaned = clean_hex(text)
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise InputError(
            f"invalid hex ({exc}); expected pairs of 0-9a-f, e.g. hex:41424344"
        ) from exc


def decode_base64(text: str) -> bytes:
    """Decode standard or URL-safe base64, adding missing '=' padding."""
    cleaned = re.sub(r"\s", "", text).replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InputError(f"invalid base64 ({exc}); expected e.g. b64:QUJDRA==") from exc


def parse_input(spec: str, stdin: BinaryIO | None = None) -> Input:
    """Parse one input specification (see module docstring) into an `Input`."""
    if spec == "-":
        stream = stdin if stdin is not None else sys.stdin.buffer
        return Input(data=stream.read(), source="stdin")

    lower = spec[:5].lower()
    if lower.startswith("hex:"):
        return Input(data=decode_hex(spec[4:]), source="hex")
    if lower.startswith("b64:"):
        return Input(data=decode_base64(spec[4:]), source="b64")
    if lower.startswith("text:"):
        return Input(data=spec[5:].encode("utf-8"), source="text")

    path = Path(spec)
    # Very long strings cannot be file names; avoid OSError("File name too long").
    if len(spec) < 4096 and path.is_file():
        return Input(data=path.read_bytes(), source=f"file:{path}")

    return parse_bare_text(spec)


def parse_bare_text(text: str) -> Input:
    """Auto-detect hex or base64 in text that has no prefix."""
    if looks_like_hex(text):
        return Input(
            data=decode_hex(text),
            source="auto-hex",
            notes=["input looked like hex and was decoded (use text:... to keep it as text)"],
        )
    if looks_like_base64(text):
        return Input(
            data=decode_base64(text),
            source="auto-b64",
            notes=["input looked like base64 and was decoded (use text:... to keep it as text)"],
        )
    return Input(
        data=text.encode("utf-8"),
        source="text",
        notes=["input is not a file, hex or base64: used as plain text"],
    )
