"""File signatures ("magic bytes") from data/magic.toml.

A file type is usually recognised by fixed bytes at its start, e.g. PNG files start
with 89 50 4E 47 ("\\x89PNG"). This module answers three questions:
- what type of file starts at offset 0?          -> match_signature()
- are other files hidden inside (at offset > 0)?  -> find_embedded()
- is there data appended after the end of the file? -> find_trailing_data()
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from ctfc.core.datafiles import load_toml


@dataclass(frozen=True)
class Signature:
    name: str
    ext: str
    magic: bytes
    offset: int = 0
    weak: bool = False
    end: bytes = b""
    end_rule: str = "last"


@dataclass(frozen=True)
class PrefixRule:
    """A regex rule on the text form of the input (encoded formats, hashes, keys)."""

    id: str
    regex: re.Pattern[str]
    label: str
    hint: str
    strength: float


@dataclass
class EmbeddedFile:
    name: str
    offset: int


@dataclass
class TrailingData:
    after: str  # name of the file type whose end marker was found
    end_offset: int  # where that file ends
    size: int  # how many bytes come after
    looks_like: str  # signature of the trailing data, if any


@lru_cache(maxsize=1)
def load_signatures() -> tuple[Signature, ...]:
    """Read the [[sig]] entries of magic.toml, longest signatures first."""
    entries = []
    for raw in load_toml("magic.toml").get("sig", []):
        entries.append(
            Signature(
                name=raw["name"],
                ext=raw.get("ext", ""),
                magic=bytes.fromhex(raw["hex"]),
                offset=raw.get("offset", 0),
                weak=raw.get("weak", False),
                end=bytes.fromhex(raw.get("end", "")),
                end_rule=raw.get("end_rule", "last"),
            )
        )
    entries.sort(key=lambda sig: len(sig.magic), reverse=True)
    return tuple(entries)


@lru_cache(maxsize=1)
def load_prefix_rules() -> tuple[PrefixRule, ...]:
    """Read the [[prefix]] entries of magic.toml."""
    rules = []
    for raw in load_toml("magic.toml").get("prefix", []):
        rules.append(
            PrefixRule(
                id=raw["id"],
                regex=re.compile(raw["regex"]),
                label=raw["label"],
                hint=raw.get("hint", ""),
                strength=raw.get("strength", 0.8),
            )
        )
    return tuple(rules)


def match_signature(data: bytes) -> Signature | None:
    """Return the file type of `data` (signature at its expected offset), or None."""
    for sig in load_signatures():
        if data[sig.offset : sig.offset + len(sig.magic)] == sig.magic:
            return sig
    return None


def find_embedded(data: bytes, limit: int = 20) -> list[EmbeddedFile]:
    """Find non-weak signatures that appear later in the data (hidden / concatenated files).

    Only signatures normally found at offset 0 are scanned, and at most `limit` hits
    are returned.
    """
    found: list[EmbeddedFile] = []
    seen_offsets: set[int] = set()
    for sig in load_signatures():
        if sig.weak or sig.offset != 0 or len(sig.magic) < 4:
            continue
        position = data.find(sig.magic, 1)
        while position != -1 and len(found) < limit:
            if position not in seen_offsets:
                seen_offsets.add(position)
                found.append(EmbeddedFile(sig.name, position))
            position = data.find(sig.magic, position + 1)
    found.sort(key=lambda item: item.offset)
    return found


def find_trailing_data(data: bytes) -> TrailingData | None:
    """If the file at offset 0 has an end marker, report bytes that come after it.

    Classic polyglot / stego trick: a ZIP appended after a PNG's IEND chunk.
    Trailing whitespace (e.g. a final newline after %%EOF) is ignored.
    """
    sig = match_signature(data)
    if sig is None or not sig.end:
        return None
    if sig.end_rule == "first":
        position = data.find(sig.end, len(sig.magic))
    else:
        position = data.rfind(sig.end)
    if position == -1:
        return None
    end = position + len(sig.end)
    if sig.ext == "zip" and end + 18 <= len(data):
        # The ZIP "end of central directory" record is 22 bytes + a comment.
        comment_length = int.from_bytes(data[end + 16 : end + 18], "little")
        end = position + 22 + comment_length
    trailing = data[end:]
    if not trailing.strip():
        return None
    inner = match_signature(trailing)
    return TrailingData(
        after=sig.name,
        end_offset=end,
        size=len(trailing),
        looks_like=inner.name if inner else "",
    )
