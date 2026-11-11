"""Search bytes for a pattern - or for a flag, which is not the same search.

Two things people do with a blob in front of them, and the second is the one
tools get wrong.

**Searching for a pattern.** A regex over the bytes, with the offset of each
match and enough around it to read. On bytes rather than on text, because a
"strings" view has already thrown away where things were, and the offset is
half the answer: a flag at 0x40 of a PNG is in the header, the same flag at the
end is appended data.

**Searching for a flag.** `CYBN{...}` is not only written as `CYBN{...}`. It may
be **base64** - and then its text depends on the alignment it was encoded at,
which is why `flags.py` precomputes the three forms of each prefix - or hex, or
UTF-16, or split across a line break. `find_flags` already knows all of that, so
a flag hunt here *is* a call to `find_flags`, plus the offsets the search view
needs. Typing `CYBN` into a regex box would find the first case and miss the
rest, and missing it quietly is worse than not looking.

The two are therefore separate entry points, not one with a checkbox.
"""

from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field

from ctfc.core.flags import FlagSet, base64_forms, default_flagset, hunt_flags

# What is sent back per match. Enough to read it in context and to know where it
# was, and no more: a search over a 64 MB dump must not answer with 64 MB.
CONTEXT = 48
MAX_MATCHES = 500
MAX_PATTERN = 400


class SearchError(ValueError):
    """The pattern is not a regex we can use."""


@dataclass
class Match:
    """One hit, with where it was and what is around it."""

    offset: int
    text: str  # the match itself, as readable text
    context: str  # the bytes around it, printable-ised
    how: str = "pattern"  # "pattern", "plain", "base64"...
    source: str = "input"  # which haystack it came from

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "hex_offset": f"{self.offset:#x}",
            "text": self.text,
            "context": self.context,
            "how": self.how,
            "source": self.source,
        }


@dataclass
class SearchReport:
    """Every hit, plus what was actually searched for."""

    matches: list[Match] = field(default_factory=list)
    searched: list[str] = field(default_factory=list)  # the patterns used
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "matches": [match.to_dict() for match in self.matches],
            "searched": list(self.searched),
            "truncated": self.truncated,
            "notes": list(self.notes),
        }


def _printable(data: bytes) -> str:
    """Bytes as one readable line: anything unprintable becomes a dot."""
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)


def search_pattern(
    data: bytes, pattern: str, ignore_case: bool = True, source: str = "input"
) -> SearchReport:
    """Every match of `pattern` in `data`, with offsets and context.

    The pattern is a regex *on bytes*, so `.` does not match a newline by
    accident and a UTF-16 string can be searched with `C.Y.B.N`.
    """
    report = SearchReport(searched=[pattern])
    if not pattern:
        raise SearchError("nothing to search for")
    if len(pattern) > MAX_PATTERN:
        raise SearchError(f"that pattern is {len(pattern)} characters long: it is not a pattern")
    flags = re.IGNORECASE if ignore_case else 0
    try:
        regex = re.compile(pattern.encode("utf-8", "surrogateescape"), flags)
    except (re.error, UnicodeEncodeError) as exc:
        raise SearchError(f"{pattern!r} is not a usable regex: {exc}") from exc

    for found in regex.finditer(data):
        start, end = found.span()
        report.matches.append(
            Match(
                offset=start,
                text=found.group(0).decode("utf-8", "replace"),
                context=_printable(data[max(0, start - CONTEXT) : end + CONTEXT]),
                how="pattern",
                source=source,
            )
        )
        if len(report.matches) >= MAX_MATCHES:
            report.truncated = True
            report.notes.append(
                f"stopped at {MAX_MATCHES} matches: narrow the pattern, or use grep on the file"
            )
            break
    if not report.matches:
        report.notes.append(f"no match for {pattern!r} in {len(data)} bytes")
    return report


def _offset_of(data: bytes, needle: str) -> int:
    """Where a flag's text is in the data, trying the encodings it may be in."""
    for candidate in (
        needle.encode(),
        needle.encode("utf-16-le"),
        needle.encode("utf-16-be"),
        needle.encode().hex().encode(),
        binascii.b2a_base64(needle.encode(), newline=False),
    ):
        found = data.find(candidate)
        if found >= 0:
            return found
    return -1


def search_flags(data: bytes, flagset: FlagSet | None = None) -> SearchReport:
    """Hunt for a flag in every form it is written in, not just the plain one.

    This is a call into `find_flags`, which is the module that knows the forms -
    plain, base64 at each of the three alignments, and the prefix seen in base64
    without the rest decoding. The offsets are added here because a search view
    needs them, and because "where was it" distinguishes a flag in a PNG header
    from one appended after the image.
    """
    flagset = flagset or default_flagset()
    report = SearchReport()
    patterns = [regex.pattern for regex, _strength in flagset.regexes]
    for regex, prefix in flagset.b64_prefixes:
        patterns.append(f"{prefix} in base64 ({regex.pattern})")
    report.searched = patterns

    for hit in hunt_flags(data, flagset):
        offset = _offset_of(data, hit.encoded or hit.text)
        context = ""
        if offset >= 0:
            end = offset + len(hit.encoded or hit.text)
            context = _printable(data[max(0, offset - CONTEXT) : end + CONTEXT])
        report.matches.append(
            Match(
                offset=max(offset, 0),
                text=hit.text,
                context=context,
                how=hit.how,
                source="input",
            )
        )
    if not report.matches:
        report.notes.append(
            "no flag in any of the forms searched (plain, UTF-16, backwards, and every "
            "hex or base64 string decoded). "
            "The prefixes come from ~/.ctfc/config.toml: add the CTF's own there"
        )
        for prefix in {prefix for _regex, prefix in flagset.b64_prefixes}:
            forms = ", ".join(base64_forms(prefix.encode()))
            report.notes.append(f"{prefix!r} in base64 is one of: {forms}")
    return report
