"""Find CTF flags in data, in clear or base64-encoded.

Two kinds of patterns come from the config:
- `flag_regexes`: searched in the data as-is (e.g. CYBN\\{[^}]*\\}).
- `flag_prefixes`: also searched in their *base64 form*. For example "CYBN{" encodes to
  "Q1lCTn..." when it starts a base64 string. Because base64 works on groups of
  3 bytes, the same prefix has 3 possible encodings depending on where it sits;
  all three are searched.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ctfc.config import DEFAULT_FLAG_PREFIXES, DEFAULT_FLAG_REGEXES

# The first default regex is the generic "XXX{...}" shape: it can match ordinary
# code like "else{ return x; }", so it is trusted a bit less than specific formats.
GENERIC_STRENGTH = 0.9
SPECIFIC_STRENGTH = 0.97
BASE64_STRENGTH = 0.9

B64_RUN_RE = re.compile(r"[A-Za-z0-9+/\-_]{8,}={0,2}")


@dataclass
class FlagHit:
    """One flag found in the data."""

    text: str  # the flag itself (decoded if it was base64)
    how: str  # "plain", "base64" or "base64-prefix" (prefix seen, full flag not decoded)
    strength: float  # how sure we are (0..1)
    pattern: str  # the regex or prefix that matched
    encoded: str = ""  # the base64 text, when how != "plain"


@dataclass
class FlagSet:
    """Compiled flag patterns, built once from the config."""

    regexes: list[tuple[re.Pattern[str], float]] = field(default_factory=list)
    b64_prefixes: list[tuple[re.Pattern[str], str]] = field(default_factory=list)


def base64_forms(prefix: bytes) -> list[str]:
    """Return the base64 text that `prefix` produces at each of the 3 possible alignments.

    Only the characters fully determined by the prefix are kept: e.g. for b"CYBN{"
    at alignment 0 that is "Q1lCTn" (the 7th character also depends on what follows).
    """
    forms = []
    for pad in range(3):
        encoded = base64.b64encode(b"\x00" * pad + prefix).decode().rstrip("=")
        known_start_bit = 8 * pad
        known_end_bit = 8 * (pad + len(prefix))
        chars = [
            ch
            for index, ch in enumerate(encoded)
            if 6 * index >= known_start_bit and 6 * index + 6 <= known_end_bit
        ]
        if len(chars) >= 4:
            forms.append("".join(chars))
    return forms


def build_flagset(regexes: list[str], prefixes: list[str]) -> FlagSet:
    """Compile the flag regexes and the base64 forms of the prefixes."""
    flagset = FlagSet()
    for pattern in regexes:
        strength = GENERIC_STRENGTH if pattern == DEFAULT_FLAG_REGEXES[0] else SPECIFIC_STRENGTH
        flagset.regexes.append((re.compile(pattern), strength))
    for prefix in prefixes:
        for form in base64_forms(prefix.encode("utf-8")):
            flagset.b64_prefixes.append((re.compile(re.escape(form)), prefix))
    return flagset


@lru_cache(maxsize=1)
def default_flagset() -> FlagSet:
    """Flag patterns from the built-in defaults (used when no config is passed)."""
    return build_flagset(DEFAULT_FLAG_REGEXES, DEFAULT_FLAG_PREFIXES)


def find_flags(data: bytes, flagset: FlagSet | None = None) -> list[FlagHit]:
    """Return every flag found in `data`, strongest first, without duplicates."""
    flagset = flagset or default_flagset()
    text = data.decode("utf-8", errors="replace")
    hits: dict[str, FlagHit] = {}

    def keep(hit: FlagHit) -> None:
        old = hits.get(hit.text)
        if old is None or hit.strength > old.strength:
            hits[hit.text] = hit

    for regex, strength in flagset.regexes:
        for match in regex.finditer(text):
            keep(FlagHit(match.group(0), "plain", strength, regex.pattern))

    for regex, prefix in flagset.b64_prefixes:
        if not regex.search(text):
            continue
        for run in B64_RUN_RE.finditer(text):
            if not regex.search(run.group(0)):
                continue
            decoded_flags = _flags_in_base64_run(run.group(0), flagset)
            for flag_text in decoded_flags:
                keep(FlagHit(flag_text, "base64", BASE64_STRENGTH, prefix, run.group(0)))
            if not decoded_flags:
                note = f"base64 of '{prefix}' found (decode it): {run.group(0)[:60]}"
                keep(FlagHit(note, "base64-prefix", 0.8, prefix, run.group(0)))

    return sorted(hits.values(), key=lambda hit: hit.strength, reverse=True)


def _flags_in_base64_run(run: str, flagset: FlagSet) -> list[str]:
    """Decode a base64 run (trying the 4 possible start offsets) and look for flags."""
    found: list[str] = []
    for start in range(4):
        chunk = run[start:].replace("-", "+").replace("_", "/").rstrip("=")
        if len(chunk) % 4 == 1:  # one dangling character cannot be decoded
            chunk = chunk[:-1]
        chunk += "=" * (-len(chunk) % 4)
        try:
            decoded = base64.b64decode(chunk).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            continue
        for regex, _strength in flagset.regexes:
            for match in regex.finditer(decoded):
                if match.group(0) not in found:
                    found.append(match.group(0))
    return found
