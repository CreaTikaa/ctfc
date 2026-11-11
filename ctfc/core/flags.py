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

# The first default regex is the generic "XXX{...}" shape. It also matches code like
# "else{ return x; }" and random bytes like "a3g{v3gvr~}", so it is trusted less:
# 0.9 when the prefix looks like a CTF name (BZHCTF, FCSC, flag...), else 0.45.
GENERIC_STRENGTH = 0.9
WEAK_GENERIC_STRENGTH = 0.45
GARBLED_STRENGTH = 0.6
# Characters seen inside real flags. Anything else ( ) ~ | ` ^ \ { suggests garbage.
FLAG_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!?@.'$#&+:=,% ")
CTF_PREFIX_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]{1,14}|.*(?:flag|ctf|FLAG|CTF|Flag|Ctf).*)$")
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


# A GUID in braces - `{01d9c0b2-0000-0000-0000-100000000000}` - matches the
# generic flag shape perfectly, and Windows is full of them: volume paths,
# registry CLSIDs, jump list names, PE resources. It is never a flag.
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def looks_like_flag(text: str) -> bool:
    """Sanity check for the generic XXX{...} pattern, which also matches random bytes.

    A real flag is printable ASCII and mostly letters, digits and underscores -
    and is not a GUID, which has exactly that shape and turns up by the hundred
    in Windows artefacts.
    """
    if not text.isascii() or not text.isprintable():
        return False
    inside = text[text.index("{") + 1 : -1]
    if GUID_RE.match(inside):
        return False
    if len(inside) > 120 or any(ch not in FLAG_CHARS for ch in inside):
        return False
    wordy = sum(ch.isalnum() or ch == "_" for ch in inside)
    return wordy >= 0.75 * len(inside)


# How many bytes on each side of a generic hit are looked at, and how many of
# them must be garbage (on BOTH sides) for the hit to be chance.
GARBAGE_WINDOW = 8
GARBAGE_MIN = 3


def _is_garbage(ch: str) -> bool:
    """A character that does not occur around a flag written on purpose.

    Printable ASCII, whitespace and NUL (the padding around a string in a
    binary) are fine; anything else - a high byte, a control character, the
    U+FFFD that an invalid UTF-8 byte decodes to - is binary noise.
    """
    code = ord(ch)
    return not (32 <= code < 127 or ch in "\t\r\n\x00")


def _in_garbage(text: str, start: int, end: int) -> bool:
    """Is a hit surrounded by binary noise on both sides?

    Shuffling binary data (rot13 then rot47 then reverse, over an HTTP stream)
    eventually lines up "K4J{btBs&7p!G}" by chance, and an uppercase prefix in
    braces looks like a CTF name. A real flag - even one inside an executable -
    sits next to text or zero bytes, not between high bytes on both sides.
    """
    before = text[max(0, start - GARBAGE_WINDOW) : start]
    after = text[end : end + GARBAGE_WINDOW]
    return (
        sum(map(_is_garbage, before)) >= GARBAGE_MIN and sum(map(_is_garbage, after)) >= GARBAGE_MIN
    )


# Characters that a flag body carries only alongside underscores ("y0u_&_m3"):
# in a body without any, they are the mark of shuffled text ("btBs&7p!G").
SOUP_CHARS = set("&$#%+=:,'@ ")
# A generic hit whose body is shorter than this, has no underscore, and whose
# prefix does not say "flag" or "ctf", is as likely to be chance as a flag.
SHORT_BODY = 12
FLAGGY_PREFIX_RE = re.compile(r"flag|ctf", re.IGNORECASE)


def _strong_body(flag: str) -> bool:
    """A body so flag-like that its surroundings no longer matter.

    "kerbrute_finding_users" inside a Kerberos packet, or a long hash: an
    underscored multi-word body, or a long one, is a real flag wherever it
    sits - so it is not downgraded for being surrounded by binary bytes, the
    way a short soup body ("btBs&7p!G") is.
    """
    body = flag[flag.index("{") + 1 : -1]
    if any(ch in SOUP_CHARS for ch in body):
        return False
    return ("_" in body and len(body) >= 8) or len(body) >= 20


def _chance_body(flag: str) -> bool:
    """Could a generic hit be chance rather than a flag, judging by its body?

    Decoding chains over binary data (rot47 -> url -> xor -> xor...) produce
    "W1{!Tgxk3b}" or "K4J{btBs&7p!G}" sooner or later: a short uppercase
    prefix, a brace, a few letters. Real flags have underscores
    ("w1ll_y0u_St4nd"), or a long body (a hash), or a prefix that says so.
    The configured prefix (CYBN) never goes through this check.
    """
    prefix, body = flag[: flag.index("{")], flag[flag.index("{") + 1 : -1]
    if "_" in body:
        return False
    if any(ch in SOUP_CHARS for ch in body):
        return True
    if FLAGGY_PREFIX_RE.search(prefix):
        return False
    return len(body) < SHORT_BODY


def plain_hits(text: str, flagset: FlagSet) -> list[tuple[str, float, str]]:
    """(flag, strength, pattern) for every regex match in clear text."""
    hits = []
    for regex, pattern_strength in flagset.regexes:
        for match in regex.finditer(text):
            flag = match.group(0)
            strength = pattern_strength
            if pattern_strength == GENERIC_STRENGTH:
                if not looks_like_flag(flag):
                    continue
                if not CTF_PREFIX_RE.match(flag[: flag.index("{")]):
                    strength = WEAK_GENERIC_STRENGTH
                elif _chance_body(flag):
                    strength = WEAK_GENERIC_STRENGTH
                elif not _strong_body(flag) and _in_garbage(text, match.start(), match.end()):
                    # A borderline body sitting in binary noise is likely chance;
                    # a strong body (underscored or long) is a real flag anywhere.
                    strength = WEAK_GENERIC_STRENGTH
            elif "{" in flag and not looks_like_flag(flag):
                # Right prefix but garbled content (e.g. a half-correct XOR key).
                strength = GARBLED_STRENGTH
            elif len(flag) - flag.index("{") - 2 < 3:
                strength = min(strength, 0.85)  # very short content: could be chance
            hits.append((flag, strength, regex.pattern))
    return hits


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

    for flag, strength, pattern in plain_hits(text, flagset):
        keep(FlagHit(flag, "plain", strength, pattern))

    # Windows writes text as UTF-16: "CYBN{" is then C\0Y\0B\0N\0{\0 and the
    # plain search above sees "C.Y.B.N.{" and misses it. Cheap to look: only
    # data with a fair number of zero bytes can hold such text at all.
    for utf16_text, encoding in _utf16_runs(data):
        for flag, strength, pattern in plain_hits(utf16_text, flagset):
            if strength > WEAK_GENERIC_STRENGTH:
                keep(FlagHit(flag, encoding, strength, pattern, flag))

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

    found = _drop_shifted(list(hits.values()))
    return sorted(found, key=lambda hit: hit.strength, reverse=True)


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
        for flag, strength, _pattern in plain_hits(decoded, flagset):
            if strength > WEAK_GENERIC_STRENGTH and flag not in found:
                found.append(flag)
    return found


# ---------------------------------------------------------------------------
# UTF-16 text inside bytes
# ---------------------------------------------------------------------------

# Six printable characters in a row, each followed (LE) or preceded (BE) by a
# zero byte: that is what a UTF-16 string looks like in a binary file, a
# registry value, a PowerShell -enc payload or a decrypted .NET string.
UTF16LE_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
UTF16BE_RUN_RE = re.compile(rb"(?:\x00[\x20-\x7e]){6,}")
# Below this many zero bytes the data cannot hold a 6-character UTF-16 run.
UTF16_MIN_ZEROS = 6


def _utf16_runs(data: bytes) -> list[tuple[str, str]]:
    """Every UTF-16 string in `data`, decoded: [(text, "utf-16-le" or "utf-16-be")].

    Both byte orders are read everywhere, which means each string is ALSO read
    the wrong way, one byte off: inside "D\0U\0C\0" the big-endian pattern
    sees "\0U\0C", i.e. the same text without its first character. That
    misreading is dropped later (`_drop_shifted`), where it is easy to spot.
    """
    if data.count(0) < UTF16_MIN_ZEROS:
        return []
    runs = []
    for match in UTF16LE_RUN_RE.finditer(data):
        runs.append((match.group(0).decode("utf-16-le"), "utf-16-le"))
    for match in UTF16BE_RUN_RE.finditer(data):
        runs.append((match.group(0).decode("utf-16-be"), "utf-16-be"))
    return runs


def _drop_shifted(hits: list[FlagHit]) -> list[FlagHit]:
    """Drop a UTF-16 hit that is another UTF-16 hit minus its first characters.

    Reading UTF-16 one byte off loses the first character: "DUCTF{x}" read in
    the wrong byte order is "UCTF{x}". The longer reading is the right one.
    """
    wide = [hit for hit in hits if hit.how.startswith("utf-16")]
    return [
        hit
        for hit in hits
        if not (
            hit.how.startswith("utf-16")
            and any(other.text != hit.text and other.text.endswith(hit.text) for other in wide)
        )
    ]


# ---------------------------------------------------------------------------
# The deep hunt: the flag behind one more layer
# ---------------------------------------------------------------------------
#
# `find_flags` is called by the scorer, i.e. thousands of times per brute
# force, so it only looks at the data as it is (plus the base64 forms of the
# configured prefixes, which cost one regex each). `hunt` is the slower search
# for when a human is waiting on ONE answer (`solve`, `scan`, `search --flags`):
#
# - every hex run and every base64 run long enough to hold a flag is DECODED
#   and searched, whatever the flag's prefix (a flag in base64 in a JPEG's XMP
#   metadata, or in clear inside a hex DNS-exfiltration stream);
# - the text is also read backwards ("}galf_a{NBYC" is a stock trick);
# - and it collects flag FRAGMENTS: "CYBN{half_one" with no end, or a decoded
#   string that is only "half_two}". Challenges split the flag in two places;
#   two fragments that make a flag together are worth showing.

# A run of base64 (or hex, which is a subset) long enough to decode to "xx{abcd}".
DECODE_RUN_RE = re.compile(r"[A-Za-z0-9+/\-_]{12,}={0,2}")
HEX_ONLY_RE = re.compile(r"[0-9a-fA-F]+")
# A reversed flag: "}...{PREFIX" - searched in the text, then read backwards.
REVERSED_FLAG_RE = re.compile(r"\}[^{}\n]{3,}\{[A-Za-z0-9_]{2,15}")
# Caps, so that a 60 MB capture costs seconds and not minutes.
MAX_DECODED_RUNS = 4000
MAX_RUN_CHARS = 4 * 1024 * 1024
# A run longer than this is decoded at offset 0 only (it is aligned in practice).
ALL_OFFSETS_UNDER = 4096
# Runs at least this long are also read backwards.
REVERSED_RUN_MIN = 32

# Fragments: a flag body is letters, digits and _!?-. "@" and "." are left out on
# purpose: they are where a flag written into an e-mail or a hostname ends.
# "PREFIX{body" where the body is NOT followed by more body or by "}".
OPEN_FRAGMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z0-9_]{2,15})\{([A-Za-z0-9_!?\-]{4,})(?![A-Za-z0-9_!?\-}])"
)
# The same, written backwards: "body{PREFIX", not preceded by more body or "}".
REVERSED_OPEN_RE = re.compile(
    r"(?<![A-Za-z0-9_!?\-}])([A-Za-z0-9_!?\-]{4,})\{([A-Za-z0-9_]{2,15})(?![A-Za-z0-9_])"
)
CLOSE_FRAGMENT_RE = re.compile(r"^([A-Za-z0-9_!?\-]{4,}\})$")
# How much readable text must come before an opening fragment in raw data: in
# random bytes "AB{x1_y" turns up by chance, in text it does not.
FRAGMENT_CONTEXT = 8
FRAGMENT_STRENGTH = 0.5
ASSEMBLED_STRENGTH = 0.75


@dataclass
class Fragment:
    """Part of a flag: its start ("CYBN{half_one") or its end ("half_two}")."""

    text: str
    side: str  # "open" or "close"
    how: str  # "plain", "reversed", "base64", "hex", "utf-16-le"...
    encoded: str = ""  # the text it was decoded from, when how is an encoding

    def to_dict(self) -> dict:
        return {"text": self.text, "side": self.side, "how": self.how, "encoded": self.encoded}


@dataclass
class Hunt:
    """What the deep hunt found: whole flags first, then fragments."""

    flags: list[FlagHit] = field(default_factory=list)
    fragments: list[Fragment] = field(default_factory=list)


def decode_run(run: str) -> list[tuple[str, str]]:
    """The readings of one run of base64-looking text: [(how, decoded text)].

    A run made only of hex digits is read as hex too. Base64 is tried at the
    four start offsets for short runs (a run may begin with a character that
    belongs to the text before it, like the "x" of "x=Q1lC...").
    """
    readings: list[tuple[str, str]] = []
    if len(run) > MAX_RUN_CHARS:
        return readings
    if HEX_ONLY_RE.fullmatch(run) and len(run) >= 16:
        even = run[: len(run) - len(run) % 2]
        readings.append(("hex", bytes.fromhex(even).decode("latin-1")))
    offsets = range(4) if len(run) < ALL_OFFSETS_UNDER else range(1)
    for start in offsets:
        chunk = run[start:].replace("-", "+").replace("_", "/").rstrip("=")
        if len(chunk) % 4 == 1:
            chunk = chunk[:-1]
        if len(chunk) < 8:
            continue
        chunk += "=" * (-len(chunk) % 4)
        try:
            decoded = base64.b64decode(chunk)
        except (binascii.Error, ValueError):
            continue
        readings.append(("base64", decoded.decode("latin-1")))
    # Reversed base64 ("==QfzN2X..." or no padding at all) is a stock way to
    # hide a payload in a script: one more decode, for the long runs only.
    if len(run) >= REVERSED_RUN_MIN:
        backwards = run[::-1].lstrip("=").replace("-", "+").replace("_", "/")
        if len(backwards) % 4 != 1:
            try:
                decoded = base64.b64decode(backwards + "=" * (-len(backwards) % 4))
                readings.append(("reversed base64", decoded.decode("latin-1")))
            except (binascii.Error, ValueError):
                pass
    return readings


def _views(data: bytes, text: str) -> list[tuple[str, str, str]]:
    """Every reading of the data worth a flag search: [(how, text, encoded)].

    The plain text itself is not in the list (`find_flags` covers it).
    """
    views: list[tuple[str, str, str]] = []
    for count, match in enumerate(DECODE_RUN_RE.finditer(text)):
        if count >= MAX_DECODED_RUNS:
            break
        run = match.group(0)
        for how, decoded in decode_run(run):
            views.append((how, decoded, run))
    for utf16_text, encoding in _utf16_runs(data):
        views.append((encoding, utf16_text, ""))
    return views


def _readable_around(text: str, start: int, end: int) -> bool:
    """Is the text just before `start` and just after `end` readable?"""
    around = text[max(0, start - FRAGMENT_CONTEXT) : start] + text[end : end + FRAGMENT_CONTEXT]
    return all(32 <= ord(ch) < 127 or ch in "\t\r\n" for ch in around)


def _fragment_is_plausible(prefix: str, body: str, flagset: FlagSet) -> bool:
    """Is "prefix{body" the start of a flag, rather than code or chance?

    The configured prefix (CYBN) is enough with a 4-character body. Any other
    prefix must look like a CTF name (HTB, FLAG, picoCTF...) and carry a longer
    body. Either way the body must hold a digit or an underscore ("w1ll_y0u"):
    a word in braces ("{Default") is template syntax, not a fragment.
    """
    if not any(ch.isdigit() or ch == "_" for ch in body):
        return False
    configured = {pfx.rstrip("{") for _regex, pfx in flagset.b64_prefixes}
    if prefix in configured:
        return True
    return len(prefix) >= 3 and len(body) >= 6 and CTF_PREFIX_RE.match(prefix) is not None


def _open_fragments(text: str, flagset: FlagSet, how: str, encoded: str) -> list[Fragment]:
    """Every "PREFIX{body" with no closing brace in `text`, forwards and backwards.

    Backwards means the text holds "body{PREFIX" ("user@tS_u0y_ll1w{BTH" at the
    end of an SSH key): it is searched as it is and turned round, rather than
    turning a whole file round to search it.
    """
    raw = how == "plain"  # raw file bytes: demand readable text around a hit
    found = []
    for match in OPEN_FRAGMENT_RE.finditer(text):
        prefix, body = match.group(1), match.group(2)
        if not _fragment_is_plausible(prefix, body, flagset):
            continue
        if raw and not _readable_around(text, match.start(), match.end()):
            continue
        found.append(Fragment(match.group(0), "open", how, encoded))
    for match in REVERSED_OPEN_RE.finditer(text):
        body, prefix = match.group(1)[::-1], match.group(2)[::-1]
        if not _fragment_is_plausible(prefix, body, flagset):
            continue
        if raw and not _readable_around(text, match.start(), match.end()):
            continue
        reversed_how = "reversed" if raw else f"{how}, reversed"
        found.append(Fragment(f"{prefix}{{{body}", "open", reversed_how, match.group(0)))
    return found


def _close_fragment(text: str, how: str, encoded: str) -> Fragment | None:
    """A decoded string that is ONLY the end of a flag ("half_two}"), or None.

    Only whole decoded strings count: in plain text, "...}" is every closing
    brace of every script.
    """
    stripped = text.strip()
    match = CLOSE_FRAGMENT_RE.match(stripped)
    if match is None or not any(ch.isdigit() or ch == "_" for ch in stripped):
        return None
    return Fragment(stripped, "close", how, encoded)


def hunt(data: bytes, flagset: FlagSet | None = None) -> Hunt:
    """Look for a flag in the data AND one layer under it (decoded, reversed, UTF-16).

    Slower than `find_flags` (it decodes every hex/base64 run), so it is meant
    for the commands where a human is waiting on the answer, not for scoring.
    """
    flagset = flagset or default_flagset()
    result = Hunt()
    hits: dict[str, FlagHit] = {}

    def keep(hit: FlagHit) -> None:
        old = hits.get(hit.text)
        if old is None or hit.strength > old.strength:
            hits[hit.text] = hit

    for hit in find_flags(data, flagset):
        keep(hit)

    text = data.decode("latin-1")
    views = _views(data, text)
    for how, decoded, encoded in views:
        for flag, strength, pattern in plain_hits(decoded, flagset):
            if strength > WEAK_GENERIC_STRENGTH:
                keep(FlagHit(flag, how, strength, pattern, encoded or flag))

    # Backwards: only the stretches that look like a reversed flag are turned
    # round, so a big file is not copied whole.
    for match in REVERSED_FLAG_RE.finditer(text):
        backwards = match.group(0)[::-1]
        for flag, strength, pattern in plain_hits(backwards, flagset):
            if strength > WEAK_GENERIC_STRENGTH:
                keep(FlagHit(flag, "reversed", strength, pattern, match.group(0)))

    found = _drop_shifted(list(hits.values()))
    result.flags = sorted(found, key=lambda hit: hit.strength, reverse=True)

    # Fragments: openings in the text (forwards and backwards) and in every
    # decoded reading; endings only as whole decoded strings.
    fragments: dict[tuple[str, str], Fragment] = {}
    candidates = _open_fragments(text, flagset, "plain", "")
    for how, decoded, encoded in views:
        candidates += _open_fragments(decoded, flagset, how, encoded)
        closing = _close_fragment(decoded, how, encoded)
        if closing is not None:
            candidates.append(closing)
    whole = [hit.text for hit in result.flags]
    for fragment in candidates:
        # The start of a flag we already have whole is not a fragment.
        if any(flag.startswith(fragment.text) or flag.endswith(fragment.text) for flag in whole):
            continue
        fragments.setdefault((fragment.side, fragment.text), fragment)
    result.fragments = list(fragments.values())
    return result


def hunt_flags(data: bytes, flagset: FlagSet | None = None) -> list[FlagHit]:
    """The whole flags `hunt` finds (see `hunt`), strongest first."""
    return hunt(data, flagset).flags


def assemble(fragments: list[Fragment], flagset: FlagSet | None = None) -> list[str]:
    """Every flag that an opening and a closing fragment make together.

    "CYBN{w1ll_y0u_" + "f1nd_m3}" -> "CYBN{w1ll_y0u_f1nd_m3}". Only pairs whose
    join passes the flag check are kept, so two unrelated pieces of text do not
    produce a flag.
    """
    flagset = flagset or default_flagset()
    openings = [fragment for fragment in fragments if fragment.side == "open"]
    closings = [fragment for fragment in fragments if fragment.side == "close"]
    joined: list[str] = []
    for opening in openings[:20]:
        for closing in closings[:20]:
            candidate = opening.text + closing.text
            for flag, strength, _pattern in plain_hits(candidate, flagset):
                if flag == candidate and strength > WEAK_GENERIC_STRENGTH and flag not in joined:
                    joined.append(flag)
    return joined
