"""Fingerprint unknown bytes: "what is this, and what should I try next?"

`detect(data)` measures the data (length, entropy, printable ratio, charset) and runs
a list of independent checks. Each check returns `Guess` objects with a confidence,
the reasons, and a suggested next step. The guesses are then ranked.

Checks (one small function each, in the order they run):
- flags in clear or base64            - magic bytes, appended data, embedded files
- text prefixes (openssl, JWT, PEM, hashes, ...)   - charset (hex, base64, base32...)
- zero-width characters               - UTF-16LE text
- entropy and block-length rules      - repeated blocks (ECB)
- repeating pattern (XOR key length)  - crypto constants (AES S-box, TEA delta...)
- custom base64 alphabets             - classical ciphers (letter statistics, see classical.py)
- AES key schedules (an expanded AES key in a memory dump, see keyhunt.py)

When the input is hex/base64 text, the binary checks also run on the decoded bytes.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from ctfc.core import classical, encodings, keyhunt
from ctfc.core.datafiles import load_toml
from ctfc.core.flags import FlagSet, default_flagset, find_flags
from ctfc.core.magic import (
    find_embedded,
    find_trailing_data,
    load_prefix_rules,
    match_signature,
)
from ctfc.core.scoring import printable_ratio, shannon_entropy, text_stats
from ctfc.core.xor import coincidence_rates, period_ratios

WINDOW = 256  # bytes per entropy window
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Which tab solves which file type, for the "Apply" buttons in the web UI.
SIG_APPLY: dict[str, dict] = {
    "enc": {"tab": "sym", "options": {"passwords": True}},
    "pem_rsa_private": {"tab": "rsa", "options": {}},
    "pem_private": {"tab": "rsa", "options": {}},
    "pem_public": {"tab": "rsa", "options": {}},
}

# What to do next for some file types (by extension in magic.toml).
SIG_HINTS = {
    "enc": "openssl enc: ctfc sym <file> --pass <password> (or --passwords), or "
    "openssl enc -d -aes-256-cbc -md sha256 -pbkdf2 -in <file> -pass pass:<password>",
    "zip": "unzip -l <file>; encrypted? zip2john <file> > h && john h",
    "7z": "7z l <file>; encrypted? 7z2john.pl <file>",
    "rar": "unrar l <file>; encrypted? rar2john <file>",
    "kdbx": "keepass2john <file> > h; hashcat -m 13400 h wordlist",
    "kdb": "keepass2john <file> > h; hashcat -m 13400 h wordlist",
    "pcap": "open in Wireshark; tshark -r <file> -qz conv,tcp",
    "pcapng": "open in Wireshark; tshark -r <file> -qz conv,tcp",
    "elf": "strings -n 8 <file>; diec <file>; look for crypto constants below",
    "exe": "diec <file>; strings -el <file> (UTF-16 strings)",
    "luks": "out of scope for ctfc: luks2john / hashcat -m 14600",
    "bitlocker": "out of scope for ctfc: bitlocker2john / hashcat -m 22100",
    "ser": "Java serialized object: inspect with SerializationDumper, never deserialize",
}


@dataclass
class Guess:
    """One hypothesis about the data."""

    rule: str  # rule id, e.g. "aes.ecb" (used later by the external tool bridge)
    label: str  # short human description
    confidence: float  # 0..1
    reasons: list[str] = field(default_factory=list)
    next_step: str = ""  # what to try next, as a command line
    # The same thing, machine-readable: which tab solves this, and with which
    # options already filled in. The web UI turns it into an "Apply" button.
    #   {"tab": "xor", "options": {"keylen": 6}}
    apply: dict | None = None


@dataclass
class DetectReport:
    """Everything detect() found. `facts` are measurements, `guesses` are hypotheses."""

    length: int
    entropy: float
    printable: float
    utf8: bool
    charset: str
    facts: list[tuple[str, str]]
    guesses: list[Guess]
    entropy_windows: list[float]

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def detect(data: bytes, flagset: FlagSet | None = None) -> DetectReport:
    """Fingerprint `data` and return ranked guesses with reasons."""
    entropy = shannon_entropy(data)
    printable, utf8 = printable_ratio(data)
    charset, charset_guesses, decoded = _check_charset(data)

    guesses: list[Guess] = []
    guesses += _check_flags(data, flagset)
    guesses += _check_magic(data)
    guesses += _check_repairable(data)
    guesses += _check_prefixes(data)
    guesses += charset_guesses
    guesses += _check_zero_width(data)
    guesses += _check_constants(data)
    guesses += _check_custom_alphabet(data)
    guesses += _check_classical(data, flagset)
    guesses += _check_key_schedules(data)
    # Zero-width characters are invisible but not "binary": ignore them here.
    visible = data.decode("utf-8", errors="ignore")
    visible = "".join(c for c in visible if c not in encodings.ZERO_WIDTH).encode()
    # A recognised file type (PNG, ZIP...) explains its own entropy and length:
    # the cipher heuristics would only add noise.
    sig = match_signature(data)
    known_file = sig is not None and not sig.weak and sig.ext != "enc"
    if not known_file and (not utf8 or printable_ratio(visible)[0] < 0.85):
        guesses += _binary_checks(data, prefix="")
    if decoded is not None:
        name, decoded_bytes = decoded
        guesses += _check_flags(decoded_bytes, flagset, prefix=f"after {name} decoding: ")
        guesses += _check_magic(decoded_bytes, prefix=f"after {name} decoding: ")
        guesses += _binary_checks(decoded_bytes, prefix=f"after {name} decoding: ")

    guesses = _dedupe(guesses)
    guesses.sort(key=lambda guess: guess.confidence, reverse=True)

    windows = entropy_windows(data)
    facts = _facts(data, entropy, printable, utf8, charset, windows)
    return DetectReport(
        length=len(data),
        entropy=round(entropy, 3),
        printable=round(printable, 3),
        utf8=utf8,
        charset=charset,
        facts=facts,
        guesses=guesses,
        entropy_windows=windows,
    )


def entropy_windows(data: bytes, window: int = WINDOW) -> list[float]:
    """Entropy of each consecutive `window`-byte slice (shows where the random parts are)."""
    return [
        round(shannon_entropy(data[start : start + window]), 2)
        for start in range(0, len(data), window)
        if len(data[start : start + window]) >= 16
    ]


def _facts(
    data: bytes,
    entropy: float,
    printable: float,
    utf8: bool,
    charset: str,
    windows: list[float],
) -> list[tuple[str, str]]:
    length = len(data)
    # With few bytes the entropy cannot reach 8: compare to the maximum possible.
    max_entropy = min(8.0, math.log2(length)) if length > 1 else 1.0
    facts = [
        ("length", f"{length} bytes"),
        ("entropy", f"{entropy:.2f} bits/byte (max possible here {max_entropy:.2f})"),
        ("printable", f"{printable:.0%}"),
        ("valid UTF-8", "yes" if utf8 else "no"),
        ("charset", charset),
        ("distinct bytes", str(len(set(data)))),
        ("block alignment", f"len % 16 = {length % 16}, len % 8 = {length % 8}"),
    ]
    if len(windows) > 1:
        facts.append(("entropy per 256 B", f"min {min(windows)}, max {max(windows)}"))
    return facts


def _dedupe(guesses: list[Guess]) -> list[Guess]:
    """Keep one guess per (rule, label), the most confident one."""
    best: dict[tuple[str, str], Guess] = {}
    for guess in guesses:
        key = (guess.rule, guess.label)
        if key not in best or guess.confidence > best[key].confidence:
            best[key] = guess
    return list(best.values())


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_flags(data: bytes, flagset: FlagSet | None, prefix: str = "") -> list[Guess]:
    guesses = []
    for hit in find_flags(data, flagset)[:5]:
        if hit.how == "base64-prefix":
            guesses.append(
                Guess(
                    "flag.base64",
                    "base64-encoded flag prefix",
                    0.8,
                    [prefix + hit.text],
                    "ctfc auto <input>",
                )
            )
            continue
        how = "in clear" if hit.how == "plain" else "base64-encoded"
        guesses.append(
            Guess(
                rule="flag",
                label=f"flag {how}: {hit.text[:60]}",
                confidence=hit.strength,
                reasons=[f"{prefix}matches {hit.pattern!r}"],
            )
        )
    return guesses


def _check_repairable(data: bytes) -> list[Guess]:
    """A magic one byte off a known one, or a header pasted over another one."""
    from ctfc.core.repair import near_miss, pasted_header

    guesses = []
    miss = near_miss(data)
    if miss is not None:
        sig, offset, actual = miss
        guesses.append(
            Guess(
                rule="magic.corrupted",
                label=f"a {sig.name} with ONE corrupted magic byte (offset {offset})",
                confidence=0.9,
                reasons=[
                    f"byte {offset} is 0x{actual:02x}, a {sig.name} has "
                    f"0x{sig.magic[offset]:02x} there; every other byte of the signature matches"
                ],
                next_step="ctfc repair <input> --out repaired/",
            )
        )
    pasted = pasted_header(data)
    if pasted is not None:
        worn, fits = pasted
        guesses.append(
            Guess(
                rule="magic.pasted",
                label=f"starts with part of a {worn.name} signature, not all of it: "
                "a pasted header",
                confidence=0.8,
                reasons=[
                    f"formats whose magic would fit underneath: {', '.join(s.ext for s in fits)}"
                ],
                next_step="ctfc repair <input> --out repaired/",
            )
        )
    return guesses


def _check_magic(data: bytes, prefix: str = "") -> list[Guess]:
    guesses = []
    sig = match_signature(data)
    if sig is not None:
        guesses.append(
            Guess(
                rule=f"magic.{sig.ext}",
                label=sig.name,
                confidence=0.5 if sig.weak else 0.95,
                reasons=[f"{prefix}signature {sig.magic.hex()} at offset {sig.offset}"]
                + (["short signature: may be a coincidence"] if sig.weak else []),
                next_step=SIG_HINTS.get(sig.ext, f"save it as .{sig.ext} and open it"),
                apply=SIG_APPLY.get(sig.ext),
            )
        )
    trailing = find_trailing_data(data)
    if trailing is not None:
        what = f" (looks like {trailing.looks_like})" if trailing.looks_like else ""
        guesses.append(
            Guess(
                rule="polyglot.trailing",
                label=f"{trailing.size} bytes appended after the {trailing.after}{what}",
                confidence=0.9,
                reasons=[f"{prefix}end of {trailing.after} at offset {trailing.end_offset}"],
                next_step=f"dd if=<file> of=tail.bin bs=1 skip={trailing.end_offset}; "
                "or binwalk -e <file>",
            )
        )
    embedded = find_embedded(data)
    if embedded:
        listing = [f"{item.name} at offset {item.offset} (0x{item.offset:x})" for item in embedded]
        guesses.append(
            Guess(
                rule="embedded",
                label=f"{len(embedded)} other file signature(s) inside the data",
                confidence=0.6,
                reasons=[prefix + line for line in listing[:8]],
                next_step="binwalk -e <file> (signatures can also be coincidences)",
            )
        )
    return guesses


# Which tab handles a text format recognised by prefix (see magic.toml [[prefix]]).
PREFIX_APPLY: dict[str, dict] = {
    "pem": {"tab": "rsa", "options": {}},
    "fernet": {"tab": "sym", "options": {}},
    "openssl.salted_b64": {"tab": "sym", "options": {"passwords": True}},
    "jwt": {"tab": "auto", "options": {}},
}


def _apply_for_prefix(rule_id: str) -> dict | None:
    """The tab that solves this text format, for the "Apply" button."""
    if rule_id.startswith("hash."):
        return {"tab": "hash", "options": {}}
    return PREFIX_APPLY.get(rule_id)


def _check_prefixes(data: bytes) -> list[Guess]:
    text = data[:200_000].decode("utf-8", errors="replace")
    guesses = []
    for rule in load_prefix_rules():
        match = rule.regex.search(text)
        if match is None:
            continue
        excerpt = match.group(0).strip()
        guesses.append(
            Guess(
                rule=rule.id,
                label=rule.label,
                confidence=rule.strength,
                reasons=[f"matched: {excerpt[:70]}{'...' if len(excerpt) > 70 else ''}"],
                next_step=rule.hint,
                apply=_apply_for_prefix(rule.id),
            )
        )
    return guesses


# Charsets, most specific first: (decoder name, label, confidence when it matches)
_CHARSETS = [
    ("binary", "binary digits (01000001 ...)", 0.9),
    ("decimal", "decimal character codes", 0.75),
    ("hex", "hexadecimal text", 0.85),
    ("base32", "base32 text (A-Z2-7)", 0.75),
    ("base64", "base64 text", 0.8),
    ("base64url", "base64url text (-_ alphabet)", 0.8),
    ("base58", "base58 text (no 0OIl)", 0.5),
    ("base62", "base62 text (alphanumeric only)", 0.35),
    ("ascii85", "ascii85 text", 0.5),
    ("base85", "base85 text", 0.45),
]


# Charsets precise enough to also analyse the decoded bytes.
DECODED_VIEW = {"binary", "decimal", "hex", "base32", "base64", "base64url"}


def _check_charset(data: bytes) -> tuple[str, list[Guess], tuple[str, bytes] | None]:
    """Return (charset name, guesses, (decoder name, decoded bytes) or None)."""
    text = encodings.as_text(data)
    if text is None:
        return ("binary data" if printable_ratio(data)[0] < 0.85 else "text (non-ASCII)"), [], None
    guesses: list[Guess] = []
    decoded: tuple[str, bytes] | None = None
    charset = "printable text"
    for name, label, confidence in _CHARSETS:
        decoder = encodings.DECODERS_BY_NAME[name]
        if not decoder.applicable(data):
            continue
        try:
            output = decoder.decode(data)
        except (encodings.DecodeError, ValueError):
            continue
        reasons = [f"only uses the {name} alphabet", f"decodes to {len(output)} bytes"]
        if name == "base64" and len(re.sub(r"\s", "", text)) % 4 == 0:
            reasons.append("length is a multiple of 4")
            confidence = min(0.9, confidence + 0.05)
        sig = match_signature(output)
        if sig is not None and not sig.weak:
            reasons.append(f"decoded data is a {sig.name}")
            confidence = min(0.95, confidence + 0.1)
        if charset == "printable text":
            charset = label
            if name in DECODED_VIEW:
                decoded = (name, output)
        else:
            confidence *= 0.6  # an earlier, more specific charset already matched
        guesses.append(Guess(f"encoding.{name}", label, confidence, reasons, "ctfc auto <input>"))
    return charset, guesses, decoded


SCHEDULE_DETECT_LIMIT = 256 * 1024 * 1024  # detect scans this much for AES key schedules


def _check_key_schedules(data: bytes) -> list[Guess]:
    """An AES key followed by its own expansion: the key itself sits in this dump."""
    if len(data) < 176:
        return []
    found = keyhunt.find_aes_schedules(data, limit=SCHEDULE_DETECT_LIMIT)
    guesses = []
    for candidate in found[:5]:
        bits = len(candidate.key) * 8
        guesses.append(
            Guess(
                rule="keys.aes_schedule",
                label=f"AES-{bits} key in memory at offset 0x{candidate.offset:x}",
                confidence=0.95,
                reasons=[candidate.how, f"key = {candidate.key.hex()}"],
                next_step="ctfc keys <input> --against <ciphertext>",
                apply={"tab": "keys", "options": {}},
            )
        )
    return guesses


CLASSICAL_APPLY = {"tab": "auto", "options": {}}
CLASSICAL_NEXT = "ctfc classical <input>  (or ctfc auto <input>)"


def _check_classical(data: bytes, flagset: FlagSet | None) -> list[Guess]:
    """Text that does not read: which family of classical cipher do the letters suggest?

    The measurements are explained in classical.py: letter frequencies (chi2) and
    the index of coincidence (IoC), plus a flag-shaped word ("PLOA{") that has the
    length of a known prefix ("CYBN{").
    """
    if not classical.is_text_like(data):
        return []
    guesses = []
    configured = {
        prefix.rstrip("{") for _regex, prefix in (flagset or default_flagset()).b64_prefixes
    }
    seen_words: set[str] = set()
    for crib in classical.find_cribs(data, flagset):
        if crib.word in seen_words:
            continue
        seen_words.add(crib.word)
        strong = crib.prefix in configured
        caesar = len(set(crib.shifts)) == 1
        how = f"Caesar shift {crib.shifts[0]}" if caesar else "Vigenère (or another shift)"
        guesses.append(
            Guess(
                rule="classical.flag_shift",
                label=f"'{crib.word}{{' could be '{crib.prefix}{{' shifted: {how}",
                confidence=0.8 if strong and caesar else 0.75 if strong else 0.5,
                reasons=[
                    f"a flag-shaped word with the length of the known prefix '{crib.prefix}'",
                    "shifts letter by letter: " + ", ".join(str(k) for k in crib.shifts),
                ],
                next_step=CLASSICAL_NEXT,
                apply=CLASSICAL_APPLY,
            )
        )

    stats = classical.analyse(data)
    if stats.letters < 20 or text_stats(data).word_rate >= 0.3:
        return guesses  # too few letters to measure, or it already reads as words
    facts = f"{stats.letters} letters, IoC {stats.ioc:.3f} (English ~0.067, random 0.038)"
    if stats.family == "natural":
        guesses.append(
            Guess(
                rule="classical.transposition",
                label="natural letter frequencies but no words: a transposition (rail fence, "
                "columnar)?",
                confidence=0.65 if stats.letters >= 80 else 0.55,
                reasons=[
                    facts,
                    f"letter frequencies close to {stats.language} "
                    f"(chi2 {stats.chi2:.0f}): the right letters, in the wrong order",
                ],
                next_step=CLASSICAL_NEXT,
                apply=CLASSICAL_APPLY,
            )
        )
    elif stats.family == "monoalphabetic":
        guesses.append(
            Guess(
                rule="classical.monoalphabetic",
                label="one substituted alphabet: Caesar / ROT-n / affine / Atbash / keyword",
                confidence=0.75,
                reasons=[
                    facts,
                    f"high IoC but frequencies far from EN/FR (chi2 {stats.chi2:.0f}): "
                    "letters were renamed, not mixed",
                ],
                next_step=CLASSICAL_NEXT + "; a keyword substitution: dcode / quipqiup",
                apply=CLASSICAL_APPLY,
            )
        )
    elif stats.family == "polyalphabetic" and stats.key_lengths:
        best = stats.key_lengths[0]
        if best.ioc >= classical.GOOD_COLUMN_IOC and best.length > 1:
            guesses.append(
                Guess(
                    rule="classical.vigenere",
                    label=f"several alphabets: Vigenère, key length {best.length}?",
                    confidence=0.75,
                    reasons=[
                        facts,
                        f"every {best.length}th letter has IoC {best.ioc:.3f}: "
                        "each column is one Caesar alphabet",
                    ],
                    next_step="ctfc classical <input> --cipher vigenere",
                    apply=CLASSICAL_APPLY,
                )
            )
    return guesses


def _check_zero_width(data: bytes) -> list[Guess]:
    hidden = encodings.zero_width_chars(data)
    if not hidden:
        return []
    kinds = Counter(hidden)
    names = ", ".join(f"U+{ord(c):04X} {encodings.ZERO_WIDTH[c]} x{n}" for c, n in kinds.items())
    reasons = [f"{len(hidden)} invisible characters: {names}"]
    if len(kinds) == 2:
        reasons.append("exactly 2 kinds: probably bits 0/1 (ctfc auto tries both mappings)")
    return [
        Guess(
            rule="stego.zero_width",
            label="hidden zero-width Unicode characters",
            confidence=0.9 if len(hidden) >= 8 else 0.6,
            reasons=reasons,
            next_step="ctfc auto <input>; otherwise a StegCloak / 'unicode steganography' "
            "zero-width decoder (StegCloak also needs a password)",
        )
    ]


@lru_cache(maxsize=1)
def _constants() -> list[tuple[str, str, bytes]]:
    return [
        (raw["name"], raw["algo"], bytes.fromhex(raw["hex"]))
        for raw in load_toml("constants.toml").get("const", [])
    ]


def _check_constants(data: bytes) -> list[Guess]:
    """Look for crypto constants as raw bytes, and as hex text in source code."""
    lowered = data.lower()
    by_algo: dict[str, list[str]] = {}
    for name, algo, value in _constants():
        position = data.find(value)
        if position != -1:
            by_algo.setdefault(algo, []).append(f"{name} at offset {position} (0x{position:x})")
            continue
        if len(value) <= 8:
            hex_text = value.hex().encode()
            position = lowered.find(hex_text)
            if position != -1:
                by_algo.setdefault(algo, []).append(f"{name} written as text at offset {position}")
    guesses = []
    for algo, found in by_algo.items():
        weak = "weak" in algo or algo == "base64"
        guesses.append(
            Guess(
                rule=f"const.{algo.split()[0].lower()}",
                label=f"{algo} constants found",
                confidence=0.4 if weak else 0.75,
                reasons=found[:5],
                next_step="this algorithm is probably implemented here: find the key near it",
            )
        )
    return guesses


def _check_custom_alphabet(data: bytes) -> list[Guess]:
    """A 64-character string with no repeated character = a (custom?) base64 alphabet."""
    text = data[:1_000_000].decode("latin-1")
    for match in re.finditer(r"[A-Za-z0-9+/=_\-.]{64,4096}", text):
        run = match.group(0)
        for start in range(0, len(run) - 63):
            window = run[start : start + 64]
            if len(set(window)) == 64 and window != STANDARD_B64:
                return [
                    Guess(
                        rule="base64.custom_alphabet",
                        label="custom base64 alphabet",
                        confidence=0.8,
                        reasons=[
                            f"64 distinct characters at offset {match.start() + start}: {window}"
                        ],
                        next_step="decode with this alphabet: CyberChef From_Base64 with a "
                        "custom alphabet, or str.maketrans() to the standard one",
                    )
                ]
    return []


# ---------------------------------------------------------------------------
# Checks for binary (non-text) data
# ---------------------------------------------------------------------------


def _binary_checks(data: bytes, prefix: str) -> list[Guess]:
    guesses: list[Guess] = []
    if len(data) < 8:
        return guesses
    guesses += _check_entropy(data, prefix)
    guesses += _check_ecb(data, prefix)
    guesses += _check_lengths(data, prefix)
    if not any(guess.rule.endswith(".ecb") for guess in guesses):
        guesses += _check_xor_period(data, prefix)
    else:
        # Repeated ECB blocks also make the data look periodic / low-entropy.
        guesses = [guess for guess in guesses if guess.rule != "xor.simple"]
    return guesses


def _check_entropy(data: bytes, prefix: str) -> list[Guess]:
    entropy = shannon_entropy(data)
    max_entropy = min(8.0, math.log2(len(data)))
    ratio = entropy / max_entropy if max_entropy else 0
    printable, _ = printable_ratio(data)
    guesses = []
    if ratio > 0.9 and entropy > 3.5:
        sig = match_signature(data)
        if sig is None:
            guesses.append(
                Guess(
                    rule="entropy.high",
                    label="random-looking bytes: encrypted, compressed or a key",
                    confidence=0.55,
                    reasons=[
                        f"{prefix}entropy {entropy:.2f} bits/byte "
                        f"({ratio:.0%} of the maximum {max_entropy:.2f})",
                        "no known file signature",
                    ],
                    next_step="check the length rules below; look for a key / IV in the challenge",
                )
            )
    elif entropy < 6.0 and printable < 0.6 and len(data) >= 16:
        guesses.append(
            Guess(
                rule="xor.simple",
                label="low entropy but unreadable: simple XOR / substitution?",
                confidence=0.5,
                reasons=[
                    f"{prefix}entropy only {entropy:.2f} bits/byte, {printable:.0%} printable",
                    "real encryption would look random (close to 8 bits/byte)",
                ],
                next_step="ctfc xor <input> / xortool <file>",
                apply={"tab": "xor", "options": {}},
            )
        )
    windows = entropy_windows(data)
    if len(windows) >= 3 and min(windows) < 5.0 and max(windows) > 7.5:
        low = [i * WINDOW for i, value in enumerate(windows) if value < 5.0][:3]
        high = [i * WINDOW for i, value in enumerate(windows) if value > 7.5][:3]
        guesses.append(
            Guess(
                rule="entropy.mixed",
                label="mixed content: some parts are random, others structured",
                confidence=0.5,
                reasons=[
                    f"{prefix}low-entropy windows at offsets {low}",
                    f"high-entropy windows at offsets {high}",
                ],
                next_step="carve the high-entropy region; binwalk -E <file> plots it",
            )
        )
    return guesses


def _check_ecb(data: bytes, prefix: str) -> list[Guess]:
    """ECB encrypts equal plaintext blocks to equal ciphertext blocks: repeats betray it."""
    guesses = []
    for size, cipher in ((16, "AES"), (8, "DES/3DES/Blowfish")):
        if len(data) < 2 * size or len(data) % size:
            continue
        blocks = [data[i : i + size] for i in range(0, len(data), size)]
        counts = Counter(blocks)
        repeated = sum(count - 1 for count in counts.values() if count > 1)
        # Real ciphertext blocks look random; XORed text repeats but stays low-entropy.
        unique = b"".join(counts)
        max_entropy = min(8.0, math.log2(len(unique)))
        if repeated and shannon_entropy(unique) >= 0.85 * max_entropy:
            guesses.append(
                Guess(
                    rule="aes.ecb" if size == 16 else "block8.ecb",
                    label=f"{cipher} in ECB mode (repeated {size}-byte blocks)",
                    confidence=0.9 if size == 16 else 0.7,
                    reasons=[
                        f"{prefix}{repeated} repeated block(s) out of {len(blocks)}",
                        "random data almost never repeats a whole block",
                    ],
                    next_step="ctfc sym <input> --mode ecb --key ...",
                    apply={"tab": "sym", "options": {"mode": "ecb"}},
                )
            )
            break  # 16-byte repeats imply 8-byte repeats: report only the first
    return guesses


# Typical lengths of keys / IVs / blobs and what they usually mean.
KEY_SHAPES = {
    8: "DES key or 8-byte IV (DES/Blowfish/3DES)",
    12: "12-byte nonce (AES-GCM / ChaCha20)",
    16: "AES-128 key or 16-byte IV",
    24: "AES-192 or 3DES key",
    32: "AES-256 key, ChaCha20 key, or 16-byte key + 16-byte IV",
    40: "24-byte key + 16-byte IV?",
    44: "32-byte key + 12-byte nonce (ChaCha20 / GCM)?",
    48: "32-byte key + 16-byte IV (AES-256-CBC key||iv)?",
    64: "two 32-byte values, or a SHA-512 / HMAC output",
}


def _check_lengths(data: bytes, prefix: str) -> list[Guess]:
    length = len(data)
    guesses = []
    if length in KEY_SHAPES:
        guesses.append(
            Guess(
                rule=f"length.key{length}",
                label=f"{length} bytes: {KEY_SHAPES[length]}",
                confidence=0.45,
                reasons=[f"{prefix}length {length} matches a common key/IV layout"],
                next_step="ctfc blob <input> --against <ciphertext>",
                apply={"tab": "sym", "options": {"blob": "<this input>"}},
            )
        )
    if length >= 32:
        if length % 16 == 0:
            label = f"{length} bytes = {length // 16} blocks of 16: AES-like block cipher (CBC/ECB)"
            reason = "length is a multiple of 16"
            confidence = 0.4
        elif length % 8 == 0:
            label = f"{length} bytes = {length // 8} blocks of 8: DES/3DES/Blowfish/TEA?"
            reason = "length is a multiple of 8 but not of 16"
            confidence = 0.35
        else:
            label = "length is not block-aligned: stream cipher / XOR / CTR / GCM / CTS?"
            reason = f"length % 16 = {length % 16}"
            confidence = 0.3
        guesses.append(Guess("length.blocks", label, confidence, [prefix + reason]))
    return guesses


def _check_xor_period(data: bytes, prefix: str) -> list[Guess]:
    """Repeating-key XOR leaves a period: bytes k apart (k = key length) match more often.

    The maths live in xor.py (coincidence_rates / period_ratios); docs/how-it-works.md
    explains them. Here we only decide if the signal is strong enough to report.
    """
    data = data[:4096]  # enough to see the period, and keeps the check fast
    length = len(data)
    if length < 64:
        return []
    rates = coincidence_rates(data, min(40, length // 4))
    ratios = period_ratios(rates)
    period, best_ratio = 0, 0.0
    for candidate, (ratio, _mean, _other) in ratios.items():
        if ratio > best_ratio * 1.1:  # a longer period must be clearly better
            period, best_ratio = candidate, ratio
    if not period:
        return []
    _ratio, best_mean, other_mean = ratios[period]
    if best_ratio < 2.5 or best_mean < 0.03:
        return []
    if rates[period] * (length - period) < 8:
        return []  # fewer than 8 matching pairs: not enough evidence
    # Keys with a repeated character (e.g. "s3cr3t") create shorter pseudo-periods,
    # so the next best lengths are worth trying too.
    ranked = sorted(ratios, key=lambda p: ratios[p][0], reverse=True)
    others = ", ".join([str(p) for p in ranked if p != period and ratios[p][0] >= 2.5][:3])
    return [
        Guess(
            rule="xor.repeating",
            label=f"repeating pattern with period {period}: repeating-key XOR (key length?)",
            confidence=0.7,
            reasons=[
                f"{prefix}bytes {period}, {2 * period}, ... apart are equal {best_mean:.1%} "
                f"of the time, other distances only {other_mean:.1%}"
            ]
            + ([f"other plausible key lengths: {others}"] if others else []),
            next_step=f"ctfc xor <input> --keylen {period} / xortool -l {period} <file>",
            apply={"tab": "xor", "options": {"keylen": period}},
        )
    ]
