"""Score bytes: "how likely is this to be the answer we are looking for?"

`score(data)` returns a number between 0 and 1 **and** the reasons behind it.
It is fully deterministic. The rules, strongest first:

1. A flag (see flags.py)                          -> 0.90 .. 0.97
2. Magic bytes of a known file type at offset 0   -> 0.85
3. Valid PKCS7 padding (only when asked: after a block-cipher decryption) -> +0.15
4. Natural-language text:
       printable ratio  (how much of it is readable characters)
       word hit rate    (how many letters belong to common EN/FR words)
       letter frequency (chi-squared distance to English / French letter frequencies)
   text_score = printable^2 * (0.35 + 0.40 * words + 0.25 * frequency)

So: flag > file with magic bytes > English/French sentence > base64/hex text > random bytes.
The details are explained in docs/how-it-works.md.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from ctfc.core.datafiles import load_words
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.magic import match_signature

# Letter frequencies (percent) of English and French text, a..z.
ENGLISH_FREQ = [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
    6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
]  # fmt: skip
FRENCH_FREQ = [
    7.64, 0.90, 3.26, 3.67, 14.72, 1.07, 0.87, 0.74, 7.53, 0.61, 0.07, 5.46, 2.97,
    7.10, 5.80, 2.52, 1.36, 6.69, 7.95, 7.24, 6.31, 1.84, 0.05, 0.43, 0.13, 0.33,
]  # fmt: skip

WORD_RE = re.compile(r"[a-zàâäéèêëïîôöùûüç]+")
ACCENTS = str.maketrans("àâäéèêëïîôöùûüç", "aaaeeeeiioouuuc")


@dataclass
class TextStats:
    """Measurements used to decide if bytes are readable text."""

    length: int
    entropy: float  # Shannon entropy, bits per byte (0..8)
    printable: float  # ratio of readable characters (0..1)
    utf8: bool  # is it valid UTF-8?
    word_rate: float  # ratio of letters that are inside known words (0..1)
    letters: int  # number of letters a-z
    chi2: float | None  # best chi-squared vs EN/FR letter frequencies (None if too few letters)
    language: str  # "English" or "French" (closest frequency table)


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits per byte: ~4.5 for English text, ~8 for encrypted/compressed data."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in Counter(data).values())


def printable_ratio(data: bytes) -> tuple[float, bool]:
    """Return (ratio of readable characters, is_valid_utf8)."""
    if not data:
        return 0.0, True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
        return good / len(data), False
    good = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return good / max(len(text), 1), True


def chi_squared(counts: list[int], expected_percent: list[float]) -> float:
    """Chi-squared distance between observed letter counts and an expected distribution.

    0 means identical. English text usually gives < 50, random letters > 150.
    """
    total = sum(counts)
    result = 0.0
    for observed, percent in zip(counts, expected_percent, strict=True):
        expected = total * percent / 100
        result += (observed - expected) ** 2 / expected
    return result


def text_stats(data: bytes) -> TextStats:
    """Compute every text measurement at once."""
    printable, utf8 = printable_ratio(data)
    text = data.decode("utf-8", errors="replace").lower()

    words = load_words()
    total_letters = 0
    word_letters = 0
    for token in WORD_RE.findall(text):
        total_letters += len(token)
        if len(token) >= 2 and (token in words or token.translate(ACCENTS) in words):
            word_letters += len(token)
    word_rate = word_letters / total_letters if total_letters else 0.0

    plain = text.translate(ACCENTS)
    counts = [plain.count(chr(ord("a") + i)) for i in range(26)]
    letters = sum(counts)
    chi2: float | None = None
    language = ""
    if letters >= 20:
        chi_en = chi_squared(counts, ENGLISH_FREQ)
        chi_fr = chi_squared(counts, FRENCH_FREQ)
        chi2, language = (chi_en, "English") if chi_en <= chi_fr else (chi_fr, "French")

    return TextStats(
        length=len(data),
        entropy=shannon_entropy(data),
        printable=printable,
        utf8=utf8,
        word_rate=word_rate,
        letters=letters,
        chi2=chi2,
        language=language,
    )


def has_valid_pkcs7(data: bytes, block_size: int = 16) -> bool:
    """PKCS7 padding: the last byte N (1..block) is repeated N times at the end."""
    if not data or len(data) % block_size:
        return False
    pad = data[-1]
    return 1 <= pad <= block_size and data[-pad:] == bytes([pad]) * pad


def score(
    data: bytes,
    flagset: FlagSet | None = None,
    check_padding: bool = False,
    block_size: int = 16,
) -> tuple[float, list[str]]:
    """Return (score 0..1, human-readable reasons). See the module docstring."""
    if not data:
        return 0.0, ["empty output"]

    reasons: list[str] = []
    best = 0.0

    for hit in find_flags(data, flagset)[:3]:
        if hit.how == "plain":
            reasons.append(f"matches flag pattern: {hit.text[:80]}")
        elif hit.how == "base64":
            reasons.append(f"contains a base64-encoded flag: {hit.text[:80]}")
        else:
            reasons.append(hit.text)
        best = max(best, hit.strength)

    signature = match_signature(data)
    if signature is not None:
        reasons.append(f"{signature.name} magic bytes at offset {signature.offset}")
        best = max(best, 0.6 if signature.weak else 0.85)

    stats = text_stats(data)
    frequency_score = 0.5  # neutral when there are too few letters to judge
    if stats.chi2 is not None:
        frequency_score = 1 / (1 + stats.chi2 / 60)
    text_score = stats.printable**2 * (0.35 + 0.40 * stats.word_rate + 0.25 * frequency_score)

    if stats.printable >= 0.95:
        reasons.append(f"{stats.printable:.0%} printable" + (" UTF-8" if stats.utf8 else ""))
    elif stats.printable >= 0.7:
        reasons.append(f"mostly printable ({stats.printable:.0%})")
    if stats.word_rate >= 0.3:
        reasons.append(f"{stats.word_rate:.0%} of letters form common EN/FR words")
    if stats.chi2 is not None and stats.chi2 < 60 and stats.printable > 0.9:
        reasons.append(f"letter frequencies close to {stats.language} (chi2={stats.chi2:.0f})")
    if stats.length >= 64 and stats.entropy > 7.5:
        reasons.append(f"high entropy {stats.entropy:.2f} bits/byte (encrypted or compressed?)")
    best = max(best, text_score)

    if check_padding and has_valid_pkcs7(data, block_size):
        pad = data[-1]
        reasons.append(f"valid PKCS7 padding ({pad} x 0x{pad:02x})")
        best = min(1.0, best + 0.15)

    if not reasons:
        reasons.append(f"no structure found (printable {stats.printable:.0%})")
    return round(best, 4), reasons
