"""XOR: the simplest cipher, and the most common one in CTF malware.

    ciphertext = plaintext XOR key        plaintext = ciphertext XOR key

The same operation encrypts and decrypts. With a *repeating* key "abc", byte 0 is
XORed with 'a', byte 1 with 'b', byte 2 with 'c', byte 3 with 'a' again, etc.

How to break it without the key (all deterministic, no AI):
1. Single byte: only 256 possible keys -> try all, keep the most readable output.
2. Repeating key:
   a. find the key length L (normalized Hamming distance + coincidence test),
   b. cut the data in L "columns" (bytes 0, L, 2L... / bytes 1, L+1, ...); each
      column is XORed with ONE key byte -> solve it like a single-byte XOR.
3. Known plaintext ("crib"): if you know a piece of the plaintext (a file header
   like "\\x89PNG", or "CYBN{"), then  key = ciphertext XOR known_plaintext  at
   that position. "Crib dragging" slides the crib over every position.
4. Two layers (repeating key, then one byte) are the same as ONE repeating key
   (key XOR byte), because XOR is associative. ctfc finds that key, then tries to
   split it back into a readable key + a byte.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass

from ctfc.core.budget import Budget
from ctfc.core.codegen import Step, chain_cyberchef, chain_snippet, key_repr
from ctfc.core.datafiles import load_passwords
from ctfc.core.flags import FlagSet
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

# XOR_TABLES[k] maps every byte b to b ^ k. bytes.translate() then XORs a whole
# buffer with k at C speed (much faster than a Python loop).
XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]

SAMPLE = 65536  # statistics are computed on at most this many bytes (speed)

# Known file headers tried as cribs at offset 0.
DEFAULT_CRIBS: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "PNG header"),
    (b"%PDF-1.", "PDF header"),
    (b"PK\x03\x04", "ZIP header"),
    (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff", "Windows PE (MZ) header"),
    (b"\x7fELF\x02\x01\x01\x00", "ELF 64-bit header"),
    (b"GIF89a", "GIF header"),
    (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", "JPEG/JFIF header"),
    (b"<?xml version=", "XML declaration"),
    (b"-----BEGIN ", "PEM block"),
    (b"#!/bin/", "shell script shebang"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"http://", "URL"),
    (b"https://", "URL"),
    (b"Salted__", "openssl enc header"),
]


# ---------------------------------------------------------------------------
# Basic operations
# ---------------------------------------------------------------------------


def xor_with_key(data: bytes, key: bytes) -> bytes:
    """XOR `data` with a repeating `key`."""
    if not key:
        raise ValueError("empty XOR key")
    if len(key) == 1:
        return data.translate(XOR_TABLES[key[0]])
    out = bytearray(len(data))
    for index, key_byte in enumerate(key):
        # every len(key)-th byte, starting at `index`, uses the same key byte
        out[index :: len(key)] = data[index :: len(key)].translate(XOR_TABLES[key_byte])
    return bytes(out)


def xor_two(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings, cut to the shorter length."""
    length = min(len(a), len(b))
    if length == 0:
        return b""
    number = int.from_bytes(a[:length], "big") ^ int.from_bytes(b[:length], "big")
    return number.to_bytes(length, "big")


def hamming_distance(a: bytes, b: bytes) -> int:
    """Number of differing bits between two byte strings of the same length."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def shrink_key(key: bytes) -> bytes:
    """'abcabc' -> 'abc': a key made of a repeated smaller key is that smaller key."""
    for size in range(1, len(key)):
        if len(key) % size == 0 and key[:size] * (len(key) // size) == key:
            return key[:size]
    return key


def is_printable(data: bytes) -> bool:
    return bool(data) and all(32 <= b < 127 for b in data)


# ---------------------------------------------------------------------------
# Text model: "how much does this look like text?" (fast version for brute force)
# ---------------------------------------------------------------------------

TOP_CHARS = b" etaoinsrhlu"  # most frequent characters in English and French
LETTERS = bytes(range(65, 91)) + bytes(range(97, 123))
PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"


def text_points(chunk: bytes) -> int:
    """Quick text score: frequent letters +3, letters +1, printable +1, other bytes -4.

    Each count uses bytes.translate(None, delete) which runs in C: fast enough to
    be called 256 times per column.
    """
    total = len(chunk)
    top = total - len(chunk.translate(None, TOP_CHARS))
    letters = total - len(chunk.translate(None, LETTERS))
    printable = total - len(chunk.translate(None, PRINTABLE))
    return 3 * top + letters + printable - 4 * (total - printable)


ALNUM = LETTERS + b"0123456789"


def code_points(chunk: bytes) -> int:
    """Quick score for source code / mixed text: printable +2, letters/digits +1,
    other bytes -6. Less picky than text_points about which letters appear."""
    total = len(chunk)
    alnum = total - len(chunk.translate(None, ALNUM))
    printable = total - len(chunk.translate(None, PRINTABLE))
    return 2 * printable + alnum - 6 * (total - printable)


def column_points(column: bytes, points=text_points) -> list[int]:
    """points() of the column XORed with each of the 256 possible key bytes."""
    return [points(column.translate(XOR_TABLES[k])) for k in range(256)]


def most_common_byte(data: bytes) -> int:
    return Counter(data).most_common(1)[0][0]


# ---------------------------------------------------------------------------
# Key length
# ---------------------------------------------------------------------------


@dataclass
class KeyLength:
    """Evidence for one possible key length."""

    length: int
    hamming: float  # differing bits per byte between key-length blocks (random ~ 4.0)
    ratio: float  # coincidence ratio at multiples of the length (1 = no signal)

    def describe(self) -> str:
        return (
            f"key length {self.length}: Hamming {self.hamming:.2f} bits/byte (random ~ 4.0), "
            f"coincidence ratio {self.ratio:.1f}"
        )


def coincidence_rates(data: bytes, max_shift: int) -> dict[int, float]:
    """For each shift k: how often data[i] == data[i + k]."""
    rates = {}
    for shift in range(1, max_shift + 1):
        same = sum(1 for i in range(len(data) - shift) if data[i] == data[i + shift])
        rates[shift] = same / (len(data) - shift)
    return rates


def period_ratios(rates: dict[int, float]) -> dict[int, tuple[float, float, float]]:
    """For each candidate length p: (ratio, mean rate at multiples of p, mean elsewhere).

    With a repeating key of length p, bytes p, 2p, 3p... apart were XORed with the same
    key byte, so they are equal as often as in the plaintext language (~6% in English);
    other distances look random (~0.4%). ratio = mean(multiples) / mean(others).
    """
    max_shift = max(rates)
    result = {}
    for candidate in range(2, max_shift // 2 + 1):
        multiples = [rates[k] for k in rates if k % candidate == 0]
        others = [rates[k] for k in rates if k % candidate != 0]
        mean_multiples = sum(multiples) / len(multiples)
        mean_others = sum(others) / len(others)
        ratio = mean_multiples / max(mean_others, 0.002)
        result[candidate] = (ratio, mean_multiples, mean_others)
    return result


def normalized_hamming(data: bytes, length: int, max_blocks: int = 20) -> float | None:
    """Average differing bits per byte between consecutive blocks of `length` bytes.

    Blocks XORed with the same key differ like the plaintexts do (~2.5-3.3 bits per
    byte for text); with a wrong length they differ like random data (~4 bits).
    """
    count = min(len(data) // length, max_blocks)
    if count < 2:
        return None
    blocks = [data[i * length : (i + 1) * length] for i in range(count)]
    total = 0
    pairs = 0
    for i in range(count):
        for j in range(i + 1, count):
            total += hamming_distance(blocks[i], blocks[j])
            pairs += 1
    return total / pairs / length


def guess_key_lengths(data: bytes, max_len: int = 40) -> list[KeyLength]:
    """Rank key lengths 2..max_len, best first, by combining both tests."""
    sample = data[:4096]
    max_len = min(max_len, len(sample) // 2)
    if max_len < 2:
        return []
    ratios = period_ratios(coincidence_rates(sample, max_len)) if max_len >= 4 else {}
    guesses = []
    for length in range(2, max_len + 1):
        hamming = normalized_hamming(sample, length)
        if hamming is None:
            continue
        ratio = ratios.get(length, (1.0, 0.0, 0.0))[0]
        guesses.append(KeyLength(length, hamming, ratio))
    if not guesses:
        return []
    by_hamming = sorted(guesses, key=lambda g: g.hamming)
    by_ratio = sorted(guesses, key=lambda g: -g.ratio)
    rank = {g.length: by_hamming.index(g) + by_ratio.index(g) for g in guesses}
    return sorted(guesses, key=lambda g: (rank[g.length], g.length))


def lengths_are_convincing(guesses: list[KeyLength]) -> bool:
    """True when the best length clearly stands out (used by `auto` to avoid noise)."""
    if not guesses:
        return False
    best = guesses[0]
    return best.ratio >= 2.5 or best.hamming <= 3.3


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


def split_layers(key: bytes) -> tuple[bytes, int] | None:
    """If `key` is unreadable but key XOR b is a readable word, return (word, b).

    Example: "secret" XOR 0x42 looks random, XOR it with 0x42 and "secret" comes back.
    """

    def wordiness(candidate: bytes) -> tuple[int, int]:
        # (letters/digits/_ count, frequent letters): "secret" beats "qgapgv" and "1'!0'6"
        alnum = sum(chr(b).isalnum() or b == 0x5F for b in candidate)
        return alnum, text_points(candidate.lower())

    if len(key) < 3:
        return None
    current = wordiness(key) if is_printable(key) else (-1, -1)
    if current[0] >= 0.75 * len(key):
        return None  # already a readable key, like "k3y!"
    best: tuple[tuple[int, int], bytes, int] | None = None
    for byte in range(1, 256):
        candidate = key.translate(XOR_TABLES[byte])
        if not is_printable(candidate):
            continue
        points = wordiness(candidate)
        if points[0] >= 0.75 * len(candidate) and points > current:
            if best is None or points > best[0]:
                best = (points, candidate, byte)
    return (best[1], best[2]) if best else None


def make_candidate(
    data: bytes,
    key: bytes,
    method: str,
    flagset: FlagSet | None,
    extra_reasons: list[str] | None = None,
    forced: tuple[int, int] | None = None,
    label: str | None = None,
) -> Candidate:
    """Decrypt `data` with `key` and describe the result.

    forced=(start, end): bytes whose plaintext we *assumed* (a crib). They are left
    out of the score, otherwise guessing "\x89PNG" would "find" a PNG every time.
    """
    key = shrink_key(key)
    output = xor_with_key(data, key)
    if forced is None:
        out_score, reasons = score(output, flagset)
    else:
        start, end = forced
        out_score, reasons = score(output[:start] + output[end:], flagset)
        reasons = [f"bytes {start}..{end - 1} were guessed, so they are not counted", *reasons]
    params = {"key_hex": key.hex(), "key_length": len(key), "method": method}
    step_params = {"key": key.hex()}
    lead = [f"{method}: key {key_repr(key)} ({len(key)} byte{'s' if len(key) > 1 else ''})"]
    layers = split_layers(key)
    if layers is not None:
        base_key, single = layers
        params["layers"] = [base_key.hex(), f"{single:02x}"]
        step_params["layers"] = params["layers"]
        lead.append(
            f"the key may be two layers: {key_repr(base_key)} then the byte 0x{single:02x} "
            "(XOR layers combine into one key, so this split is only the most readable guess)"
        )
    steps = [Step("xor", step_params)]
    if label is None:
        label = f"xor key={key_repr(key)}"
        if layers is not None:
            label = f"xor key={key_repr(layers[0])} + byte 0x{layers[1]:02x}"
    return Candidate(
        label=label,
        data=output,
        score=out_score,
        reasons=lead + (extra_reasons or []) + reasons,
        params=params,
        python=chain_snippet(data, steps),
        cyberchef=chain_cyberchef(steps),
    )


def _best_unique(candidates: list[Candidate], top_n: int) -> list[Candidate]:
    """Sort by score, drop candidates with the same output, keep top_n.

    On near-ties the shorter key wins (a tiny penalty per key byte): with short
    ciphertexts a long key often has one wrong byte that changes little.
    """

    def rank(candidate: Candidate) -> float:
        return candidate.score - 0.003 * candidate.params.get("key_length", 0)

    seen: set[bytes] = set()
    result = []
    for candidate in sorted(candidates, key=rank, reverse=True):
        if candidate.data in seen:
            continue
        seen.add(candidate.data)
        result.append(candidate)
    return result[:top_n]


# ---------------------------------------------------------------------------
# Solvers
# ---------------------------------------------------------------------------


def solve_single_byte(
    data: bytes, flagset: FlagSet | None = None, top_n: int = 3
) -> list[Candidate]:
    """Try the 256 one-byte keys; fully score the 8 most text-like ones."""
    if not data:
        return []
    sample = data[:SAMPLE]
    points = column_points(sample)
    keys = sorted(range(256), key=lambda k: points[k], reverse=True)[:8]
    # Binary plaintexts are full of 0x00: the most common byte is then the key.
    null_key = most_common_byte(sample)
    if null_key not in keys:
        keys.append(null_key)
    candidates = [
        make_candidate(data, bytes([key]), "single-byte XOR (all 256 keys tried)", flagset)
        for key in keys
    ]
    return _best_unique(candidates, top_n)


def solve_key_for_length(data: bytes, length: int) -> tuple[bytes, bytes, bytes]:
    """Return (text key, code key, binary key) for this length, one column at a time.

    text key  : each key byte makes its column look most like English/French prose
    code key  : each key byte makes its column most printable (scripts, hex arrays...)
    binary key: each key byte turns the column's most common byte into 0x00
    """
    sample = data[: SAMPLE * 4]
    text_key = bytearray()
    code_key = bytearray()
    binary_key = bytearray()
    for column_index in range(length):
        column = sample[column_index::length]
        points = column_points(column)
        text_key.append(max(range(256), key=lambda k: points[k]))
        points = column_points(column, code_points)
        code_key.append(max(range(256), key=lambda k: points[k]))
        binary_key.append(most_common_byte(column))
    return bytes(text_key), bytes(code_key), bytes(binary_key)


def solve_repeating(
    data: bytes,
    lengths: list[int],
    flagset: FlagSet | None = None,
    guesses: list[KeyLength] | None = None,
    budget: Budget | None = None,
    top_n: int = 5,
) -> list[Candidate]:
    """Solve a repeating-key XOR for each key length in `lengths`."""
    evidence = {g.length: g.describe() for g in guesses or []}
    candidates = []
    for length in lengths:
        if budget is not None and not budget.spend():
            break
        text_key, code_key, binary_key = solve_key_for_length(data, length)
        why = [evidence.get(length, f"key length {length} (given)")]
        candidates.append(
            make_candidate(
                data, text_key, "repeating-key XOR, columns solved as text", flagset, why
            )
        )
        if code_key != text_key:
            method = "repeating-key XOR, columns solved as printable text/code"
            candidates.append(make_candidate(data, code_key, method, flagset, why))
        candidates.append(
            make_candidate(
                data, binary_key, "repeating-key XOR, columns solved as binary (0x00)", flagset, why
            )
        )
        # The real key may be shorter (a divisor of this length): rebuild it by
        # majority vote, e.g. "BBBBUBBBB" -> "B" (one column was solved wrong).
        for divisor in range(1, length):
            if length % divisor:
                continue
            short_key = bytes(
                Counter(text_key[j::divisor]).most_common(1)[0][0] for j in range(divisor)
            )
            reason = f"majority vote of the {length}-byte key folded to {divisor} byte(s)"
            candidates.append(
                make_candidate(data, short_key, "repeating-key XOR, folded key", flagset, [reason])
            )
    return _best_unique(candidates, top_n)


MIN_CONFIRMATIONS = 4  # repeated key bytes needed to trust a key recovered from a crib


def _periodic_key(stream: bytes) -> bytes | None:
    """Smallest key that explains `stream` because it repeats inside it, else None.

    The repetition must be confirmed by at least MIN_CONFIRMATIONS bytes: with
    fewer, a random match is too likely.
    """
    for size in range(1, len(stream) - MIN_CONFIRMATIONS + 1):
        if all(stream[i] == stream[i % size] for i in range(len(stream))):
            return stream[:size]
    return None


def known_plaintext_at_start(
    data: bytes,
    lengths: list[int],
    flagset: FlagSet | None = None,
    cribs: list[tuple[bytes, str]] | None = None,
    budget: Budget | None = None,
) -> list[Candidate]:
    """Assume the plaintext starts with a known header: key = data[:n] XOR header."""
    candidates = []
    for crib, name in cribs if cribs is not None else DEFAULT_CRIBS:
        if len(data) <= len(crib):
            continue
        if budget is not None and not budget.spend():
            break
        stream = xor_two(data, crib)
        key = _periodic_key(stream)
        if key is not None:
            reason = (
                f"plaintext assumed to start with the {name}: the recovered key bytes "
                f"repeat every {len(key)} byte(s), which confirms it"
            )
            method = f"known plaintext ({name})"
            candidates.append(make_candidate(data, key, method, flagset, [reason]))
            continue
        # Key longer than the crib: the crib gives the first key bytes, the
        # column solver gives the others.
        for length in lengths:
            if length < len(stream):
                continue
            text_key = solve_key_for_length(data, length)[0]
            key = stream + text_key[len(stream) :]
            reason = f"plaintext assumed to start with the {name} (key bytes 0..{len(stream) - 1})"
            method = f"known plaintext ({name}) + columns"
            candidates.append(
                make_candidate(data, key, method, flagset, [reason], forced=(0, len(stream)))
            )
    return candidates


def drag_crib(
    data: bytes,
    crib: bytes,
    lengths: list[int],
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    keep: int = 3,
) -> list[Candidate]:
    """Slide a known plaintext (e.g. b"CYBN{") over every position of the data.

    - key not longer than the crib: each position gives the whole key; when the key
      is shorter, the recovered bytes must also repeat (wrong positions rarely do).
      Positions are ranked by how readable the whole decryption is.
    - key longer than the crib: the crib fixes some key bytes, the column solver
      fixes the others; positions are ranked by how readable that makes the
      affected columns.
    """
    sample = data[:16384]  # crib dragging is O(positions): keep it bounded
    size = len(crib)
    if len(sample) < size or size == 0:
        return []
    candidates: list[Candidate] = []
    offsets = range(len(sample) - size + 1)

    # 1) short keys (length <= crib length): fully determined by the crib
    for length in range(1, size + 1):
        if budget is not None and not budget.spend():
            return candidates
        found: list[tuple[int, int, bytes]] = []
        for offset in offsets:
            stream = xor_two(sample[offset : offset + size], crib)
            if any(stream[i] != stream[i - length] for i in range(length, size)):
                continue  # the key bytes do not repeat: wrong position
            key = bytearray(length)
            for i in range(length):
                key[(offset + i) % length] = stream[i]
            points = text_points(xor_with_key(sample[:2048], bytes(key)))
            found.append((points, offset, bytes(key)))
        # The crib is not masked from the score here: a flag crib placed at a wrong
        # position gives garbled flag content and unreadable text, which scoring
        # already punishes (see flags.looks_like_flag and the readability penalty).
        for _points, offset, key in sorted(found, reverse=True)[:keep]:
            reason = f"crib {crib!r} placed at offset {offset} gives the whole key"
            candidates.append(make_candidate(data, key, "crib dragging", flagset, [reason]))

    # 2) longer keys: crib bytes override the column solution
    for length in lengths:
        if length <= size or (budget is not None and not budget.spend()):
            continue
        columns = [column_points(sample[c::length]) for c in range(length)]
        best = [max(range(256), key=lambda k, p=points: p[k]) for points in columns]
        ranked: list[tuple[int, int]] = []
        for offset in offsets:
            delta = 0
            for i in range(size):
                column = (offset + i) % length
                key_byte = sample[offset + i] ^ crib[i]
                delta += columns[column][key_byte] - columns[column][best[column]]
            ranked.append((delta, offset))
        for _delta, offset in sorted(ranked, reverse=True)[:keep]:
            key = bytearray(best)
            for i in range(size):
                key[(offset + i) % length] = sample[offset + i] ^ crib[i]
            reason = f"crib {crib!r} placed at offset {offset}, other key bytes from columns"
            candidates.append(
                make_candidate(data, bytes(key), "crib dragging + columns", flagset, [reason])
            )
    return candidates


# Hashes used to turn a word into a key. "key = md5('secret')" is one of the most
# common things a CTF dropper does, and the key is then 16 bytes of pure noise
# that no statistical method will ever guess.
KEY_HASHES = ("md5", "sha1", "sha256")
HASHED_SAMPLE = 256  # bytes used to pre-filter the thousands of candidate keys
HASHED_SHORTLIST = 20  # how many pre-filtered keys get a real score
# Below this score, solve_xor falls back to the hashed-key search on its own.
# Real text scores 0.9+; a column solve with one or two wrong key bytes lands
# around 0.55, and that is exactly the case the fallback must still cover.
HASHED_FALLBACK = 0.8


def _keystream(key: bytes, length: int) -> bytes:
    """The repeating key, stretched to `length` bytes."""
    return (key * (length // len(key) + 1))[:length]


def solve_hashed_key(
    data: bytes,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    top_n: int = 3,
    words: list[bytes] | None = None,
) -> list[Candidate]:
    """Try md5 / sha1 / sha256 of common words as the repeating key.

    Column solving cannot help here: the key is a digest, so its bytes are random
    and no amount of frequency analysis will recover them. But the *word* behind
    the digest is usually ordinary ("secret", "infected", the challenge name), so
    hashing a small word list and testing each result is the way in.

    Both forms are tried, because code writes both: the raw 16/20/32-byte digest,
    and the 32/40/64-character hex string (`.hexdigest()`).
    """
    sample = data[:HASHED_SAMPLE]
    if len(sample) < 16:
        return []
    budget = budget or Budget(max_attempts=200_000, max_seconds=15)
    word_list = words if words is not None else list(load_passwords())

    ranked: list[tuple[int, bytes, bytes, str]] = []
    for word in word_list:
        if not budget.spend():
            break
        for name in KEY_HASHES:
            digest = hashlib.new(name, word).digest()
            for key, how in (
                (digest, f"{name}(word)"),
                (digest.hex().encode(), f"{name}(word).hexdigest()"),
            ):
                points = text_points(xor_two(sample, _keystream(key, len(sample))))
                ranked.append((points, key, word, how))

    ranked.sort(key=lambda item: -item[0])
    candidates = []
    for _points, key, word, how in ranked[:HASHED_SHORTLIST]:
        text = word.decode("utf-8", errors="replace")
        candidates.append(
            make_candidate(
                data,
                key,
                f"key = {how}",
                flagset,
                [f'the key is {how} with word = "{text}", from the embedded word list'],
                label=f"xor key={how.replace('word', repr(text))}",
            )
        )
    return _best_unique(candidates, top_n)


def solve_xor(
    data: bytes,
    flagset: FlagSet | None = None,
    key: bytes | None = None,
    keylen: int | None = None,
    cribs: list[bytes] | None = None,
    budget: Budget | None = None,
    top_n: int = 10,
    try_hashed: bool | None = None,
) -> list[Candidate]:
    """Everything at once: the entry point used by `ctfc xor` and the web XOR tab.

    - key given: just decrypt with it.
    - otherwise: single byte, repeating key (guessed or forced length), file
      headers at offset 0, and crib dragging with the flag prefixes + your crib.
    - `try_hashed`: also test md5/sha of common words as the key. Left to None it
      runs only when nothing else convinced, so it costs nothing in the usual case.
    """
    budget = budget or Budget(max_attempts=500, max_seconds=30)
    if key:
        return [make_candidate(data, key, "XOR with the given key", flagset)]

    guesses = guess_key_lengths(data)
    if keylen:
        lengths = [keylen]
    else:
        lengths = [g.length for g in guesses[:8]]

    candidates: list[Candidate] = []
    if not keylen or keylen == 1:
        candidates += solve_single_byte(data, flagset)
    if keylen != 1:
        candidates += solve_repeating(data, lengths, flagset, guesses, budget)
        candidates += known_plaintext_at_start(data, lengths, flagset, budget=budget)
    for crib in cribs or []:
        candidates += drag_crib(data, crib, lengths, flagset, budget)

    best_so_far = max((candidate.score for candidate in candidates), default=0.0)
    if try_hashed or (try_hashed is None and best_so_far < HASHED_FALLBACK):
        candidates += solve_hashed_key(data, flagset, budget)
    return _best_unique(candidates, top_n)


def xor_inputs(
    first: bytes,
    second: bytes,
    flagset: FlagSet | None = None,
    crib: bytes | None = None,
    top_n: int = 10,
) -> list[Candidate]:
    """XOR two ciphertexts (e.g. two messages encrypted with the same key stream).

    If c1 = p1 ^ k and c2 = p2 ^ k, then c1 ^ c2 = p1 ^ p2: the key disappears.
    Sliding a guessed word of p1 over it reveals the matching part of p2.
    """
    combined = xor_two(first, second)
    out_score, reasons = score(combined, flagset)
    note = []
    if len(first) != len(second):
        note.append(f"inputs have different lengths: cut to {len(combined)} bytes")
    snippet = (
        '"""XOR two inputs (generated by ctfc)"""\n'
        'a = open("first.bin", "rb").read()\n'
        'b = open("second.bin", "rb").read()\n'
        "data = bytes(x ^ y for x, y in zip(a, b))\n"
        'print(data.decode("utf-8", errors="replace"))\n'
    )
    candidates = [
        Candidate(
            label="first XOR second",
            data=combined,
            score=out_score,
            reasons=["c1 XOR c2 = p1 XOR p2 when both used the same key stream", *note, *reasons],
            params={"method": "xor two inputs"},
            python=snippet,
        )
    ]
    if crib:
        ranked = []
        for offset in range(len(combined) - len(crib) + 1):
            fragment = xor_two(combined[offset : offset + len(crib)], crib)
            ranked.append((text_points(fragment), offset, fragment))
        best_points = 5 * len(crib)  # text_points maximum: 3 + 1 + 1 per character
        for points, offset, fragment in sorted(ranked, reverse=True)[:top_n]:
            candidates.append(
                Candidate(
                    label=f"crib {crib!r} at offset {offset}",
                    data=fragment,
                    score=round(max(0.0, points / best_points), 3),
                    reasons=[
                        f"if one plaintext has {crib!r} at offset {offset}, the other has "
                        f"{fragment!r} there",
                        "score = how text-like this short fragment is (frequent letters, "
                        "printable characters)",
                    ],
                    params={"method": "crib dragging on two inputs", "offset": offset},
                )
            )
    return sorted(candidates, key=lambda candidate: -candidate.score)
