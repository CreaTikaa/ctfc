"""Key hunting: find candidate keys in a dump, then try them on a ciphertext.

The usual forensics situation: a memory dump, a binary or a `strings` output
holds the key somewhere, and a file was encrypted with it. ctfc looks for keys
in several independent ways, strongest first:

1. **AES key schedules.** To encrypt, AES first expands its 16/24/32-byte key
   into 176/208/240 bytes of round keys, and programs keep that expansion in
   memory. Every byte of it is computed from the key, so finding the key followed
   by its own expansion is near-proof (this is how `aeskeyfind` works). The scan
   is cheap: at each offset only the first derived word (4 bytes) is computed and
   compared; the full expansion is checked only on a match.
2. **Labelled values**: `aes_key = 4f2a...`, `password: hunter2`, `IV=...` in
   text (configs, scripts, `strings` output).
3. **Hex / base64 strings of a key length**: 32/48/64 hex digits (16/24/32
   bytes; 96 = a 48-byte key||iv blob), base64 of 16/24/32/48 bytes.
4. **ASCII strings of exactly 16/24/32 characters** ("Sup3rS3cr3tK3y!!"),
   ranked higher when they sit near a crypto constant (AES S-box...).
5. **High-entropy windows**: 16 or 32 bytes that look random. The weakest
   signal (compressed data looks random too), so these come last and are tried
   with AES only.

Each candidate is then handed to the symmetric solver (M3) with a small slice of
the time budget: it tries the modes, IV positions and paddings by itself. The
first candidate that decrypts to something convincing wins, and the report says
where in the dump it was found.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.datafiles import load_toml
from ctfc.core.flags import FlagSet
from ctfc.core.scoring import shannon_entropy
from ctfc.core.types import Candidate

KEY_SIZES = (16, 24, 32)
SCHEDULE_SIZES = {16: 176, 24: 208, 32: 240}  # bytes of round keys per AES key size
SCHEDULE_SCAN_LIMIT = 2 * 1024**3  # bytes scanned for key schedules (~15 s per GB)
FOUND = 0.9  # a decryption this convincing ends the hunt
PER_KEY_SECONDS = 2.0  # time slice of the solver per candidate key
MAX_ENTROPY_WINDOWS = 300
NEAR_CONSTANT = 4096  # an ASCII key this close after a crypto constant is ranked higher

# How much each kind of evidence is trusted, i.e. the order keys are tried in.
STRENGTH = {
    "aes_schedule": 0.95,
    "labelled": 0.85,
    "hex": 0.65,
    "base64": 0.6,
    "ascii_near_constant": 0.6,
    "passphrase": 0.55,
    "ascii": 0.45,
    "entropy": 0.25,
}

LABEL_RE = re.compile(
    rb"(?i)\b(aes[_-]?key|enc(?:ryption)?[_-]?key|secret[_-]?key|private[_-]?key|key|"
    rb"secret|iv|nonce|passphrase|password|passwd|pwd|pass)\b\s*[:=]\s*[\"']?([^\s\"',;]{4,128})"
)
HEX_RE = re.compile(
    rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{48}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{96})(?![0-9A-Fa-f])"
)
BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{22,64}={0,2}(?![A-Za-z0-9+/=])")
PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{16,32}")


@dataclass
class KeyCandidate:
    """A possible key, and where and how it was found."""

    key: bytes
    offset: int
    kind: str  # a STRENGTH key
    how: str  # "AES-256 key schedule (240 bytes)"
    strength: float
    role: str = "key"  # "key", "blob" (key||iv), "passphrase" or "iv"

    def to_dict(self) -> dict:
        return {
            "key_hex": self.key.hex(),
            "key_text": self.key.decode("latin-1") if self.key.isascii() else "",
            "length": len(self.key),
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "kind": self.kind,
            "how": self.how,
            "strength": self.strength,
            "role": self.role,
        }


@dataclass
class KeyReport:
    """Everything the hunt found and tried."""

    candidates: list[KeyCandidate] = field(default_factory=list)
    tested: int = 0
    results: list[Candidate] = field(default_factory=list)
    winner: KeyCandidate | None = None
    notes: list[str] = field(default_factory=list)
    budget_summary: str = ""
    # When --against is a LUKS volume: the confirmed master key and how to use it.
    luks: dict | None = None

    def to_dict(self, limit: int = 50) -> dict:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates[:limit]],
            "candidate_count": len(self.candidates),
            "tested": self.tested,
            "results": [result.to_dict() for result in self.results],
            "winner": self.winner.to_dict() if self.winner else None,
            "luks": self.luks,
            "notes": list(self.notes),
            "budget": self.budget_summary,
        }


# ---------------------------------------------------------------------------
# 1. AES key schedules
# ---------------------------------------------------------------------------


def _aes_sbox() -> bytes:
    """The AES S-box: multiplicative inverse in GF(2^8), then a fixed affine map.

    Built with log/antilog tables of the generator 3 (every non-zero byte is a
    power of 3 in this field), so the inverse of 3^k is 3^(255-k).
    """
    exp, log = [0] * 256, [0] * 256
    value = 1
    for power in range(255):
        exp[power], log[value] = value, power
        value ^= (value << 1) ^ (0x11B if value & 0x80 else 0)  # value * 3
    box = bytearray(256)
    for byte in range(256):
        inverse = exp[(255 - log[byte]) % 255] if byte else 0
        result = 0x63
        for shift in range(5):  # inverse ^ rotl1 ^ rotl2 ^ rotl3 ^ rotl4, ^ 0x63
            result ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
        box[byte] = result
    return bytes(box)


SBOX = _aes_sbox()


def expand_key(key: bytes) -> bytes:
    """FIPS-197 key expansion: the round keys AES derives from a 16/24/32-byte key."""
    nk = len(key) // 4
    total_words = 4 * (nk + 7)
    words = [key[4 * i : 4 * i + 4] for i in range(nk)]
    rcon = 1
    for i in range(nk, total_words):
        temp = words[i - 1]
        if i % nk == 0:
            temp = bytes(SBOX[b] for b in temp[1:] + temp[:1])  # SubWord(RotWord)
            temp = bytes([temp[0] ^ rcon]) + temp[1:]
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        elif nk > 6 and i % nk == 4:
            temp = bytes(SBOX[b] for b in temp)  # AES-256 only: an extra SubWord
        words.append(bytes(a ^ b for a, b in zip(words[i - nk], temp, strict=True)))
    return b"".join(words)


def _xor3(a: bytes, b: bytes, c: bytes) -> bytes:
    """a XOR b XOR c, byte by byte, done at C speed through Python's big integers."""
    size = min(len(a), len(b), len(c))
    value = (
        int.from_bytes(a[:size], "big")
        ^ int.from_bytes(b[:size], "big")
        ^ int.from_bytes(c[:size], "big")
    )
    return value.to_bytes(size, "big")


def _schedule_at(data: bytes, offset: int, size: int) -> KeyCandidate | None:
    """Full check: is data[offset:] a key followed by (at least 90% of) its expansion?"""
    schedule = SCHEDULE_SIZES[size]
    key = data[offset : offset + size]
    if len(set(key)) < 4:
        return None  # a run of the same byte is no key
    actual = data[offset : offset + schedule]
    agree = sum(a == b for a, b in zip(expand_key(key), actual, strict=True))
    if agree < 0.9 * schedule:
        return None
    return KeyCandidate(
        key,
        offset,
        "aes_schedule",
        f"AES-{size * 8} key followed by its key schedule "
        f"({schedule} bytes, {agree}/{schedule} match)",
        STRENGTH["aes_schedule"],
    )


def find_aes_schedules(
    data: bytes, limit: int = SCHEDULE_SCAN_LIMIT, chunk: int = 16 * 1024 * 1024
) -> list[KeyCandidate]:
    """Find AES keys followed by their own key expansion, at any offset.

    The first word the expansion derives is
        w[nk] = w[0] XOR SubWord(RotWord(w[nk-1])) XOR (0x01, 0, 0, 0)
    so for a key of n bytes at offset o, for j = 0, 1, 2:
        data[o+n+j] XOR data[o+j] XOR S(data[o+n-3+j])  ==  1, 0, 0
    That is ONE array X[i] = data[i+n] ^ data[i] ^ S(data[i+n-3]) for the whole
    dump - three shifted copies XORed together, which Python does at C speed -
    in which we look for the bytes 01 00 00. Only those few offsets get the
    fourth byte and then the full expansion checked (90% equal bytes, so a
    slightly damaged dump still matches).
    """
    data = data[:limit]
    found: list[KeyCandidate] = []
    for size in KEY_SIZES:
        schedule = SCHEDULE_SIZES[size]
        # Chunks overlap by one schedule, so no key is cut in half.
        for start in range(0, max(1, len(data) - schedule + 1), chunk):
            piece = data[start : start + chunk + schedule]
            positions = len(piece) - size
            if positions <= 0:
                break
            substituted = piece.translate(SBOX)  # S(byte) for every byte
            x = _xor3(piece[size:], piece[:positions], substituted[size - 3 : size - 3 + positions])
            hit = x.find(b"\x01\x00\x00")
            while hit != -1:
                offset = start + hit
                fourth_ok = (
                    offset + schedule <= len(data)
                    and data[offset + size + 3] == data[offset + 3] ^ SBOX[data[offset + size - 4]]
                )
                if fourth_ok and start + hit < start + chunk:
                    candidate = _schedule_at(data, offset, size)
                    if candidate and all(c.offset != offset for c in found):
                        found.append(candidate)
                hit = x.find(b"\x01\x00\x00", hit + 1)
    return found


# ---------------------------------------------------------------------------
# 2-5. Strings and windows
# ---------------------------------------------------------------------------


def _decode_value(value: bytes) -> list[tuple[bytes, str]]:
    """The readings of a labelled value: hex, base64, and the text itself."""
    readings = []
    text = value.decode("latin-1")
    if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", text) and len(text.removeprefix("0x")) % 2 == 0:
        readings.append((bytes.fromhex(text.removeprefix("0x")), "hex"))
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
        try:
            readings.append((base64.b64decode(text, validate=True), "base64"))
        except (binascii.Error, ValueError):
            pass
    readings.append((value, "text"))
    return readings


def find_labelled(data: bytes) -> list[KeyCandidate]:
    """`key = ...`, `password: ...`, `IV=...` written next to their value."""
    found = []
    for match in LABEL_RE.finditer(data):
        label = match.group(1).decode().lower()
        value = match.group(2)
        is_password = label.startswith("pass") or label in ("pwd", "passphrase")
        is_iv = label in ("iv", "nonce")
        for raw, reading in _decode_value(value):
            if is_iv:
                if len(raw) in (8, 12, 16):
                    found.append(_labelled(raw, match, label, reading, "iv"))
                continue
            if len(raw) in KEY_SIZES or (len(raw) == 48 and reading != "text"):
                role = "blob" if len(raw) == 48 else "key"
                found.append(_labelled(raw, match, label, reading, role))
            elif reading == "text" and (is_password or len(raw) not in KEY_SIZES):
                found.append(_labelled(raw, match, label, reading, "passphrase"))
    return found


def _labelled(raw: bytes, match: re.Match, label: str, reading: str, role: str) -> KeyCandidate:
    kind = "passphrase" if role == "passphrase" else "labelled"
    what = {"key": "key", "blob": "key||iv blob", "passphrase": "passphrase", "iv": "IV"}[role]
    return KeyCandidate(
        raw,
        match.start(2),
        kind,
        f"labelled '{label}' ({reading}, {len(raw)} bytes): used as {what}",
        STRENGTH[kind] if role != "passphrase" or label.startswith("pass") else 0.5,
        role,
    )


def find_encoded(data: bytes) -> list[KeyCandidate]:
    """Hex and base64 strings that decode to a key length (16/24/32, or 48 = key||iv)."""
    found = []
    for match in HEX_RE.finditer(data):
        raw = bytes.fromhex(match.group(0).decode())
        role = "blob" if len(raw) == 48 else "key"
        found.append(
            KeyCandidate(
                raw,
                match.start(),
                "hex",
                f"{len(match.group(0))} hex digits",
                STRENGTH["hex"],
                role,
            )
        )
    for match in BASE64_RE.finditer(data):
        text = match.group(0)
        if len(text) % 4 or re.fullmatch(rb"[0-9A-Fa-f]+", text):
            continue  # hex digits are valid base64 too: the hex finder has them
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) in (*KEY_SIZES, 48) and not text.isalpha():
            role = "blob" if len(raw) == 48 else "key"
            found.append(
                KeyCandidate(
                    raw,
                    match.start(),
                    "base64",
                    f"base64 of {len(raw)} bytes",
                    STRENGTH["base64"],
                    role,
                )
            )
    return found


def _constant_offsets(data: bytes) -> list[int]:
    """Where crypto constants (AES S-box, TEA delta...) sit in the data."""
    offsets = []
    for row in load_toml("constants.toml")["const"]:
        value = bytes.fromhex(row["hex"])
        position = data.find(value)
        while position != -1 and len(offsets) < 100:
            offsets.append(position)
            position = data.find(value, position + 1)
    return sorted(offsets)


def _looks_like_key_text(text: bytes) -> bool:
    """A key-like string: varied characters, not a sentence, not a separator line."""
    return len(set(text)) >= 6 and text.count(b" ") <= 2


def find_ascii_keys(data: bytes) -> list[KeyCandidate]:
    """Printable strings of exactly 16/24/32 characters.

    A run of exactly that length counts. So do the end of a longer run that
    stops on a NUL byte (a C string: whatever printable bytes came before it
    are probably not part of it) and the start of a run that follows a NUL.
    Those within NEAR_CONSTANT bytes after a crypto constant come first.
    """
    constants = _constant_offsets(data)
    found = []
    for match in re.finditer(rb"[\x20-\x7e]{16,}", data):
        run, start, end = match.group(0), match.start(), match.end()
        pieces = []
        if len(run) in KEY_SIZES:
            pieces.append((run, start, "string"))
        else:
            for size in KEY_SIZES:
                if len(run) > size and data[end : end + 1] == b"\x00":
                    pieces.append((run[-size:], end - size, "end of a C string"))
                if len(run) > size and start > 0 and data[start - 1] == 0:
                    pieces.append((run[:size], start, "start of a string"))
        for text, offset, where in pieces:
            if not _looks_like_key_text(text):
                continue
            near = any(0 <= offset - position <= NEAR_CONSTANT for position in constants)
            kind = "ascii_near_constant" if near else "ascii"
            how = f"{len(text)}-character {where}" + (" near a crypto constant" if near else "")
            found.append(KeyCandidate(text, offset, kind, how, STRENGTH[kind]))
    return found


def find_entropy_windows(data: bytes, limit: int = MAX_ENTROPY_WINDOWS) -> list[KeyCandidate]:
    """16- and 32-byte windows (16-aligned) that look random: almost no repeated byte.

    A random 32-byte key has ~30 distinct bytes, text or code far fewer.
    Compressed or encrypted data also looks random, hence the low strength.
    """
    found = []
    for size, minimum in ((32, 28), (16, 15)):
        for offset in range(0, len(data) - size + 1, 16):
            window = data[offset : offset + size]
            if len(set(window)) < minimum:
                continue
            printable = sum(32 <= b < 127 for b in window)
            if printable > 0.8 * size:
                continue  # text: the ASCII finder handles it
            found.append(
                KeyCandidate(
                    window,
                    offset,
                    "entropy",
                    f"{size} random-looking bytes (entropy {shannon_entropy(window):.2f})",
                    STRENGTH["entropy"],
                )
            )
            if len(found) >= limit:
                return found
    return found


def extract_candidates(data: bytes, include_windows: bool = True) -> list[KeyCandidate]:
    """Every candidate key, strongest first, each key bytes once."""
    candidates = find_aes_schedules(data)
    candidates += find_labelled(data)
    candidates += find_encoded(data)
    candidates += find_ascii_keys(data)
    if include_windows:
        candidates += find_entropy_windows(data)
    unique: dict[tuple[bytes, str], KeyCandidate] = {}
    for candidate in sorted(candidates, key=lambda c: (-c.strength, c.offset)):
        unique.setdefault((candidate.key, candidate.role), candidate)
    return list(unique.values())


# ---------------------------------------------------------------------------
# Testing the candidates
# ---------------------------------------------------------------------------


def hunt(
    dump: bytes,
    ciphertext: bytes | None = None,
    flagset: FlagSet | None = None,
    cipher: str | None = None,
    mode: str | None = None,
    budget: Budget | None = None,
    top_n: int = 10,
    per_key_seconds: float = PER_KEY_SECONDS,
) -> KeyReport:
    """Find candidate keys in `dump`; with a ciphertext, try them on it.

    Candidates are tried strongest first, each with its own small time slice of
    the solver, and the hunt stops at the first convincing decryption. Weak
    candidates (random-looking windows) are tried with AES only, unless
    `cipher` says otherwise.
    """
    from ctfc.core.symmetric import solve_symmetric  # imported here: it is big

    budget = budget or Budget(max_attempts=100_000, max_seconds=60)
    report = KeyReport(candidates=extract_candidates(dump, include_windows=ciphertext is not None))
    counts: dict[str, int] = {}
    for candidate in report.candidates:
        counts[candidate.kind] = counts.get(candidate.kind, 0) + 1
    report.notes.append(
        f"{len(report.candidates)} candidate keys: "
        + (
            ", ".join(f"{count} {kind.replace('_', ' ')}" for kind, count in counts.items())
            or "none"
        )
    )
    if ciphertext is None:
        report.notes.append("no ciphertext given (--against): candidates listed, nothing tested")
        report.budget_summary = "nothing tested"
        return report

    from ctfc.core import luks

    header = luks.find_header(ciphertext)
    if header is not None:
        _hunt_luks(report, header, budget)
        return report

    ivs = [c.key for c in report.candidates if c.role == "iv"][:3]
    best: list[Candidate] = []
    for candidate in report.candidates:
        if candidate.role == "iv":
            continue
        if not budget.spend():
            report.notes.append(f"stopped after {report.tested} keys: {budget.summary()}")
            break
        report.tested += 1
        slice_seconds = min(per_key_seconds, max(0.1, budget.max_seconds - budget.elapsed()))
        own = Budget(
            max_attempts=200_000, max_seconds=slice_seconds, cancel_event=budget.cancel_event
        )
        weak = candidate.kind in ("entropy", "aes_schedule")
        options = {
            "cipher": cipher or ("aes" if weak else None),
            "mode": mode,
            "budget": own,
            "top_n": 3,
        }
        if candidate.role == "passphrase":
            options["passphrase"] = candidate.key
        elif candidate.role == "blob":
            options["blob"] = candidate.key
        else:
            options["key"] = candidate.key
        attempts = [None]
        if candidate.kind == "labelled" and candidate.role == "key":
            attempts += ivs  # a labelled IV goes with a labelled key
        for iv in attempts:
            found = solve_symmetric(ciphertext, flagset=flagset, iv=iv, **options).candidates
            for result in found[:1]:
                best.append(_attribute(result, candidate))
            if found and found[0].score >= FOUND:
                break
        if best and max(result.score for result in best) >= FOUND:
            report.winner = candidate
            break

    best.sort(key=lambda result: -result.score)
    report.results = best[:top_n]
    if report.winner is None:
        report.notes.append(
            f"no candidate decrypted the ciphertext convincingly ({report.tested} tried). "
            "Try --cipher / --mode, a longer --seconds, or check the key is really in this dump"
        )
    report.budget_summary = f"{report.tested} candidate keys tested in {budget.elapsed():.1f} s"
    return report


def _hunt_luks(report: KeyReport, header, budget: Budget) -> None:
    """--against is a LUKS volume: confirm a master key with the header's own digest.

    The symmetric solver cannot open LUKS (the data is encrypted sector by
    sector with a key that keyslots protect), but the header holds a PBKDF2
    digest of the master key: every candidate - alone, or two keys glued, in
    both orders - is checked against it, offline.
    """
    from ctfc.core import luks

    report.notes.append(header.describe())
    usable = [
        candidate
        for candidate in report.candidates
        if candidate.role == "key" and len(candidate.key) in (16, 24, 32, 64)
    ]
    # A mounted LUKS volume keeps its master key in memory as AES key schedules
    # (that is what aeskeyfind looks for): when some were found, they are the
    # candidates; the weaker kinds (random-looking windows) only come as a fallback.
    strong = [c for c in usable if c.kind in ("aes_schedule", "labelled", "hex", "base64")]
    keys = [(c.key, f"{c.how} @0x{c.offset:x}") for c in (strong or usable)]
    tries = luks.candidates(keys, header.key_bytes)
    report.notes.append(
        f"{len(tries)} master-key candidates of {header.key_bytes} bytes built from "
        f"{len(keys)} keys (alone, or two glued in both orders), each checked "
        "against the header's PBKDF2 digest"
    )
    for key, how in tries:
        if not budget.spend():
            report.notes.append(f"stopped: {budget.summary()}")
            break
        report.tested += 1
        if luks.is_master_key(header, key):
            report.luks = {
                **header.to_dict(),
                "master_key_hex": key.hex(),
                "built_from": how,
                "commands": luks.open_commands(key),
            }
            report.notes.append(f"master key CONFIRMED by the LUKS header: {how}")
            break
    else:
        report.notes.append(
            "no candidate matches the header's digest: the key is not among the AES "
            "keys found in this dump (another dump? a different partition?)"
        )
    report.budget_summary = (
        f"{report.tested} master-key candidates checked in {budget.elapsed():.1f} s"
    )


def _attribute(result: Candidate, candidate: KeyCandidate) -> Candidate:
    """Say in the result where the key came from."""
    where = f"key found at offset 0x{candidate.offset:x}: {candidate.how}"
    result.label = f"{result.label}  [{candidate.kind.replace('_', ' ')} @0x{candidate.offset:x}]"
    result.reasons = [where, *result.reasons]
    result.params = {**result.params, "found_at": candidate.offset, "found_how": candidate.how}
    if result.python:
        result.python = f"# {where}\n{result.python}"
    return result
