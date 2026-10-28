"""Code Lens with the encrypted file: mirror the encryptor on real data.

Static analysis alone cannot always tell *which* string of a script is the key.
Obfuscated names (`$a53Va`) give no hint, and the key often travels through two
or three function calls before it reaches the `-bxor`. A regex cannot follow that.

But when you also have the file the script produced (`map.pdf.secured`), you do
not need to know: try them. The script's own literals are the only possible
keys, so:

1. collect every string literal of the script, as written and decoded (base64,
   hex) - a handful of candidates, plus the keys Code Lens already extracted;
2. read the operations Code Lens found: how many keys the XOR line uses
   (`-bxor $a -bxor $b` = two), whether a cipher is used, whether the output was
   base64-encoded (then the file is base64 text, decode it first);
3. try every combination on the first 4 KB, score each output with
   `scoring.py` (a PDF header, a flag, readable text), and replay the best one
   on the whole file.

Nothing is executed: the operations are re-implemented, the script is only read.
Every result says which literal (line, variable) was used as which key.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import re
from dataclasses import dataclass

from ctfc.core.budget import Budget
from ctfc.core.codegen import Step, chain_cyberchef, chain_label, chain_snippet
from ctfc.core.flags import FlagSet
from ctfc.core.lens import LensReport
from ctfc.core.magic import match_signature
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

SAMPLE = 4096  # combinations are scored on this many bytes, the best is replayed on all
MAX_LITERALS = 80  # a script with more string literals than this: keep the longest
FOUND = 0.9
STRING_RE = re.compile(r"\"((?:[^\"\\\n]|\\.){2,4096})\"|'((?:[^'\\\n]|\\.){2,4096})'")
XOR_TOKEN_RE = re.compile(r"-bxor|\^")


@dataclass(frozen=True)
class Material:
    """One possible key: a literal of the script, in one reading."""

    value: bytes
    reading: str  # "text", "base64", "hex", or the artifact's own description
    line: int
    name: str  # the variable it is assigned to, when there is one

    def describe(self) -> str:
        where = f"line {self.line}" + (f" ({self.name})" if self.name else "")
        return f"{where}, {self.reading}: {_short(self.value)}"


def _short(value: bytes) -> str:
    if value and all(32 <= b < 127 for b in value):
        text = value.decode()
        return repr(text if len(text) <= 32 else text[:29] + "...")
    return "0x" + (value.hex() if len(value) <= 16 else value[:16].hex() + "...")


def _readings(literal: str) -> list[tuple[bytes, str]]:
    """The bytes a literal can stand for: as written, base64-decoded, hex-decoded."""
    raw = literal.encode("utf-8", errors="replace")
    readings = [(raw, "text")]
    compact = literal.strip()
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and len(compact) >= 8:
        readings.append((bytes.fromhex(compact), "hex"))
    elif (
        re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact)
        and len(compact) % 4 == 0
        and len(compact) >= 8
    ):
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded:
            readings.append((decoded, "base64"))
    return readings


def collect_material(source: str, report: LensReport) -> list[Material]:
    """Every literal of the script (in each reading) plus the extracted keys."""
    found: dict[bytes, Material] = {}
    for artifact in report.artifacts:
        if artifact.kind in ("key", "iv", "nonce", "password", "salt") and artifact.value:
            found.setdefault(
                artifact.value,
                Material(
                    artifact.value,
                    f"extracted {artifact.kind} ({artifact.how})",
                    artifact.line,
                    artifact.name,
                ),
            )
    literals = []
    for number, line in enumerate(source.splitlines(), start=1):
        assigned = re.match(r"\s*\$?([A-Za-z_][\w]*)\s*=", line)
        for match in STRING_RE.finditer(line):
            literal = match.group(1) if match.group(1) is not None else match.group(2)
            literals.append((literal, number, assigned.group(1) if assigned else ""))
    literals.sort(key=lambda item: -len(item[0]))
    for literal, number, name in literals[:MAX_LITERALS]:
        if "$(" in literal or literal.startswith(("http", "/", "\\")):
            continue  # an interpolated string, a URL or a path is no key
        for value, reading in _readings(literal):
            found.setdefault(value, Material(value, reading, number, name))
    return list(found.values())


def _xor_key_count(source: str, report: LensReport) -> int:
    """How many keys the XOR expression combines (`a -bxor k1 -bxor k2` = 2)."""
    lines = source.splitlines()
    best = 1
    for operation in report.operations:
        if operation.kind == "xor" and 0 < operation.line <= len(lines):
            count = len(XOR_TOKEN_RE.findall(lines[operation.line - 1]))
            best = max(best, min(count, 3))
    return best


def _input_readings(data: bytes, report: LensReport) -> list[tuple[list[Step], bytes]]:
    """The file as it is, or base64/hex-decoded when the script encoded its output."""
    readings: list[tuple[list[Step], bytes]] = [([], data)]
    text = data.strip()
    if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", text) and len(text) >= 8:
        try:
            readings.insert(
                0, ([Step("base64")], base64.b64decode(b"".join(text.split()), validate=True))
            )
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(rb"[0-9A-Fa-f\s]+", text) and len(b"".join(text.split())) % 2 == 0:
        readings.insert(0, ([Step("hex")], bytes.fromhex(b"".join(text.split()).decode())))
    return readings


def _keystream_xor(data: bytes, keys: tuple[bytes, ...]) -> bytes:
    out = bytearray(data)
    for key in keys:
        for i in range(len(out)):
            out[i] ^= key[i % len(key)]
    return bytes(out)


@dataclass
class _Hit:
    steps: list[Step]
    used: list[str]  # which literal was used for which key
    score: float


def mirror_against(
    source: bytes | str,
    report: LensReport,
    encrypted: bytes,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    top_n: int = 5,
) -> list[Candidate]:
    """Try the script's literals as the keys of its own operations on `encrypted`.

    Returns the best decryptions (Candidates with reasons and a Python script),
    best first. Notes about what was tried are added to `report.notes`.
    """
    budget = budget or Budget(max_attempts=200_000, max_seconds=30)
    text = source.decode("utf-8", errors="replace") if isinstance(source, bytes) else source
    material = collect_material(text, report)
    kinds = {operation.kind for operation in report.operations if operation.kind}
    hits: list[_Hit] = []

    readings = _input_readings(encrypted, report)
    if "xor" in kinds:
        count = _xor_key_count(text, report)
        keys = [m for m in material if 1 <= len(m.value) <= 4096]
        report.notes.append(
            f"--against: {len(keys)} literals x {len(readings)} readings of the file, "
            f"XOR with {count} key(s) combined"
        )
        for prefix, data in readings:
            sample = data[:SAMPLE]
            for size in range(1, count + 1):
                for combo in itertools.combinations(keys, size):
                    if not budget.spend():
                        break
                    output = _keystream_xor(sample, tuple(m.value for m in combo))
                    value, _ = score(output, flagset)
                    if value >= 0.5:
                        steps = prefix + [Step("xor", {"key": m.value.hex()}) for m in combo]
                        used = [f"XOR key {i + 1}: {m.describe()}" for i, m in enumerate(combo)]
                        hits.append(_Hit(steps, used, value))
    if "cipher" in kinds:
        hits += _cipher_hits(report, material, readings, flagset, budget)
    if not hits:
        report.notes.append(
            "--against: no combination of the script's literals decrypted the file "
            "(the key may be computed at run time, or come from outside the script)"
        )
        return []

    hits.sort(key=lambda hit: (-round(hit.score, 2), len(hit.steps)))
    results = []
    seen: set[bytes] = set()
    from ctfc.core.lens import apply_chain

    for hit in hits:
        output = (
            hit_output(encrypted, hit) if _has_cipher(hit) else apply_chain(encrypted, hit.steps)
        )
        if output is None or output in seen:
            continue
        seen.add(output)
        value, reasons = score(output, flagset)
        signature = match_signature(output)
        save_as = f"output.{signature.ext}" if signature and signature.ext not in ("xml",) else None
        results.append(
            Candidate(
                label=chain_label(hit.steps),
                data=output,
                score=value,
                reasons=[
                    "the script's own operations, undone with its literals",
                    *hit.used,
                    *reasons,
                ],
                params={"chain": [step.to_dict() for step in hit.steps]},
                python=chain_snippet(encrypted, hit.steps, save_as=save_as),
                cyberchef=chain_cyberchef(hit.steps),
            )
        )
        if len(results) >= top_n:
            break
    results.sort(key=lambda candidate: -candidate.score)
    return results


def _has_cipher(hit: _Hit) -> bool:
    return any(step.name == "cipher" for step in hit.steps)


def hit_output(encrypted: bytes, hit: _Hit) -> bytes | None:
    """Replay a chain with a cipher step on the whole file (the pipeline knows
    every cipher field). PKCS7 padding is removed when it is valid, which is
    only knowable on the whole file, not on the sample."""
    from ctfc.core import pipeline

    padded = [
        Step(step.name, {**step.params, "unpad": "pkcs7"}) if step.name == "cipher" else step
        for step in hit.steps
    ]
    for steps in (padded, hit.steps):
        result = pipeline.run(encrypted, steps)
        if result.ok:
            hit.steps = steps
            return result.output
    return None


def _cipher_hits(
    report: LensReport,
    material: list[Material],
    readings: list[tuple[list[Step], bytes]],
    flagset: FlagSet | None,
    budget: Budget,
) -> list[_Hit]:
    """AES / DES / ...: literals of a key size as key, literals of 8/12/16 bytes as IV."""
    from ctfc.core import pipeline
    from ctfc.core.symmetric import CIPHERS

    hits = []
    for operation in report.operations:
        if operation.kind != "cipher":
            continue
        name = str(operation.params.get("cipher") or "aes").lower()
        if name not in CIPHERS:
            continue
        spec = CIPHERS[name]
        mode = str(operation.params.get("mode") or "cbc").lower()
        if mode not in spec.modes:
            mode = spec.modes[0]
        keys = [m for m in material if len(m.value) in spec.key_sizes]
        ivs = [m for m in material if len(m.value) in (8, 12, 16)] + [None]
        report.notes.append(
            f"--against: {spec.label}-{mode.upper()} with {len(keys)} key-sized literals "
            f"and {len(ivs) - 1} IV-sized ones (plus: IV at the start of the file)"
        )
        for prefix, data in readings:
            for key, iv in itertools.product(keys, ivs):
                if not budget.spend():
                    return hits
                params = {
                    "cipher": name,
                    "mode": mode,
                    "key": key.value.hex(),
                    "label": f"{spec.label}-{len(key.value) * 8}-{mode.upper()}",
                }
                if iv is not None:
                    params["iv"] = iv.value.hex()
                else:
                    params["iv_from"] = "prefix"
                params = pipeline.complete_cipher(params)  # iv_size etc., as codegen expects
                # A block-aligned sample, decrypted without unpadding (see hit_output).
                sample = data[
                    : SAMPLE + 16 - (SAMPLE % spec.block_size if spec.block_size > 1 else 0)
                ]
                result = pipeline.run(sample, [Step("cipher", params)])
                if not result.ok:
                    continue
                value, _ = score(result.output, flagset)
                if value >= 0.5:
                    used = [f"key: {key.describe()}"]
                    used.append(f"IV: {iv.describe()}" if iv else "IV: the first bytes of the file")
                    hits.append(_Hit(prefix + [Step("cipher", params)], used, value))
    return hits
