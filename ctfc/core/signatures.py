"""Recover a signing key from two signatures that reused the same nonce.

ECDSA and DSA both sign with a secret random number `k` (the "nonce") that must
never be reused. One signature is `(r, s)` with

    r = (k*G).x mod n          # ECDSA; DSA uses r = (g^k mod p) mod q
    s = k^-1 * (h + r*d) mod n

The private key `d` is protected by `k`, and only by `k`. Sign two different
messages with the same `k` and the two equations become a two-unknown linear
system an afternoon of school algebra solves:

    s1 - s2 = k^-1 * (h1 - h2)      ->  k = (h1 - h2) / (s1 - s2)  mod n
    d       = (s1*k - h1) / r       mod n

The giveaway is free: the same `k` gives the same `r`, so **two signatures with
an identical r** announce the bug in public. That is the whole detection rule,
and it is why this module starts by grouping signatures by `r`.

What goes wrong in practice, and is handled here:

- Some signers normalise `s` to the lower half of the range ("low-s", standard in
  Bitcoin), which flips a sign. The four sign combinations are all tried, and
  the one that verifies against the public key wins.
- ECDSA reduces the message hash to the bit length of `n` by keeping the
  *leftmost* bits, so SHA-256 under P-192 is not simply `int(digest)`.
- Verification is real, not assumed: `d*G` is computed with the curve arithmetic
  below and compared with the public key when one is given.

Nothing here attacks a curve or a hash: it exploits one misuse, exactly.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from functools import lru_cache

from ctfc.core.datafiles import load_toml


class SignatureError(ValueError):
    """The signatures or parameters given cannot feed the nonce-reuse recovery."""


# --- curves ------------------------------------------------------------------


@dataclass(frozen=True)
class Curve:
    """A short Weierstrass curve: y^2 = x^3 + a*x + b over GF(p)."""

    id: str
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int  # the order of G: every scalar lives modulo this

    @property
    def g(self) -> tuple[int, int]:
        return (self.gx, self.gy)

    def is_on_curve(self, point: tuple[int, int] | None) -> bool:
        if point is None:
            return True  # the point at infinity is on every curve
        x, y = point
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, first: tuple[int, int] | None, second: tuple[int, int] | None):
        """Point addition. `None` is the point at infinity (the neutral element)."""
        if first is None:
            return second
        if second is None:
            return first
        x1, y1 = first
        x2, y2 = second
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # P + (-P)
        if first == second:
            slope = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (slope * slope - x1 - x2) % self.p
        return (x3, (slope * (x1 - x3) - y1) % self.p)

    def multiply(self, scalar: int, point: tuple[int, int] | None = None):
        """Scalar multiplication by double-and-add (verification only, not secret)."""
        result = None
        current = self.g if point is None else point
        scalar %= self.n
        while scalar:
            if scalar & 1:
                result = self.add(result, current)
            current = self.add(current, current)
            scalar >>= 1
        return result


@lru_cache(maxsize=1)
def load_curves() -> dict[str, Curve]:
    """Read ctfc/data/curves.toml, indexed by id and by every alias."""
    curves: dict[str, Curve] = {}
    for row in load_toml("curves.toml")["curve"]:

        def number(name: str, row=row) -> int:
            return int(re.sub(r"\s", "", row[name]), 16)

        curve = Curve(
            id=row["id"],
            name=row["name"],
            p=number("p"),
            a=number("a"),
            b=number("b"),
            gx=number("gx"),
            gy=number("gy"),
            n=number("n"),
        )
        for key in (curve.id, *row.get("aliases", [])):
            curves[key.lower()] = curve
    return curves


def find_curve(name: str) -> Curve:
    curves = load_curves()
    curve = curves.get(name.strip().lower())
    if curve is None:
        known = ", ".join(sorted({c.id for c in curves.values()}))
        raise SignatureError(f"unknown curve {name!r}; known: {known}")
    return curve


# --- signatures --------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    """One signature, with the message hash it was made over."""

    r: int
    s: int
    h: int  # the hash as the signer reduced it (see `hash_to_int`)
    label: str = ""


@dataclass
class Recovery:
    """One recovered key, and how sure we are of it."""

    variant: str  # which sign combination produced it
    nonce: int  # k
    private_key: int  # d
    verified: bool  # d*G matched the public key (or y = g^d mod p for DSA)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "variant": self.variant,
            "nonce": f"{self.nonce:x}",
            "private_key": f"{self.private_key:x}",
            "private_key_decimal": str(self.private_key),
            "verified": self.verified,
            "reasons": list(self.reasons),
        }


@dataclass
class SignatureReport:
    """What the signatures gave away."""

    algorithm: str = "ECDSA"
    curve: str = ""
    order_bits: int = 0
    signatures: int = 0
    reused: list[tuple[str, str]] = field(default_factory=list)  # pairs sharing r
    recoveries: list[Recovery] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    python: str = ""

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "curve": self.curve,
            "order_bits": self.order_bits,
            "signatures": self.signatures,
            "reused": [list(pair) for pair in self.reused],
            "recoveries": [item.to_dict() for item in self.recoveries],
            "notes": list(self.notes),
            "python": self.python,
        }


def hash_to_int(digest: bytes, order: int) -> int:
    """Reduce a message digest the way ECDSA and DSA do: keep the leftmost bits.

    A SHA-256 digest signed under P-192 is *not* `int(digest)`: the standard
    takes the leftmost 192 bits. Getting this wrong makes the recovered key
    wrong, with nothing to say why - so it is worth its own function.
    """
    value = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - order.bit_length()
    return value >> excess if excess > 0 else value


def parse_der_signature(data: bytes) -> tuple[int, int]:
    """Read (r, s) out of a DER SEQUENCE of two INTEGERs, as OpenSSL writes it."""
    if len(data) < 8 or data[0] != 0x30:
        raise SignatureError("not a DER signature: it should start with 0x30 (SEQUENCE)")
    position = 2
    if data[1] & 0x80:  # long form length
        position = 2 + (data[1] & 0x7F)
    values = []
    for _ in range(2):
        if position + 2 > len(data) or data[position] != 0x02:
            raise SignatureError("not a DER signature: expected an INTEGER (0x02)")
        length = data[position + 1]
        start = position + 2
        if start + length > len(data):
            raise SignatureError("the DER signature is truncated")
        values.append(int.from_bytes(data[start : start + length], "big"))
        position = start + length
    return values[0], values[1]


NUMBER = r"(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{16,}|\d+)"
FIELD_RE = re.compile(rf"\b(r|s|h|z|m|hash)\s*[=:]\s*({NUMBER})", re.IGNORECASE)


def _as_int(text: str) -> int:
    """Read a number the way a challenge prints it: 0x hex, decimal, or bare hex.

    An all-digit string is read as decimal, which is the common case; a bare run
    of hex digits with a letter in it is read as hex. When it matters, write 0x -
    a misread shows up at once as "no two signatures share an r".
    """
    cleaned = text.strip().replace("_", "")
    if cleaned.lower().startswith(("0x", "-0x")):
        return int(cleaned, 16)
    if re.fullmatch(r"-?\d+", cleaned):
        return int(cleaned)
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return int(cleaned, 16)
    raise SignatureError(f"{text.strip()[:40]!r} is not a number (decimal, 0x hex, or bare hex)")


def parse_signatures(
    text: str, *, order: int | None = None, algorithm: str = "sha256"
) -> list[Signature]:
    """Read signatures out of JSON or out of `r=... s=... h=...` lines.

    Accepted shapes, because a challenge prints whichever it likes:

        [{"r": "0x..", "s": "0x..", "h": "0x.."}, ...]
        [{"r": .., "s": .., "message": "hex or text"}, ...]   (hashed here)
        r=0x.. s=0x.. h=0x..                                   (one per line)
        r,s,h                                                  (CSV, one per line)
    """
    text = text.strip()
    if not text:
        raise SignatureError("no signatures found: the input is empty")

    found: list[Signature] = []
    if text.startswith(("[", "{")):
        found = _parse_json(text, order=order, algorithm=algorithm)
    else:
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = {name.lower(): value for name, value in FIELD_RE.findall(line)}
            if "r" in fields and "s" in fields:
                digest = fields.get("h") or fields.get("z") or fields.get("m") or fields.get("hash")
                if digest is None:
                    raise SignatureError(
                        f"line {number} has r and s but no message hash (h=...): "
                        "the hash is what makes the two equations solvable"
                    )
                found.append(
                    Signature(
                        _as_int(fields["r"]),
                        _as_int(fields["s"]),
                        _as_int(digest),
                        label=f"line {number}",
                    )
                )
                continue
            parts = [part for part in re.split(r"[,;\s]+", line) if part]
            if len(parts) >= 3:
                try:
                    found.append(
                        Signature(
                            _as_int(parts[0]),
                            _as_int(parts[1]),
                            _as_int(parts[2]),
                            label=f"line {number}",
                        )
                    )
                except ValueError as exc:
                    raise SignatureError(f"line {number}: {line[:60]!r} is not r, s, h") from exc
            else:
                raise SignatureError(
                    f"line {number}: {line[:60]!r} is not a signature. Use "
                    "'r=.. s=.. h=..', or 'r,s,h', or a JSON list"
                )
    if not found:
        raise SignatureError("no signature could be read from the input")
    return found


def _parse_json(text: str, *, order: int | None, algorithm: str) -> list[Signature]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SignatureError(f"the input starts like JSON but does not parse: {exc}") from exc
    rows = parsed if isinstance(parsed, list) else [parsed]
    found: list[Signature] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise SignatureError(f"entry {index} is not an object with r, s and h")
        if "r" not in row or "s" not in row:
            raise SignatureError(f"entry {index} has no r/s")
        digest_value = row.get("h", row.get("z", row.get("hash")))
        if digest_value is None:
            message = row.get("message", row.get("msg"))
            if message is None:
                raise SignatureError(
                    f"entry {index} has no h and no message: one of the two is needed"
                )
            if order is None:
                raise SignatureError(
                    "a message can only be hashed once the curve (or --order) is known"
                )
            raw = _message_bytes(str(message))
            digest = hashlib.new(algorithm, raw).digest()
            digest_value = hash_to_int(digest, order)
        found.append(
            Signature(
                _number(row["r"]),
                _number(row["s"]),
                _number(digest_value),
                label=str(row.get("label") or f"entry {index}"),
            )
        )
    return found


def _message_bytes(message: str) -> bytes:
    """A message given as hex (long even run of hex digits) or as text."""
    cleaned = message.strip()
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cleaned) and len(cleaned.removeprefix("0x")) % 2 == 0:
        return bytes.fromhex(cleaned.removeprefix("0x"))
    return cleaned.encode()


def _number(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _as_int(value)
    raise SignatureError(f"{value!r} is not a number")


# --- the recovery ------------------------------------------------------------


def find_reuse(signatures: Sequence[Signature]) -> list[tuple[Signature, Signature]]:
    """Every pair of signatures that shares an `r` - that is the whole detection."""
    by_r: dict[int, list[Signature]] = {}
    for signature in signatures:
        by_r.setdefault(signature.r, []).append(signature)
    pairs: list[tuple[Signature, Signature]] = []
    for group in by_r.values():
        for index, first in enumerate(group):
            for second in group[index + 1 :]:
                if first.h != second.h:  # same r AND same h is just a duplicate
                    pairs.append((first, second))
    return pairs


# The four sign combinations. A signer that normalises s (Bitcoin's "low-s"
# rule) silently negates it, and a verifier accepts both - so the attack has to
# try them rather than assume.
VARIANTS = (
    ("s1 - s2", 1, 1),
    ("s1 + s2", 1, -1),
    ("-s1 - s2", -1, 1),
    ("-s1 + s2", -1, -1),
)


def recover(
    first: Signature,
    second: Signature,
    order: int,
    *,
    check: object = None,
) -> list[Recovery]:
    """Solve for `k` and `d` from two signatures sharing `r`.

    `check` is called with a candidate private key and returns True when it
    matches the public key; without it, every sign variant is returned and the
    user picks (or supplies a public key).
    """
    if first.r != second.r:
        raise SignatureError(
            f"these two signatures have different r values ({first.r:x} vs "
            f"{second.r:x}): nothing says they share a nonce, and the recovery "
            "needs that"
        )
    if first.h == second.h:
        raise SignatureError(
            "both signatures are over the same hash: that is one signature twice, "
            "and h1 - h2 = 0 leaves nothing to solve"
        )
    if first.r % order == 0:
        raise SignatureError("r = 0 mod n: the signature is invalid, not just reused")

    results: list[Recovery] = []
    for label, sign1, sign2 in VARIANTS:
        s1 = (sign1 * first.s) % order
        s2 = (sign2 * second.s) % order
        bottom = (s1 - s2) % order
        if bottom == 0:
            continue
        nonce = ((first.h - second.h) * pow(bottom, -1, order)) % order
        private = ((s1 * nonce - first.h) * pow(first.r, -1, order)) % order
        if private == 0:
            continue
        verified = bool(check(private)) if check is not None else False
        reasons = [
            f"k = (h1 - h2) / ({label}) mod n",
            "d = (s1*k - h1) / r mod n",
        ]
        if check is not None:
            reasons.append(
                "the public key matches d*G" if verified else "the public key does not match d*G"
            )
        results.append(
            Recovery(
                variant=label, nonce=nonce, private_key=private, verified=verified, reasons=reasons
            )
        )
    if not results:
        raise SignatureError(
            "every sign combination gave s1 - s2 = 0 mod n: these two signatures "
            "carry the same s as well as the same r, so there is nothing to solve"
        )
    # Negating *both* s values gives the same private key with the opposite nonce,
    # so half the variants are duplicates. Keep one entry per key.
    unique: list[Recovery] = []
    for item in results:
        twin = next((kept for kept in unique if kept.private_key == item.private_key), None)
        if twin is None:
            unique.append(item)
        else:
            twin.reasons.append(f"{item.variant} gives the same key, with k negated")
    # A verified key first; otherwise the textbook variant stays first.
    unique.sort(key=lambda item: not item.verified)
    return unique


def ec_checker(curve: Curve, public_point: tuple[int, int]):
    """A `check` for `recover`: does d*G land on the given public key?"""
    if not curve.is_on_curve(public_point):
        raise SignatureError(
            f"the public point is not on {curve.id}: wrong curve, or x and y swapped"
        )

    def check(private: int) -> bool:
        return curve.multiply(private) == public_point

    return check


def dsa_checker(p: int, g: int, y: int):
    """A `check` for DSA: does g^d mod p give the public y?"""

    def check(private: int) -> bool:
        return pow(g, private, p) == y

    return check


def solve(
    signatures: Sequence[Signature],
    *,
    curve: Curve | None = None,
    order: int | None = None,
    public_point: tuple[int, int] | None = None,
    dsa_public: tuple[int, int, int] | None = None,
) -> SignatureReport:
    """Look for a reused nonce among `signatures` and recover the key from it."""
    if curve is None and order is None:
        raise SignatureError(
            "give the curve (--curve secp256k1, p-256, ...) or the group order "
            "(--order <q> for DSA): every scalar is reduced by it, so the recovery "
            "cannot start without it"
        )
    modulus = order if order is not None else curve.n
    report = SignatureReport(
        algorithm="DSA" if curve is None else "ECDSA",
        curve=curve.name if curve is not None else f"order of {modulus.bit_length()} bits",
        order_bits=modulus.bit_length(),
        signatures=len(signatures),
    )

    check = None
    if public_point is not None and curve is not None:
        check = ec_checker(curve, public_point)
    elif dsa_public is not None:
        check = dsa_checker(*dsa_public)

    # Fill in labels so the report can name which pair was used.
    signatures = [
        signature if signature.label else replace(signature, label=f"#{index}")
        for index, signature in enumerate(signatures, start=1)
    ]
    pairs = find_reuse(signatures)
    if not pairs:
        report.notes.append(
            f"no two of the {len(signatures)} signatures share an r, so no nonce was "
            "reused: there is nothing here to recover. (r is public and depends only "
            "on k, which is exactly why reuse is visible without any key)"
        )
        return report

    report.reused = [(first.label, second.label) for first, second in pairs]
    first, second = pairs[0]
    report.recoveries = recover(first, second, modulus, check=check)
    report.notes.append(
        f"{len(pairs)} pair(s) share an r: {first.label} and {second.label} were used"
    )
    if check is None:
        report.notes.append(
            "no public key was given, so the four sign variants are all listed: a "
            "signer that normalises s (Bitcoin's low-s rule) flips one. Pass the "
            "public key to have ctfc compute d*G and pick the right one"
        )
    elif not any(item.verified for item in report.recoveries):
        report.notes.append(
            "none of the variants matches the public key given: check the curve, "
            "that the hashes are reduced the way the signer did it (leftmost bits), "
            "and that r/s are not swapped"
        )
    report.python = _snippet(first, second, modulus, report.algorithm)
    return report


def _snippet(first: Signature, second: Signature, order: int, algorithm: str) -> str:
    return f'''"""{algorithm} nonce reuse: two signatures sharing r give the private key.

The same r means the same k. Two equations, two unknowns, no search.
"""

n = {order}      # the group order (curve order for ECDSA, q for DSA)
r = {first.r}
s1, h1 = {first.s}, {first.h}
s2, h2 = {second.s}, {second.h}

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n       # the nonce that should have been secret
d = ((s1 * k - h1) * pow(r, -1, n)) % n         # the private key

print("k =", hex(k))
print("d =", hex(d))

# Check it: re-sign the first message with the recovered k and d.
assert (pow(k, -1, n) * (h1 + r * d)) % n == s1 % n

# If this fails, try s1 -> -s1 or s2 -> -s2: some signers normalise s to the
# lower half of the range, which flips the sign without changing validity.
'''


# --- public keys -------------------------------------------------------------


def _field_size(curve: Curve) -> int:
    return (curve.p.bit_length() + 7) // 8


def decompress_point(curve: Curve, parity: int, x: int) -> tuple[int, int]:
    """Rebuild y from x and its parity: y^2 = x^3 + a*x + b, then a square root."""
    if curve.p % 4 != 3:
        raise SignatureError(
            f"{curve.id} has p = 1 mod 4, so the square root needs Tonelli-Shanks: "
            "give the uncompressed point (04||X||Y) or x,y instead"
        )
    square = (x * x * x + curve.a * x + curve.b) % curve.p
    y = pow(square, (curve.p + 1) // 4, curve.p)
    if (y * y) % curve.p != square:
        raise SignatureError(f"x = {x:x} is not on {curve.id}: no y exists for it")
    if y % 2 != parity:
        y = curve.p - y
    return (x, y)


def parse_public_point(spec: str, curve: Curve) -> tuple[int, int]:
    """Read a public key as `x,y`, as an SEC1 point, or out of a PEM/DER file.

    A PEM public key is parsed the blunt way - the uncompressed point is the only
    run of `04` + 2*field-size bytes in a SubjectPublicKeyInfo - which avoids a
    full ASN.1 reader and works for curves pycryptodome does not know (secp256k1
    being the one that matters).
    """
    import base64
    from pathlib import Path

    text = spec.strip()
    size = _field_size(curve)

    pair = re.fullmatch(r"\(?\s*([^,\s]+)\s*,\s*([^,\s)]+)\s*\)?", text)
    if pair and not Path(text).exists():
        return (_as_int(pair.group(1)), _as_int(pair.group(2)))

    data: bytes
    path = Path(text)
    if len(text) < 4096 and path.is_file():
        data = path.read_bytes()
    elif re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", text):
        data = bytes.fromhex(text.removeprefix("0x"))
    else:
        data = text.encode()

    if b"-----BEGIN" in data:
        body = b"".join(
            line for line in data.splitlines() if line and not line.startswith(b"-----")
        )
        try:
            data = base64.b64decode(body)
        except (ValueError, TypeError) as exc:
            raise SignatureError(f"the PEM body does not decode: {exc}") from exc

    # An SEC1 point on its own.
    if len(data) == 1 + 2 * size and data[0] == 0x04:
        return (
            int.from_bytes(data[1 : 1 + size], "big"),
            int.from_bytes(data[1 + size :], "big"),
        )
    if len(data) == 1 + size and data[0] in (0x02, 0x03):
        return decompress_point(curve, data[0] & 1, int.from_bytes(data[1:], "big"))

    # Inside a DER structure: find the uncompressed point.
    for start in range(len(data) - 2 * size):
        if data[start] != 0x04:
            continue
        candidate = (
            int.from_bytes(data[start + 1 : start + 1 + size], "big"),
            int.from_bytes(data[start + 1 + size : start + 1 + 2 * size], "big"),
        )
        if curve.is_on_curve(candidate) and candidate[1] != 0:
            return candidate
    raise SignatureError(
        f"no point on {curve.id} found in that public key ({len(data)} bytes). Give "
        "it as x,y, or as the uncompressed point 04||X||Y in hex"
    )
