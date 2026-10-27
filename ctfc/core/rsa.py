"""RSA: read keys, decrypt, and recover a key that was generated badly.

A reminder of the whole scheme, because every CTF question about RSA is really a
question about one of these five numbers:

    n = p * q            the modulus, public
    e                    the public exponent, usually 65537
    d = e^-1 mod phi(n)  the private exponent, with phi(n) = (p-1)(q-1)
    encryption:  c = m^e mod n
    decryption:  m = c^d mod n

Knowing p and q gives phi(n), which gives d, which gives the message. That is why
everything here is about **getting p and q** (see `rsa_attacks.py`) or about
**noticing that the message itself was unprotected** (a small `e` on a short
message needs no key at all).

Padding matters as much as the maths: textbook RSA (`m^e mod n` and nothing else)
is deterministic and malleable, so real code wraps the message in PKCS#1 v1.5 or
OAEP first. ctfc tries all three and scores the results, because a challenge can
use any of them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes

from ctfc.core.budget import Budget
from ctfc.core.flags import FlagSet
from ctfc.core.rsa_attacks import AttackResult, iroot, run_attacks
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

COMMON_EXPONENTS = (3, 5, 7, 11, 17, 257, 65537)
SMALL_E_LIMIT = 101  # above this, the "short message" attack is hopeless
SMALL_E_MULTIPLES = 200  # how many k to try in m^e = c + k*n


class RsaError(ValueError):
    """Raised when a key or its parts cannot be used. The message says what is missing."""


# ---------------------------------------------------------------------------
# What we know about a key
# ---------------------------------------------------------------------------


@dataclass
class KeyInfo:
    """One RSA key, public or private, however we got hold of it."""

    n: int
    e: int
    d: int | None = None
    p: int | None = None
    q: int | None = None
    source: str = "given numbers"

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def is_private(self) -> bool:
        return self.d is not None

    def facts(self) -> list[tuple[str, str]]:
        """Rows for the report: short values in full, long ones abbreviated."""
        rows = [
            ("source", self.source),
            ("kind", "private key" if self.is_private else "public key"),
            ("size", f"{self.bits} bits"),
            ("n", _short_number(self.n)),
            ("e", str(self.e)),
        ]
        if self.e in (1, 2) or self.e % 2 == 0:
            rows.append(("warning", f"e = {self.e} is not a valid RSA exponent"))
        elif self.e <= SMALL_E_LIMIT:
            rows.append(("note", f"e = {self.e} is very small: a short message is recoverable"))
        if self.d is not None:
            rows.append(("d", _short_number(self.d)))
            if self.d.bit_length() * 4 < self.bits:
                rows.append(("note", "d is small compared to n: Wiener's attack applies"))
        if self.p is not None and self.q is not None:
            rows.append(("p", _short_number(self.p)))
            rows.append(("q", _short_number(self.q)))
            difference = abs(self.p - self.q)
            if difference.bit_length() * 3 < self.bits:
                rows.append(("note", "p and q are close: Fermat's attack applies"))
        return rows

    def to_dict(self) -> dict:
        return {
            "n": str(self.n),
            "e": self.e,
            "d": str(self.d) if self.d is not None else None,
            "p": str(self.p) if self.p is not None else None,
            "q": str(self.q) if self.q is not None else None,
            "bits": self.bits,
            "is_private": self.is_private,
            "source": self.source,
            "facts": self.facts(),
        }

    def rsa_key(self) -> RSA.RsaKey:
        """A pycryptodome key object, for the padded decryption modes."""
        if self.d is not None:
            if self.p is not None and self.q is not None:
                return RSA.construct((self.n, self.e, self.d, self.p, self.q))
            return RSA.construct((self.n, self.e, self.d), consistency_check=False)
        return RSA.construct((self.n, self.e))


def _short_number(value: int, keep: int = 24) -> str:
    """Long integers are shown as head...tail plus their length."""
    text = str(value)
    if len(text) <= 2 * keep:
        return text
    return f"{text[:keep]}...{text[-keep:]} ({len(text)} digits)"


# ---------------------------------------------------------------------------
# Reading and building keys
# ---------------------------------------------------------------------------


def parse_key(data: bytes, passphrase: str | None = None) -> KeyInfo:
    """Read a PEM / DER / OpenSSH key, public or private."""
    try:
        key = RSA.import_key(data, passphrase=passphrase)
    except (ValueError, IndexError, TypeError) as exc:
        raise RsaError(
            f"this does not look like an RSA key ({exc}). Expected PEM "
            "(-----BEGIN ... KEY-----), DER, or an OpenSSH public key"
        ) from exc
    kind = "PEM/DER private key" if key.has_private() else "PEM/DER public key"
    return KeyInfo(
        n=int(key.n),
        e=int(key.e),
        d=int(key.d) if key.has_private() else None,
        p=int(key.p) if key.has_private() else None,
        q=int(key.q) if key.has_private() else None,
        source=kind,
    )


def build_key(
    n: int | None = None,
    e: int | None = None,
    d: int | None = None,
    p: int | None = None,
    q: int | None = None,
) -> KeyInfo:
    """Build a key from whatever parts are known: (n,e), (p,q,e), (n,e,d)...

    Completes what it can: n from p*q, d from p, q and e, and p and q from n, e
    and d (pycryptodome does that last one for us).
    """
    if p is not None and q is not None:
        n = n or p * q
        if n != p * q:
            raise RsaError("n is not equal to p * q: check the numbers")
    if n is None:
        raise RsaError("n is missing: give --n, or --p and --q")
    e = e or 65537
    source = "given numbers"

    if d is None and p is not None and q is not None:
        phi = (p - 1) * (q - 1) if p != q else p * (p - 1)
        if math.gcd(e, phi) != 1:
            raise RsaError(f"e = {e} is not coprime with phi(n): this key cannot work")
        d = inverse(e, phi)
        source = "built from p, q and e"
    elif d is not None and (p is None or q is None):
        try:  # pycryptodome recovers p and q from (n, e, d)
            recovered = RSA.construct((n, e, d))
            p, q = int(recovered.p), int(recovered.q)
            source = "built from n, e and d"
        except ValueError:
            source = "built from n, e and d (p and q not recovered)"
    return KeyInfo(n=n, e=e, d=d, p=p, q=q, source=source)


def keys_match(first: KeyInfo, second: KeyInfo) -> tuple[bool, str]:
    """Do these two keys belong together? Compare the moduli, nothing else."""
    if first.n == second.n:
        return True, "same modulus n: these two keys are a pair"
    shared = math.gcd(first.n, second.n)
    if shared > 1:
        return False, (
            "different moduli, but they share a factor: both keys are broken "
            "(see the shared-prime attack)"
        )
    return False, "different moduli: these keys have nothing to do with each other"


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------


def _snippet(body: str, key: KeyInfo, with_private: bool = True) -> str:
    """A standalone script: the numbers, then the decryption."""
    lines = ['"""Decrypt with RSA (generated by ctfc)."""', "from Crypto.PublicKey import RSA"]
    if "PKCS1_OAEP" in body:
        lines.append("from Crypto.Cipher import PKCS1_OAEP")
    if "PKCS1_v1_5" in body:
        lines.append("from Crypto.Cipher import PKCS1_v1_5")
    if "SHA" in body:
        lines.append("from Crypto.Hash import SHA1, SHA256")
    if "long_to_bytes" in body:
        lines.append("from Crypto.Util.number import long_to_bytes")
    lines.append("")
    lines.append(f"n = {key.n}")
    lines.append(f"e = {key.e}")
    if with_private and key.d is not None:
        lines.append(f"d = {key.d}")
    if with_private and key.p is not None and key.q is not None:
        lines.append(f"p = {key.p}")
        lines.append(f"q = {key.q}")
    lines.append('ciphertext = open("ct.bin", "rb").read()  # <- your ciphertext')
    lines.append("")
    lines.append(body.rstrip())
    return "\n".join(lines) + "\n"


def _unpad_attempts(raw: bytes) -> list[tuple[bytes, str]]:
    """Ways to read the result of a textbook decryption."""
    attempts = [(raw, "raw bytes")]
    stripped = raw.lstrip(b"\x00")
    if stripped != raw and stripped:
        attempts.append((stripped, "leading zero bytes removed"))
    # PKCS#1 v1.5: 00 02 <random, no zero> 00 <message>
    if raw[:1] == b"\x02" or raw[:2] == b"\x00\x02":
        body = raw[1:] if raw[:1] == b"\x02" else raw[2:]
        separator = body.find(b"\x00")
        if separator >= 0:
            attempts.append((body[separator + 1 :], "PKCS#1 v1.5 padding removed by hand"))
    return attempts


def decrypt_candidates(
    key: KeyInfo, ciphertext: bytes, flagset: FlagSet | None = None, top_n: int = 10
) -> list[Candidate]:
    """Decrypt with every padding scheme that could have been used, and score each."""
    if key.d is None:
        raise RsaError(
            "this is a public key: there is no d to decrypt with. Find p and q "
            "(ctfc rsa --attack), or give --d"
        )
    number = int.from_bytes(ciphertext, "big")
    if number >= key.n:
        raise RsaError(
            f"the ciphertext ({len(ciphertext)} bytes) is larger than n "
            f"({key.bits} bits): wrong key, or the data is not a single RSA block"
        )

    candidates: list[Candidate] = []
    rsa_key = key.rsa_key()

    for label, hash_module, name in (
        ("RSA-OAEP (SHA-1)", SHA1, "SHA1"),
        ("RSA-OAEP (SHA-256)", SHA256, "SHA256"),
    ):
        try:
            plain = PKCS1_OAEP.new(rsa_key, hashAlgo=hash_module).decrypt(ciphertext)
        except (ValueError, TypeError):
            continue
        value, reasons = score(plain, flagset)
        candidates.append(
            Candidate(
                label=label,
                data=plain,
                score=min(1.0, value + 0.2),  # OAEP only succeeds if everything matches
                reasons=[
                    "the OAEP padding checked out, which only happens with the right key",
                    *reasons,
                ],
                params={"scheme": "oaep", "hash": name, "bits": key.bits},
                python=_snippet(
                    f"key = RSA.construct((n, e, d))\n"
                    f"plain = PKCS1_OAEP.new(key, hashAlgo={name}).decrypt(ciphertext)\n"
                    "print(plain)",
                    key,
                ),
            )
        )

    try:
        plain = PKCS1_v1_5.new(rsa_key).decrypt(ciphertext, None)
    except (ValueError, TypeError):
        plain = None
    if plain:
        value, reasons = score(plain, flagset)
        candidates.append(
            Candidate(
                label="RSA PKCS#1 v1.5",
                data=plain,
                score=min(1.0, value + 0.2),
                reasons=["the PKCS#1 v1.5 padding was valid", *reasons],
                params={"scheme": "pkcs1v15", "bits": key.bits},
                python=_snippet(
                    "key = RSA.construct((n, e, d))\n"
                    "plain = PKCS1_v1_5.new(key).decrypt(ciphertext, None)\n"
                    "print(plain)",
                    key,
                ),
            )
        )

    # Textbook RSA: no padding at all, which plenty of challenges use.
    raw = long_to_bytes(pow(number, key.d, key.n))
    for data, how in _unpad_attempts(raw):
        if not data:
            continue
        value, reasons = score(data, flagset)
        candidates.append(
            Candidate(
                label=f"textbook RSA, {how}",
                data=data,
                score=value,
                reasons=[
                    "m = c^d mod n with no padding scheme",
                    f"result read as: {how}",
                    *reasons,
                ],
                params={"scheme": "textbook", "bits": key.bits},
                python=_snippet(
                    "plain = long_to_bytes(pow(int.from_bytes(ciphertext, 'big'), d, n))\n"
                    "print(plain)",
                    key,
                ),
            )
        )

    return _best(candidates, top_n)


def small_exponent_candidates(
    n: int, e: int, ciphertext: bytes, flagset: FlagSet | None = None
) -> list[Candidate]:
    """No key needed: when `e` is small and the message was short, take the e-th root.

    If m^e is smaller than n, the modulus never wrapped around, so c = m^e exactly
    and m is just the integer e-th root of c. If it wrapped a few times, c + k*n is
    a perfect power for the right k, so we try a few hundred values of k.
    """
    if not 1 < e <= SMALL_E_LIMIT:
        return []
    number = int.from_bytes(ciphertext, "big")
    candidates = []
    for k in range(SMALL_E_MULTIPLES):
        root, exact = iroot(number + k * n, e)
        if not exact:
            continue
        plain = long_to_bytes(root)
        value, reasons = score(plain, flagset)
        wrapped = "" if k == 0 else f" (after adding {k} * n: the message wrapped {k} times)"
        candidates.append(
            Candidate(
                label=f"{e}th root of the ciphertext{wrapped}",
                data=plain,
                score=min(1.0, value + 0.2),
                reasons=[
                    f"e = {e} and the message was short, so c = m^{e} without wrapping"
                    f"{' much' if k else ''}: m is an exact {e}th root, no key needed",
                    *reasons,
                ],
                params={"scheme": "small-e", "e": e, "k": k},
                python=(
                    '"""Small public exponent: the message is just the e-th root."""\n'
                    "from Crypto.Util.number import long_to_bytes\n"
                    "from gmpy2 import iroot  # or see ctfc/core/rsa_attacks.py for pure Python\n\n"
                    f"n = {n}\ne = {e}\n"
                    'c = int.from_bytes(open("ct.bin", "rb").read(), "big")\n'
                    f"root, exact = iroot(c + {k} * n, e)\n"
                    "print(exact, long_to_bytes(int(root)))\n"
                ),
            )
        )
        if k == 0:
            break
    return candidates


def _best(candidates: list[Candidate], top_n: int) -> list[Candidate]:
    seen: set[bytes] = set()
    result = []
    for candidate in sorted(candidates, key=lambda item: -item.score):
        if candidate.data in seen:
            continue
        seen.add(candidate.data)
        result.append(candidate)
    return result[:top_n]


# ---------------------------------------------------------------------------
# The whole job
# ---------------------------------------------------------------------------


@dataclass
class RsaReport:
    """Everything ctfc worked out about this key and this ciphertext."""

    key: KeyInfo | None = None
    candidates: list[Candidate] = field(default_factory=list)
    attacks: AttackResult | None = None
    notes: list[str] = field(default_factory=list)
    comparison: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key.to_dict() if self.key else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "attacks": {
                "tried": self.attacks.tried,
                "notes": self.attacks.notes,
                "factorisation": (
                    {
                        "p": str(self.attacks.factorisation.p),
                        "q": str(self.attacks.factorisation.q),
                        "method": self.attacks.factorisation.method,
                        "explanation": self.attacks.factorisation.explanation,
                        "python": self.attacks.factorisation.python,
                    }
                    if self.attacks.factorisation
                    else None
                ),
                "private_exponent": (
                    {
                        "d": str(self.attacks.private_exponent.d),
                        "method": self.attacks.private_exponent.method,
                        "explanation": self.attacks.private_exponent.explanation,
                    }
                    if self.attacks.private_exponent
                    else None
                ),
            }
            if self.attacks
            else None,
            "notes": list(self.notes),
            "comparison": self.comparison,
        }


def solve_rsa(
    key: KeyInfo,
    ciphertext: bytes | None = None,
    flagset: FlagSet | None = None,
    attack: bool = False,
    other_moduli: list[int] | None = None,
    budget: Budget | None = None,
    top_n: int = 10,
) -> RsaReport:
    """Inspect the key, run the attacks if asked, and decrypt what can be decrypted."""
    report = RsaReport(key=key)

    # The message may be readable with no key at all.
    if ciphertext:
        report.candidates += small_exponent_candidates(key.n, key.e, ciphertext, flagset)
        if report.candidates:
            report.notes.append(
                "the message came out without the private key: a small e on a short "
                "message is an unprotected message"
            )

    if attack and not key.is_private:
        report.attacks = run_attacks(key.n, key.e, other_moduli, budget)
        found = report.attacks
        if found.factorisation is not None:
            p, q = found.factorisation.p, found.factorisation.q
            report.notes.append(f"factored n: {found.factorisation.method}")
            try:
                key = build_key(n=key.n, e=key.e, p=p, q=q)
                key.source = f"recovered by {found.factorisation.method}"
                report.key = key
            except RsaError as exc:
                report.notes.append(f"could not build the private key: {exc}")
        elif found.private_exponent is not None:
            report.notes.append(f"recovered d: {found.private_exponent.method}")
            key = KeyInfo(
                n=key.n,
                e=key.e,
                d=found.private_exponent.d,
                source=f"recovered by {found.private_exponent.method}",
            )
            report.key = key

    if ciphertext and key.is_private:
        try:
            report.candidates += decrypt_candidates(key, ciphertext, flagset, top_n)
        except RsaError as exc:
            report.notes.append(str(exc))
    elif ciphertext and not key.is_private and not report.candidates:
        report.notes.append(
            "a public key cannot decrypt: add --attack to look for a weakness, or "
            "give the private key with --key"
        )

    report.candidates = _best(report.candidates, top_n)
    _note_if_key_material(report)
    return report


# Lengths that mean "this is not the message, it is key material".
KEY_MATERIAL_SIZES = {
    16: "an AES-128 key, or an IV",
    24: "an AES-192 or 3DES key",
    32: "an AES-256 key, or a ChaCha20 key",
    44: "a 32-byte key plus a 12-byte nonce",
    48: "a 32-byte key plus a 16-byte IV (key||iv)",
}


def _note_if_key_material(report: RsaReport) -> None:
    """RSA often wraps a symmetric key, not the message: say where to go next.

    `nonce||ct||tag` style challenges put the AES key in the RSA blob and the real
    payload in a second file. A decryption that comes out as 48 unreadable bytes
    is not a failure, it is the key.
    """
    for candidate in report.candidates[:2]:
        size = len(candidate.data)
        if size not in KEY_MATERIAL_SIZES or candidate.score > 0.5:
            continue
        printable = sum(32 <= byte < 127 for byte in candidate.data) / size
        if printable > 0.8:
            continue  # readable: it is probably the message after all
        report.notes.append(
            f"the result is {size} unreadable bytes, which is exactly "
            f"{KEY_MATERIAL_SIZES[size]}: RSA was used to wrap a symmetric key, not the "
            "message. Save it and run `ctfc blob <that file> --against <the payload>`"
        )
        return
