"""Key derivation functions (KDF): turn a passphrase into a key (and sometimes an IV).

A cipher needs a key of an exact size (16/24/32 bytes for AES). When a challenge
gives a *password* instead, the program that encrypted the data derived the key
from it. The usual ways, from the most naive to the most robust:

- a plain hash:      key = md5(password), sha256(password), sha1(password)[:16]...
- EVP_BytesToKey:    what `openssl enc` did before OpenSSL 1.1 / without -pbkdf2
                     (MD5 or SHA-256, one pass, key AND iv derived together)
- PBKDF2:            HMAC repeated many times over a salt (`openssl enc -pbkdf2`)
- scrypt:            PBKDF2 plus a lot of memory, to slow down GPU cracking

A derivation is described by a `Derived`: the bytes it produced, how it was done
(in words), the Python line that redoes it, and the matching `openssl enc` flags.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from Crypto.Protocol.KDF import scrypt as _scrypt

# (digest, iterations) pairs that `openssl enc` may have used, likeliest first.
# iterations = 0 means the legacy EVP_BytesToKey KDF (no -pbkdf2 flag).
OPENSSL_LAYOUTS: tuple[tuple[str, int], ...] = (
    ("md5", 0),  # openssl < 1.1 default, still what most CTF files use
    ("sha256", 0),  # openssl >= 1.1 default without -pbkdf2
    ("sha256", 10000),  # -pbkdf2 default iteration count
    ("sha1", 10000),
    ("sha256", 1000),
    ("sha256", 10),  # `-iter 10`: seen in Dockerfiles and droppers, PBKDF2 is slow
    ("sha256", 100),
    ("sha256", 1),
    ("sha256", 2048),
    ("sha256", 100000),
    ("md5", 10000),
)

# The three cheapest layouts: safe to run over a whole password list.
FAST_OPENSSL_LAYOUTS = OPENSSL_LAYOUTS[:3]

# Iteration counts tried for a PBKDF2 that is not an openssl file.
PBKDF2_ITERATIONS = (10000, 1000, 100, 10, 1, 2048, 4096, 100000)


@dataclass(frozen=True)
class Derived:
    """A key (and optional IV) derived from a passphrase, with how it was done."""

    key: bytes
    iv: bytes | None
    method: str  # "openssl -pbkdf2 -md sha256 -iter 10000"
    python: str  # line(s) defining `key` (and `iv`) from `password` and `salt`
    openssl_flags: str = ""  # flags for the equivalent `openssl enc -d` command


def evp_bytes_to_key(
    password: bytes, salt: bytes, key_len: int, iv_len: int, digest: str = "md5"
) -> tuple[bytes, bytes]:
    """openssl's legacy KDF: D_1 = H(password || salt), D_i = H(D_{i-1} || password || salt).

    The blocks D_1, D_2, ... are concatenated, then cut into the key and then the IV.
    """
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.new(digest, block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]


def pbkdf2(password: bytes, salt: bytes, iterations: int, length: int, digest: str) -> bytes:
    """PBKDF2-HMAC: HMAC(password, ...) chained `iterations` times (stdlib)."""
    return hashlib.pbkdf2_hmac(digest, password, salt, iterations, length)


def scrypt(
    password: bytes, salt: bytes, length: int, n: int = 2**14, r: int = 8, p: int = 1
) -> bytes:
    """scrypt: a memory-hard KDF. N/r/p below are the most common parameters."""
    result = _scrypt(password, salt, length, N=n, r=r, p=p)
    return result if isinstance(result, bytes) else result[0]


def openssl_derive(
    password: bytes, salt: bytes, key_len: int, iv_len: int, digest: str, iterations: int
) -> Derived:
    """One `openssl enc` key+IV derivation (legacy EVP when iterations == 0)."""
    if iterations == 0:
        key, iv = evp_bytes_to_key(password, salt, key_len, iv_len, digest)
        return Derived(
            key=key,
            iv=iv or None,
            method=f"openssl EVP_BytesToKey (-md {digest}, no -pbkdf2)",
            python=f'key, iv = evp_bytes_to_key(password, salt, {key_len}, {iv_len}, "{digest}")',
            openssl_flags=f"-md {digest}",
        )
    raw = pbkdf2(password, salt, iterations, key_len + iv_len, digest)
    return Derived(
        key=raw[:key_len],
        iv=raw[key_len:] or None,
        method=f"openssl -pbkdf2 -md {digest} -iter {iterations}",
        python=(
            f'raw = hashlib.pbkdf2_hmac("{digest}", password, salt, {iterations}, '
            f"{key_len + iv_len})\nkey, iv = raw[:{key_len}], raw[{key_len}:]"
        ),
        openssl_flags=f"-pbkdf2 -md {digest} -iter {iterations}",
    )


def openssl_keys(password: bytes, salt: bytes, key_len: int, iv_len: int) -> list[Derived]:
    """Every openssl layout, likeliest first (used when the user gave one password)."""
    return [
        openssl_derive(password, salt, key_len, iv_len, digest, iterations)
        for digest, iterations in OPENSSL_LAYOUTS
    ]


def hash_keys(password: bytes, key_len: int) -> list[Derived]:
    """Naive KDFs: one hash of the password, used whole or cut to the key size."""
    results = []
    for name in ("md5", "sha256", "sha1", "sha512"):
        digest = hashlib.new(name, password).digest()
        if len(digest) < key_len:
            continue
        cut = "" if len(digest) == key_len else f"[:{key_len}]"
        results.append(
            Derived(
                key=digest[:key_len],
                iv=None,
                method=f"key = {name}(password){cut}",
                python=f"key = hashlib.{name}(password).digest(){cut}",
            )
        )
    # Hex digests are used as keys surprisingly often (32 hex chars "look like" a key).
    for name in ("md5", "sha256"):
        hexdigest = hashlib.new(name, password).hexdigest().encode()
        if len(hexdigest) >= key_len:
            results.append(
                Derived(
                    key=hexdigest[:key_len],
                    iv=None,
                    method=f"key = the {name} HEX digest of the password, cut to {key_len}",
                    python=f"key = hashlib.{name}(password).hexdigest().encode()[:{key_len}]",
                )
            )
    return results


def salted_keys(password: bytes, salt: bytes, key_len: int) -> list[Derived]:
    """PBKDF2 and scrypt with a salt that is not an openssl header (key only)."""
    results = []
    for digest in ("sha256", "sha1"):
        for iterations in PBKDF2_ITERATIONS:
            results.append(
                Derived(
                    key=pbkdf2(password, salt, iterations, key_len, digest),
                    iv=None,
                    method=f"PBKDF2-HMAC-{digest.upper()}, {iterations} iterations, "
                    f"salt {salt.hex() or 'empty'}",
                    python=(
                        f'key = hashlib.pbkdf2_hmac("{digest}", password, salt, {iterations}, '
                        f"{key_len})"
                    ),
                )
            )
    results.append(
        Derived(
            key=scrypt(password, salt, key_len),
            iv=None,
            method=f"scrypt N=16384 r=8 p=1, salt {salt.hex() or 'empty'}",
            python=(
                "from Crypto.Protocol.KDF import scrypt\n"
                f"key = scrypt(password, salt, {key_len}, N=16384, r=8, p=1)"
            ),
        )
    )
    return results


# Helper copied into generated scripts that use EVP_BytesToKey.
EVP_HELPER = '''
def evp_bytes_to_key(password, salt, key_len, iv_len, digest="md5"):
    """openssl's legacy KDF: D_i = H(D_{i-1} || password || salt), cut into key || iv."""
    derived, block = b"", b""
    while len(derived) < key_len + iv_len:
        block = hashlib.new(digest, block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]
'''
