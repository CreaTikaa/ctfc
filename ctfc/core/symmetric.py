"""Symmetric ciphers, and the "unknown layout" solver.

The usual CTF situation is not "decrypt AES-256-CBC with this key and this IV".
It is "here is a ciphertext and a 48-byte blob, good luck". The pieces that have
to be guessed are always the same:

- which **cipher**: AES, DES, 3DES, Blowfish, ChaCha20, Salsa20, RC4, TEA, XTEA,
- which **mode**: ECB, CBC, CTR, CFB, OFB, GCM, CBC-CTS,
- how the **key and IV** were cut out of what we have: `key||iv`? `iv||key`? hex?
  base64? IV at the start of the ciphertext? IV all zeros? IV = start of the key?
- whether the key was **derived from a passphrase**: md5, PBKDF2, openssl's
  EVP_BytesToKey...,
- which **padding** was used: PKCS7, zeros, none.

`solve_symmetric()` walks those possibilities in order of likelihood under a
`Budget`, scores every plaintext with `scoring.py`, and returns the best ones with
their reasons. Two signals make this work much better than it sounds:

- **valid PKCS7 padding** after a CBC/ECB decryption: a wrong key produces valid
  padding only about once in 256 tries, so it is strong evidence,
- a **GCM tag (or Fernet HMAC) that verifies**: that is a proof, not a guess.

No key is ever brute-forced byte by byte. We only try the *layouts* of the
material the user already has (plus, on request, a small embedded password list).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from Crypto.Cipher import AES, ARC4, DES, DES3, Blowfish, ChaCha20, Salsa20

from ctfc.core.blockmodes import cbc_cts_decrypt, cbc_decrypt, ecb_decrypt
from ctfc.core.budget import Budget
from ctfc.core.codegen import Step, chain_cyberchef, chain_snippet, key_repr
from ctfc.core.datafiles import load_passwords
from ctfc.core.flags import FlagSet
from ctfc.core.kdf import (
    FAST_OPENSSL_LAYOUTS,
    Derived,
    hash_keys,
    openssl_derive,
    openssl_keys,
    salted_keys,
)
from ctfc.core.scoring import has_valid_pkcs7, score
from ctfc.core.tea import tea_decrypt_block, xtea_decrypt_block
from ctfc.core.types import Candidate

MIN_SCORE = 0.25  # below this, a plaintext is noise
# A flag in readable text, or an authenticated mode that verified: stop searching.
STOP_AT = 0.95
PKCS7_BONUS = 0.15  # added when the padding is valid (scoring.has_valid_pkcs7)
TAG_BONUS = 0.25  # added when a GCM tag / Fernet HMAC verifies: that is a proof
OPENSSL_MAGIC = b"Salted__"
GCM_TAG_SIZE = 16


class CryptoError(ValueError):
    """Raised when a cipher refuses the parameters (bad key size, short data...)."""


# ---------------------------------------------------------------------------
# What each cipher accepts
# ---------------------------------------------------------------------------

# Modes in the order they are tried: CBC and ECB cover most challenges.
BLOCK_MODES = ("cbc", "ecb", "ctr", "gcm", "cfb", "ofb", "cts", "cts3", "cfb8")
# openssl enc only knows these (no GCM, no ciphertext stealing).
OPENSSL_MODES = ("cbc", "ecb", "ctr", "cfb", "ofb")


@dataclass(frozen=True)
class CipherSpec:
    """One cipher: block size, the key sizes it accepts, the modes it can run."""

    name: str
    label: str
    block_size: int  # 1 for stream ciphers: no blocks, no padding
    key_sizes: tuple[int, ...]  # sizes we try, likeliest first
    modes: tuple[str, ...]
    nonce_sizes: tuple[int, ...] = ()  # stream ciphers and GCM
    key_range: tuple[int, int] | None = None  # set when any size in a range is allowed

    def key_ok(self, key: bytes) -> bool:
        """Can this cipher use a key of that size?"""
        if self.key_range is not None:
            return self.key_range[0] <= len(key) <= self.key_range[1]
        return len(key) in self.key_sizes


CIPHERS: dict[str, CipherSpec] = {
    "aes": CipherSpec("aes", "AES", 16, (32, 16, 24), BLOCK_MODES, (12, 16, 8)),
    "3des": CipherSpec("3des", "3DES", 8, (24, 16), OPENSSL_MODES, (8,)),
    "des": CipherSpec("des", "DES", 8, (8,), OPENSSL_MODES, (8,)),
    "blowfish": CipherSpec(
        "blowfish", "Blowfish", 8, (16, 32, 8, 24, 56), OPENSSL_MODES, (8,), key_range=(4, 56)
    ),
    "chacha20": CipherSpec("chacha20", "ChaCha20", 1, (32,), ("stream",), (12, 8)),
    "salsa20": CipherSpec("salsa20", "Salsa20", 1, (32, 16), ("stream",), (8,)),
    "rc4": CipherSpec("rc4", "RC4", 1, (16, 32, 8, 5), ("stream",), key_range=(1, 256)),
    "tea": CipherSpec("tea", "TEA", 8, (16,), ("cbc", "ecb")),
    "xtea": CipherSpec("xtea", "XTEA", 8, (16,), ("cbc", "ecb")),
}

# Order in which ciphers are tried when the user did not name one.
CIPHER_ORDER = ("aes", "3des", "des", "blowfish", "chacha20", "salsa20", "rc4", "tea", "xtea")
# Aliases accepted on the command line.
CIPHER_ALIASES = {"tripledes": "3des", "desede": "3des", "des3": "3des", "arc4": "rc4"}

PYCRYPTO_MODULES = {
    "aes": AES,
    "des": DES,
    "3des": DES3,
    "blowfish": Blowfish,
    "rc4": ARC4,
    "chacha20": ChaCha20,
    "salsa20": Salsa20,
}

MODE_LABELS = {
    "cbc": "CBC",
    "ecb": "ECB",
    "ctr": "CTR",
    "gcm": "GCM",
    "cfb": "CFB",
    "cfb8": "CFB8",
    "ofb": "OFB",
    "cts": "CBC-CTS-CS1",
    "cts3": "CBC-CTS-CS3",
    "stream": "stream",
}

# Cipher name used by the `openssl enc` command line.
OPENSSL_NAMES = {"aes": "aes", "des": "des", "3des": "des-ede3", "blowfish": "bf", "rc4": "rc4"}


def cipher_label(spec: CipherSpec, key: bytes, mode: str) -> str:
    """ "AES-256-CBC", "RC4", "TEA-CBC"..."""
    if spec.name == "aes":
        return f"AES-{len(key) * 8}-{MODE_LABELS[mode]}"
    if mode == "stream":
        return spec.label
    return f"{spec.label}-{MODE_LABELS[mode]}"


def openssl_name(spec: CipherSpec, key: bytes, mode: str) -> str:
    """Cipher name for `openssl enc -d -<name>`, e.g. "aes-256-cbc"."""
    name = OPENSSL_NAMES.get(spec.name, spec.name)
    if spec.name == "aes":
        return f"aes-{len(key) * 8}-{mode}"
    if spec.name == "rc4":
        return "rc4"
    return f"{name}-{mode}"


# ---------------------------------------------------------------------------
# Low-level decryption: one set of parameters in, raw plaintext out
# ---------------------------------------------------------------------------


def _ecb_block_decrypt(spec: CipherSpec, key: bytes):
    """A `block_decrypt(block, key, endian)` callable, for the hand-written modes."""
    module = PYCRYPTO_MODULES[spec.name]
    engine = module.new(key, module.MODE_ECB)
    return lambda block, _key, _endian="big": engine.decrypt(block)


def decrypt_raw(
    spec: CipherSpec,
    mode: str,
    key: bytes,
    iv: bytes | None,
    data: bytes,
    endian: str = "big",
    counter: int = 0,
    ctr_style: str = "block",
    tag: bytes | None = None,
) -> bytes:
    """Decrypt `data` with exactly these parameters. CryptoError if they cannot work."""
    if not data:
        raise CryptoError("no ciphertext")
    block = spec.block_size
    if mode in ("cbc", "ecb") and block > 1 and len(data) % block:
        raise CryptoError(
            f"ciphertext length {len(data)} is not a multiple of {block}: "
            "try CTR / CFB / OFB / GCM, or CTS"
        )
    try:
        if spec.name in ("tea", "xtea"):
            decrypt_block = tea_decrypt_block if spec.name == "tea" else xtea_decrypt_block
            if mode == "cbc":
                return cbc_decrypt(data, key, iv or bytes(8), decrypt_block, 8, endian)
            return ecb_decrypt(data, key, decrypt_block, 8, endian)

        module = PYCRYPTO_MODULES[spec.name]
        if mode in ("cts", "cts3"):
            return cbc_cts_decrypt(
                data,
                key,
                iv or bytes(block),
                _ecb_block_decrypt(spec, key),
                block,
                swapped=(mode == "cts3"),
            )
        if mode == "stream":
            if spec.name == "rc4":
                return module.new(key).decrypt(data)
            engine = module.new(key=key, nonce=iv or bytes(8))
            if counter:
                engine.seek(counter * 64)  # start at another ChaCha20/Salsa20 block
            return engine.decrypt(data)
        if mode == "ecb":
            return module.new(key, module.MODE_ECB).decrypt(data)
        if mode == "cbc":
            return module.new(key, module.MODE_CBC, iv).decrypt(data)
        if mode == "ctr":
            if ctr_style == "nonce8":
                # pycryptodome's default: half nonce, half counter.
                return module.new(key, module.MODE_CTR, nonce=iv).decrypt(data)
            # A full counter block, which is what `openssl enc -aes-256-ctr` uses.
            return module.new(key, module.MODE_CTR, nonce=b"", initial_value=iv).decrypt(data)
        if mode == "cfb":
            return module.new(key, module.MODE_CFB, iv, segment_size=block * 8).decrypt(data)
        if mode == "cfb8":
            return module.new(key, module.MODE_CFB, iv).decrypt(data)
        if mode == "ofb":
            return module.new(key, module.MODE_OFB, iv).decrypt(data)
        if mode == "gcm":
            engine = module.new(key, module.MODE_GCM, nonce=iv)
            if tag is not None:
                # A wrong key raises ValueError here, which is exactly the signal
                # we want: an authenticated mode tells us when we got it right.
                return engine.decrypt_and_verify(data, tag)
            return engine.decrypt(data)
    except (ValueError, TypeError, OverflowError) as exc:
        raise CryptoError(str(exc)) from exc
    raise CryptoError(f"unsupported mode {mode!r} for {spec.name}")


# ---------------------------------------------------------------------------
# Padding and scoring
# ---------------------------------------------------------------------------


def strip_padding(raw: bytes, block_size: int) -> tuple[bytes, str | None]:
    """Remove the padding when we recognise one. Returns (plaintext, padding name)."""
    if block_size > 1 and has_valid_pkcs7(raw, block_size):
        return raw[: -raw[-1]], "pkcs7"
    if raw.endswith(b"\x00"):
        return raw.rstrip(b"\x00"), "zero"
    return raw, None


def score_plaintext(
    raw: bytes, flagset: FlagSet | None, block_size: int, proven: bool = False
) -> tuple[bytes, float, list[str], str | None]:
    """Score one decryption. Returns (plaintext, score, reasons, padding name)."""
    plain, padding = strip_padding(raw, block_size)
    value, reasons = score(plain, flagset)
    if padding == "pkcs7":
        pad = raw[-1]
        value = min(1.0, value + PKCS7_BONUS)
        reasons.insert(
            0,
            f"valid PKCS7 padding ({pad} x 0x{pad:02x}): a wrong key gives valid "
            "padding only about once in 256 tries",
        )
    elif padding == "zero":
        reasons.insert(0, "ended with zero bytes (zero padding?), they were removed")
    if proven:
        value = min(1.0, value + TAG_BONUS)
    return plain, round(value, 4), reasons, padding


# ---------------------------------------------------------------------------
# Key and IV material: every plausible way to read what the user gave us
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Blob:
    """Some bytes given by the user, and how we read them."""

    data: bytes
    reason: str


def _looks_hex(data: bytes) -> bool:
    if len(data) < 2 or len(data) % 2:
        return False
    return re.fullmatch(rb"[0-9a-fA-F]+", data) is not None


def decoded_forms(raw: bytes, what: str) -> list[Blob]:
    """`raw`, plus its hex / base64 decoding when that is plausible.

    Challenges hand out keys as "6b6579..." or "a2V5..." as often as raw bytes.
    """
    forms = [Blob(raw, f"{what} as given ({len(raw)} bytes)")]
    if _looks_hex(raw):
        forms.append(Blob(bytes.fromhex(raw.decode()), f"{what} hex-decoded"))
    text = raw.strip()
    if len(text) >= 8 and len(text) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/=_-]+", text):
        try:
            decoded = base64.b64decode(text.replace(b"-", b"+").replace(b"_", b"/"), validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded:
            forms.append(Blob(decoded, f"{what} base64-decoded"))
    return forms


def key_forms(raw: bytes, key_size: int, what: str = "key") -> list[Blob]:
    """Every way to turn `raw` into a key (or IV) of exactly `key_size` bytes."""
    forms: list[Blob] = []
    seen: set[bytes] = set()

    def add(data: bytes, reason: str) -> None:
        if len(data) == key_size and data not in seen:
            seen.add(data)
            forms.append(Blob(data, reason))

    for form in decoded_forms(raw, what):
        add(form.data, form.reason)
        if len(form.data) > key_size:
            add(form.data[:key_size], f"{form.reason}, cut to {key_size} bytes")
        elif len(form.data) < key_size:
            add(
                form.data + bytes(key_size - len(form.data)),
                f"{form.reason}, zero-padded to {key_size} bytes",
            )
    # A "key" that fits no size is often really a passphrase.
    for name in ("md5", "sha256", "sha1"):
        digest = hashlib.new(name, raw).digest()
        if len(digest) >= key_size:
            add(digest[:key_size], f"{what} treated as a passphrase: {name}(...)[:{key_size}]")
    return forms


def blob_splits(raw: bytes, key_size: int, iv_size: int) -> list[tuple[Blob, Blob | None]]:
    """The usual ways a blob holds a key and an IV, likeliest first."""
    splits: list[tuple[Blob, Blob | None]] = []
    length = len(raw)
    if length == key_size:
        splits.append((Blob(raw, f"key = the whole blob ({length} bytes)"), None))
    if iv_size and length == key_size + iv_size:
        splits.append(
            (
                Blob(raw[:key_size], f"key = blob[:{key_size}]"),
                Blob(raw[key_size:], f"iv = blob[{key_size}:]"),
            )
        )
        splits.append(
            (
                Blob(raw[iv_size:], f"key = blob[{iv_size}:] (iv||key layout)"),
                Blob(raw[:iv_size], f"iv = blob[:{iv_size}]"),
            )
        )
    if length > key_size:
        splits.append((Blob(raw[:key_size], f"key = blob[:{key_size}]"), None))
        splits.append((Blob(raw[-key_size:], f"key = blob[-{key_size}:]"), None))
    return splits


@dataclass(frozen=True)
class Material:
    """A key, maybe an IV that came with it, and where they came from."""

    key: bytes
    key_reason: str
    iv: bytes | None = None
    iv_reason: str = ""
    extra_reasons: tuple[str, ...] = ()
    kdf: Derived | None = None
    salt: bytes = b""
    password: str = ""

    def reasons(self) -> list[str]:
        out = [*self.extra_reasons, self.key_reason]
        if self.iv is not None and self.iv_reason:
            out.append(self.iv_reason)
        return out


def materials(
    spec: CipherSpec,
    key: bytes | None,
    iv: bytes | None,
    blob: bytes | None,
    passphrase: bytes | None,
    password_list: tuple[bytes, ...],
    salt: bytes | None,
) -> Iterator[Material]:
    """Every (key, maybe IV) worth trying for this cipher, likeliest first."""
    for key_size in spec.key_sizes:
        iv_size = spec.block_size if spec.block_size > 1 else (spec.nonce_sizes or (8,))[0]

        if key is not None:
            for form in key_forms(key, key_size):
                yield Material(form.data, form.reason)
        if blob is not None:
            for form in decoded_forms(blob, "blob"):
                for key_part, iv_part in blob_splits(form.data, key_size, iv_size):
                    yield Material(
                        key=key_part.data,
                        key_reason=key_part.reason,
                        iv=iv_part.data if iv_part else None,
                        iv_reason=iv_part.reason if iv_part else "",
                        extra_reasons=(form.reason,),
                    )
        if passphrase is not None:
            for derived in _derivations(passphrase, key_size, iv_size, salt):
                yield _passphrase_material(passphrase, derived, salt)
        # The embedded list is tried KDF-major: the cheap derivations first, over
        # the whole list, instead of spending the budget on one slow KDF.
        if password_list:
            for digest, iterations in FAST_OPENSSL_LAYOUTS:
                for candidate in password_list:
                    derived = openssl_derive(
                        candidate, salt or b"", key_size, iv_size, digest, iterations
                    )
                    yield _passphrase_material(candidate, derived, salt)


def _passphrase_material(passphrase: bytes, derived: Derived, salt: bytes | None) -> Material:
    text = passphrase.decode("utf-8", errors="replace")
    return Material(
        key=derived.key,
        key_reason=f'passphrase "{text}" -> {derived.method}',
        iv=derived.iv,
        iv_reason=f"iv derived from the passphrase too ({derived.method})",
        kdf=derived,
        salt=salt or b"",
        password=text,
    )


def _derivations(
    passphrase: bytes, key_size: int, iv_size: int, salt: bytes | None
) -> list[Derived]:
    """KDFs tried for one passphrase: openssl's layouts when we have a salt."""
    if salt is not None:
        return openssl_keys(passphrase, salt, key_size, iv_size)
    return hash_keys(passphrase, key_size) + salted_keys(passphrase, b"", key_size)


# ---------------------------------------------------------------------------
# One attempt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attempt:
    """One complete set of parameters to try, and why we are trying it."""

    spec: CipherSpec
    mode: str
    material: Material
    ct: bytes  # the bytes actually fed to the cipher
    iv: bytes | None = None
    iv_reason: str = ""
    skip: int = 0  # bytes dropped from the front of the input
    iv_from_prefix: bool = False
    tag: bytes | None = None
    endian: str = "big"
    counter: int = 0
    ctr_style: str = "block"

    def identity(self) -> tuple:
        """Used to skip attempts that were already made."""
        return (
            self.spec.name,
            self.mode,
            self.material.key,
            self.iv,
            self.ct,
            self.tag,
            self.endian,
            self.counter,
            self.ctr_style,
        )


def iv_choices(
    spec: CipherSpec, mode: str, material: Material, data: bytes, explicit_iv: bytes | None
) -> list[tuple[bytes | None, str, int, bool]]:
    """(iv, reason, bytes to skip, iv came from the ciphertext) for this mode."""
    if mode == "ecb" or (mode == "stream" and spec.name == "rc4"):
        return [(None, "", 0, False)]
    # When a KDF produced the IV (openssl enc), there is nothing to guess.
    if material.kdf is not None and material.iv is not None:
        return [(material.iv, material.iv_reason, 0, False)]

    if mode in ("gcm", "stream"):
        sizes = spec.nonce_sizes or (8,)
    elif mode == "ctr":
        sizes = (spec.block_size, spec.block_size // 2)
    else:
        sizes = (spec.block_size,)

    out: list[tuple[bytes | None, str, int, bool]] = []
    for size in sizes:
        if material.iv is not None and len(material.iv) == size:
            out.append((material.iv, material.iv_reason, 0, False))
        if explicit_iv is not None:
            for form in key_forms(explicit_iv, size, "iv"):
                out.append((form.data, form.reason, 0, False))
        if len(data) > size:
            out.append((data[:size], f"iv = the first {size} bytes of the ciphertext", size, True))
        out.append((bytes(size), f"iv = {size} zero bytes", 0, False))
        if len(material.key) >= size:
            out.append((material.key[:size], f"iv = the first {size} bytes of the key", 0, False))
    return out


def attempts_for(
    spec: CipherSpec, mode: str, material: Material, data: bytes, explicit_iv: bytes | None
) -> Iterator[Attempt]:
    """Build every attempt for one (cipher, mode, key material) triple."""
    endians = ("big", "little") if spec.name in ("tea", "xtea") else ("big",)
    counters = (0, 1) if spec.name in ("chacha20", "salsa20") else (0,)
    ctr_styles = ("block", "nonce8") if mode == "ctr" else ("block",)

    for iv, iv_reason, skip, from_prefix in iv_choices(spec, mode, material, data, explicit_iv):
        ct = data[skip:]
        if not ct:
            continue
        for ctr_style in ctr_styles:
            if mode == "ctr" and iv is not None:
                wanted = spec.block_size // 2 if ctr_style == "nonce8" else spec.block_size
                if len(iv) != wanted:
                    continue
            for endian in endians:
                for counter in counters:
                    common = {
                        "spec": spec,
                        "mode": mode,
                        "material": material,
                        "iv": iv,
                        "iv_reason": iv_reason,
                        "skip": skip,
                        "iv_from_prefix": from_prefix,
                        "endian": endian,
                        "counter": counter,
                        "ctr_style": ctr_style,
                    }
                    if mode == "gcm" and len(ct) > GCM_TAG_SIZE:
                        # The tag is usually glued to the end: nonce || ct || tag.
                        yield Attempt(ct=ct[:-GCM_TAG_SIZE], tag=ct[-GCM_TAG_SIZE:], **common)
                    yield Attempt(ct=ct, **common)


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


def step_params(attempt: Attempt, padding: str | None, container: OpensslEnc | None = None) -> dict:
    """Parameters of the "cipher" codegen step (see codegen.cipher_step_code)."""
    material = attempt.material
    params: dict = {
        "cipher": attempt.spec.name,
        "mode": attempt.mode,
        "key": material.key.hex(),
        "label": cipher_label(attempt.spec, material.key, attempt.mode),
    }
    if attempt.iv is not None:
        params["iv"] = attempt.iv.hex()
        params["iv_size"] = len(attempt.iv)
    if attempt.iv_from_prefix:
        params["iv_from"] = "prefix"
    if container is not None:
        # The generated script starts from the whole file, so it must drop the
        # 16-byte openssl header before anything else.
        params["header_skip"] = 16
        params["header_why"] = 'drop the "Salted__" magic and the 8-byte salt'
    if attempt.tag is not None:
        params["tag"] = attempt.tag.hex()
    if padding:
        params["unpad"] = padding
    if attempt.spec.name in ("tea", "xtea"):
        params["endian"] = attempt.endian
    if attempt.counter:
        params["counter"] = attempt.counter
    if attempt.mode == "ctr":
        params["ctr_style"] = attempt.ctr_style
    if material.kdf is not None:
        params["kdf"] = {
            "method": material.kdf.method,
            "python": material.kdf.python,
            "password": material.password,
            "salt": material.salt.hex(),
            "gives_iv": material.kdf.iv is not None,
        }
    return params


def make_candidate(
    attempt: Attempt,
    raw: bytes,
    flagset: FlagSet | None,
    input_data: bytes,
    extra_reasons: tuple[str, ...] = (),
    container: OpensslEnc | None = None,
    pre_steps: tuple[Step, ...] = (),
) -> Candidate:
    """Score one decryption and wrap it with its reasons, parameters and code."""
    spec = attempt.spec
    proven = attempt.mode == "gcm" and attempt.tag is not None
    plain, value, reasons, padding = score_plaintext(raw, flagset, spec.block_size, proven)
    if proven:
        reasons.insert(0, "the GCM authentication tag verifies: key and nonce are correct")

    params = step_params(attempt, padding, container)
    # The generated script starts from the file as the user has it, so a base64
    # `openssl enc -a` file needs a base64 step before the cipher step.
    steps = [Step("base64")] if container is not None and container.was_base64 else []
    steps += pre_steps  # the ciphertext was given as base64 / hex text
    steps.append(Step("cipher", params))
    material = attempt.material

    bits = [params["label"], material.key_reason]
    if attempt.iv is not None and attempt.iv_reason:
        bits.append(attempt.iv_reason)
    display = {
        "cipher": spec.name,
        "mode": attempt.mode,
        "key_hex": material.key.hex(),
        "key_length": len(material.key),
    }
    if attempt.iv is not None:
        display["iv_hex"] = attempt.iv.hex()
    if material.kdf is not None:
        display["kdf"] = material.kdf.method
        display["password"] = material.password
    if padding:
        display["padding"] = padding
    if attempt.spec.name in ("tea", "xtea"):
        display["endian"] = attempt.endian

    return Candidate(
        label=", ".join(bits),
        data=plain,
        score=value,
        reasons=[f"key {key_repr(material.key)} ({len(material.key)} bytes)"]
        + material.reasons()
        + ([attempt.iv_reason] if attempt.iv_reason and not material.iv_reason else [])
        + list(extra_reasons)
        + reasons,
        params=display,
        python=chain_snippet(input_data, steps),
        cyberchef=chain_cyberchef(steps),
    )


def _best_unique(candidates: list[Candidate], top_n: int) -> list[Candidate]:
    """Sort by score, drop duplicate outputs, keep the best `top_n`."""
    seen: set[bytes] = set()
    result: list[Candidate] = []
    for candidate in sorted(candidates, key=lambda item: -item.score):
        if candidate.data in seen:
            continue
        seen.add(candidate.data)
        result.append(candidate)
    return result[:top_n]


# ---------------------------------------------------------------------------
# Containers: `openssl enc` files and Fernet tokens
# ---------------------------------------------------------------------------


@dataclass
class OpensslEnc:
    """An `openssl enc` file: the magic "Salted__", an 8-byte salt, then the ciphertext."""

    salt: bytes
    ciphertext: bytes
    was_base64: bool


def decode_text_ciphertext(data: bytes) -> tuple[Step, bytes] | None:
    """A ciphertext written as base64 or hex text (mails, logs, C2 traffic).

    Encrypted bytes never consist only of base64 or hex characters, so text like
    that is an encoding of the ciphertext: decode it first. Hex is checked first
    (hex digits are valid base64 too).
    """
    text = b"".join(data.split())
    if len(text) < 16:
        return None
    if re.fullmatch(rb"[0-9A-Fa-f]+", text) and len(text) % 2 == 0:
        return Step("hex"), bytes.fromhex(text.decode())
    if re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
        try:
            return Step("base64"), base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return None
    return None


def parse_openssl_enc(data: bytes) -> OpensslEnc | None:
    """Recognise an `openssl enc` file, raw or base64 ("U2FsdGVkX1...")."""
    if data[:8] == OPENSSL_MAGIC and len(data) > 16:
        return OpensslEnc(data[8:16], data[16:], False)
    pieces = data.split()
    text = pieces[0] if pieces else b""
    if text[:10] == b"U2FsdGVkX1":
        try:
            decoded = base64.b64decode(text + b"=" * (-len(text) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
        if decoded[:8] == OPENSSL_MAGIC and len(decoded) > 16:
            return OpensslEnc(decoded[8:16], decoded[16:], True)
    return None


def openssl_command(attempt: Attempt, container: OpensslEnc) -> str:
    """The `openssl enc -d ...` command that reproduces this candidate."""
    flags = attempt.material.kdf.openssl_flags if attempt.material.kdf else "-md md5"
    name = openssl_name(attempt.spec, attempt.material.key, attempt.mode)
    base64_flag = " -a" if container.was_base64 else ""
    password = attempt.material.password or "<password>"
    return f"openssl enc -d -{name} {flags}{base64_flag} -in <file> -pass pass:{password}"


def fernet_candidates(token: bytes, keys: list[bytes], flagset: FlagSet | None) -> list[Candidate]:
    """Fernet = base64url(version | timestamp | IV | AES-128-CBC | HMAC-SHA256).

    A 32-byte Fernet key is really two keys: the first half signs, the second half
    encrypts. The HMAC tells us for certain whether the key is the right one.
    """
    text = token.strip()
    if not text.startswith(b"gAAAA"):
        return []
    try:
        raw = base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return []
    if len(raw) < 57 or raw[0] != 0x80:
        return []

    candidates = []
    for given in keys:
        for form in decoded_forms(given, "fernet key"):
            if len(form.data) != 32:
                continue
            signing_key, encryption_key = form.data[:16], form.data[16:]
            mac = hmac.new(signing_key, raw[:-32], hashlib.sha256).digest()
            verified = hmac.compare_digest(mac, raw[-32:])
            try:
                decrypted = AES.new(encryption_key, AES.MODE_CBC, raw[9:25]).decrypt(raw[25:-32])
            except ValueError:
                continue
            plain, value, reasons, _ = score_plaintext(decrypted, flagset, 16, proven=verified)
            if verified:
                reasons.insert(0, "the Fernet HMAC-SHA256 verifies: this key is the right one")
            else:
                reasons.insert(0, "the Fernet HMAC does NOT verify: wrong key (or edited token)")
            timestamp = int.from_bytes(raw[1:9], "big")
            candidates.append(
                Candidate(
                    label=f"Fernet token, {form.reason}",
                    data=plain,
                    score=value,
                    reasons=[
                        "Fernet: AES-128-CBC + HMAC-SHA256, key = signing[:16] || encryption[16:]",
                        f"token timestamp: {timestamp} (unix seconds)",
                        *reasons,
                    ],
                    params={
                        "cipher": "fernet",
                        "key_hex": form.data.hex(),
                        "iv_hex": raw[9:25].hex(),
                        "verified": verified,
                    },
                    python=_fernet_snippet(text, form.data),
                )
            )
    return candidates


def _fernet_snippet(token: bytes, key: bytes) -> str:
    """Standalone script for a Fernet token, without the `cryptography` package."""
    return (
        '"""Decrypt a Fernet token (generated by ctfc)."""\n'
        "import base64\n"
        "import hashlib\n"
        "import hmac\n"
        "from Crypto.Cipher import AES\n\n"
        f"token = {token.decode('ascii', errors='replace')!r}\n"
        f'key = bytes.fromhex("{key.hex()}")  # 32 bytes: signing || encryption\n'
        'raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))\n'
        "# layout: version(1) timestamp(8) iv(16) ciphertext(...) hmac(32)\n"
        "mac = hmac.new(key[:16], raw[:-32], hashlib.sha256).digest()\n"
        'print("hmac ok:", hmac.compare_digest(mac, raw[-32:]))\n'
        "data = AES.new(key[16:], AES.MODE_CBC, raw[9:25]).decrypt(raw[25:-32])\n"
        "data = data[: -data[-1]]  # remove the PKCS7 padding\n"
        'print(data.decode("utf-8", errors="replace"))\n'
    )


# ---------------------------------------------------------------------------
# The solver
# ---------------------------------------------------------------------------


@dataclass
class SolveReport:
    """What the solver found, plus what it did (for the user to read)."""

    candidates: list[Candidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    budget_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "notes": list(self.notes),
            "budget": self.budget_summary,
        }


def ciphers_to_try(cipher: str | None, data_length: int) -> list[CipherSpec]:
    """The ciphers worth trying, in order. A name given by the user wins."""
    if cipher:
        wanted = cipher.lower().replace("-", "").replace("_", "")
        wanted = CIPHER_ALIASES.get(wanted, wanted)
        if wanted not in CIPHERS:
            raise CryptoError(f"unknown cipher {cipher!r}; known: {', '.join(sorted(CIPHERS))}")
        return [CIPHERS[wanted]]
    order = CIPHER_ORDER
    if data_length < 8:
        # Too short for any block cipher: only stream ciphers can apply.
        order = tuple(name for name in order if CIPHERS[name].block_size == 1)
    return [CIPHERS[name] for name in order]


def modes_to_try(
    spec: CipherSpec, mode: str | None, data_length: int, allowed: tuple[str, ...] | None = None
) -> list[str]:
    """The modes worth trying for this cipher and this ciphertext length."""
    if mode:
        wanted = mode.lower().replace("-", "").replace("_", "")
        wanted = {"cts1": "cts", "ctscs1": "cts", "ctscs3": "cts3"}.get(wanted, wanted)
        if wanted not in spec.modes:
            raise CryptoError(f"{spec.label} has no mode {mode!r}; known: {', '.join(spec.modes)}")
        return [wanted]
    modes = [name for name in spec.modes if allowed is None or name in allowed]
    if spec.block_size > 1:
        aligned = data_length % spec.block_size == 0
        # CBC and ECB need whole blocks; ciphertext stealing exists for the rest.
        modes = [name for name in modes if aligned or name not in ("cbc", "ecb")]
        if aligned:
            modes = [name for name in modes if name not in ("cts", "cts3")]
    return modes


def solve_symmetric(
    data: bytes,
    flagset: FlagSet | None = None,
    cipher: str | None = None,
    mode: str | None = None,
    key: bytes | None = None,
    iv: bytes | None = None,
    blob: bytes | None = None,
    passphrase: bytes | None = None,
    try_passwords: bool = False,
    budget: Budget | None = None,
    top_n: int = 10,
) -> SolveReport:
    """Try the plausible cipher / mode / key-layout combinations on `data`.

    Pass whatever you have: a key, an IV, a blob holding both, a passphrase.
    Everything left out is guessed, in the order given in the module docstring.
    """
    budget = budget or Budget(max_attempts=1_000_000, max_seconds=30)
    report = SolveReport()
    candidates: list[Candidate] = []

    # Fernet tokens and `openssl enc` files are recognised shapes: look first.
    # Fernet results are "pinned": their verdict is shown whatever it says.
    recognised = fernet_candidates(data, [b for b in (key, blob) if b is not None], flagset)

    container = parse_openssl_enc(data)
    work_data = data
    salt: bytes | None = None
    allowed_modes: tuple[str, ...] | None = None
    if container is not None:
        work_data = container.ciphertext
        salt = container.salt
        allowed_modes = OPENSSL_MODES
        report.notes.append(
            f'"Salted__" header found: salt {container.salt.hex()}, '
            f"{len(container.ciphertext)} bytes of ciphertext"
            + (" (the file was base64)" if container.was_base64 else "")
        )
        if passphrase is None and not try_passwords:
            report.notes.append(
                "this file needs the password: add --pass <password>, or --passwords "
                "to try the embedded list"
            )

    pre_steps: tuple[Step, ...] = ()
    if container is None and not recognised:
        text_form = decode_text_ciphertext(data)
        if text_form is not None:
            step, work_data = text_form
            pre_steps = (step,)
            report.notes.append(
                f"the ciphertext is {step.name} text: decoded first "
                f"({len(data)} characters -> {len(work_data)} bytes)"
            )

    password_list: tuple[bytes, ...] = ()
    if try_passwords:
        password_list = load_passwords()
        report.notes.append(
            f"trying the embedded password list ({len(password_list)} entries) with the "
            "openssl KDFs, cheapest first"
        )

    if key is None and blob is None and passphrase is None and not password_list:
        report.notes.append(
            "no key material given: pass --key, --blob or --pass (ctfc blob <blob> "
            "--against <ciphertext> tests the usual key||iv splits)"
        )
        report.candidates = _finish(candidates, top_n, report, recognised)
        return report

    seen: set[tuple] = set()
    stopped = False
    for spec in ciphers_to_try(cipher, len(work_data)):
        if stopped:
            break
        for material in materials(spec, key, iv, blob, passphrase, password_list, salt):
            if stopped:
                break
            if not spec.key_ok(material.key):
                continue
            for mode_name in modes_to_try(spec, mode, len(work_data), allowed_modes):
                if stopped:
                    break
                for attempt in attempts_for(spec, mode_name, material, work_data, iv):
                    identity = attempt.identity()
                    if identity in seen:
                        continue
                    seen.add(identity)
                    if not budget.spend():
                        stopped = True
                        break
                    try:
                        raw = decrypt_raw(
                            spec,
                            mode_name,
                            material.key,
                            attempt.iv,
                            attempt.ct,
                            attempt.endian,
                            attempt.counter,
                            attempt.ctr_style,
                            attempt.tag,
                        )
                    except CryptoError:
                        continue
                    extra: tuple[str, ...] = ()
                    if container is not None:
                        extra = (
                            "the ciphertext is what follows the 16-byte openssl header",
                            "same thing with openssl: " + openssl_command(attempt, container),
                        )
                    candidate = make_candidate(
                        attempt, raw, flagset, data, extra, container, pre_steps
                    )
                    candidates.append(candidate)
                    if candidate.score >= STOP_AT:
                        # Certain enough (a flag, or a tag that verified): no point
                        # in burning the rest of the budget.
                        report.notes.append(
                            f"stopped as soon as a convincing result appeared "
                            f"(score {candidate.score:.2f}) after {budget.attempts} attempts"
                        )
                        stopped = True
                        break

    report.candidates = _finish(candidates, top_n, report, recognised)
    report.budget_summary = budget.summary()
    if budget.stopped_reason:
        report.notes.append("the search stopped early: " + budget.summary())
    return report


def _finish(
    candidates: list[Candidate],
    top_n: int,
    report: SolveReport,
    pinned: list[Candidate] | None = None,
) -> list[Candidate]:
    """Keep what looks meaningful, and always keep `pinned`.

    `pinned` holds candidates that come from a *recognised structure* (a Fernet
    token). Those must be shown even when the plaintext is garbage, because
    "this key does not verify" is itself the answer the user needs.
    """
    pinned = pinned or []
    good = [candidate for candidate in candidates if candidate.score >= MIN_SCORE]
    if not good and not pinned:
        if candidates:
            report.notes.append(
                "nothing scored well: the results below are only the least-bad ones "
                "(wrong cipher? wrong key? another layer on top?)"
            )
        return _best_unique(candidates, min(top_n, 3))
    ranked = _best_unique(good + pinned, top_n)
    for candidate in pinned:  # a low-scoring verdict must not be cut off the list
        if candidate not in ranked:
            ranked.append(candidate)
    return sorted(ranked, key=lambda candidate: -candidate.score)


def solve_blob(
    blob: bytes,
    ciphertext: bytes,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    top_n: int = 10,
) -> SolveReport:
    """`ctfc blob`: an unknown key/iv blob, tested against a ciphertext."""
    return solve_symmetric(ciphertext, flagset=flagset, blob=blob, budget=budget, top_n=top_n)
