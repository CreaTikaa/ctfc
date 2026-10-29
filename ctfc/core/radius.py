"""Recover a RADIUS PAP password from a capture.

In a RADIUS Access-Request the user's password is not sent in clear: it is hidden
with the construction of RFC 2865 section 5.2. It is NOT a real cipher - it is the
password XORed with a stream of MD5 digests - so once the shared secret is known
(or guessed) the password falls out, no key schedule, no brute force of the
password itself.

The hiding, for a 16*n byte password padded with NUL bytes, with the 16-byte
Request Authenticator from the packet header and the client/server shared secret:

    b1 = MD5(secret + authenticator)          p1 = c1 = password[0:16]  XOR b1
    b2 = MD5(secret + c1)                      p2 = c2 = password[16:32] XOR b2
    ...                                        ci are the previous *ciphertext* block

so decryption is the same walk the other way. The only unknown is usually the
shared secret, and in practice it is a weak, well-known word ("testing123" is the
FreeRADIUS default), so ctfc tries a short list of classics and then its embedded
password list and keeps whatever decrypts to a readable password - the user only
has to paste the capture in.

Pure functions on bytes. Nothing here touches the network or runs anything.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from ctfc.core.datafiles import load_passwords

# RADIUS packet codes we care about (RFC 2865).
ACCESS_REQUEST = 1
# Attribute types.
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
# UDP ports RADIUS authentication runs on (1812 standard, 1645 the old default).
AUTH_PORTS = (1812, 1645)
# Shared secrets worth trying before the big list: vendor defaults and classics.
COMMON_SECRETS = (
    b"testing123",
    b"secret",
    b"radius",
    b"password",
    b"cisco",
    b"changeme",
    b"test",
    b"admin",
)
MAX_SECRETS = 20_000  # keep the brute force fast


def decrypt_password(encrypted: bytes, authenticator: bytes, secret: bytes) -> bytes:
    """Undo RFC 2865 section 5.2 given the shared secret. Trailing NULs are stripped.

    `encrypted` is the User-Password attribute value (a multiple of 16 bytes),
    `authenticator` the 16-byte Request Authenticator from the packet header.
    """
    if len(authenticator) != 16 or not encrypted or len(encrypted) % 16 != 0:
        return b""
    out = bytearray()
    previous = authenticator  # the first block mixes in the authenticator...
    for start in range(0, len(encrypted), 16):
        block = encrypted[start : start + 16]
        stream = hashlib.md5(secret + previous).digest()  # noqa: S324 - RADIUS mandates MD5
        out += bytes(c ^ s for c, s in zip(block, stream, strict=True))
        previous = block  # ...every later block mixes in the previous ciphertext
    return bytes(out).rstrip(b"\x00")


@dataclass
class AccessRequest:
    """The parts of an Access-Request a PAP recovery needs."""

    identifier: int
    authenticator: bytes
    user_name: bytes
    user_password: bytes  # the still-encrypted User-Password attribute


def parse_access_request(payload: bytes) -> AccessRequest | None:
    """Read a RADIUS Access-Request out of a UDP payload, or None if it is not one.

    Layout: code(1) identifier(1) length(2) authenticator(16), then attributes,
    each type(1) length(1) value(length-2).
    """
    if len(payload) < 20 or payload[0] != ACCESS_REQUEST:
        return None
    length = int.from_bytes(payload[2:4], "big")
    if length < 20 or length > len(payload):
        return None
    authenticator = payload[4:20]
    user_name = b""
    user_password = b""
    offset = 20
    while offset + 2 <= length:
        attr_type = payload[offset]
        attr_length = payload[offset + 1]
        if attr_length < 2 or offset + attr_length > length:
            return None  # a malformed attribute: not a RADIUS packet we can trust
        value = payload[offset + 2 : offset + attr_length]
        if attr_type == ATTR_USER_NAME:
            user_name = value
        elif attr_type == ATTR_USER_PASSWORD:
            user_password = value
        offset += attr_length
    if not user_password:
        return None
    return AccessRequest(payload[1], authenticator, user_name, user_password)


@dataclass
class Recovered:
    """A shared secret that decrypted the password, and the password it gave."""

    secret: bytes
    password: bytes
    score: float
    is_flag: bool


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data)


def recover(
    encrypted: bytes,
    authenticator: bytes,
    secrets: Iterable[bytes] | None = None,
    flagset=None,
) -> list[Recovered]:
    """Try shared secrets against the hidden password; keep the readable results.

    Without `secrets`, a short list of well-known secrets is tried first, then the
    embedded password list. A password that matches a flag regex wins outright; a
    fully printable one is reported too, most readable first.
    """
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    candidates = list(secrets) if secrets is not None else [*COMMON_SECRETS, *load_passwords()]
    seen: set[bytes] = set()
    results: list[Recovered] = []
    for secret in candidates[:MAX_SECRETS]:
        if secret in seen:
            continue
        seen.add(secret)
        password = decrypt_password(encrypted, authenticator, secret)
        if not password:
            continue
        ratio = _printable_ratio(password)
        is_flag = bool(find_flags(password, flagset))
        if is_flag or ratio == 1.0:
            results.append(Recovered(secret, password, ratio + (1.0 if is_flag else 0.0), is_flag))
    results.sort(key=lambda r: -r.score)
    return results
