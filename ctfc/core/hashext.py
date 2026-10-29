"""Hash length extension: forge `H(secret || data || anything)` without the secret.

The attack exists because MD5, SHA-1, SHA-256 and SHA-512 are **Merkle-Damgard**
constructions. They walk the message block by block through a compression
function, and the digest they print *is* the internal state when they run out of
message:

    state = IV
    for block in pad(message):          # pad = 0x80, zeros, then the bit length
        state = compress(state, block)
    digest = state                      # the whole state, nothing held back

So a digest is a *resumable* position. Given `H(secret || data)` and the length
of the secret - the only thing we need to know about it - we can:

1. rebuild the padding the hash already consumed (it depends on the total length,
   not on the bytes), which becomes the "glue" in the middle of our message;
2. load the digest back as the state;
3. keep hashing whatever we want on top.

The result is a valid digest of `secret || data || glue || append`, and the
server that checks `H(secret || message)` accepts it. This is why a MAC must be
HMAC and not a hash of a concatenation.

`hashlib` cannot resume from a state, so the four compression functions are
written out here. Two notes worth keeping:

- **SHA-224 and SHA-384 are not extendable this way**: they run the same
  compression but print only part of the final state, so the digest no longer is
  the position. SHA-3 and BLAKE2 are sponges/trees - the attack does not apply
  at all.
- When the secret's length is unknown, there is nothing to guess: produce one
  forgery per plausible length and let the target say which one it accepts. That
  is a handful of candidates, not a brute force.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import quote


class HashExtError(ValueError):
    """The digest, algorithm or lengths given cannot produce a forgery."""


# --- MD5 ---------------------------------------------------------------------

MD5_SHIFTS = (
    (7, 12, 17, 22),
    (5, 9, 14, 20),
    (4, 11, 16, 23),
    (6, 10, 15, 21),
)
# Round constants: floor(abs(sin(i + 1)) * 2**32), exactly as RFC 1321 lists them.
MD5_K = tuple(int(abs(math.sin(index + 1)) * (1 << 32)) & 0xFFFFFFFF for index in range(64))


def _rotl32(value: int, count: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def md5_compress(state: Sequence[int], block: bytes) -> tuple[int, ...]:
    """One MD5 block. Words are little-endian, which is MD5's one oddity."""
    words = struct.unpack("<16I", block)
    a, b, c, d = state
    for index in range(64):
        if index < 16:
            mixed, source = (b & c) | (~b & d), index
            shift = MD5_SHIFTS[0][index % 4]
        elif index < 32:
            mixed, source = (d & b) | (~d & c), (5 * index + 1) % 16
            shift = MD5_SHIFTS[1][index % 4]
        elif index < 48:
            mixed, source = b ^ c ^ d, (3 * index + 5) % 16
            shift = MD5_SHIFTS[2][index % 4]
        else:
            mixed, source = c ^ (b | (~d & 0xFFFFFFFF)), (7 * index) % 16
            shift = MD5_SHIFTS[3][index % 4]
        mixed = (mixed + a + MD5_K[index] + words[source]) & 0xFFFFFFFF
        a, d, c = d, c, b
        b = (b + _rotl32(mixed, shift)) & 0xFFFFFFFF
    return tuple((old + new) & 0xFFFFFFFF for old, new in zip(state, (a, b, c, d), strict=True))


# --- SHA-1 -------------------------------------------------------------------


def sha1_compress(state: Sequence[int], block: bytes) -> tuple[int, ...]:
    """One SHA-1 block: 80 rounds over an expanded 16-word message schedule."""
    words = list(struct.unpack(">16I", block))
    for index in range(16, 80):
        mixed = words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]
        words.append(_rotl32(mixed, 1))
    a, b, c, d, e = state
    for index in range(80):
        if index < 20:
            mixed, constant = (b & c) | (~b & d), 0x5A827999
        elif index < 40:
            mixed, constant = b ^ c ^ d, 0x6ED9EBA1
        elif index < 60:
            mixed, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            mixed, constant = b ^ c ^ d, 0xCA62C1D6
        temporary = _rotl32(a, 5) + (mixed & 0xFFFFFFFF) + e + constant + words[index]
        temporary &= 0xFFFFFFFF
        a, b, c, d, e = temporary, a, _rotl32(b, 30), c, d
    return tuple((old + new) & 0xFFFFFFFF for old, new in zip(state, (a, b, c, d, e), strict=True))


# --- SHA-2 (256 and 512 share one body, with different sizes and constants) ---

SHA256_K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

SHA512_K = (
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)


def _sha2_compress(
    state: Sequence[int],
    block: bytes,
    *,
    bits: int,
    constants: Sequence[int],
    sigma: tuple[tuple[int, int, int], tuple[int, int, int]],
    gamma: tuple[tuple[int, int, int], tuple[int, int, int]],
) -> tuple[int, ...]:
    """The SHA-2 body. `sigma`/`gamma` are the rotate/shift amounts of the family."""
    mask = (1 << bits) - 1
    word_bytes = bits // 8
    rounds = len(constants)

    def rotr(value: int, count: int) -> int:
        return ((value >> count) | (value << (bits - count))) & mask

    words = list(
        int.from_bytes(block[index : index + word_bytes], "big")
        for index in range(0, len(block), word_bytes)
    )
    for index in range(16, rounds):
        low, high = words[index - 15], words[index - 2]
        s0 = rotr(low, gamma[0][0]) ^ rotr(low, gamma[0][1]) ^ (low >> gamma[0][2])
        s1 = rotr(high, gamma[1][0]) ^ rotr(high, gamma[1][1]) ^ (high >> gamma[1][2])
        words.append((words[index - 16] + s0 + words[index - 7] + s1) & mask)

    a, b, c, d, e, f, g, h = state
    for index in range(rounds):
        s1 = rotr(e, sigma[1][0]) ^ rotr(e, sigma[1][1]) ^ rotr(e, sigma[1][2])
        choose = (e & f) ^ (~e & mask & g)
        temporary1 = (h + s1 + choose + constants[index] + words[index]) & mask
        s0 = rotr(a, sigma[0][0]) ^ rotr(a, sigma[0][1]) ^ rotr(a, sigma[0][2])
        majority = (a & b) ^ (a & c) ^ (b & c)
        temporary2 = (s0 + majority) & mask
        h, g, f = g, f, e
        e = (d + temporary1) & mask
        d, c, b = c, b, a
        a = (temporary1 + temporary2) & mask
    return tuple(
        (old + new) & mask for old, new in zip(state, (a, b, c, d, e, f, g, h), strict=True)
    )


def sha256_compress(state: Sequence[int], block: bytes) -> tuple[int, ...]:
    return _sha2_compress(
        state,
        block,
        bits=32,
        constants=SHA256_K,
        sigma=((2, 13, 22), (6, 11, 25)),
        gamma=((7, 18, 3), (17, 19, 10)),
    )


def sha512_compress(state: Sequence[int], block: bytes) -> tuple[int, ...]:
    return _sha2_compress(
        state,
        block,
        bits=64,
        constants=SHA512_K,
        sigma=((28, 34, 39), (14, 18, 41)),
        gamma=((1, 8, 7), (19, 61, 6)),
    )


# --- the algorithm table -----------------------------------------------------


@dataclass(frozen=True)
class Algorithm:
    """Everything the attack needs to know about one hash function."""

    name: str
    block_size: int  # bytes per compression call
    word_bytes: int  # size of a state word
    words: int  # how many of them
    endian: str  # "little" for MD5, "big" for the SHA family
    length_bytes: int  # how many bytes the padding spends on the bit length
    compress: Callable[[Sequence[int], bytes], tuple[int, ...]]

    @property
    def digest_size(self) -> int:
        return self.word_bytes * self.words

    def state_from_digest(self, digest: bytes) -> tuple[int, ...]:
        """A digest *is* the state: read it back word by word."""
        return tuple(
            int.from_bytes(digest[index : index + self.word_bytes], self.endian)
            for index in range(0, len(digest), self.word_bytes)
        )

    def digest_from_state(self, state: Sequence[int]) -> bytes:
        return b"".join(word.to_bytes(self.word_bytes, self.endian) for word in state)

    def padding(self, length: int) -> bytes:
        """The bytes the hash itself appends after a message of `length` bytes.

        0x80, then zeros up to the length field, then the message length in
        *bits*. It depends only on the length, which is why a secret of known
        size can be padded without knowing a single one of its bytes.
        """
        free = self.block_size - self.length_bytes
        pad_length = (free - (length + 1) % self.block_size) % self.block_size
        bit_length = (length * 8).to_bytes(self.length_bytes, self.endian)
        return b"\x80" + b"\x00" * pad_length + bit_length


ALGORITHMS: dict[str, Algorithm] = {
    "md5": Algorithm("md5", 64, 4, 4, "little", 8, md5_compress),
    "sha1": Algorithm("sha1", 64, 4, 5, "big", 8, sha1_compress),
    "sha256": Algorithm("sha256", 64, 4, 8, "big", 8, sha256_compress),
    "sha512": Algorithm("sha512", 128, 8, 8, "big", 16, sha512_compress),
}

# Digests that look extendable but are not, and why.
TRUNCATED = {
    28: ("sha224", "SHA-224 prints only 7 of its 8 state words"),
    48: ("sha384", "SHA-384 prints only 6 of its 8 state words"),
}


def algorithm_for_digest(digest: bytes) -> Algorithm:
    """Pick the algorithm from the digest's length, and refuse the truncated ones."""
    if len(digest) in TRUNCATED:
        name, why = TRUNCATED[len(digest)]
        raise HashExtError(
            f"{len(digest)} bytes looks like {name}, which length extension cannot "
            f"touch: {why}, so the digest is no longer the state the hash stopped at"
        )
    for algo in ALGORITHMS.values():
        if algo.digest_size == len(digest):
            return algo
    raise HashExtError(
        f"no supported hash has a {len(digest)}-byte digest "
        f"(md5 16, sha1 20, sha256 32, sha512 64). SHA-3 and BLAKE2 are sponges "
        "and trees: length extension does not apply to them at all"
    )


# --- the attack --------------------------------------------------------------


@dataclass
class Forgery:
    """One candidate: the message to send and the digest that will check out."""

    algorithm: str
    secret_length: int
    digest: str  # hex
    message: bytes  # data || glue || append, i.e. everything after the secret
    glue: bytes  # the padding the original hash consumed
    verified: bool = False  # True when the secret was given and the forgery checked
    python: str = ""

    @property
    def url_encoded(self) -> str:
        """How a web challenge takes it: every byte percent-encoded."""
        return quote(self.message, safe="")

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "secret_length": self.secret_length,
            "digest": self.digest,
            "message_hex": self.message.hex(),
            "message_url": self.url_encoded,
            "glue_hex": self.glue.hex(),
            "verified": self.verified,
            "python": self.python,
        }


def forge(
    digest: bytes,
    data: bytes,
    append: bytes,
    secret_length: int,
    *,
    algorithm: str | None = None,
    secret: bytes | None = None,
) -> Forgery:
    """Forge `H(secret || data || glue || append)` from `H(secret || data)`."""
    algo = ALGORITHMS[algorithm] if algorithm else algorithm_for_digest(digest)
    if len(digest) != algo.digest_size:
        raise HashExtError(
            f"{algo.name} digests are {algo.digest_size} bytes, this one is {len(digest)}"
        )
    if secret_length < 0:
        raise HashExtError("a secret cannot have a negative length")

    glue = algo.padding(secret_length + len(data))
    # What the original hash consumed is a whole number of blocks; we carry on
    # from there, so our own padding counts that length plus what we append.
    consumed = secret_length + len(data) + len(glue)
    state = algo.state_from_digest(digest)
    tail = append + algo.padding(consumed + len(append))
    for start in range(0, len(tail), algo.block_size):
        state = algo.compress(state, tail[start : start + algo.block_size])

    forged = algo.digest_from_state(state)
    message = data + glue + append
    verified = False
    if secret is not None:
        # The one case where we can check locally rather than trust the maths.
        verified = hashlib.new(algo.name, secret + message).digest() == forged
    return Forgery(
        algorithm=algo.name,
        secret_length=secret_length,
        digest=forged.hex(),
        message=message,
        glue=glue,
        verified=verified,
        python=_snippet(algo, digest, data, append, secret_length),
    )


def forge_range(
    digest: bytes,
    data: bytes,
    append: bytes,
    lengths: Sequence[int],
    *,
    algorithm: str | None = None,
    secret: bytes | None = None,
) -> list[Forgery]:
    """One forgery per candidate secret length - the unknown-length case."""
    if not lengths:
        raise HashExtError("no secret length to try")
    found = [
        forge(digest, data, append, length, algorithm=algorithm, secret=secret)
        for length in lengths
    ]
    # If the secret was given, the one that verifies is the answer: put it first.
    found.sort(key=lambda forgery: (not forgery.verified, forgery.secret_length))
    return found


def parse_lengths(spec: str, limit: int = 128) -> list[int]:
    """Read `16`, `8-32` or `8,16,24` as a list of candidate secret lengths."""
    cleaned = spec.replace(" ", "")
    if not cleaned:
        raise HashExtError("no secret length given (try --secret-length 1-64)")
    lengths: list[int] = []
    for part in cleaned.split(","):
        if "-" in part.lstrip("-"):
            low_text, _, high_text = part.partition("-")
            try:
                low, high = int(low_text), int(high_text)
            except ValueError as exc:
                raise HashExtError(f"{part!r} is not a length or a range like 8-32") from exc
            if low > high:
                raise HashExtError(f"{part!r} runs backwards")
            lengths += list(range(low, high + 1))
        else:
            try:
                lengths.append(int(part))
            except ValueError as exc:
                raise HashExtError(f"{part!r} is not a length") from exc
    if any(length < 0 for length in lengths):
        raise HashExtError("a secret cannot have a negative length")
    if len(lengths) > limit:
        raise HashExtError(f"{len(lengths)} lengths is more than the {limit} allowed at once")
    return lengths


def notes(found: Sequence[Forgery]) -> list[str]:
    """The three things the user has to know to use the output."""
    if not found:
        return []
    lines = [
        "the forged digest is valid for secret || message, with the padding bytes "
        "(the 'glue') kept in the middle: send the message exactly as given, bytes "
        "and all - URL-encode it rather than retyping it",
        f"{found[0].algorithm} is a Merkle-Damgard hash, so its digest is the state it "
        "stopped at: that is the whole weakness. HMAC is immune, which is why a MAC "
        "should never be H(secret || message)",
    ]
    if len(found) > 1:
        lines.append(
            f"{len(found)} candidates, one per secret length: the target accepts exactly "
            "one of them, and that also tells you how long the secret is"
        )
    # Lengths that keep the padded total inside the same number of blocks give the
    # *same* digest - only the glue, and so the message, differs. Saying it avoids
    # the "why are they all identical?" moment.
    digests = {forgery.digest for forgery in found}
    if len(found) > 1 and len(digests) < len(found):
        lines.append(
            f"only {len(digests)} distinct digest(s) for {len(found)} lengths: the glue "
            "pads the secret and data up to a whole number of blocks, so lengths that "
            "land in the same block are hashed identically - what differs between those "
            "candidates is the message, not the digest"
        )
    return lines


def _snippet(algo: Algorithm, digest: bytes, data: bytes, append: bytes, secret_length: int) -> str:
    """A standalone script: resume the hash from the digest, by hand."""
    return f'''"""Hash length extension on {algo.name}: continue a hash from its digest.

hashlib cannot resume from a state, so this uses the compression function ctfc
carries in ctfc/core/hashext.py. The maths is the same three lines either way:
rebuild the padding the hash already ate, load the digest back as the state,
keep hashing.
"""

from ctfc.core.hashext import ALGORITHMS, forge

digest = bytes.fromhex("{digest.hex()}")
data = {data!r}            # the message you already have a digest for
append = {append!r}        # what you want to add
secret_length = {secret_length}             # the only thing you must know about the secret

forgery = forge(digest, data, append, secret_length, algorithm="{algo.name}")
print("send this message:", forgery.message)
print("url-encoded      :", forgery.url_encoded)
print("with this digest :", forgery.digest)

# And the check, when you do know the secret (a local test):
# import hashlib
# print(hashlib.{algo.name}(b"<secret>" + forgery.message).hexdigest() == forgery.digest)
'''
