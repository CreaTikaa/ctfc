"""PDF "Standard" encryption: open a PDF whose password is empty (or known).

A PDF can be encrypted with two passwords. The *user* password opens it; the
*owner* password only restricts what a viewer allows (print, copy...). Very
often the user password is EMPTY: every viewer opens the file without asking,
but every stream and every string inside is still encrypted, so `strings`,
`grep` and a naive parser see nothing (uoftctf 2024 "secret message"). Here the
file key is rebuilt from the password exactly as the specification says, and
each object is decrypted.

The handler, by revision (`/R` in the `/Encrypt` dictionary):

* R2 (40-bit RC4), R3 (RC4 up to 128 bits), R4 (RC4 or AES-128): the file key
  is MD5(password padded to 32 bytes + /O + /P + the first /ID string), hashed
  50 more times for R3+. Each object then gets its own key:
  MD5(file key + object number + generation [+ "sAlT" for AES]).
* R5 / R6 (AES-256): the password is checked with SHA-256 (R5) or the
  SHA-256/384/512 loop of ISO 32000-2 (R6), and the file key is stored
  encrypted in /UE (or /OE for the owner password). One key for every object.

A password is tried as the user password, then as the owner password (from
which R2-R4 recover the user password). Pure Python plus pycryptodome; checked
against `qpdf --decrypt` on files qpdf itself encrypted at every revision.
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
from collections.abc import Iterable
from dataclasses import dataclass

from Crypto.Cipher import AES, ARC4

# The 32 bytes a password is padded with (PDF 1.7, 7.6.3.3, step a).
PAD = bytes.fromhex("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")

ENCRYPT_REF = re.compile(rb"/Encrypt\s+(\d{1,10})\s+(\d{1,5})\s+R")
ENCRYPT_INLINE = re.compile(rb"/Encrypt\s*<<")
ID_ARRAY = re.compile(rb"/ID\s*\[\s*")


class PdfCryptError(ValueError):
    """The /Encrypt dictionary cannot be read or uses a handler ctfc does not do."""


@dataclass
class PdfCrypt:
    """What is needed to decrypt every object of one file."""

    revision: int
    key: bytes  # the file key
    method: str  # "rc4", "aes128", "aes256" or "none" (the crypt filter /Identity)
    password: str  # the password that worked ("" for the empty one)
    which: str  # "user" or "owner"
    encrypt_object: int = -1  # the /Encrypt dictionary's own object: never decrypted
    encrypt_metadata: bool = True

    def describe(self) -> str:
        bits = {"rc4": f"RC4 {len(self.key) * 8}-bit", "aes128": "AES-128", "aes256": "AES-256"}
        shown = "the empty password" if not self.password else f"the password {self.password!r}"
        return (
            f"{bits.get(self.method, self.method)}, revision {self.revision}, "
            f"opened with {shown} (as the {self.which} password)"
        )

    def object_key(self, number: int, generation: int) -> bytes:
        """The per-object key of R2-R4 (Algorithm 1); R5/R6 use the file key itself."""
        if self.method == "aes256":
            return self.key
        material = self.key + struct.pack("<I", number)[:3] + struct.pack("<H", generation)
        if self.method == "aes128":
            material += b"sAlT"
        return hashlib.md5(material).digest()[: min(len(self.key) + 5, 16)]

    def decrypt(self, data: bytes, number: int, generation: int) -> bytes:
        """Decrypt one string or stream of object `number`."""
        if self.method == "none" or not data:
            return data
        key = self.object_key(number, generation)
        if self.method == "rc4":
            return ARC4.new(key).decrypt(data)
        # AES: the first 16 bytes are the IV, then CBC with PKCS#7 padding.
        if len(data) < 32 or len(data) % 16:
            return data
        plain = AES.new(key, AES.MODE_CBC, data[:16]).decrypt(data[16:])
        pad = plain[-1]
        if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
            plain = plain[:-pad]
        return plain


# ---------------------------------------------------------------------------
# Reading the /Encrypt dictionary
# ---------------------------------------------------------------------------


def _read_string(data: bytes, start: int) -> bytes | None:
    """The PDF string token at `start` (a literal "(...)" or a hex "<...>")."""
    from ctfc.core.pdf import _balanced_literal, _unescape  # pdf imports this module

    if data[start : start + 1] == b"(":
        return _unescape(_balanced_literal(data, start + 1))
    if data[start : start + 1] == b"<" and data[start + 1 : start + 2] != b"<":
        end = data.find(b">", start)
        if end < 0:
            return None
        digits = re.sub(rb"\s", b"", data[start + 1 : end])
        if len(digits) % 2:
            digits += b"0"
        try:
            return bytes.fromhex(digits.decode("ascii"))
        except ValueError:
            return None
    return None


def _string_value(dictionary: bytes, key: bytes) -> bytes | None:
    match = re.search(re.escape(key) + rb"\s*(?=[(<])", dictionary)
    return _read_string(dictionary, match.end()) if match else None


def _int_value(dictionary: bytes, key: bytes, default: int | None = None) -> int | None:
    match = re.search(re.escape(key) + rb"\s+(-?\d+)", dictionary)
    return int(match.group(1)) if match else default


def _balanced_dictionary(data: bytes, start: int) -> bytes:
    """The "<< ... >>" dictionary that starts at `start`, nested ones included."""
    depth = 0
    index = start
    while index < len(data) - 1:
        pair = data[index : index + 2]
        if pair == b"<<":
            depth += 1
            index += 2
            continue
        if pair == b">>":
            depth -= 1
            index += 2
            if depth == 0:
                return data[start:index]
            continue
        if data[index : index + 1] == b"(":  # a string may hold "<<" or ">>" bytes
            from ctfc.core.pdf import _balanced_literal

            index += len(_balanced_literal(data, index + 1)) + 2
            continue
        index += 1
    return data[start:]


def find_encrypt(data: bytes) -> tuple[bytes, int] | None:
    """(the /Encrypt dictionary, its object number or -1), or None when not encrypted."""
    # The last trailer wins (an incremental update repeats it).
    references = list(ENCRYPT_REF.finditer(data))
    if references:
        number, generation = references[-1].group(1), references[-1].group(2)
        header = re.compile(rb"(?<!\d)" + number + rb"\s+" + generation + rb"\s+obj\b")
        definitions = list(header.finditer(data))
        if definitions:  # the last definition of that object wins
            start = data.find(b"<<", definitions[-1].end())
            if start >= 0:
                return _balanced_dictionary(data, start), int(number)
    inline = list(ENCRYPT_INLINE.finditer(data))
    if inline:
        return _balanced_dictionary(data, inline[-1].end() - 2), -1
    return None


def _first_id(data: bytes) -> bytes:
    """The first string of the trailer's /ID array (b"" when there is none)."""
    matches = list(ID_ARRAY.finditer(data))
    if not matches:
        return b""
    return _read_string(data, matches[-1].end()) or b""


# ---------------------------------------------------------------------------
# Revisions 2 to 4 (MD5 + RC4)
# ---------------------------------------------------------------------------


def _padded(password: bytes) -> bytes:
    return (password + PAD)[:32]


def _key_r2_r4(
    password: bytes, owner: bytes, permissions: int, file_id: bytes, revision: int,
    length: int, encrypt_metadata: bool,
) -> bytes:  # fmt: skip
    """Algorithm 2: the file key from a user password."""
    digest = hashlib.md5()
    digest.update(_padded(password))
    digest.update(owner[:32])
    digest.update(struct.pack("<i", permissions))
    digest.update(file_id)
    if revision >= 4 and not encrypt_metadata:
        digest.update(b"\xff\xff\xff\xff")
    key = digest.digest()
    if revision >= 3:
        for _ in range(50):
            key = hashlib.md5(key[:length]).digest()
    return key[:length]


def _user_check(key: bytes, user: bytes, file_id: bytes, revision: int) -> bool:
    """Algorithms 4 and 5: does this key re-create the /U entry?"""
    if revision == 2:
        return ARC4.new(key).encrypt(PAD) == user[:32]
    value = ARC4.new(key).encrypt(hashlib.md5(PAD + file_id).digest())
    for step in range(1, 20):
        value = ARC4.new(bytes(byte ^ step for byte in key)).encrypt(value)
    return value == user[:16]


def _user_from_owner(password: bytes, owner: bytes, revision: int, length: int) -> bytes:
    """Algorithm 7: an owner password decrypts /O back into the user password."""
    key = hashlib.md5(_padded(password)).digest()
    if revision >= 3:
        for _ in range(50):
            key = hashlib.md5(key).digest()
    key = key[:length]
    value = owner[:32]
    if revision == 2:
        return ARC4.new(key).decrypt(value)
    for step in range(19, -1, -1):
        value = ARC4.new(bytes(byte ^ step for byte in key)).decrypt(value)
    return value


# ---------------------------------------------------------------------------
# Revisions 5 and 6 (AES-256)
# ---------------------------------------------------------------------------


def _hash_r6(password: bytes, salt: bytes, extra: bytes = b"") -> bytes:
    """Algorithm 2.B of ISO 32000-2: the slow hash of revision 6."""
    key = hashlib.sha256(password + salt + extra).digest()
    rounds = 0
    while True:
        block = (password + key + extra) * 64
        encrypted = AES.new(key[:16], AES.MODE_CBC, key[16:32]).encrypt(block)
        choice = sum(encrypted[:16]) % 3
        key = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[choice](encrypted).digest()
        rounds += 1
        if rounds >= 64 and encrypted[-1] <= rounds - 32:
            return key[:32]


def _hash_r5_r6(revision: int, password: bytes, salt: bytes, extra: bytes = b"") -> bytes:
    if revision == 5:
        return hashlib.sha256(password + salt + extra).digest()
    return _hash_r6(password, salt, extra)


def _key_r5_r6(dictionary: bytes, password: bytes, revision: int) -> tuple[bytes, str] | None:
    user = _string_value(dictionary, b"/U") or b""
    owner = _string_value(dictionary, b"/O") or b""
    user_key = _string_value(dictionary, b"/UE") or b""
    owner_key = _string_value(dictionary, b"/OE") or b""
    if len(user) < 48 or len(owner) < 48:
        raise PdfCryptError("/U or /O is too short for AES-256")
    password = password[:127]
    zero_iv = b"\x00" * 16
    if _hash_r5_r6(revision, password, user[32:40]) == user[:32] and len(user_key) == 32:
        intermediate = _hash_r5_r6(revision, password, user[40:48])
        return AES.new(intermediate, AES.MODE_CBC, zero_iv).decrypt(user_key), "user"
    if _hash_r5_r6(revision, password, owner[32:40], user[:48]) == owner[:32] and owner_key:
        intermediate = _hash_r5_r6(revision, password, owner[40:48], user[:48])
        return AES.new(intermediate, AES.MODE_CBC, zero_iv).decrypt(owner_key[:32]), "owner"
    return None


# ---------------------------------------------------------------------------
# The entry point
# ---------------------------------------------------------------------------


def _method(dictionary: bytes, version: int) -> str:
    if version >= 5:
        return "aes256"
    if version == 4:
        stream_filter = re.search(rb"/StmF\s*/(\w+)", dictionary)
        if stream_filter and stream_filter.group(1) == b"Identity":
            return "none"
        cfm = re.search(rb"/CFM\s*/(\w+)", dictionary)
        if cfm and cfm.group(1) == b"AESV2":
            return "aes128"
        if cfm and cfm.group(1) == b"None":
            return "none"
    return "rc4"


def open_pdf(
    data: bytes, passwords: Iterable[bytes] = (b"",), seconds: float | None = None
) -> PdfCrypt | None:
    """The decryption state for this file, if one of `passwords` opens it.

    Raises PdfCryptError when the file is encrypted with something other than
    the Standard handler (a certificate, a custom plug-in). Returns None when it
    is not encrypted, or when no password worked (within `seconds`, if given).
    """
    deadline = None if seconds is None else time.monotonic() + seconds
    found = find_encrypt(data)
    if found is None:
        return None
    dictionary, number = found
    handler = re.search(rb"/Filter\s*/(\w+)", dictionary)
    if handler and handler.group(1) != b"Standard":
        raise PdfCryptError(
            f"security handler /{handler.group(1).decode()} is not the Standard one"
        )
    version = _int_value(dictionary, b"/V", 0) or 0
    revision = _int_value(dictionary, b"/R", 0) or 0
    encrypt_metadata = re.search(rb"/EncryptMetadata\s+false", dictionary) is None
    method = _method(dictionary, version)

    if revision >= 5:
        for password in passwords:
            if deadline is not None and time.monotonic() > deadline:
                return None
            result = _key_r5_r6(dictionary, password, revision)
            if result:
                key, which = result
                text = password.decode("utf-8", "replace")
                return PdfCrypt(revision, key, method, text, which, number, encrypt_metadata)
        return None

    if revision not in (2, 3, 4):
        raise PdfCryptError(f"unknown Standard revision {revision}")
    owner = _string_value(dictionary, b"/O") or b""
    user = _string_value(dictionary, b"/U") or b""
    permissions = _int_value(dictionary, b"/P", 0) or 0
    if revision == 2:
        length = 5
    elif version == 4:
        length = 16
    else:
        length = (_int_value(dictionary, b"/Length", 40) or 40) // 8
    file_id = _first_id(data)
    args = (owner, permissions, file_id, revision, length, encrypt_metadata)
    for password in passwords:
        if deadline is not None and time.monotonic() > deadline:
            return None
        key = _key_r2_r4(password, *args)
        if _user_check(key, user, file_id, revision):
            text = password.decode("latin-1")
            return PdfCrypt(revision, key, method, text, "user", number, encrypt_metadata)
        recovered = _user_from_owner(password, owner, revision, length)
        key = _key_r2_r4(recovered, *args)
        if _user_check(key, user, file_id, revision):
            text = password.decode("latin-1")
            return PdfCrypt(revision, key, method, text, "owner", number, encrypt_metadata)
    return None


def _literal(value: bytes) -> bytes:
    """A PDF literal string for these bytes: ( ) and backslash escaped, the rest
    of the unprintable bytes as \\ooo octal."""
    out = bytearray(b"(")
    for byte in value:
        if byte in b"()\\":
            out += b"\\" + bytes([byte])
        elif 32 <= byte < 127:
            out.append(byte)
        else:
            out += b"\\%03o" % byte
    return bytes(out + b")")


def decrypt_strings(dictionary: bytes, crypt: PdfCrypt, number: int, generation: int) -> bytes:
    """Every string of an object's dictionary, decrypted and written back in clear.

    Strings are encrypted too (a /JS action, a /Title, an /F file name), so the
    dictionary is rewritten with each "(...)" or "<...>" string replaced by its
    plaintext as an escaped literal "(...)", the form every other part of
    `pdf.py` reads.
    """
    from ctfc.core.pdf import _balanced_literal

    out = bytearray()
    index = 0
    while index < len(dictionary):
        byte = dictionary[index : index + 1]
        if byte == b"(":
            raw = _balanced_literal(dictionary, index + 1)
            value = _read_string(dictionary, index) or b""
            out += _literal(crypt.decrypt(value, number, generation))
            index += len(raw) + 2
            continue
        if byte == b"<" and dictionary[index + 1 : index + 2] == b"<":
            out += b"<<"
            index += 2
            continue
        if byte == b"<":
            end = dictionary.find(b">", index)
            if end < 0:
                out += dictionary[index:]
                break
            value = _read_string(dictionary, index) or b""
            out += _literal(crypt.decrypt(value, number, generation))
            index = end + 1
            continue
        out += byte
        index += 1
    return bytes(out)
