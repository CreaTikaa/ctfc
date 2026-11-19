"""Techniques borrowed from solved-noai (another LLM-free solver), 2026-11-19.

solved-noai was benchmarked on the same 296 corpus challenges as ctfc; these
are the cases it flagged and ctfc missed, rebuilt as fixtures with a fake CYBN
flag (lot 1), then the general techniques it has and ctfc lacked (lot 2).

Lot 1:
- ICMP covert channel in the header fields: one character per ping in the
  echo identifier (hackini-2022 "smurf");
- a ZIP folder entry ("flag/") that carries bytes `unzip` drops
  (tjctf-2022 "sneaker zipper");
- an archive of 1024 images where only the pieces past the 120 followed ones
  hold the flag, in clear, in one EXIF field (tamu-fallctf-2023 "modified");
- a ZipCrypto password written in the challenge itself: a PNG text chunk of
  the image the ZIP is glued to (tjctf-2023 "nothing to see").
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from ctfc.core import hints, pcap, readers, zipinfo
from ctfc.core.solve import solve
from ctfc.core.workspace import analyse as analyse_folder
from tests.make_fixtures import ethernet_ipv4, pcap_packet, zipcrypto_zip

FLAG = "CYBN{b0rr0wed_fr0m_s0lved}"


# ---------------------------------------------------------------- ICMP header channel


def _capture(frames: list[bytes]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(pcap_packet(frame, 1700000000 + i) for i, frame in enumerate(frames))


WINDOWS_FILLER = b"abcdefghijklmnopqrstuvwabcdefghi"


def _ping(identifier: int, sequence: int, data: bytes = WINDOWS_FILLER) -> bytes:
    icmp = struct.pack(">BBHHH", 8, 0, 0, identifier, sequence) + data
    return ethernet_ipv4("10.10.99.255", "127.0.0.1", 1, icmp)


def test_flag_in_the_echo_identifier_one_char_per_ping():
    frames = [_ping(ord(char), 0) for char in FLAG]
    report = pcap.analyse(_capture(frames))
    channels = [o for o in report.objects if o.kind == "icmp-header"]
    assert [o.data for o in channels if "echo-identifier" in o.name] == [FLAG.encode()]
    assert [f.text for f in solve(_capture(frames), "smurf.pcap").flags] == [FLAG]


def test_flag_in_the_sequence_number_and_ttl_too():
    by_sequence = _capture([_ping(0x4242, ord(char)) for char in FLAG])
    assert FLAG in [f.text for f in solve(by_sequence, "seq.pcap").flags]


def test_a_plain_ping_counter_is_not_a_channel():
    # A normal ping: same identifier, sequence 1, 2, 3...; stock filler data.
    frames = [_ping(0x1234, 40 + n) for n in range(30)]
    report = pcap.analyse(_capture(frames))
    assert not [o for o in report.objects if o.kind == "icmp-header"]


# ---------------------------------------------------------------- ZIP folder entry


def _zip_with_folder_content() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for n in range(100):
            archive.writestr(f"flag-{n:03d}.txt", "your flag is in another castle")
        archive.writestr(zipfile.ZipInfo("flag/"), FLAG)
    return buffer.getvalue()


def test_a_folder_entry_with_bytes_is_read():
    data = _zip_with_folder_content()
    opened = readers.open_with("zip", data)
    assert any(child.data == FLAG.encode() for child in opened.children)
    assert [f.text for f in solve(data, "chall.zip").flags] == [FLAG]


def test_ctfc_zip_names_the_folder_entry():
    report = zipinfo.analyse(_zip_with_folder_content())
    assert any("folder entry" in note and "flag/" in note for note in report.notes)


# ---------------------------------------------------------------- past CHILD_LIMIT


def test_a_flag_in_clear_past_the_followed_pieces_is_found():
    # 400 "photos"; the flag sits in clear in the 377th (the EXIF of the real one).
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for n in range(400):
            body = b"\xff\xd8\xff\xe0" + bytes([n % 256]) * 2000
            if n == 377:
                body += b"Description: " + FLAG.encode()
            archive.writestr(f"img_{n}.jpeg", body + b"\xff\xd9")
    data = buffer.getvalue()
    opened = readers.open_with("zip", data)
    assert len(opened.children) == readers.CHILD_LIMIT
    assert opened.children[0].name == "img_377.jpeg"
    assert [f.text for f in solve(data, "imgs.zip").flags] == [FLAG]


# ---------------------------------------------------------------- password hints


def _png_with_text(keyword: str, text: str) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = struct.pack(">I", zlib.crc32(kind + body))
        return struct.pack(">I", len(body)) + kind + body + crc

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"tEXt", keyword.encode() + b"\x00" + text.encode())
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def _locked_zip(password: bytes) -> bytes:
    return zipcrypto_zip("flag.txt", FLAG.encode() + b"\n", password)


def test_png_text_chunks_and_their_encoded_forms_are_hints():
    png = _png_with_text("Title", "panda_d02b3ab3")
    assert hints.png_text_chunks(png) == [("Title", "panda_d02b3ab3")]
    assert b"panda_d02b3ab3" in hints.password_hints(png)
    encoded = _png_with_text("Password", "cGFuZGFfZDAyYjNhYjM=")  # base64 of the same
    assert b"panda_d02b3ab3" in hints.password_hints(encoded)


def test_the_zip_glued_to_a_png_opens_with_the_png_title():
    data = _png_with_text("Title", "panda_d02b3ab3") + _locked_zip(b"panda_d02b3ab3")
    report = solve(data, "nothing.png")
    assert [f.text for f in report.flags] == [FLAG]


def test_a_hint_read_after_the_zip_still_opens_it():
    # A tar-like order: the ZIP comes first, the note with the password after.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as outer:
        outer.writestr("a_backup.zip", _locked_zip(b"tr0ub4dor&3"))
        outer.writestr("z_note.txt", "remember: tr0ub4dor&3\n")
    report = solve(buffer.getvalue(), "chall.zip")
    assert [f.text for f in report.flags] == [FLAG]


def test_workspace_opens_a_zip_with_a_string_of_another_file(tmp_path):
    (tmp_path / "hidden.zip").write_bytes(_locked_zip(b"panda_d02b3ab3"))
    (tmp_path / "nothing.png").write_bytes(_png_with_text("Title", "panda_d02b3ab3"))
    report = analyse_folder(tmp_path)
    assert FLAG in report.flags
    assert any(hit.secret == "panda_d02b3ab3" for hit in report.hits)


# ================================================================ lot 2
#
# The general techniques solved-noai has and ctfc lacked, each checked on a
# synthetic file (and, for the text dumps, against the real xxd/hexdump/od).

import bz2  # noqa: E402
import gzip  # noqa: E402
import lzma  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402

from ctfc.core import crib, matryoshka, textdump  # noqa: E402
from ctfc.core.encodings import DECODERS_BY_NAME  # noqa: E402
from ctfc.core.flags import build_flagset  # noqa: E402

# ---------------------------------------------------------------- matryoshka


def _nested(layers: int) -> bytes:
    data = FLAG.encode()
    for n in range(layers):
        kind = n % 4
        if kind == 0:
            data = bz2.compress(data)
        elif kind == 1:
            data = gzip.compress(data)
        elif kind == 2:
            data = lzma.compress(data)
        else:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("flag.txt", data)
            data = buffer.getvalue()
    return data


def test_matryoshka_peels_hundreds_of_layers():
    peeled = matryoshka.peel(_nested(300))
    assert peeled.data == FLAG.encode()
    assert peeled.depth == 300
    assert set(peeled.kinds) == {"bzip2", "gzip", "xz", "zip"}


def test_matryoshka_is_solved_past_the_walk_depth():
    report = solve(_nested(300), "flag.txt")
    assert [f.text for f in report.flags] == [FLAG]


def test_matryoshka_stops_at_a_multi_file_archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", "one")
        archive.writestr("b.txt", "two")
    peeled = matryoshka.peel(gzip.compress(gzip.compress(buffer.getvalue())))
    assert peeled.depth == 2 and peeled.data == buffer.getvalue()


# ---------------------------------------------------------------- text hex dumps


@pytest.mark.parametrize(
    "command",
    [["xxd"], ["xxd", "-g1"], ["hexdump", "-C"], ["hexdump"], ["od", "-A", "x", "-t", "x1z", "-v"]],
)
def test_text_dumps_revert_to_the_bytes(command):
    if shutil.which(command[0]) is None:
        pytest.skip(f"{command[0]} not installed")
    for data in (os.urandom(1), os.urandom(333), b"\x00" * 200 + os.urandom(50) + b"\x00" * 64):
        dump = subprocess.run(command, input=data, capture_output=True, check=True).stdout
        result = textdump.revert(dump)
        assert result is not None and result[0] == data, command


def test_a_dump_of_a_gzip_is_solved():
    data = gzip.compress(b"notes\n" + FLAG.encode() + b"\n")
    lines = []
    for offset in range(0, len(data), 16):
        row = data[offset : offset + 16]
        words = " ".join(row[i : i + 2].hex() for i in range(0, len(row), 2))
        lines.append(f"{offset:08x}: {words:<39}  {'.' * len(row)}")
    dump = ("\n".join(lines) + "\n").encode()
    assert textdump.revert(dump)[0] == data
    assert FLAG in [f.text for f in solve(dump, "dump.txt").flags]


def test_ordinary_text_is_not_a_dump():
    assert not textdump.looks_like_dump(b"hello world\nthis is text\n")
    assert textdump.revert(b"deadbeef cafe\nnot a dump at all\n") is None


# ---------------------------------------------------------------- Unicode tags, kcpassword


def test_unicode_tag_characters_are_decoded():
    text = "Nothing to see here." + "".join(chr(0xE0000 + ord(c)) for c in FLAG)
    decoder = DECODERS_BY_NAME["unicode_tags"]
    assert decoder.applicable(text.encode())
    assert decoder.decode(text.encode()) == FLAG.encode()
    assert FLAG in [f.text for f in solve(text.encode(), "tags.txt").flags]


def test_kcpassword_is_decoded():
    key = bytes.fromhex("7d895223d2bcddeaa3b91f")
    plain = FLAG.encode() + b"\x00"
    plain += b"\x00" * (-len(plain) % 12)
    data = bytes(byte ^ key[i % 11] for i, byte in enumerate(plain))
    assert DECODERS_BY_NAME["kcpassword"].decode(data) == FLAG.encode()
    assert FLAG in [f.text for f in solve(data, "kcpassword").flags]
    assert not DECODERS_BY_NAME["kcpassword"].applicable(os.urandom(24) + b"\xff" * 12)


# ---------------------------------------------------------------- known-prefix crib


def _buried(middle: bytes) -> bytes:
    return os.urandom(3000) + middle + os.urandom(3000)


@pytest.mark.parametrize(
    "disguise",
    [
        lambda f: bytes(c ^ 0x5A for c in f),  # single-byte XOR
        lambda f: bytes((c + 7) % 256 for c in f),  # +7 on every byte
        lambda f: f.translate(
            bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
        ),  # rot13
        lambda f: f.hex().encode(),
        lambda f: f.hex(" ").upper().encode(),
        lambda f: ", ".join(str(c) for c in f).encode(),
    ],
)
def test_the_known_prefix_finds_a_disguised_flag_in_noise(disguise):
    data = _buried(disguise(FLAG.encode()))
    assert FLAG in [hit.flag for hit in crib.search(data, ["CYBN{"])]
    assert FLAG in [f.text for f in solve(data, "blob.bin").flags]


def test_a_longer_prefix_allows_a_repeating_xor_key():
    secret = b"shellmates{r3peat1ng_k3y_x0r}"
    key = b"\x13\x37\x42"
    data = _buried(bytes(c ^ key[i % 3] for i, c in enumerate(secret)))
    hits = crib.search(data, ["shellmates{"])
    assert [hit.flag for hit in hits] == [secret.decode()]
    assert hits[0].how == "xor key 133742 (3-byte key)"


def test_the_crib_does_not_invent_flags_in_noise():
    for _attempt in range(20):
        noise = os.urandom(200_000)
        assert not [hit for hit in crib.search(noise, ["CYBN{"]) if hit.flag]
    flagset = build_flagset([], ["CYBN{"])
    assert flagset.b64_prefixes  # the prefixes crib.search is handed by flags.hunt
