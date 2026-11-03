"""Tests for the archives that are not ZIPs (core/archive.py and its readers).

Every fixture used here is a real archive: the 7z ones pass `7z t`, the RAR 4
one passes `unrar t`, the two RAR 5 ones came out of RAR itself, and the cabinet
is listed and extracted by `7z`. Where those tools are installed, the tests
below check our reading *against them* rather than against our own writer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import zlib

import pytest

from ctfc.core import archive, cab, dockerimg, rar, sevenzip, tarfmt

# ---------------------------------------------------------------------------
# sniff
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("archive_lzma.7z", "7z"),
        ("archive_encoded_header.7z", "7z"),
        ("archive_aes.7z", "7z"),
        ("archive_stored.rar", "rar4"),
        ("archive_rar5_stored.rar", "rar5"),
        ("archive_mszip.cab", "cab"),
        ("archive_appended.tar", "tar"),
        ("archive_docker_image.tar", "tar"),
    ],
)
def test_sniff_names_the_format(fixture_bytes, name, expected):
    assert archive.sniff(fixture_bytes(name)) == expected


def test_a_zip_is_sent_to_the_zip_command(fixture_bytes):
    with pytest.raises(archive.ArchiveError, match="ctfc zip"):
        archive.analyse(fixture_bytes("png_with_zip.png")[-200:])


def test_random_bytes_are_not_an_archive():
    assert archive.sniff(bytes(range(256))) == ""


# ---------------------------------------------------------------------------
# tar
# ---------------------------------------------------------------------------


def test_tar_entries_and_sizes(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_appended.tar"), "a.tar")
    assert report.format == "tar"
    names = [entry.name for entry in report.entries]
    assert names == ["flag.txt", "notes/readme.txt", "notes/deep/file.bin"]
    assert report.entries[2].size == 64
    assert report.entries[2].data == bytes(range(64))


def test_tar_sees_what_is_appended_after_the_end_marker(fixture_bytes):
    """The point of reading tar by hand: `tar tf` stops at the zero blocks."""
    report = archive.analyse(fixture_bytes("archive_appended.tar"), "a.tar")
    assert report.trailing.startswith(b"\x89PNG")
    assert any("follow the end-of-archive marker" in note for note in report.notes)


def test_tar_finds_the_flag_in_a_member(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_appended.tar"), "a.tar")
    assert "CYBN{tar_plain}" in report.flags


def test_tar_octal_and_gnu_binary_sizes():
    """Sizes are octal, except GNU's binary form for sizes that do not fit."""
    assert tarfmt._octal(b"00000000144\x00") == 0o144
    assert tarfmt._octal(b"\x80\x00\x00\x00\x00\x00\x00\x08") == 8


def test_a_tar_header_with_a_broken_checksum_is_refused():
    data = bytearray(tarfmt.BLOCK * 3)
    data[0:5] = b"a.txt"
    data[257:262] = b"ustar"
    with pytest.raises(tarfmt.TarError, match="checksum"):
        tarfmt.read_entries(bytes(data))


@pytest.mark.skipif(shutil.which("tar") is None, reason="tar is not installed")
def test_tar_listing_matches_the_real_tar(fixture_bytes, tmp_path):
    path = tmp_path / "a.tar"
    path.write_bytes(fixture_bytes("archive_appended.tar"))
    out = subprocess.run(
        ["tar", "tf", str(path)], capture_output=True, timeout=30, check=True
    ).stdout.decode()
    listed = [line for line in out.split("\n") if line]
    entries, _end = tarfmt.read_entries(fixture_bytes("archive_appended.tar"))
    assert [entry.name for entry in entries] == listed


# ---------------------------------------------------------------------------
# 7z
# ---------------------------------------------------------------------------


def test_sevenzip_lzma_is_decompressed_offline(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_lzma.7z"), "a.7z")
    assert report.format == "7z"
    assert [entry.name for entry in report.entries] == ["flag.txt"]
    assert report.entries[0].method == "LZMA"
    assert b"CYBN{sevenzip_lzma}" in (report.entries[0].data or b"")
    assert "CYBN{sevenzip_lzma}" in report.flags


def test_sevenzip_crc_is_checked_when_it_is_there(fixture_bytes):
    archive_ = sevenzip.extract(fixture_bytes("archive_lzma.7z"))
    for entry in archive_.entries:
        if entry.crc is not None and entry.data is not None:
            assert zlib.crc32(entry.data) == entry.crc


def test_sevenzip_compressed_header_is_decoded(fixture_bytes):
    """kEncodedHeader: the file list is LZMA inside the file, so strings shows nothing."""
    data = fixture_bytes("archive_encoded_header.7z")
    assert b"hidden.txt" not in data
    assert b"h\x00i\x00d\x00d\x00e\x00n\x00" not in data
    report = archive.analyse(data, "a.7z")
    assert [entry.name for entry in report.entries] == ["hidden.txt"]
    assert "CYBN{sevenzip_encoded_header}" in report.flags


def test_sevenzip_aes_is_reported_not_guessed(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_aes.7z"), "a.7z")
    assert report.entries[0].name == "secret.txt"  # names in clear: 7z a -p
    assert report.entries[0].encrypted
    assert not report.encrypted_names
    assert report.entries[0].data is None
    assert any("AES-256" in note for note in report.notes)
    assert any("hashcat -m 11600" in command for command in report.commands)


def test_sevenzip_aes_iteration_count_is_read(fixture_bytes):
    archive_ = sevenzip.read(fixture_bytes("archive_aes.7z"))
    # The fixture uses 2**6 rounds so the tests stay fast; 7z's own default is 2**19.
    assert archive_.kdf_iterations == 64
    assert archive_.iv == bytes(range(16))


def test_sevenzip_truncated_file_says_so(fixture_bytes):
    data = fixture_bytes("archive_lzma.7z")
    with pytest.raises(sevenzip.SevenZipError, match="truncated"):
        sevenzip.read(data[: len(data) // 2])


def test_sevenzip_number_encoding():
    """The mask byte says how many bytes follow; the low bits are the top of the value."""
    assert sevenzip.Reader(bytes([0x7F])).number() == 0x7F
    assert sevenzip.Reader(bytes([0x80, 0x34])).number() == 0x34
    assert sevenzip.Reader(bytes([0xC0, 0x34, 0x12])).number() == 0x1234


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z is not installed")
@pytest.mark.parametrize("name", ["archive_lzma.7z", "archive_encoded_header.7z", "archive_aes.7z"])
def test_sevenzip_listing_matches_the_real_7z(fixture_bytes, tmp_path, name):
    path = tmp_path / name
    path.write_bytes(fixture_bytes(name))
    out = subprocess.run(
        ["7z", "l", str(path)], capture_output=True, timeout=60, check=True
    ).stdout.decode()
    for entry in sevenzip.read(fixture_bytes(name)).entries:
        assert entry.name in out


# ---------------------------------------------------------------------------
# RAR
# ---------------------------------------------------------------------------


def test_rar4_entries(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_stored.rar"), "a.rar")
    assert report.format == "rar4"
    assert [entry.name for entry in report.entries] == ["flag.txt", "notes.txt"]
    assert report.entries[0].method == "stored"
    assert not report.any_encrypted


def test_rar4_encrypted_entry_is_flagged(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_encrypted.rar"), "a.rar")
    assert report.entries[0].encrypted
    assert any("rar2john" in command for command in report.commands)
    assert any("hashcat -m 12500" in command for command in report.commands)


def test_rar5_entries(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_rar5_stored.rar"), "a.rar")
    assert report.format == "rar5"
    assert [entry.name for entry in report.entries] == ["flag.txt", "notes.txt"]
    assert report.entries[0].size == 16
    assert report.entries[0].crc == zlib.crc32(b"CYBN{rar5_flag}\n")


def test_rar5_encrypted_files_keep_their_names(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_rar5_encrypted.rar"), "a.rar")
    assert not report.encrypted_names
    assert all(entry.encrypted for entry in report.entries)
    assert any("2^15" in note for entry in report.entries for note in entry.notes)
    assert any("hashcat -m 13000" in command for command in report.commands)


def test_rar5_encrypted_headers_hide_the_listing(fixture_bytes):
    """-hp encrypts the headers too: not even the names can be listed."""
    report = archive.analyse(fixture_bytes("archive_rar5_header_encrypted.rar"), "a.rar")
    assert report.encrypted_names
    assert report.entries == []
    assert any("PBKDF2-HMAC-SHA256" in note for note in report.notes)
    assert any("hashcat -m 13000" in command for command in report.commands)


def test_rar_vint():
    """RAR 5 numbers: 7 bits per byte, high bit means "one more byte"."""
    assert rar.read_vint(bytes([0x7F]), 0) == (0x7F, 1)
    assert rar.read_vint(bytes([0x80, 0x01]), 0) == (128, 2)
    with pytest.raises(rar.RarError, match="longer than ten"):
        rar.read_vint(b"\xff" * 12, 0)


def test_not_a_rar():
    with pytest.raises(rar.RarError, match="not a RAR"):
        rar.read(b"PK\x03\x04" + bytes(100))


@pytest.mark.skipif(shutil.which("unrar") is None, reason="unrar is not installed")
@pytest.mark.parametrize(
    "name", ["archive_stored.rar", "archive_rar5_stored.rar", "archive_rar5_encrypted.rar"]
)
def test_rar_listing_matches_unrar(fixture_bytes, tmp_path, name):
    path = tmp_path / name
    path.write_bytes(fixture_bytes(name))
    out = subprocess.run(
        ["unrar", "l", "-p-", str(path)], capture_output=True, timeout=60
    ).stdout.decode()
    for entry in rar.read(fixture_bytes(name)).entries:
        assert entry.name in out


# ---------------------------------------------------------------------------
# Cabinet
# ---------------------------------------------------------------------------


def test_cab_mszip_is_decompressed(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_mszip.cab"), "a.cab")
    assert report.format == "cab"
    assert [entry.name for entry in report.entries] == ["flag.txt", "readme.txt"]
    assert report.entries[0].method == "MSZIP"
    assert report.entries[0].data == b"CYBN{cabinet_mszip}\n"
    assert "CYBN{cabinet_mszip}" in report.flags


def test_cab_mszip_chains_the_dictionary_across_blocks():
    """A file bigger than 32 KB needs block N to inflate with block N-1's output."""
    import zlib as _zlib

    payload = bytes((index * 7) % 251 for index in range(100_000))
    files = [("big.bin", payload)]
    # Build the same way the fixture generator does, through the reader's own
    # inverse: compress, then read it back.
    from tests.make_fixtures import cab_write  # noqa: PLC0415

    cabinet = cab.extract(cab_write(files, "mszip"))
    assert cabinet.files[0].data == payload
    assert _zlib.crc32(cabinet.files[0].data) == _zlib.crc32(payload)


def test_cab_dos_timestamp():
    file = cab.CabFile(name="x", size=0, folder=0, offset=0, attributes=0, date=0x5A21, time=0x4800)
    assert file.dos_timestamp == "2025-01-01 09:00:00"


def test_cab_truncated(fixture_bytes):
    with pytest.raises(cab.CabError):
        cab.read(fixture_bytes("archive_mszip.cab")[:20])


# ---------------------------------------------------------------------------
# Docker image
# ---------------------------------------------------------------------------


def test_docker_image_is_recognised(fixture_bytes):
    assert dockerimg.looks_like_image(fixture_bytes("archive_docker_image.tar"))
    assert not dockerimg.looks_like_image(fixture_bytes("archive_appended.tar"))


def test_docker_layers_are_in_build_order_with_their_dockerfile_line(fixture_bytes):
    report = dockerimg.analyse(fixture_bytes("archive_docker_image.tar"))
    assert report.tags == ["ctfc/demo:1"]
    assert [layer.created_by for layer in report.layers] == [
        "COPY app /usr/bin/app",
        "COPY secret.txt keep.txt /app/",
        "RUN rm /app/secret.txt",
    ]


def test_docker_whiteout_gives_the_deleted_file_back(fixture_bytes):
    """The whole point: `rm` in a Dockerfile only hides the file, it is still there."""
    report = dockerimg.analyse(fixture_bytes("archive_docker_image.tar"))
    assert report.layers[2].whiteouts == ["app/secret.txt"]
    assert len(report.deleted) == 1
    deleted = report.deleted[0]
    assert deleted.name == "app/secret.txt"
    assert deleted.present_in == 1
    assert deleted.hidden_by == 2
    assert deleted.content == b"CYBN{docker_whiteout}\n"


def test_docker_flags_include_the_environment(fixture_bytes):
    report = dockerimg.analyse(fixture_bytes("archive_docker_image.tar"))
    assert "CYBN{docker_whiteout}" in report.flags
    assert "CYBN{docker_env_token}" in report.flags
    assert report.command == ["/usr/bin/app"]


def test_archive_reports_the_docker_layers_too(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_docker_image.tar"), "img.tar")
    assert report.docker is not None
    assert "CYBN{docker_whiteout}" in report.flags
    assert any("saved Docker image" in note for note in report.notes)


def test_docker_opaque_whiteout_hides_a_whole_directory():
    """`.wh..wh..opq` means "ignore everything below here from the layers under me"."""
    from tests.make_fixtures import docker_image_tar  # noqa: PLC0415

    data = docker_image_tar()
    report = dockerimg.analyse(data)
    # The fixture uses a plain whiteout; the opaque form is parsed the same way.
    layer = dockerimg.Layer(index=0, digest="x")
    dockerimg._read_layer(
        layer,
        __import__("tests.make_fixtures", fromlist=["tar_archive"]).tar_archive(
            [("app/.wh..wh..opq", b"")]
        ),
    )
    assert layer.whiteouts == ["app/*"]
    assert report.layers  # the real fixture still reads


def test_docker_zstd_layer_is_named_not_guessed():
    layer = dockerimg.Layer(index=0, digest="x")
    dockerimg._read_layer(layer, b"\x28\xb5\x2f\xfd" + bytes(50))
    assert any("zstd" in note for note in layer.notes)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_extract_writes_the_members(fixture_bytes, tmp_path):
    report = archive.analyse(fixture_bytes("archive_appended.tar"), "a.tar")
    written = archive.extract(report, tmp_path)
    assert (tmp_path / "flag.txt").read_bytes() == b"CYBN{tar_plain}\n"
    assert (tmp_path / "notes" / "deep" / "file.bin").exists()
    # The bytes after the end-of-archive marker are written out as well.
    assert (tmp_path / "trailing-data.bin").read_bytes().startswith(b"\x89PNG")
    assert len(written) == 4


def test_extract_refuses_to_escape_the_destination(tmp_path):
    """An archive may name a member `../../etc/passwd`. It lands inside anyway."""
    target = archive._safe_destination(tmp_path, "../../etc/passwd")
    assert target == tmp_path / "etc" / "passwd"
    assert archive._safe_destination(tmp_path, "/abs/x") == tmp_path / "abs" / "x"
    assert archive._safe_destination(tmp_path, "..") == tmp_path / "unnamed"


def test_extract_lays_the_docker_layers_out_one_folder_each(fixture_bytes, tmp_path):
    report = archive.analyse(fixture_bytes("archive_docker_image.tar"), "img.tar")
    archive.extract(report, tmp_path)
    folders = sorted(path.name for path in tmp_path.iterdir() if path.is_dir())
    layer_folders = [name for name in folders if name.startswith("layer-")]
    assert len(layer_folders) == 3
    assert layer_folders[0].startswith("layer-00-")
    secret = next(tmp_path.glob("layer-01-*/app/secret.txt"))
    assert secret.read_bytes() == b"CYBN{docker_whiteout}\n"


# ---------------------------------------------------------------------------
# JSON and the CLI
# ---------------------------------------------------------------------------


def test_to_dict_round_trips(fixture_bytes):
    report = archive.analyse(fixture_bytes("archive_docker_image.tar"), "img.tar")
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["format"] == "tar"
    assert payload["docker"]["layers"][2]["whiteouts"] == ["app/secret.txt"]
    assert "CYBN{docker_whiteout}" in payload["flags"]


def test_cli_archive(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("archive", "tests/fixtures/archive_lzma.7z", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["format"] == "7z"
    assert payload["entries"][0]["name"] == "flag.txt"


def test_cli_archive_extract(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc(
        "archive", "tests/fixtures/archive_mszip.cab", "--extract", str(tmp_path), "--json"
    )
    assert result.returncode == 0
    assert (tmp_path / "flag.txt").read_bytes() == b"CYBN{cabinet_mszip}\n"
