"""`ctfc workspace` tests: the key is never in the same file as the ciphertext.

Each folder below is built the way a real multi-file challenge is: the secret
in one file, the thing it opens in another, and a couple of files that are
there only to be ruled out. The test then asks the one question the command
exists for - *which secret opens which ciphertext* - and checks that the answer
names both sides and prints a command that reproduces it.
"""

from __future__ import annotations

import io
import random
import subprocess
import zipfile
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ctfc.core import workspace
from ctfc.core.budget import Budget

FLAG = "CYBN{the_other_file_had_the_key}"


def zipcrypto(path: Path, name: str, body: bytes, password: str) -> None:
    """A ZipCrypto archive. Python writes no encrypted ZIP, so `zip` does it."""
    plain = path.parent / name
    plain.write_bytes(body)
    subprocess.run(
        ["zip", "-q", "-e", "-P", password, str(path), name],
        cwd=path.parent,
        check=True,
    )
    plain.unlink()


@pytest.fixture
def folder_with_a_password_elsewhere(tmp_path):
    """A mail that says the password, and an encrypted archive in another file."""
    (tmp_path / "mail.txt").write_bytes(
        b"From: admin@corp.local\n\nI zipped the files. The password is Tr0ub4dor&3.\n"
    )
    (tmp_path / "readme.txt").write_bytes(b"Nothing to see in this one.\n")
    zipcrypto(tmp_path / "backup.zip", "flag.txt", FLAG.encode(), "Tr0ub4dor&3")
    return tmp_path


@pytest.fixture
def folder_with_a_key_in_a_dump(tmp_path):
    """An AES key written at an arbitrary offset of a dump; the blob is elsewhere."""
    rnd = random.Random(11)
    key = bytes(rnd.randrange(256) for _ in range(32))
    iv = bytes(rnd.randrange(256) for _ in range(16))
    plaintext = f"{FLAG} plus enough ordinary English text to score as readable.\n".encode()
    (tmp_path / "payload.enc").write_bytes(
        iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    )

    # A dump that looks like one: strings, structures, zeroes - and the key at
    # an offset that is not a multiple of 16, which is where a *written* key
    # ends up (an allocated one would be aligned).
    chunk = b"C:\\Windows\\System32\\lsass.exe\x00" + bytes(48) + b"user=alice;sid=S-1-5-21\x00\x00"
    dump = bytearray()
    while len(dump) < 20_000:
        dump += chunk
    dump[9_997 : 9_997 + 32] = key
    (tmp_path / "memory.raw").write_bytes(bytes(dump))
    return tmp_path, key


def run(root: Path, seconds: float = 40.0) -> workspace.WorkspaceReport:
    return workspace.analyse(root, budget=Budget(max_attempts=5_000_000, max_seconds=seconds))


# ---------------------------------------------------------------------------
# The two shapes the command exists for
# ---------------------------------------------------------------------------


def test_the_password_in_the_mail_opens_the_archive(folder_with_a_password_elsewhere):
    report = run(folder_with_a_password_elsewhere)

    assert FLAG in report.flags
    assert len(report.hits) == 1
    hit = report.hits[0]
    assert hit.secret == "Tr0ub4dor&3"
    assert hit.secret_where.endswith("mail.txt")
    assert "backup.zip" in hit.target
    assert "unzip" in hit.command and "Tr0ub4dor&3" in hit.command


def test_the_key_in_the_dump_opens_the_blob(folder_with_a_key_in_a_dump):
    root, key = folder_with_a_key_in_a_dump
    report = run(root)

    assert FLAG in report.flags
    assert len(report.hits) == 1
    hit = report.hits[0]
    assert hit.secret == key.hex()
    assert "memory.raw" in hit.secret_where
    assert "payload.enc" in hit.target
    assert hit.command.startswith("ctfc keys ")


# ---------------------------------------------------------------------------
# The pools, and what is reported when nothing worked
# ---------------------------------------------------------------------------


def test_secrets_come_from_configs_and_from_sentences(tmp_path):
    (tmp_path / "app.ini").write_bytes(b"[db]\nhost = 10.0.0.5\ndb_password = hunter2\n")
    (tmp_path / "note.txt").write_bytes(b"ping me; mdp : azerty123 for the share\n")
    report = run(tmp_path, seconds=10)

    values = {found.value for found in report.secrets}
    assert "hunter2" in values
    assert "azerty123" in values
    assert "10.0.0.5" not in values  # a host is not a secret


def test_an_archive_python_cannot_open_is_reported_not_skipped_silently(fixture_bytes, tmp_path):
    (tmp_path / "archive_aes.7z").write_bytes(fixture_bytes("archive_aes.7z"))
    (tmp_path / "note.txt").write_bytes(b"The password is swordfish.\n")
    report = run(tmp_path, seconds=15)

    assert report.hits == []
    assert any(target.kind == "archive" and not target.testable for target in report.ciphertexts)
    assert any("7z x" in line for line in report.skipped)


def test_nothing_in_an_empty_folder(tmp_path):
    report = run(tmp_path, seconds=5)
    assert report.files == 0
    assert report.notes


def test_a_missing_folder_is_a_note_not_a_crash(tmp_path):
    report = run(tmp_path / "nope", seconds=5)
    assert report.hits == []
    assert any("does not exist" in note for note in report.notes)


def test_the_budget_is_shared_and_what_is_left_is_named(tmp_path):
    """A folder of blobs with no secret: the walk must stop and say where."""
    rnd = random.Random(5)
    for index in range(12):
        (tmp_path / f"blob{index}.enc").write_bytes(
            b"Salted__" + bytes(rnd.randrange(256) for _ in range(256))
        )
    (tmp_path / "words.txt").write_bytes(
        b"\n".join(f"password = guess{index}".encode() for index in range(40))
    )
    report = workspace.analyse(tmp_path, budget=Budget(max_attempts=1_000_000, max_seconds=3))

    assert report.hits == []
    assert report.skipped or report.notes


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_a_memory_dump_is_a_key_source_not_a_ciphertext(folder_with_a_key_in_a_dump):
    root, _key = folder_with_a_key_in_a_dump
    report = run(root)
    names = [target.name for target in report.ciphertexts]
    assert not any("memory.raw" in name for name in names)


def test_a_short_random_payload_is_a_ciphertext():
    rnd = random.Random(3)
    data = bytes(rnd.randrange(256) for _ in range(96))
    assert workspace._looks_like_a_blob(data, "payload.enc")


def test_text_is_not_a_ciphertext():
    assert not workspace._looks_like_a_blob(b"an ordinary sentence, repeated. " * 8, "notes.txt")


def test_report_round_trips_through_json(folder_with_a_password_elsewhere):
    import json

    report = run(folder_with_a_password_elsewhere)
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["hits"][0]["secret"] == "Tr0ub4dor&3"
    assert "sources" not in payload  # working memory, not a result


# ---------------------------------------------------------------------------
# The unaligned key hunt this feature needed
# ---------------------------------------------------------------------------


def test_keyhunt_finds_a_key_written_at_an_odd_offset():
    from ctfc.core import keyhunt

    rnd = random.Random(17)
    key = bytes(rnd.randrange(256) for _ in range(32))
    dump = bytearray(b"name=value;path=/usr/local/bin;\x00\x00\x00\x00" * 300)
    dump[1_003 : 1_003 + 32] = key  # 1003 is not a multiple of 16, nor of 4

    runs = keyhunt.find_entropy_runs(bytes(dump))
    assert any(candidate.key == key for candidate in runs)
    # And the 16-aligned pass alone does not find it, which is why runs exist.
    aligned = keyhunt.find_entropy_windows(bytes(dump))
    assert not any(candidate.key == key for candidate in aligned)


def test_zip_hit_needs_the_right_password(folder_with_a_password_elsewhere):
    """The ZIP test must not accept a wrong password: the CRC is what decides."""
    archive = folder_with_a_password_elsewhere / "backup.zip"
    target = workspace.Ciphertext(
        name="backup.zip",
        path=str(archive),
        kind="zip",
        data=archive.read_bytes(),
        entry="flag.txt",
    )
    assert workspace._try_zip(target, b"wrong") is None
    opened = workspace._try_zip(target, b"Tr0ub4dor&3")
    assert opened is not None and FLAG.encode() in opened[0]


def test_an_encrypted_zip_without_the_password_in_the_folder(tmp_path):
    zipcrypto(tmp_path / "locked.zip", "flag.txt", FLAG.encode(), "notinthisfolder")
    (tmp_path / "decoy.txt").write_bytes(b"password = wrongone\n")
    report = run(tmp_path, seconds=10)

    assert report.hits == []
    assert report.tried >= 1
    assert any(target.kind == "zip" for target in report.ciphertexts)


def test_zipfile_is_only_trusted_for_zipcrypto(tmp_path):
    """A WinZip AES entry is reported as not testable here, with the 7z line."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.txt", "plain")
    (tmp_path / "plain.zip").write_bytes(buf.getvalue())
    report = run(tmp_path, seconds=5)
    # Nothing encrypted at all here: the ZIP is not listed as a ciphertext.
    assert report.ciphertexts == []
