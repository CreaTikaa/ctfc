"""Tests for reading deleted rows out of a SQLite database (core/sqlitedb.py)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ctfc.core import sqlitedb

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def db_path() -> Path:
    return FIXTURES / "audit_notes.sqlite"


# ---------------------------------------------------------------------------
# Format primitives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"\x00", 0),
        (b"\x7f", 127),
        (b"\x81\x00", 128),
        (b"\x82\x2c", 300),
        # Nine bytes: eight carry 7 bits each, the ninth a full 8 = 64 bits.
        (b"\xff" * 8 + b"\xff", (1 << 64) - 1),
    ],
)
def test_varint_reads_sqlites_big_endian_form(raw, expected):
    value, position = sqlitedb.varint(raw, 0)
    assert position == len(raw)
    assert value == expected


def test_varint_past_the_end_raises():
    with pytest.raises(sqlitedb.SqliteError, match="past the end"):
        sqlitedb.varint(b"\x81", 0)


def test_a_non_database_is_refused():
    with pytest.raises(sqlitedb.SqliteError, match="not a SQLite database"):
        sqlitedb.read_header(b"PK\x03\x04" + bytes(200))


def test_a_truncated_header_is_refused():
    with pytest.raises(sqlitedb.SqliteError, match="truncated"):
        sqlitedb.read_header(sqlitedb.MAGIC + bytes(10))


def test_page_size_of_one_means_65536():
    """SQLite writes 65536 as 1, because it does not fit in two bytes."""
    header = bytearray(sqlitedb.MAGIC + bytes(100))
    header[16:18] = (1).to_bytes(2, "big")
    assert sqlitedb.read_header(bytes(header)).page_size == 65536


def test_an_implausible_page_size_is_refused():
    header = bytearray(sqlitedb.MAGIC + bytes(100))
    header[16:18] = (777).to_bytes(2, "big")  # not a power of two
    with pytest.raises(sqlitedb.SqliteError, match="implausible page size"):
        sqlitedb.read_header(bytes(header))


# ---------------------------------------------------------------------------
# Records and cells
# ---------------------------------------------------------------------------


def build_record(values: list[object]) -> bytes:
    """Serialise a record the way SQLite does, to test the decoder against it."""
    kinds = bytearray()
    body = bytearray()
    for value in values:
        if value is None:
            kinds.append(0)
        elif isinstance(value, int):
            kinds.append(6)
            body += value.to_bytes(8, "big", signed=True)
        elif isinstance(value, str):
            encoded = value.encode()
            kinds.append(13 + len(encoded) * 2)
            body += encoded
        else:
            kinds.append(12 + len(value) * 2)
            body += value
    header = bytes([len(kinds) + 1]) + bytes(kinds)
    return header + bytes(body)


def build_cell(rowid: int, values: list[object]) -> bytes:
    record = build_record(values)
    return bytes([len(record)]) + bytes([rowid]) + record


def test_a_record_round_trips():
    values = ["hello", 42, None, b"\x01\x02\x03\x04\x05"]
    decoded = sqlitedb.decode_record(build_record(values), 0)
    assert decoded is not None
    assert decoded[0] == values


def test_a_cell_round_trips_with_its_rowid():
    cell = sqlitedb.decode_cell(build_cell(7, ["flagged", "content here"]), 0)
    assert cell == (7, ["flagged", "content here"])


def test_a_cell_whose_record_does_not_fill_it_is_refused():
    """The declared payload length is what makes carving trustworthy."""
    record = build_record(["abc"])
    bad = bytes([len(record) + 5]) + bytes([1]) + record
    assert sqlitedb.decode_cell(bad, 0) is None


def test_text_that_is_not_utf8_is_refused():
    """A real TEXT column is valid UTF-8; anything else is a misread offset."""
    record = bytes([2, 13 + 2 * 2]) + b"\xff\xfe"
    assert sqlitedb.decode_record(record, 0) is None


def test_a_reserved_serial_type_is_refused():
    assert sqlitedb.decode_record(bytes([2, 10]), 0) is None


def test_noise_almost_never_decodes_as_a_cell():
    """Carving must not turn random bytes into rows."""
    import random

    rng = random.Random(7)
    blob = bytes(rng.randrange(256) for _ in range(20000))
    assert len(sqlitedb.carve(blob, "noise")) <= 2


def test_a_blob_of_mostly_zeroes_is_not_reported_as_a_column():
    """Freed space is largely zeroes, which is the shape a bad decode takes."""
    assert not sqlitedb._worth_keeping([bytes(64)])
    assert sqlitedb._worth_keeping(["a real value"])


def test_control_characters_in_text_reject_the_record():
    assert not sqlitedb._worth_keeping(["ok\x01bad"])


# ---------------------------------------------------------------------------
# The thing the tool exists for
# ---------------------------------------------------------------------------


def test_the_deleted_flag_row_comes_back(db_path):
    report = sqlitedb.analyse(db_path.read_bytes(), db_path)
    assert report.deleted
    best = report.deleted[0]
    assert best.flags == ["CYBN{fixture_sqlite_deleted}"]
    assert best.rowid == 80
    assert "freelist page" in best.where


def test_the_deleted_credentials_row_is_surfaced(db_path):
    report = sqlitedb.analyse(db_path.read_bytes(), db_path)
    row = next(row for row in report.deleted if row.secrets)
    assert row.secrets == ["admin_password = hunter2hunter2"]


def test_the_live_tables_are_read_too(db_path):
    report = sqlitedb.analyse(db_path.read_bytes(), db_path)
    assert report.tables == {"notes": 30}
    assert report.freelist == [3, 4]


def test_carving_works_without_a_path_on_disk(db_path):
    """A pasted database still gives the deleted rows, only not the live counts."""
    report = sqlitedb.analyse(db_path.read_bytes(), None)
    assert report.tables == {}
    assert any(row.flags for row in report.deleted)


def test_the_same_row_is_not_reported_twice(db_path):
    """A freed cell often survives in two regions at once; the report dedupes."""
    report = sqlitedb.analyse(db_path.read_bytes(), db_path)
    texts = [row.text for row in report.deleted]
    assert len(texts) == len(set(texts))


def test_old_copies_of_rows_that_are_still_live_also_come_back(db_path):
    """SQLite moves cells around, so freed space holds superseded copies too.

    That is correct forensic behaviour, not a bug: the row exists now *and* an
    older copy of it is readable. Worth a test so nobody "fixes" it later.
    """
    report = sqlitedb.analyse(db_path.read_bytes(), db_path)
    carved = {value for row in report.deleted for value in row.values if isinstance(value, str)}
    surviving = {f"note {index}" for index in range(50, 80)}
    assert carved & surviving, "expected at least one superseded copy of a live row"


def test_a_secure_delete_database_says_the_rows_are_gone(tmp_path):
    """Debian's SQLite defaults secure_delete ON, so this is worth explaining."""
    path = tmp_path / "wiped.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA secure_delete=ON")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    connection.executemany(
        "INSERT INTO t (v) VALUES (?)", [(f"value number {index} here",) for index in range(1, 200)]
    )
    connection.commit()
    connection.execute("DELETE FROM t WHERE id < 190")
    connection.commit()
    connection.close()
    report = sqlitedb.analyse(path.read_bytes(), path)
    assert report.freelist, "the delete should have released pages"
    assert report.deleted == []
    assert any("secure_delete" in note for note in report.notes)


def test_an_untouched_database_says_the_freelist_is_empty(tmp_path):
    path = tmp_path / "fresh.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE t (v TEXT)")
    connection.execute("INSERT INTO t (v) VALUES ('only row')")
    connection.commit()
    connection.close()
    report = sqlitedb.analyse(path.read_bytes(), path)
    assert report.freelist == []
    assert any("freelist is empty" in note for note in report.notes)
