"""Read a SQLite database, including the rows it is supposed to have deleted.

Why this exists: browser history, chat apps, Android backups and "notes" apps are
all SQLite, and the interesting row is routinely the one the challenge author
deleted. `DELETE` in SQLite does not erase anything - it unlinks the cell and
puts the space on a free list. Unless the database was built with
`PRAGMA secure_delete=ON` (it almost never is) the old bytes are still there.

Three places hold them:

- **freelist pages**: whole pages released by a `DROP` or a big `DELETE`. Their
  old content is untouched, only the first bytes get reused as list pointers;
- **unallocated space** inside a live page: the gap between the cell pointer
  array and the first live cell, which old cells sit in;
- **freeblocks**: small gaps a `DELETE` left between live cells, chained
  together inside the page.

A deleted cell has no index pointing at it any more, so it has to be *carved*:
try to read a record at each offset and keep the ones that decode cleanly. That
is a heuristic, and it is treated as one - a candidate is only kept when every
one of its columns decodes, its text is valid UTF-8, and it holds something other
than nulls. The live side is read through the standard library's `sqlite3`, which
is exact.

Nothing is executed: the database is opened read-only and immutable, and no SQL
from the file (view, trigger) is ever run.
"""

from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass, field
from pathlib import Path

MAGIC = b"SQLite format 3\x00"
HEADER_SIZE = 100
# Page types, from the first byte of a page's b-tree header.
LEAF_TABLE = 0x0D
INTERIOR_TABLE = 0x05
LEAF_INDEX = 0x0A
INTERIOR_INDEX = 0x02
MAX_COLUMNS = 64  # a carved record claiming more than this is a false match
MAX_TEXT = 64 * 1024
MIN_INTERESTING = 3  # a record needs this many bytes of content to be worth showing


class SqliteError(Exception):
    """The file is not a SQLite database we can read."""


def varint(data: bytes, position: int) -> tuple[int, int]:
    """SQLite's big-endian variable-length integer: (value, new position).

    Up to nine bytes. The first eight carry seven bits each, with the top bit
    saying "another byte follows"; if all eight have it set, a ninth byte
    contributes a full eight bits, which is how 64 bits fit in nine bytes.
    """
    value = 0
    for _ in range(8):
        if position >= len(data):
            raise SqliteError("varint runs past the end")
        byte = data[position]
        position += 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, position
    if position >= len(data):
        raise SqliteError("varint runs past the end")
    return (value << 8) | data[position], position + 1


@dataclass
class DbHeader:
    """The parts of the 100-byte file header we need."""

    page_size: int
    pages: int
    freelist_trunk: int
    freelist_count: int
    reserved: int
    secure_delete: bool = False


def read_header(data: bytes) -> DbHeader:
    if data[:16] != MAGIC:
        raise SqliteError("not a SQLite database (the file must start with 'SQLite format 3')")
    if len(data) < HEADER_SIZE:
        raise SqliteError("truncated: the header alone is 100 bytes")
    raw_size = int.from_bytes(data[16:18], "big")
    # 1 is the documented way of writing 65536, which does not fit in two bytes.
    page_size = 65536 if raw_size == 1 else raw_size
    if page_size < 512 or page_size & (page_size - 1):
        raise SqliteError(f"implausible page size {page_size}")
    return DbHeader(
        page_size=page_size,
        pages=int.from_bytes(data[28:32], "big"),
        freelist_trunk=int.from_bytes(data[32:36], "big"),
        freelist_count=int.from_bytes(data[36:40], "big"),
        reserved=data[20],
    )


def page_bytes(data: bytes, header: DbHeader, number: int) -> bytes:
    """Page `number` (1-based, as SQLite counts them)."""
    start = (number - 1) * header.page_size
    if number < 1 or start + header.page_size > len(data):
        return b""
    return data[start : start + header.page_size]


def freelist(data: bytes, header: DbHeader) -> list[int]:
    """The freelist page numbers, by walking the trunk pages.

    A trunk page holds the next trunk's number, a count, and then that many leaf
    page numbers. Those leaves are whole pages whose old content is still intact.
    """
    pages: list[int] = []
    trunk = header.freelist_trunk
    seen: set[int] = set()
    while trunk and trunk not in seen and len(pages) <= header.freelist_count + 1:
        seen.add(trunk)
        page = page_bytes(data, header, trunk)
        if len(page) < 8:
            break
        next_trunk = int.from_bytes(page[0:4], "big")
        count = int.from_bytes(page[4:8], "big")
        if count > (header.page_size - 8) // 4:
            break  # nonsense count: a damaged or encrypted file
        for index in range(count):
            offset = 8 + index * 4
            number = int.from_bytes(page[offset : offset + 4], "big")
            if number:
                pages.append(number)
        pages.append(trunk)  # the trunk itself was a page once too
        trunk = next_trunk
    return pages


def free_regions(page: bytes, is_first: bool) -> list[tuple[int, bytes]]:
    """The unallocated gap and the freeblocks of a live leaf-table page.

    Returns (offset in page, bytes). The gap between the end of the cell pointer
    array and the first live cell is where a deleted cell most often survives.
    """
    base = HEADER_SIZE if is_first else 0
    if len(page) < base + 8 or page[base] != LEAF_TABLE:
        return []
    first_free = int.from_bytes(page[base + 1 : base + 3], "big")
    cells = int.from_bytes(page[base + 3 : base + 5], "big")
    content_start = int.from_bytes(page[base + 5 : base + 7], "big")
    if content_start == 0:
        content_start = 65536
    pointer_end = base + 8 + cells * 2
    regions: list[tuple[int, bytes]] = []
    if 0 < pointer_end < content_start <= len(page):
        regions.append((pointer_end, page[pointer_end:content_start]))
    # The freeblock chain: each block holds the next block's offset and its size.
    offset = first_free
    seen: set[int] = set()
    while 0 < offset < len(page) - 4 and offset not in seen:
        seen.add(offset)
        size = int.from_bytes(page[offset + 2 : offset + 4], "big")
        if size < 4 or offset + size > len(page):
            break
        regions.append((offset, page[offset : offset + size]))
        offset = int.from_bytes(page[offset : offset + 2], "big")
    return regions


def _serial_size(kind: int) -> int | None:
    """How many bytes a column of this serial type occupies."""
    sizes = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
    if kind in sizes:
        return sizes[kind]
    if kind in (10, 11):
        return None  # reserved: a record using them is not a real record
    return (kind - 12) // 2 if kind % 2 == 0 else (kind - 13) // 2


def decode_record(data: bytes, position: int) -> tuple[list[object], int] | None:
    """Decode one record and say where it ends: (values, end offset), or None.

    Returns None whenever anything does not add up, which is what makes carving
    usable: a wrong offset almost always fails one of these checks.
    """
    try:
        header_length, cursor = varint(data, position)
    except SqliteError:
        return None
    header_end = position + header_length
    if header_length < 2 or header_end > len(data):
        return None
    kinds: list[int] = []
    while cursor < header_end:
        try:
            kind, cursor = varint(data, cursor)
        except SqliteError:
            return None
        kinds.append(kind)
        if len(kinds) > MAX_COLUMNS:
            return None
    if cursor != header_end or not kinds:
        return None

    values: list[object] = []
    body = header_end
    for kind in kinds:
        size = _serial_size(kind)
        if size is None or size < 0 or body + size > len(data) or size > MAX_TEXT:
            return None
        chunk = data[body : body + size]
        body += size
        if kind == 0:
            values.append(None)
        elif 1 <= kind <= 6:
            values.append(int.from_bytes(chunk, "big", signed=True))
        elif kind == 7:
            values.append(struct.unpack(">d", chunk)[0])
        elif kind == 8:
            values.append(0)
        elif kind == 9:
            values.append(1)
        elif kind % 2 == 0:
            values.append(chunk)  # blob
        else:
            try:
                values.append(chunk.decode("utf-8"))
            except UnicodeDecodeError:
                return None  # a real TEXT column is valid UTF-8
    return values, body


def decode_cell(data: bytes, position: int) -> tuple[int, list[object]] | None:
    """Decode a whole leaf-table cell: (rowid, values), or None.

    This is the anchor that makes carving trustworthy. A cell is
    `payload length, rowid, record`, so the payload length states exactly how
    many bytes the record must occupy - and a record decoded at the wrong offset
    practically never comes out the declared length. Without that check, carving
    reports a lot of plausible-looking rubbish.
    """
    try:
        payload_length, cursor = varint(data, position)
        rowid, cursor = varint(data, cursor)
    except SqliteError:
        return None
    if not MIN_INTERESTING <= payload_length <= len(data) or rowid < 0:
        return None
    decoded = decode_record(data, cursor)
    if decoded is None:
        return None
    values, end = decoded
    if end - cursor != payload_length:
        return None  # the record did not fill the cell: wrong offset
    return rowid, values


def _worth_keeping(values: list[object]) -> bool:
    """Is this carved record real content rather than a lucky decode of noise?"""
    if all(value is None for value in values):
        return False
    size = 0
    for value in values:
        if isinstance(value, str):
            # Control characters in a text column mean we mis-read the offsets.
            if any(char < " " and char not in "\t\n\r" for char in value):
                return False
            size += len(value)
        elif isinstance(value, bytes):
            # Freed space is largely zeroes, so a "blob" of them is the shape a
            # mis-aligned decode takes, not a column anybody stored.
            if len(value) > 4 and value.count(0) > len(value) // 2:
                return False
            size += len(value)
        elif value is not None:
            size += 1
    return size >= MIN_INTERESTING


@dataclass
class DeletedRow:
    """A record carved out of space the database considers free."""

    values: list[object]
    where: str
    rowid: int | None = None  # known when the whole cell was recovered
    flags: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " | ".join("" if value is None else str(value) for value in self.values)


def carve(blob: bytes, where: str, limit: int = 200) -> list[DeletedRow]:
    """Try to read a whole cell at every offset of `blob` and keep what decodes.

    Every offset is tried, because a deleted cell has nothing pointing at it any
    more. The cell's declared payload length is what keeps this honest: a record
    read at the wrong offset almost never comes out exactly that long.
    """
    rows: list[DeletedRow] = []
    position = 0
    while position < len(blob) and len(rows) < limit:
        cell = decode_cell(blob, position)
        if cell is not None and _worth_keeping(cell[1]):
            rowid, values = cell
            rows.append(DeletedRow(values=values, where=where, rowid=rowid))
        position += 1
    return rows


@dataclass
class SqliteReport:
    """What the database holds, live and deleted."""

    page_size: int = 0
    pages: int = 0
    freelist: list[int] = field(default_factory=list)
    tables: dict[str, int] = field(default_factory=dict)
    deleted: list[DeletedRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "page_size": self.page_size,
            "pages": self.pages,
            "freelist": list(self.freelist),
            "tables": dict(self.tables),
            "deleted": [
                {
                    "values": [_jsonable(value) for value in row.values],
                    "where": row.where,
                    "rowid": row.rowid,
                    "flags": list(row.flags),
                    "secrets": list(row.secrets),
                }
                for row in self.deleted
            ],
            "notes": list(self.notes),
        }


def _jsonable(value: object) -> object:
    return value.hex() if isinstance(value, bytes) else value


def live_tables(path: Path) -> tuple[dict[str, int], list[str]]:
    """Table names and their row counts, read with the standard library.

    Opened read-only and immutable, so nothing in the file can be modified and
    no locking is attempted on a sample that may sit on a read-only medium.
    """
    counts: dict[str, int] = {}
    notes: list[str] = []
    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return counts, [f"the live tables could not be read ({exc}); carving still works"]
    try:
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )
        names = [row[0] for row in cursor.fetchall()]
        for name in names:
            if not name.replace("_", "").isalnum():
                notes.append(f"table {name!r} has an unusual name: skipped")
                continue
            try:
                # The name is checked above, and a table name cannot be bound.
                total = connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            except sqlite3.Error:
                continue
            counts[name] = total
    except sqlite3.Error as exc:
        notes.append(f"the schema could not be read: {exc}")
    finally:
        connection.close()
    return counts, notes


def analyse(data: bytes, path: Path | None = None, flagset=None) -> SqliteReport:
    """Read the database and carve the rows it thinks it deleted."""
    from ctfc.core import secrets as secrets_module
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    header = read_header(data)
    report = SqliteReport(page_size=header.page_size, pages=header.pages)
    report.freelist = sorted(set(freelist(data, header)))

    if path is not None and path.is_file():
        report.tables, notes = live_tables(path)
        report.notes += notes

    # Whole pages the database released: their old content is untouched.
    for number in report.freelist:
        page = page_bytes(data, header, number)
        if page:
            # The first 8 bytes are reused as freelist pointers, the rest is old data.
            report.deleted += carve(page[8:], f"freelist page {number}")
    # Gaps inside live pages.
    for number in range(1, min(header.pages, len(data) // header.page_size) + 1):
        if number in report.freelist:
            continue
        page = page_bytes(data, header, number)
        for offset, blob in free_regions(page, is_first=number == 1):
            report.deleted += carve(blob, f"page {number} free space at {offset}")

    # Drop duplicates: the same row often sits in both a gap and a freeblock.
    unique: list[DeletedRow] = []
    seen: set[str] = set()
    for row in report.deleted:
        if row.text in seen:
            continue
        seen.add(row.text)
        row.flags = [hit.text for hit in find_flags(row.text.encode(), flagset)]
        # One value per line, not the pipe-joined display form: secrets.py looks
        # for `name = value` the way a config file writes it.
        as_config = "\n".join(str(value) for value in row.values if isinstance(value, str)).encode()
        row.secrets = [
            f"{secret.name} = {secret.value}" for secret in secrets_module.find_secrets(as_config)
        ]
        unique.append(row)
    report.deleted = sorted(
        unique, key=lambda row: (not row.flags, not row.secrets, -len(row.text))
    )

    if not report.freelist:
        report.notes.append(
            "the freelist is empty: nothing was deleted, or the database was "
            "VACUUMed afterwards (which really does erase it)"
        )
    elif not report.deleted:
        # Debian's own SQLite ships with secure_delete ON, so a database made on
        # this machine really is wiped - while a browser's or an app's is not.
        report.notes.append(
            f"{len(report.freelist)} freelist page(s) but nothing carved out of them: "
            "they are zeroed, so this database was written with secure_delete on and "
            "the deleted rows are genuinely gone"
        )
    if report.deleted:
        report.notes.append(
            f"{len(report.deleted)} record(s) carved out of free space: these are rows "
            "the database considers deleted. Carving is a heuristic - read them, do not "
            "trust the column order blindly"
        )
    return report
