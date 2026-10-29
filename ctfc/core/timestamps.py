"""Read a number as a date, across the epochs forensics actually runs into.

A challenge hands you `133476575820000000` or `13350574800000000` or
`1700000000`, and the only question is which clock it came from. They are all
"time since an epoch" - what differs is *when* the epoch is and *how big* the
tick is:

    Unix            seconds since 1970-01-01            1700000000
    Unix ms / us    the same, finer                     1700000000000
    Windows FILETIME 100-nanosecond ticks since 1601    133476575820000000
    WebKit/Chrome   microseconds since 1601             13350574800000000
    Mac absolute    seconds since 2001 (Core Data)      720000000
    Active Directory same ticks as FILETIME             133476575820000000
    DOS             a packed 32-bit date+time field     0x5A3C1234

So the useful answer is not one date but the shortlist of readings that land in a
plausible range, with the epoch named. Anything that comes out before 1990 or
after 2100 is dropped: those are the readings that are wrong, and keeping them
would bury the one that is right.

Pure functions; nothing here needs the network or a tzdata database beyond UTC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# Epoch offsets, as seconds before the Unix epoch.
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# A reading outside this window is the wrong interpretation, not a strange date.
EARLIEST = datetime(1990, 1, 1, tzinfo=UTC)
LATEST = datetime(2100, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class Reading:
    """One way of reading the number, and the date it gives."""

    epoch: str  # the name a forensic report would use
    when: datetime
    note: str = ""

    @property
    def text(self) -> str:
        return self.when.strftime("%Y-%m-%d %H:%M:%S UTC")


def _plausible(when: datetime) -> bool:
    return EARLIEST <= when <= LATEST


def _safe(epoch: datetime, seconds: float, name: str, note: str = "") -> Reading | None:
    """Build a reading, dropping the ones that overflow or land absurdly.

    Two filters. The date has to fall in the 1990..2100 window, and it has to be
    more than a day past its own epoch: landing *on* the epoch means the number
    is far too small for that clock's tick size, which is how a 10-digit Unix
    timestamp used to come out as "2001-01-01 00:00:01, Mac nanoseconds".
    """
    try:
        when = epoch + timedelta(seconds=seconds)
    except (OverflowError, OSError, ValueError):
        return None
    if when - epoch < timedelta(days=1):
        return None
    return Reading(name, when, note) if _plausible(when) else None


def decode_dos(value: int) -> Reading | None:
    """A DOS/ZIP packed date: high 16 bits the date, low 16 the time."""
    if not 0 <= value <= 0xFFFFFFFF:
        return None
    date, time = value >> 16, value & 0xFFFF
    year = 1980 + (date >> 9)
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = time >> 11
    minute = (time >> 5) & 0x3F
    second = (time & 0x1F) * 2
    try:
        when = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=UTC)
    except ValueError:
        return None
    return (
        Reading("DOS / ZIP packed date", when, "as stored in a ZIP entry")
        if _plausible(when)
        else None
    )


def readings(value: int) -> list[Reading]:
    """Every plausible way of reading `value` as a moment in time, best first.

    "Best" means the finest tick that still lands in range, because a number big
    enough to be FILETIME is never also a plausible Unix timestamp.
    """
    found: list[Reading | None] = [
        _safe(UNIX_EPOCH, value, "Unix seconds"),
        _safe(UNIX_EPOCH, value / 1_000, "Unix milliseconds"),
        _safe(UNIX_EPOCH, value / 1_000_000, "Unix microseconds"),
        _safe(UNIX_EPOCH, value / 1_000_000_000, "Unix nanoseconds"),
        _safe(
            FILETIME_EPOCH,
            value / 10_000_000,
            "Windows FILETIME",
            "100-nanosecond ticks since 1601; also Active Directory and Kerberos",
        ),
        _safe(
            FILETIME_EPOCH,
            value / 1_000_000,
            "WebKit / Chrome",
            "microseconds since 1601; Chrome history and cookies",
        ),
        _safe(MAC_EPOCH, value, "Mac absolute time", "seconds since 2001; Core Data, iOS"),
        decode_dos(value),
    ]
    unique: list[Reading] = []
    seen: set[str] = set()
    for reading in found:
        if reading is None or reading.text in seen:
            continue
        seen.add(reading.text)
        unique.append(reading)
    return unique


def from_bytes(data: bytes) -> list[tuple[str, list[Reading]]]:
    """Read an 8- or 4-byte field as a timestamp, both byte orders.

    Windows writes FILETIME little-endian, so a raw field lifted out of a binary
    needs both tried before it means anything.
    """
    results: list[tuple[str, list[Reading]]] = []
    for size in (8, 4):
        if len(data) != size:
            continue
        for order in ("little", "big"):
            value = int.from_bytes(data, order)
            found = readings(value)
            if found:
                results.append((f"{size} bytes, {order}-endian ({value})", found))
    return results
