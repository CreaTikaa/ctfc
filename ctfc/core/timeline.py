"""`ctfc timeline`: every timestamp in a file or a folder, in one table.

A forensics challenge is usually the question *what happened, and in which
order*. The answer is already in the files - a prefetch run time, a shortcut's
three dates, an event log record, a ZIP entry's modification date, a cabinet's,
a PE build stamp, a Docker build step, a mail's Date header - but it takes six
commands to see them and a human to merge them.

Each format reader already reads those fields (`core/readers.py` hands them
back as `Event`s), so this module is plumbing on purpose: walk the files, take
every event, sort, print. Three rules make the table trustworthy:

- **one shape, one zone.** Every event is "YYYY-MM-DD HH:MM:SS UTC", which is
  also why sorting is a plain string comparison. Where a format has no zone at
  all - MS-DOS stamps in ZIP and cabinet entries - the row says so, because
  the value is the writer's local clock and comparing it with a UTC row is
  worth a second of doubt.
- **a forged stamp is evidence.** A date in the future, or one that sits years
  away from everything else in the same file, is **kept** and flagged. Dropping
  it would hide exactly the thing the challenge is about.
- **the source is named.** Every row says which file, and which piece inside
  it, the date came from.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ctfc.core import timestamps
from ctfc.core.budget import Budget
from ctfc.core.flags import FlagSet
from ctfc.core.scan import list_files
from ctfc.core.solve import walk

# Formats that store a date with no time zone: the value is whatever the clock
# of the machine that wrote it said.
LOCAL_CLOCK = ("ZIP entry", "cab member")


@dataclass
class Entry:
    """One row of the timeline."""

    when: str  # "YYYY-MM-DD HH:MM:SS UTC"
    kind: str  # "prefetch run", "ZIP entry modified"...
    what: str  # the program, the member, the record
    source: str  # the file (and the piece inside it) it came from
    note: str = ""  # "in the future", "local clock, no time zone"

    def to_dict(self) -> dict:
        return {
            "when": self.when,
            "kind": self.kind,
            "what": self.what,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class TimelineReport:
    """Every date found, in order."""

    root: str = ""
    files: int = 0
    entries: list[Entry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    budget: str = ""

    @property
    def span(self) -> str:
        if not self.entries:
            return ""
        return f"{self.entries[0].when} .. {self.entries[-1].when}"

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files": self.files,
            "span": self.span,
            "entries": [entry.to_dict() for entry in self.entries],
            "notes": list(self.notes),
            "budget": self.budget,
        }


def _note_for(entry_kind: str, when: str, now: str) -> str:
    """Why this row deserves a second look - or "" when it does not."""
    notes = []
    if any(entry_kind.startswith(prefix) for prefix in LOCAL_CLOCK):
        notes.append("local clock, no time zone")
    if when > now:
        notes.append("in the future: a forged or mis-set clock")
    return "; ".join(notes)


def events_of(
    data: bytes,
    name: str,
    now: str,
    flagset: FlagSet | None,
    budget: Budget,
    notes: list[str],
) -> list[Entry]:
    """Every date one file carries, itself and every piece inside it.

    Bytes in, rows out: nothing here touches the disk, which is why the web page
    (that only ever has bytes) can call it as well as `build` below.
    """
    entries: list[Entry] = []
    for visit in walk(
        data,
        name,
        flagset=flagset,
        budget=budget,
        decode=False,  # a decoding chain has nothing to say about time
        notes=notes,
    ):
        if visit.opened is None:
            continue
        for event in visit.opened.events:
            if not event.when:
                continue
            entries.append(
                Entry(
                    when=event.when,
                    kind=event.kind,
                    what=event.what,
                    source=visit.piece.name,
                    note=_note_for(event.kind, event.when, now),
                )
            )
    return entries


def from_files(
    files: Iterable[tuple[str, bytes]],
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    since: str = "",
    until: str = "",
    root: str = "",
    mtimes: dict[str, float] | None = None,
) -> TimelineReport:
    """The timeline of files given as (name, bytes) pairs.

    `files` may be a list or a generator: `build` hands a generator so that a
    folder of large dumps is read one file at a time, never all at once.

    `mtimes` optionally gives each name's filesystem modification time (a Unix
    timestamp): `build` passes the real ones, the web page passes none.
    """
    budget = budget or Budget(max_attempts=200_000, max_seconds=60)
    report = TimelineReport(root=root)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    entries: list[Entry] = []

    for name, data in files:
        report.files += 1
        if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
            report.notes.append(
                f"budget spent after {len(entries)} date(s): raise --seconds for the rest"
            )
            break
        if mtimes and name in mtimes:
            # The file's own mtime. It is the weakest evidence on the table -
            # copying a folder rewrites it - but its absence is confusing.
            when = timestamps.from_unix(mtimes[name])
            if when:
                short = Path(name).name
                entries.append(
                    Entry(when, "filesystem mtime", short, name, _note_for("", when, now))
                )
        walk_budget = Budget(
            max_attempts=20_000,
            max_seconds=max(0.5, min(5.0, budget.max_seconds - budget.elapsed())),
            cancel_event=budget.cancel_event,
        )
        entries += events_of(data, name, now, flagset, walk_budget, report.notes)
        budget.spend(walk_budget.attempts)

    if since:
        entries = [entry for entry in entries if entry.when >= since]
    if until:
        # "--until 2024-05-01" means the whole of that day.
        entries = [entry for entry in entries if entry.when[:10] <= until[:10]]
    entries.sort(key=lambda entry: entry.when)
    report.entries = entries

    if not entries:
        report.notes.append(
            "no timestamp came out: the formats here record none, or the window "
            "given by --since/--until excludes them all"
        )
    else:
        kinds = len({entry.kind for entry in entries})
        report.notes.append(f"{len(entries)} date(s) from {kinds} kind(s) of record")
    report.budget = budget.summary()
    return report


def build(
    root: Path,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    recursive: bool = True,
    since: str = "",
    until: str = "",
    max_files: int = 500,
    filesystem: bool = True,
) -> TimelineReport:
    """Collect every timestamp under `root` (a file or a folder) and sort them."""
    if not root.exists():
        report = TimelineReport(root=str(root))
        report.notes.append(f"{root} does not exist")
        return report

    paths = [root] if root.is_file() else list_files(root, recursive, max_files)
    unreadable: list[str] = []
    mtimes: dict[str, float] = {}

    def read_one_by_one() -> Iterator[tuple[str, bytes]]:
        for path in paths:
            try:
                data = path.read_bytes()
            except OSError as exc:
                unreadable.append(f"{path}: {exc}")
                continue
            if filesystem:
                mtimes[str(path)] = path.stat().st_mtime
            yield str(path), data

    report = from_files(
        read_one_by_one(), flagset, budget, since=since, until=until, root=str(root), mtimes=mtimes
    )
    report.files = len(paths)
    report.notes[:0] = unreadable
    return report
