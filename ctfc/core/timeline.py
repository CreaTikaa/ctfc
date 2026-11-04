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
    budget = budget or Budget(max_attempts=200_000, max_seconds=60)
    report = TimelineReport(root=str(root))
    if not root.exists():
        report.notes.append(f"{root} does not exist")
        return report

    paths = [root] if root.is_file() else list_files(root, recursive, max_files)
    report.files = len(paths)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    entries: list[Entry] = []

    for path in paths:
        if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
            report.notes.append(
                f"budget spent after {len(entries)} date(s): raise --seconds for the rest"
            )
            break
        try:
            data = path.read_bytes()
        except OSError as exc:
            report.notes.append(f"{path}: {exc}")
            continue

        if filesystem:
            # The file's own mtime. It is the weakest evidence on the table -
            # copying a folder rewrites it - but its absence is confusing.
            when = timestamps.from_unix(path.stat().st_mtime)
            if when:
                entries.append(
                    Entry(when, "filesystem mtime", path.name, str(path), _note_for("", when, now))
                )

        walk_budget = Budget(
            max_attempts=20_000,
            max_seconds=max(0.5, min(5.0, budget.max_seconds - budget.elapsed())),
            cancel_event=budget.cancel_event,
        )
        for visit in walk(
            data,
            str(path),
            flagset=flagset,
            budget=walk_budget,
            decode=False,  # a decoding chain has nothing to say about time
            notes=report.notes,
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
