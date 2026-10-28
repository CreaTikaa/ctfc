"""Sessions: keep what you did on a challenge, to write it up afterwards.

During a CTF nobody takes notes. A session does it for you: every command run
with `--session <name>` (or after `ctfc session use <name>`) appends one *step*
to the session - the command, the input, the best result with its reasons, the
Python script and the CyberChef recipe. Your own notes go in between
(`ctfc session note`). `ctfc report <name>` then turns all of it into a
Markdown write-up (see report.py).

On disk, one folder per challenge, plain files you can read and edit:

    ~/.ctfc/sessions/<name>/
        session.json   title, CTF, category, the statement, the flag
        steps.jsonl    one JSON object per line, appended (a crash loses nothing)
        inputs/        copies of the input files (up to INPUT_COPY_LIMIT bytes)

Names are restricted to letters, digits, "-" and "_": a session name is a
folder name, and must never be a path (`../../etc`).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.types import Candidate

# CTFC_SESSIONS_DIR overrides the default (the test suite uses it, so running the
# tests never writes into your real sessions).
DEFAULT_DIR = Path(os.environ.get("CTFC_SESSIONS_DIR") or Path.home() / ".ctfc" / "sessions")
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
CURRENT_FILE = ".current"  # in the sessions folder: the session `ctfc session use` chose
INPUT_COPY_LIMIT = 10 * 1024 * 1024  # bigger inputs (memory dumps) are referenced, not copied
PREVIEW_LIMIT = 2000  # characters of output kept per step
PYTHON_LIMIT = 20000


class SessionError(ValueError):
    """A bad session name or a missing session. The message says what to do."""


def check_name(name: str) -> str:
    """A session name is a folder name: letters, digits, - and _ only."""
    if not NAME_RE.fullmatch(name or ""):
        raise SessionError(
            f"bad session name {name!r}: use letters, digits, '-' and '_' (max 64), "
            "e.g. cave-expedition"
        )
    return name


@dataclass
class Meta:
    """What the write-up says about the challenge itself."""

    name: str
    title: str = ""
    ctf: str = ""
    category: str = ""
    description: str = ""  # the challenge statement
    flag: str = ""  # set by `ctfc session flag`, else the best flag the steps found
    created: str = ""

    def display_title(self) -> str:
        return self.title or self.name.replace("-", " ").replace("_", " ").title()


@dataclass
class Entry:
    """One line of steps.jsonl: a command and its result, or a note."""

    kind: str  # "step" or "note"
    time: str
    text: str = ""  # the note, for kind == "note"
    tool: str = ""  # "auto", "xor", "lens"...
    command: str = ""  # the command line, as typed (or rebuilt for the web UI)
    input: dict = field(default_factory=dict)  # name, size, sha256, saved_as
    result: dict = field(default_factory=dict)  # label, score, reasons, preview, python...

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def _now() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


class Session:
    """One challenge's folder. Create it with Session.open(name)."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.name = folder.name

    # -- opening -----------------------------------------------------------

    @classmethod
    def open(cls, name: str, base: Path | None = None, create: bool = True) -> Session:
        """The session called `name` (created when missing, unless create=False)."""
        folder = (base or DEFAULT_DIR) / check_name(name)
        if not folder.is_dir():
            if not create:
                raise SessionError(f"no session {name!r} (ctfc session new {name})")
            (folder / "inputs").mkdir(parents=True)
            session = cls(folder)
            session.save_meta(Meta(name=name, created=_now()))
            return session
        return cls(folder)

    # -- metadata ----------------------------------------------------------

    @property
    def meta_path(self) -> Path:
        return self.folder / "session.json"

    def meta(self) -> Meta:
        try:
            raw = json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        known = {key: raw[key] for key in Meta.__dataclass_fields__ if key in raw}
        known["name"] = self.name
        return Meta(**known)

    def save_meta(self, meta: Meta) -> None:
        self.meta_path.write_text(json.dumps(asdict(meta), indent=2, ensure_ascii=False) + "\n")

    def update_meta(self, **changes: str) -> Meta:
        meta = self.meta()
        for key, value in changes.items():
            if value is not None and key in Meta.__dataclass_fields__ and key != "name":
                setattr(meta, key, value)
        self.save_meta(meta)
        return meta

    # -- entries -----------------------------------------------------------

    @property
    def steps_path(self) -> Path:
        return self.folder / "steps.jsonl"

    def _append(self, entry: Entry) -> Entry:
        with self.steps_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json() + "\n")
        return entry

    def add_note(self, text: str) -> Entry:
        return self._append(Entry(kind="note", time=_now(), text=text.strip()))

    def add_step(
        self,
        tool: str,
        command: str,
        data: bytes | None = None,
        input_name: str = "",
        candidates: list[Candidate] | None = None,
        summary: list[str] | None = None,
        flagset: FlagSet | None = None,
    ) -> Entry:
        """Record one command: its input, and its best result (or a summary)."""
        entry = Entry(kind="step", time=_now(), tool=tool, command=command)
        if data is not None:
            entry.input = self._keep_input(data, input_name)
        if candidates:
            entry.result = result_of(candidates[0], flagset)
            entry.result["others"] = len(candidates) - 1
        if summary:
            entry.result.setdefault("summary", [line[:300] for line in summary[:12]])
        return self._append(entry)

    def _keep_input(self, data: bytes, name: str) -> dict:
        """Describe the input, and copy it into inputs/ when it is not huge."""
        digest = hashlib.sha256(data).hexdigest()
        info = {"name": name or "input", "size": len(data), "sha256": digest}
        if len(data) <= INPUT_COPY_LIMIT:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "input").name)[:60] or "input"
            target = self.folder / "inputs" / f"{digest[:8]}_{safe}"
            if not target.exists():
                target.write_bytes(data)
            info["saved_as"] = f"inputs/{target.name}"
        return info

    def entries(self) -> list[Entry]:
        """Every note and step, in the order they happened."""
        entries = []
        if not self.steps_path.is_file():
            return entries
        for line in self.steps_path.read_text(encoding="utf-8").splitlines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue  # a line cut by a crash: skip it, keep the rest
            known = {key: raw[key] for key in Entry.__dataclass_fields__ if key in raw}
            entries.append(Entry(**known))
        return entries

    def flags(self) -> list[str]:
        """Flags the steps found, best first (the meta flag wins if set)."""
        meta_flag = self.meta().flag
        found = [meta_flag] if meta_flag else []
        for entry in self.entries():
            for flag in entry.result.get("flags", []):
                if flag not in found:
                    found.append(flag)
        return found


def result_of(candidate: Candidate, flagset: FlagSet | None = None) -> dict:
    """The part of a Candidate a write-up needs."""
    text = candidate.data.decode("utf-8", errors="replace")
    flags = [hit.text for hit in find_flags(candidate.data, flagset) if hit.how != "base64-prefix"]
    return {
        "label": candidate.label,
        "score": round(candidate.score, 3),
        "reasons": list(candidate.reasons[:6]),
        "preview": text[:PREVIEW_LIMIT],
        "binary": _looks_binary(candidate.data),
        "length": len(candidate.data),
        "python": (candidate.python or "")[:PYTHON_LIMIT],
        "cyberchef": candidate.cyberchef or "",
        "flags": flags[:3],
    }


def _looks_binary(data: bytes) -> bool:
    sample = data[:512]
    if not sample:
        return False
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample)
    return printable < 0.85 * len(sample)


# ---------------------------------------------------------------------------
# All sessions, and the "current" one
# ---------------------------------------------------------------------------


def list_sessions(base: Path | None = None) -> list[Session]:
    folder = base or DEFAULT_DIR
    if not folder.is_dir():
        return []
    return sorted(
        (
            Session(path)
            for path in folder.iterdir()
            if path.is_dir() and NAME_RE.fullmatch(path.name)
        ),
        key=lambda session: session.name,
    )


def current_session(base: Path | None = None) -> str | None:
    """The session chosen with `ctfc session use <name>`, if any."""
    marker = (base or DEFAULT_DIR) / CURRENT_FILE
    try:
        name = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name if NAME_RE.fullmatch(name) else None


def use_session(name: str | None, base: Path | None = None) -> None:
    """Make `name` the session every command records into (None: stop recording)."""
    folder = base or DEFAULT_DIR
    marker = folder / CURRENT_FILE
    if name is None:
        marker.unlink(missing_ok=True)
        return
    Session.open(name, folder)
    marker.write_text(check_name(name) + "\n", encoding="utf-8")
