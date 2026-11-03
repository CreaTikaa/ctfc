"""Watch a folder and triage whatever lands in it.

The shape this exists for: a challenge that drips files out. A capture is
extracted, then the files it carried, then the archive one of those turns out to
be - and each time the question is the same ("what is this, and is the flag in
it?"), asked by hand, one file at a time.

`ctfc watch <folder>` asks it automatically. Every new or changed file gets a
`detect` fingerprint and a short `auto` run, and only the answer is printed: one
line per file, plus the flag when there is one.

Two details decide whether something like this is usable or merely clever:

- **a file being written is not a file yet.** A download or an extraction
  appears at size 0 and grows; triaging it then gives a confident "this is not a
  ZIP" about the first 4 KB of one. So a file is only read once its size has
  stopped changing between two passes - which is also why `watch` reports a file
  one pass after it appears.
- **the budget has to be small.** This runs while the user is doing something
  else, so each file gets a couple of seconds, not the thirty a deliberate
  `ctfc auto` would take. A file that deserves more says so in its line and the
  user runs the real command on it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.detect import detect
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.magic import match_signature

# A file this big is not triaged automatically: `ctfc detect` on a 2 GB memory
# dump is a deliberate act, not something to do in the background.
MAX_SIZE = 64 << 20
# How long each file gets. Deliberately small: see the module docstring.
SECONDS_PER_FILE = 2.0
ATTEMPTS_PER_FILE = 400
POLL_SECONDS = 1.0


@dataclass
class Finding:
    """What one file turned out to be."""

    path: Path  # relative to the watched folder, which is what the user reads
    size: int
    kind: str = ""  # the file type, or the charset detect reports
    summary: str = ""  # the one line printed for this file
    flags: list[str] = field(default_factory=list)
    chain: str = ""  # the decoding chain `auto` found, when it found one
    next_command: str = ""  # what to run on this file to go further
    skipped: str = ""  # why it was not read, when it was not

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "size": self.size,
            "kind": self.kind,
            "summary": self.summary,
            "flags": list(self.flags),
            "chain": self.chain,
            "next_command": self.next_command,
            "skipped": self.skipped,
        }


def triage(path: Path, flagset: FlagSet | None = None) -> Finding:
    """Fingerprint one file and have a short go at decoding it."""
    size = path.stat().st_size
    finding = Finding(path=path, size=size)
    if size == 0:
        finding.skipped = "empty"
        finding.summary = "empty file"
        return finding
    if size > MAX_SIZE:
        finding.skipped = f"{size} bytes is over the {MAX_SIZE}-byte watch limit"
        finding.summary = f"{size} bytes: too big to triage in the background"
        finding.next_command = f"ctfc detect {path}"
        return finding

    data = path.read_bytes()
    signature = match_signature(data)
    report = detect(data, flagset)
    finding.kind = signature.name if signature is not None else report.charset or "data"

    found = [hit.text for hit in find_flags(data, flagset)]
    budget = Budget(max_attempts=ATTEMPTS_PER_FILE, max_seconds=SECONDS_PER_FILE)
    candidates = auto_decode(data, flagset=flagset, budget=budget, top_n=1)
    if candidates:
        best = candidates[0]
        finding.chain = best.label
        found += [hit.text for hit in find_flags(best.data, flagset)]

    seen: list[str] = []
    for text in found:
        if text not in seen:
            seen.append(text)
    finding.flags = seen

    # The first guess detect is confident about is the best "what next" there is.
    for guess in report.guesses:
        if guess.next_step:
            finding.next_command = guess.next_step
            break
    parts = [f"{size} bytes", finding.kind]
    if finding.chain:
        parts.append(f"auto: {finding.chain}")
    if finding.flags:
        parts.append("FLAG: " + ", ".join(finding.flags))
    finding.summary = " | ".join(parts)
    return finding


class Watcher:
    """The folder watch, as an object so a caller can run one pass or many."""

    def __init__(
        self, folder: Path, flagset: FlagSet | None = None, recursive: bool = True
    ) -> None:
        self.folder = Path(folder)
        if not self.folder.is_dir():
            raise ValueError(f"{self.folder} is not a folder")
        self.flagset = flagset
        self.recursive = recursive
        self.state: dict[Path, tuple[int, float]] = {}
        self.done: set[Path] = set()

    def pass_once(self) -> list[Finding]:
        """One pass: triage every file that is new or changed and has settled."""
        findings: list[Finding] = []
        pattern = "**/*" if self.recursive else "*"
        for path in sorted(self.folder.glob(pattern)):
            if not path.is_file() or path in self.done:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            state = (stat.st_size, stat.st_mtime)
            if self.state.get(path) != state:
                self.state[path] = state  # seen for the first time, or still growing
                continue
            self.done.add(path)
            finding = triage(path, self.flagset)
            # A full path buries the answer at the end of the line; the folder is
            # already in the header.
            finding.path = path.relative_to(self.folder)
            findings.append(finding)
        return findings

    def catch_up(self) -> list[Finding]:
        """Triage what is already in the folder, without waiting a pass.

        The settle rule exists for files that arrive *while* watching; the ones
        that were there before `ctfc watch` started are not being written, so
        making the user wait a second for them would be theatre.
        """
        self.pass_once()  # record the sizes
        return self.pass_once()  # and now triage them

    def run(self, seconds: float = POLL_SECONDS, passes: int | None = None):
        """Poll the folder, yielding findings as they come. Runs until stopped."""
        count = 0
        while passes is None or count < passes:
            yield from self.pass_once()
            count += 1
            if passes is None or count < passes:
                time.sleep(seconds)
