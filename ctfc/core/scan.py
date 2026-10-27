"""Scan a whole folder: run detect + auto on every file and rank what looks interesting.

The situation this is for: `binwalk -e`, `foremost`, `zsteg`, or Wireshark's
"export objects" have just dropped two hundred files in a folder, and one of them
holds the flag. Opening them one by one is exactly the kind of work a tool should
do for you.

For each file ctfc runs the same two things you would run by hand - `detect` for
the fingerprint, `auto` for the decoding chains - keeps the best result, and sorts
the folder by how promising it is. Everything is budgeted: a 200-file folder must
not take ten minutes, so each file gets a slice and the scan stops when the whole
budget is spent (it says so, and the partial ranking is still printed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.detect import detect
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.magic import match_signature
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

# Files bigger than this are fingerprinted but not pushed through `auto`: the
# decoding chains are for payloads, not for disk images.
AUTO_SIZE_LIMIT = 2 * 1024 * 1024
# Files we skip entirely, because they are never the answer.
SKIP_NAMES = {".DS_Store", "Thumbs.db"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
# "this file is readable text" is the weakest finding of all: cap it so it ranks
# below anything that really decoded or matched a crypto rule.
PLAIN_TEXT_CAP = 0.55

# File types that are worth opening even when nothing decoded: containers, archives,
# captures, key stores. Carved media (png/jpg/...) is deliberately *not* here: in a
# folder of carved files it is usually just a carved file.
CONTAINER_EXTENSIONS = {
    "enc": "an encrypted blob with its own header",
    "zip": "an archive, maybe password-protected",
    "7z": "an archive, maybe password-protected",
    "rar": "an archive, maybe password-protected",
    "gz": "a compressed stream",
    "bz2": "a compressed stream",
    "xz": "a compressed stream",
    "tar": "an archive",
    "kdbx": "a KeePass database",
    "kdb": "a KeePass database",
    "pcap": "a network capture",
    "pcapng": "a network capture",
    "sqlite": "a database file",
    "pem": "a key or certificate",
}
CONTAINER_INTEREST = 0.6
MEDIA_INTEREST = 0.25

# detect rules that mean "there is crypto or an encoding here", not just "a file".
CRYPTO_RULE_PREFIXES = (
    "flag",
    "hash.",
    "openssl",
    "fernet",
    "aes.",
    "block8.",
    "xor.",
    "base64.",
    "pem",
    "jwt",
    "const.",
    "stego.",
    "polyglot",
    "embedded",
    "length.key",
)


@dataclass
class FileResult:
    """What the scan found in one file."""

    path: Path
    size: int
    kind: str  # the file type, or "unknown"
    interest: float  # 0..1, how much this file deserves a look
    reasons: list[str] = field(default_factory=list)
    best: Candidate | None = None  # the best decoding chain, when there is one
    top_guesses: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "size": self.size,
            "kind": self.kind,
            "interest": round(self.interest, 3),
            "reasons": list(self.reasons),
            "guesses": list(self.top_guesses),
            "best": self.best.to_dict() if self.best else None,
            "error": self.error,
        }


@dataclass
class ScanReport:
    """The whole folder, ranked."""

    root: Path
    files: list[FileResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    budget_summary: str = ""

    def interesting(self, threshold: float = 0.4) -> list[FileResult]:
        return [result for result in self.files if result.interest >= threshold]

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "files": [result.to_dict() for result in self.files],
            "notes": list(self.notes),
            "budget": self.budget_summary,
        }


def list_files(root: Path, recursive: bool = True, max_files: int = 2000) -> list[Path]:
    """Every readable file under `root`, sorted, skipping the usual noise."""
    if root.is_file():
        return [root]
    pattern = "**/*" if recursive else "*"
    found = []
    for path in sorted(root.glob(pattern)):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in SKIP_NAMES or path.suffix in SKIP_SUFFIXES:
            continue
        found.append(path)
        if len(found) >= max_files:
            break
    return found


def scan_file(
    path: Path,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    read_limit: int = 8 * 1024 * 1024,
) -> FileResult:
    """Fingerprint one file and try to decode it. Never raises: errors are reported."""
    try:
        size = path.stat().st_size
        data = path.read_bytes()[:read_limit]
    except OSError as exc:
        return FileResult(path=path, size=0, kind="unreadable", interest=0.0, error=str(exc))

    signature = match_signature(data)
    kind = signature.name if signature is not None else "unknown"
    result = FileResult(path=path, size=size, kind=kind, interest=0.0)
    if not data:
        result.reasons.append("empty file")
        return result

    # The interest score is built from independent signals, strongest first. Each
    # one says *why* in its own words, because "0.75" on its own helps nobody.

    # 1. Is the flag simply in there? Cheapest and best signal of all.
    hits = find_flags(data, flagset)
    if hits:
        result.interest = max(hit.strength for hit in hits)
        result.reasons.append(f"contains a flag: {hits[0].text[:60]}")

    # 2. What the fingerprint says. Only crypto/encoding rules raise the score:
    #    "this is a PNG" is information, not a finding.
    report = detect(data, flagset)
    result.top_guesses = [f"{guess.label} ({guess.confidence:.2f})" for guess in report.guesses[:3]]
    for guess in report.guesses[:4]:
        if guess.rule.startswith(CRYPTO_RULE_PREFIXES):
            result.interest = max(result.interest, min(0.75, guess.confidence))
            result.reasons.append(f"detect: {guess.label}")

    # 3. A container is worth opening even if nothing decoded here.
    if signature is not None and signature.ext in CONTAINER_EXTENSIONS:
        result.interest = max(result.interest, CONTAINER_INTEREST)
        result.reasons.append(f"{kind}: {CONTAINER_EXTENSIONS[signature.ext]}")
    elif signature is not None and not signature.weak:
        result.interest = max(result.interest, MEDIA_INTEREST)
        result.reasons.append(f"{kind}: a known file type, nothing hidden found in it")

    # 4. The decoding chains, for anything small enough to be a payload.
    if len(data) <= AUTO_SIZE_LIMIT:
        candidates = auto_decode(data, flagset=flagset, budget=budget, top_n=1)
        if candidates:
            result.best = candidates[0]
            result.interest = max(result.interest, candidates[0].score)
            result.reasons.append(f"auto: {candidates[0].label} (score {candidates[0].score:.2f})")
    else:
        result.reasons.append(f"{size} bytes: too big for the decoding chains, only fingerprinted")

    # 5. Last resort: plain readable text with nothing else to say about it.
    if result.interest == 0.0 and signature is None:
        plain_score, plain_reasons = score(data, flagset)
        if plain_score >= 0.4:
            result.interest = min(plain_score, PLAIN_TEXT_CAP)
            result.reasons.append("readable text: " + "; ".join(plain_reasons[:2]))
    return result


def scan(
    root: Path,
    flagset: FlagSet | None = None,
    recursive: bool = True,
    budget: Budget | None = None,
    per_file_seconds: float = 3.0,
    max_files: int = 2000,
) -> ScanReport:
    """Scan every file under `root` and rank them by how promising they look."""
    report = ScanReport(root=root)
    if not root.exists():
        report.notes.append(f"{root} does not exist")
        return report

    budget = budget or Budget(max_attempts=10_000_000, max_seconds=120)
    paths = list_files(root, recursive, max_files)
    if not paths:
        report.notes.append(f"no file to scan in {root}")
        return report
    report.notes.append(f"{len(paths)} file(s) to scan")

    for path in paths:
        if budget.cancel_event.is_set():
            report.notes.append("cancelled")
            break
        remaining = budget.max_seconds - budget.elapsed()
        if remaining <= 0:
            report.notes.append(
                f"time budget spent after {len(report.files)} of {len(paths)} files: "
                "raise --seconds, or scan a subfolder"
            )
            break
        # Each file gets its own slice, so one big blob cannot eat the whole scan.
        slice_budget = Budget(
            max_attempts=2000,
            max_seconds=min(per_file_seconds, remaining),
            cancel_event=budget.cancel_event,
        )
        result = scan_file(path, flagset, slice_budget)
        budget.attempts += slice_budget.attempts
        report.files.append(result)

    report.files.sort(key=lambda result: -result.interest)
    report.budget_summary = budget.summary()
    flagged = [result for result in report.files if "contains a flag" in " ".join(result.reasons)]
    if flagged:
        report.notes.insert(0, f"a flag pattern was found in {len(flagged)} file(s)")
    return report
