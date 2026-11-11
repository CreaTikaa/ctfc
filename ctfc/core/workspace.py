"""`ctfc workspace`: the key is never in the same file as the ciphertext.

Every other command here takes one file. A real forensics challenge is a
folder: a mail that mentions a password, a config with a shared secret, a
memory dump with an AES key in it - and, somewhere else entirely, the archive
or the blob those open. Doing that by hand means reading everything, writing
the candidates on a sheet of paper, and trying them one by one.

This module does exactly that, in three steps.

1. **Read everything once.** Each file is walked with `solve.walk()`, so a
   password inside a mail attachment, inside a ZIP, inside a decoded payload
   counts as found - not only the ones lying at the top level.
2. **Fill three pools** from every piece seen:
   - *secrets*: credentials written in a config (`find_secrets`) or in a
     sentence (`find_prose_secrets`), plus whatever a reader pulled out as text
     (a ZIP comment, a Docker `ENV`, a shortcut's arguments, an MSI string).
   - *keys*: the high-entropy 16/24/32-byte windows and the hex/base64 strings
     of the right length, from `keyhunt`.
   - *ciphertexts*: everything that is encrypted - an encrypted ZIP, an
     `openssl enc` file, a Fernet token, a block-shaped high-entropy blob, and
     the archives whose password only an external tool can try.
3. **Try the cross product**, cheapest test first, under **one** budget shared
   by the whole thing - not one per pair. 40 secrets x 12 ciphertexts is a long
   afternoon if each pair gets its own allowance.

What it will not do: invent passwords. Only the secrets found in the folder are
tried (plus the embedded common-password list when asked for). A 7z or a RAR
cannot be opened from here at all - Python does not decrypt them - so those are
reported with the exact `7z x -p...` line to run, which is more honest than a
silent skip.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core import archive as archive_module
from ctfc.core import gpp, keyhunt, secrets, zipinfo
from ctfc.core.budget import Budget
from ctfc.core.flags import FlagSet, find_flags, hunt_flags
from ctfc.core.scan import list_files
from ctfc.core.solve import walk
from ctfc.core.symmetric import CryptoError, solve_symmetric

# A result below this is not a hit, it is a coincidence.
HIT_SCORE = 0.5
# Pieces larger than this are still read for keys, but not treated as a
# ciphertext to attack: a 50 MB blob is a disk image, not a challenge payload.
CIPHERTEXT_MAX = 4 * 1024 * 1024
# A blob has to look like one before it is worth trying keys on.
MIN_BLOB = 32
# Past this size, high-entropy bytes are a dump, a disk image or a compressed
# file - not a challenge payload - unless the name says otherwise. Getting this
# wrong is expensive: every wrong key against 40 KB costs more than a second,
# and the cross product then spends the whole budget on one non-ciphertext.
BLOB_MAX = 64 * 1024
# Names that say "I am encrypted", and names that say "I am a dump".
ENCRYPTED_SUFFIXES = {".enc", ".aes", ".encrypted", ".locked", ".crypt", ".cipher", ".secured"}
DUMP_SUFFIXES = {".raw", ".dmp", ".mem", ".vmem", ".img", ".core", ".dd", ".e01", ".sav"}
# How many of each pool are kept. The point is a cross product that finishes.
MAX_SECRETS = 80
MAX_KEYS = 40  # only for display: the hunt below re-finds them per ciphertext
MAX_SOURCES = 20  # files whose bytes are searched for a key
MAX_CIPHERTEXTS = 25


@dataclass
class Found:
    """One candidate secret or key, and where it was found."""

    value: str  # printable form (the password, or the key in hex)
    raw: bytes  # what is actually tried
    where: str  # "mail.eml > body.txt"
    why: str  # "prose: the password is ..."

    def to_dict(self) -> dict:
        return {"value": self.value, "where": self.where, "why": self.why}


@dataclass
class Ciphertext:
    """One thing in the folder that is encrypted."""

    name: str  # "backup.zip > secret.txt"
    path: str  # the file on disk it came from
    kind: str  # "zip" | "openssl-enc" | "fernet" | "blob" | "archive"
    data: bytes = field(repr=False, default=b"")
    entry: str = ""  # the member, for an archive
    testable: bool = True  # can ctfc try a password itself?
    command: str = ""  # what to run when it cannot

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "kind": self.kind,
            "size": len(self.data),
            "entry": self.entry,
            "testable": self.testable,
            "command": self.command,
        }


@dataclass
class Hit:
    """A pair that worked: this secret opens that ciphertext."""

    secret: str
    secret_where: str
    target: str
    how: str  # "ZipCrypto", "AES-256-CBC, key = SHA-256(password)"...
    preview: str
    flags: list[str] = field(default_factory=list)
    command: str = ""

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "secret_where": self.secret_where,
            "target": self.target,
            "how": self.how,
            "preview": self.preview,
            "flags": list(self.flags),
            "command": self.command,
        }


@dataclass
class WorkspaceReport:
    """Everything the folder holds, and which pairs worked."""

    root: str = ""
    files: int = 0
    pieces: int = 0
    secrets: list[Found] = field(default_factory=list)
    keys: list[Found] = field(default_factory=list)
    # (name, bytes) of every piece whose bytes are worth searching for a key.
    # Kept out of to_dict(): it is working memory, not a result.
    sources: list[tuple[str, bytes]] = field(default_factory=list, repr=False)
    ciphertexts: list[Ciphertext] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    tried: int = 0
    skipped: list[str] = field(default_factory=list)  # pairs never reached
    notes: list[str] = field(default_factory=list)
    budget: str = ""

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files": self.files,
            "pieces": self.pieces,
            "secrets": [item.to_dict() for item in self.secrets],
            "keys": [item.to_dict() for item in self.keys],
            "ciphertexts": [item.to_dict() for item in self.ciphertexts],
            "hits": [hit.to_dict() for hit in self.hits],
            "flags": list(self.flags),
            "tried": self.tried,
            "skipped": list(self.skipped),
            "notes": list(self.notes),
            "budget": self.budget,
        }


# ---------------------------------------------------------------------------
# Filling the pools
# ---------------------------------------------------------------------------


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte - 8.0 is perfectly random."""
    import math

    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _looks_like_a_blob(data: bytes, name: str = "") -> bool:
    """High entropy, block-aligned, the right size, and not obviously a dump.

    Entropy is compared with the most a sample that short *could* have: 96
    random bytes cannot score above log2(96) = 6.6 bits per byte, so a fixed
    threshold of 7.0 would reject every short ciphertext - which is exactly the
    size a challenge payload has.
    """
    import math

    size = len(data)
    if not (MIN_BLOB <= size <= CIPHERTEXT_MAX) or size % 8:
        return False
    suffix = Path(name).suffix.lower()
    if suffix in DUMP_SUFFIXES:
        return False
    if size > BLOB_MAX and suffix not in ENCRYPTED_SUFFIXES:
        return False
    sample = data[:4096]
    ceiling = math.log2(min(256, len(sample)))
    return _entropy(sample) >= 0.92 * ceiling


def _text_secrets(data: bytes, where: str) -> list[Found]:
    """Both kinds of written credential, in one list, deduplicated by value."""
    found: list[Found] = []
    for entry in gpp.find_cpasswords(data):
        if entry.password:
            found.append(
                Found(
                    value=entry.password,
                    raw=entry.password.encode(),
                    where=where,
                    why=f"GPP cpassword of {entry.user or 'an account'} (line {entry.line}), "
                    "decrypted with Microsoft's published key",
                )
            )
    for secret in secrets.find_secrets(data) + secrets.find_prose_secrets(data):
        found.append(
            Found(
                value=secret.value,
                raw=secret.value.encode(),
                where=where,
                why=f"{secret.kind}: {secret.name} (line {secret.line})",
            )
        )
        if secret.rot13:
            # The text said "rotation": the ROT13 reading is a candidate too.
            found.append(
                Found(
                    value=secret.rot13,
                    raw=secret.rot13.encode(),
                    where=where,
                    why=f"ROT13 of {secret.name} (the text mentions a rotation)",
                )
            )
    return found


def _ciphertexts_from(visit, path: str) -> list[Ciphertext]:
    """What is encrypted in this piece, if anything."""
    piece, opened = visit.piece, visit.opened
    data = piece.data
    out: list[Ciphertext] = []

    if visit.reader == "zip":
        try:
            report = zipinfo.analyse(data, path)
        except Exception:  # noqa: BLE001 - a damaged ZIP is not a ciphertext
            return out
        for entry in report.entries:
            if not entry.encrypted:
                continue
            out.append(
                Ciphertext(
                    name=f"{piece.name} > {entry.name}",
                    path=piece.disk,
                    kind="zip",
                    data=data,
                    entry=entry.name,
                    # Python's zipfile does the traditional PKWARE cipher only.
                    testable=entry.zipcrypto,
                    command=(
                        ""
                        if entry.zipcrypto
                        else f"7z x -p<password> {piece.disk}   # WinZip AES, not done here"
                    ),
                )
            )
        return out

    if visit.reader == "archive":
        try:
            report = archive_module.analyse(data, piece.disk, read_contents=False)
        except Exception:  # noqa: BLE001
            return out
        if report.any_encrypted:
            out.append(
                Ciphertext(
                    name=piece.name,
                    path=piece.disk,
                    kind="archive",
                    data=b"",
                    testable=False,
                    command=f"7z x -p<password> {piece.disk}",
                )
            )
        return out

    if data[:8] == b"Salted__":
        out.append(Ciphertext(name=piece.name, path=piece.disk, kind="openssl-enc", data=data))
    elif data[:5] == b"gAAAA":
        out.append(Ciphertext(name=piece.name, path=piece.disk, kind="fernet", data=data))
    elif not visit.reader and _looks_like_a_blob(data, piece.disk):
        out.append(Ciphertext(name=piece.name, path=piece.disk, kind="blob", data=data))
    if opened is not None and opened.error:
        return out
    return out


# ---------------------------------------------------------------------------
# Trying one pair
# ---------------------------------------------------------------------------


def _try_zip(target: Ciphertext, password: bytes) -> tuple[bytes, str] | None:
    """Open one encrypted ZIP entry with this password. Cheap: a check byte first.

    `zipfile` verifies the 1-byte password check *and* the CRC of what comes
    out, so a success here is a real success, not a 1-in-256 coincidence.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(target.data)) as archive:
            archive.setpassword(password)
            return archive.read(target.entry), "ZipCrypto"
    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, ValueError):
        return None


def _try_symmetric(
    target: Ciphertext,
    candidate: Found,
    as_key: bool,
    flagset: FlagSet | None,
    budget: Budget,
) -> tuple[bytes, str] | None:
    """Try one secret against one blob, as a raw key or as a passphrase."""
    slice_budget = Budget(
        max_attempts=4000,
        max_seconds=max(0.2, min(3.0, budget.max_seconds - budget.elapsed())),
        cancel_event=budget.cancel_event,
    )
    try:
        report = solve_symmetric(
            target.data,
            flagset=flagset,
            key=candidate.raw if as_key else None,
            passphrase=None if as_key else candidate.raw,
            budget=slice_budget,
            top_n=1,
        )
    except (CryptoError, ValueError):
        return None
    finally:
        budget.spend(max(1, slice_budget.attempts))
    for result in report.candidates:
        if result.score >= HIT_SCORE:
            return result.data, result.label
    return None


# ---------------------------------------------------------------------------
# The whole folder
# ---------------------------------------------------------------------------


def analyse(
    root: Path,
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    recursive: bool = True,
    max_files: int = 500,
    read_seconds: float | None = None,
) -> WorkspaceReport:
    """Read every file in the folder, pool what it found, and try the pairs."""
    if not root.exists():
        report = WorkspaceReport(root=str(root))
        report.notes.append(f"{root} does not exist")
        return report

    paths = [root] if root.is_file() else list_files(root, recursive, max_files)
    if not paths:
        report = WorkspaceReport(root=str(root))
        report.notes.append(f"no file to read in {root}")
        return report
    unreadable: list[str] = []

    def read_one_by_one() -> Iterator[tuple[str, bytes]]:
        # A generator: a folder of large dumps is never all in memory at once.
        for path in paths:
            try:
                data = path.read_bytes()
            except OSError as exc:
                unreadable.append(f"{path}: {exc}")
                continue
            yield str(path), data

    report = from_files(read_one_by_one(), flagset, budget, read_seconds, root=str(root))
    report.files = len(paths)
    report.notes[:0] = unreadable
    return report


def from_files(
    files: Iterable[tuple[str, bytes]],
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    read_seconds: float | None = None,
    root: str = "",
) -> WorkspaceReport:
    """The same, for files given as (name, bytes) pairs - what a browser drop gives.

    Nothing here needs a path: the pools do not care where the bytes came from.
    The names are only used to say where a secret was found, and in the
    commands printed beside a hit.
    """
    budget = budget or Budget(max_attempts=5_000_000, max_seconds=90)
    report = WorkspaceReport(root=root)

    # Half the budget goes to reading, half to trying - otherwise a folder full
    # of archives spends everything before a single pair is tested.
    reading = read_seconds if read_seconds is not None else budget.max_seconds / 2
    _read_everything(files, report, flagset, budget, reading)
    _try_pairs(report, flagset, budget)

    report.budget = budget.summary()
    if not report.hits and report.ciphertexts and not report.secrets:
        report.notes.append(
            "nothing in this folder looks like a password: the secret may be in a "
            "file type no reader covers, or outside the folder entirely"
        )
    return report


def _read_everything(
    files: Iterable[tuple[str, bytes]],
    report: WorkspaceReport,
    flagset: FlagSet | None,
    budget: Budget,
    reading_seconds: float,
) -> None:
    """Walk every file and fill the three pools."""
    deadline = budget.elapsed() + reading_seconds
    seen_secrets: set[str] = set()
    seen_keys: set[bytes] = set()

    for path, data in files:
        report.files += 1
        if budget.cancel_event.is_set() or budget.elapsed() >= deadline:
            report.notes.append(
                f"stopped reading after {len(report.ciphertexts)} ciphertext(s): "
                "the time went on opening files (raise --seconds)"
            )
            break

        walk_budget = Budget(
            max_attempts=50_000,
            max_seconds=max(0.5, min(5.0, deadline - budget.elapsed())),
            cancel_event=budget.cancel_event,
        )
        for visit in walk(
            data,
            str(path),
            flagset=flagset,
            budget=walk_budget,
            notes=report.notes,
        ):
            report.pieces += 1
            piece = visit.piece

            # A flag that simply falls out while reading is still the answer.
            for hit in hunt_flags(piece.data, flagset):
                if hit.text not in report.flags:
                    report.flags.append(hit.text)

            # 1. Secrets: from the text itself, and from what the reader said
            #    (a ZIP comment, a Docker ENV line, a shortcut's arguments).
            texts = [(piece.data, piece.name)]
            if visit.opened is not None and visit.opened.notes:
                texts.append(("\n".join(visit.opened.notes).encode(), f"{piece.name} (reader)"))
            for blob, where in texts:
                if len(blob) > 1_000_000:
                    continue
                for found in _text_secrets(blob, where):
                    if found.value in seen_secrets or len(report.secrets) >= MAX_SECRETS:
                        continue
                    seen_secrets.add(found.value)
                    report.secrets.append(found)

            # 2. Keys. Two different things happen here. For the report, the
            #    *named* candidates are listed - an AES key schedule, a hex or
            #    base64 string of the right length - because those are what a
            #    human wants to see. The raw high-entropy windows are not
            #    listed and not pooled: there are hundreds of them, and
            #    `keyhunt.hunt` re-finds them per ciphertext and tries them
            #    strongest first, which is the search that was already written
            #    and measured. So the pool here is of *files to search*.
            if len(piece.data) <= CIPHERTEXT_MAX:
                for candidate in keyhunt.extract_candidates(piece.data, include_windows=False):
                    if candidate.kind == "prose":
                        continue  # already in the secrets pool, from _text_secrets
                    if candidate.key in seen_keys or len(report.keys) >= MAX_KEYS:
                        continue
                    seen_keys.add(candidate.key)
                    report.keys.append(
                        Found(
                            value=candidate.key.hex(),
                            raw=candidate.key,
                            where=piece.name,
                            why=f"{candidate.how} (offset {candidate.offset})",
                        )
                    )
                if len(report.sources) < MAX_SOURCES and len(piece.data) >= MIN_BLOB:
                    # The disk path, not the display name: the command printed
                    # beside a hit has to be one the user can run.
                    report.sources.append((piece.disk, piece.data))

            # 3. Ciphertexts.
            for target in _ciphertexts_from(visit, str(path)):
                if len(report.ciphertexts) >= MAX_CIPHERTEXTS:
                    break
                report.ciphertexts.append(target)
        budget.spend(walk_budget.attempts)


def _try_pairs(report: WorkspaceReport, flagset: FlagSet | None, budget: Budget) -> None:
    """The cross product, cheapest test first, under the remaining budget."""
    testable = [target for target in report.ciphertexts if target.testable]
    for target in report.ciphertexts:
        if not target.testable:
            report.skipped.append(f"{target.name}: {target.command}")

    # Phase 1: the ZIP entries. One attempt is a key schedule and twelve bytes,
    # so the whole pool goes through in the time one PBKDF2 call takes.
    for target in [item for item in testable if item.kind == "zip"]:
        for candidate in report.secrets:
            if not budget.spend():
                report.skipped.append(f"{target.name}: budget spent before every password")
                return
            report.tried += 1
            result = _try_zip(target, candidate.raw)
            if result is None:
                continue
            opened, _how = result
            report.hits.append(
                Hit(
                    secret=candidate.value,
                    secret_where=candidate.where,
                    target=target.name,
                    how="ZipCrypto (the CRC of the entry checks out)",
                    preview=_preview(opened),
                    flags=[hit.text for hit in find_flags(opened, flagset)],
                    command=f"unzip -P {candidate.value!r} -d out {target.path}",
                )
            )
            for hit in find_flags(opened, flagset):
                if hit.text not in report.flags:
                    report.flags.append(hit.text)
            break  # this archive is open; move to the next one

    # Phase 2: the keys. For each blob, every file in the folder is searched
    # for a key that opens it - which is the point of the whole command: the
    # key is in the memory dump, the ciphertext is in the other file.
    blobs = [item for item in testable if item.kind in ("blob", "fernet", "openssl-enc")]
    for target in blobs:
        for name, source in report.sources:
            if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
                report.skipped.append(f"{target.name}: budget spent before every file was searched")
                return
            if source is target.data:
                continue  # the file is its own ciphertext; the hunt below covers it anyway
            report.tried += 1
            slice_budget = Budget(
                max_attempts=20_000,
                max_seconds=max(0.5, min(5.0, budget.max_seconds - budget.elapsed())),
                cancel_event=budget.cancel_event,
            )
            found = keyhunt.hunt(source, target.data, flagset=flagset, budget=slice_budget, top_n=1)
            budget.spend(max(1, slice_budget.attempts))
            if found.winner is None or not found.results:
                continue
            result = found.results[0]
            report.hits.append(
                Hit(
                    secret=found.winner.key.hex(),
                    secret_where=f"{name} (offset {found.winner.offset}, {found.winner.how})",
                    target=target.name,
                    how=result.label,
                    preview=_preview(result.data),
                    flags=[hit.text for hit in find_flags(result.data, flagset)],
                    command=f"ctfc keys {name} --against {target.path}",
                )
            )
            for hit in find_flags(result.data, flagset):
                if hit.text not in report.flags:
                    report.flags.append(hit.text)
            break

    # Phase 3: the passphrases, which cost a KDF each - last, on purpose.
    for target in blobs:
        if any(hit.target == target.name for hit in report.hits):
            continue
        for candidate in report.secrets:
            if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
                report.skipped.append(f"{target.name}: budget spent before every passphrase")
                return
            report.tried += 1
            result = _try_symmetric(target, candidate, False, flagset, budget)
            if result is None:
                continue
            plaintext, how = result
            report.hits.append(
                Hit(
                    secret=candidate.value,
                    secret_where=candidate.where,
                    target=target.name,
                    how=how,
                    preview=_preview(plaintext),
                    flags=[hit.text for hit in find_flags(plaintext, flagset)],
                    command=f"ctfc sym {target.path} --pass {candidate.value!r}",
                )
            )
            for hit in find_flags(plaintext, flagset):
                if hit.text not in report.flags:
                    report.flags.append(hit.text)
            break


def _preview(data: bytes, limit: int = 120) -> str:
    """What came out, in one line: text if it reads, hex if it does not."""
    head = data[:limit]
    printable = sum(1 for byte in head if 32 <= byte < 127 or byte in (9, 10, 13))
    if head and printable / len(head) > 0.85:
        return head.decode("utf-8", "replace").replace("\n", " ")
    return head[:32].hex()


def interest(report: WorkspaceReport) -> float:
    """How much this folder gave up, 0..1 - used to decide the exit code."""
    if report.flags:
        return 1.0
    if report.hits:
        return 0.8
    if report.ciphertexts and report.secrets:
        return 0.4
    return 0.0
