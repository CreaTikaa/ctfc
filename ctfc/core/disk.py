"""Read a disk image (ext2/3/4, FAT, exFAT, NTFS, HFS+, ...) via The Sleuth Kit.

A disk or partition image is one of the richest forensics artefacts: the flag
is a file somewhere in a filesystem, sometimes a **deleted** one still on disk.
Parsing every filesystem by hand would be a project of its own, and getting ext4
extent trees or NTFS right is exactly what The Sleuth Kit already does, byte for
byte. So this module drives TSK rather than reimplementing it:

- `mmls` lists the partitions (an image may hold several);
- `fsstat` names each filesystem;
- `fls -r -p` walks every filesystem recursively, **including deleted entries**;
- `icat` reads a file's bytes by its inode - deleted files included, as long as
  their data blocks were not reused.

TSK only ever *reads* the image; nothing in it is executed. Calls are argument
lists (no shell), each under a timeout, and the whole walk is bounded by a file
count, a per-file size cap and a total-bytes cap, so a 50 GB image cannot turn
one command into an afternoon. When TSK is not installed, `available()` is False
and the caller falls back to searching the raw image bytes (which already finds
a flag written in clear anywhere in the image).

The flag is often not in the biggest file, so the files a challenge hides things
in - small files, and anything under a user's home, the desktop, /tmp or a path
that mentions "flag" - are extracted first, before the gigabytes of /usr.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

# The TSK programs this module uses.
TSK_TOOLS = ("mmls", "fsstat", "fls", "icat")

# Budgets: a big image must not make one command run for minutes.
MAX_FILES = 1500  # files pulled out of the image
MAX_FILE_SIZE = 32 * 1024 * 1024  # a single file larger than this is skipped
MAX_TOTAL = 256 * 1024 * 1024  # total bytes extracted
CALL_TIMEOUT = 120  # seconds for one TSK call

# Paths whose files are extracted first (the flag is rarely in /usr/share).
INTERESTING = re.compile(
    r"(?:^|/)(?:root|home|desktop|documents|tmp|media|mnt|flag|secret|user|share/flag)",
    re.IGNORECASE,
)
# System noise: extracted last, and only if the budget allows.
NOISE = re.compile(r"(?:^|/)(?:usr|lib|lib32|lib64|libx32|sbin|bin|proc|sys|snap|\.cache)/", re.I)

# One fls line: "r/r 12:\tpath", or "r/r * 15:\tpath" for a deleted entry. The
# inode can be a compound like "16-128-1" on NTFS.
FLS_LINE = re.compile(
    r"^(?P<type>[^/]+)/(?P<alloc>[^ ]+)\s+(?P<del>\*\s+)?(?P<inode>[0-9][-0-9]*):\t(?P<path>.*)$"
)


class DiskError(ValueError):
    """The image could not be read as a disk image."""


@dataclass
class DiskFile:
    """One file recovered from the image."""

    path: str
    inode: str
    data: bytes
    deleted: bool = False
    partition: int = 0


@dataclass
class Partition:
    """One filesystem found in the image."""

    offset: int  # start sector
    fs_type: str
    description: str


@dataclass
class DiskReport:
    """What the image holds."""

    partitions: list[Partition] = field(default_factory=list)
    files: list[DiskFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "partitions": [
                {"offset": p.offset, "fs_type": p.fs_type, "description": p.description}
                for p in self.partitions
            ],
            "files": [
                {
                    "path": f.path,
                    "inode": f.inode,
                    "size": len(f.data),
                    "deleted": f.deleted,
                    "partition": f.partition,
                }
                for f in self.files
            ],
            "notes": list(self.notes),
            "truncated": self.truncated,
        }


def available() -> bool:
    """True when The Sleuth Kit is installed (all the programs we need)."""
    return all(shutil.which(tool) for tool in TSK_TOOLS)


# ---------------------------------------------------------------------------
# Detecting a disk image
# ---------------------------------------------------------------------------

EXT_MAGIC_OFFSET = 0x438  # the ext superblock magic 0x53 0xEF
NTFS_OEM = b"NTFS    "
EXFAT_OEM = b"EXFAT   "
FAT_HINTS = (b"FAT12   ", b"FAT16   ", b"FAT32   ")


def _has_partition_table(data: bytes) -> bool:
    """An MBR (0x55AA at 510) with at least one plausible partition entry, or GPT."""
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return len(data) >= 0x210 and data[0x200:0x208] == b"EFI PART"
    for base in (0x1BE, 0x1CE, 0x1DE, 0x1EE):
        boot_flag = data[base]
        part_type = data[base + 4]
        if boot_flag in (0x00, 0x80) and part_type != 0:
            return True
    return data[0x200:0x208] == b"EFI PART"


def looks_like_disk_image(data: bytes) -> bool:
    """True when the bytes look like a partitioned image or a bare filesystem.

    ISO 9660 is left to the dedicated reader (it is handled offline), so this
    does not claim it.
    """
    if len(data) < 1024:
        return False
    if data[EXT_MAGIC_OFFSET : EXT_MAGIC_OFFSET + 2] == b"\x53\xef":
        return True  # ext2/3/4 superblock magic
    if data[3:11] in (NTFS_OEM, EXFAT_OEM):
        return True
    if data[0x36:0x3E] in FAT_HINTS or data[0x52:0x5A] in FAT_HINTS:
        return True
    return _has_partition_table(data)


# ---------------------------------------------------------------------------
# Driving The Sleuth Kit
# ---------------------------------------------------------------------------


def _run(args: list[str], want_bytes: bool = False):
    """Run one TSK program with an argument list (no shell). Returns output or None."""
    program = shutil.which(args[0])
    if program is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed program, argument list
            [program, *args[1:]],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=CALL_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 and not completed.stdout:
        return None
    return completed.stdout if want_bytes else completed.stdout.decode("utf-8", "replace")


def _partitions(image: str) -> list[Partition]:
    """`mmls` partitions, or a single whole-image filesystem when there is no table."""
    out = _run(["mmls", "-a", image])  # -a: only allocated partitions
    partitions: list[Partition] = []
    if out:
        for line in out.splitlines():
            # "  002:  000:000   0000002048   0000206847   ...   Linux (0x83)"
            fields = line.split()
            if len(fields) >= 5 and fields[0].rstrip(":").isdigit() and fields[2].isdigit():
                offset = int(fields[2])
                description = " ".join(fields[5:]) if len(fields) > 5 else ""
                partitions.append(Partition(offset=offset, fs_type="", description=description))
    if not partitions:
        partitions.append(Partition(offset=0, fs_type="", description="whole image"))
    # Name each filesystem with fsstat (and drop offsets that hold no filesystem).
    named: list[Partition] = []
    for part in partitions:
        stat = (
            _run(["fsstat", "-o", str(part.offset), image])
            if part.offset
            else _run(["fsstat", image])
        )
        if stat and "File System Type:" in stat:
            match = re.search(r"File System Type:\s*(.+)", stat)
            part.fs_type = match.group(1).strip() if match else "unknown"
            named.append(part)
    return named


def _list_files(image: str, offset: int) -> list[tuple[str, str, bool]]:
    """`fls -r -p` -> [(inode, path, deleted)] for every file in one filesystem."""
    args = ["fls", "-r", "-p"]
    if offset:
        args += ["-o", str(offset)]
    args.append(image)
    out = _run(args)
    if not out:
        return []
    files: list[tuple[str, str, bool]] = []
    for line in out.splitlines():
        match = FLS_LINE.match(line)
        if not match or match.group("type") != "r":  # regular files only
            continue
        files.append((match.group("inode"), match.group("path"), bool(match.group("del"))))
    return files


def _priority(path: str) -> int:
    """Lower sorts first: interesting paths, then neutral, then system noise."""
    if INTERESTING.search(path):
        return 0
    if NOISE.search(path):
        return 2
    return 1


def analyse(data: bytes, max_files: int = MAX_FILES, max_seconds: float = 90.0) -> DiskReport:
    """Read a disk image into its filesystems and files, deleted ones included.

    `max_files` caps how many files are pulled out and `max_seconds` how long
    the extraction runs - so `solve`, with a tight budget, can ask for a quick
    pass while `ctfc disk` takes its time.
    """
    import time

    if not available():
        raise DiskError(
            "The Sleuth Kit is not installed (needs fls, icat, mmls, fsstat): "
            "`apt install sleuthkit`. ctfc still searches the raw image for a flag in clear."
        )
    report = DiskReport()
    started = time.monotonic()
    with tempfile.NamedTemporaryFile(suffix=".img") as handle:
        handle.write(data)
        handle.flush()
        image = handle.name
        report.partitions = _partitions(image)
        if not report.partitions:
            raise DiskError("no filesystem recognised in the image (mmls/fsstat found nothing)")

        # Gather every file across every filesystem, then extract by priority.
        listing: list[
            tuple[int, int, str, str, bool]
        ] = []  # (priority, part_index, inode, path, del)
        for index, part in enumerate(report.partitions):
            for inode, path, deleted in _list_files(image, part.offset):
                listing.append((_priority(path), index, inode, path, deleted))
        listing.sort(key=lambda row: (row[0], len(row[3])))  # priority, then shorter paths

        total = 0
        for _prio, index, inode, path, deleted in listing:
            over_budget = (
                len(report.files) >= max_files
                or total >= MAX_TOTAL
                or time.monotonic() - started > max_seconds
            )
            if over_budget:
                report.truncated = True
                break
            offset = report.partitions[index].offset
            args = ["icat"]
            if deleted:
                args.append("-r")  # recover: follow the file even if unallocated
            if offset:
                args += ["-o", str(offset)]
            args += [image, inode]
            content = _run(args, want_bytes=True)
            if not content or len(content) > MAX_FILE_SIZE:
                continue
            total += len(content)
            report.files.append(
                DiskFile(path=path, inode=inode, data=content, deleted=deleted, partition=index)
            )

    names = ", ".join(f"{p.fs_type} at sector {p.offset}" for p in report.partitions)
    report.notes.append(f"{len(report.partitions)} filesystem(s): {names}")
    deleted_count = sum(1 for f in report.files if f.deleted)
    if deleted_count:
        report.notes.append(f"{deleted_count} of the files recovered were deleted")
    if report.truncated:
        report.notes.append(
            f"stopped at {len(report.files)} file(s): the image holds more "
            "(raise the budget, or mount it and look by hand)"
        )
    return report
