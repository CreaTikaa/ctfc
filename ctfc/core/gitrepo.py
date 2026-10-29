"""Read a `.git` directory and find what was committed and then taken back out.

The challenge shape: a folder with a `.git` in it, and the flag is in a file that
was committed, noticed, and removed in a later commit. `git log` shows nothing
because the working tree is clean - but git never deletes anything until it is
told to, so every old version is still sitting in `.git/objects`.

Git's storage is small enough to read directly:

- an object is `"<type> <size>\\0<content>"`, zlib-compressed, and its name is the
  SHA-1 of exactly those bytes. **Loose** objects live one per file under
  `.git/objects/ab/cdef...`; a **pack** holds thousands back to back in
  `.git/objects/pack/*.pack`;
- a **commit** names a tree and its parents, a **tree** lists names with the SHA
  of each entry, a **blob** is a file's contents. So walking from a ref reaches
  every object that is still "live";
- anything not reached that way is **unreachable**: an old version, an abandoned
  branch, or a commit that was `reset --hard` away. That is where the answer is.

Packs also store objects as **deltas** against another object, which is why a
pack cannot simply be decompressed: the copy/insert instructions have to be
applied. That is implemented here too, so a cloned repository works and not just
a hand-made one.

Nothing is executed and `git` itself is never called: this reads the files.
"""

from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path

PACK_MAGIC = b"PACK"
IDX_MAGIC = b"\xfftOc"
# Pack object types (git's own numbering).
OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, OBJ_TAG = 1, 2, 3, 4
OBJ_OFS_DELTA, OBJ_REF_DELTA = 6, 7
TYPE_NAMES = {OBJ_COMMIT: "commit", OBJ_TREE: "tree", OBJ_BLOB: "blob", OBJ_TAG: "tag"}
MAX_OBJECT = 64 * 1024 * 1024
MAX_OBJECTS = 200_000
SHA_PATTERN = re.compile(r"\b[0-9a-f]{40}\b")


class GitError(Exception):
    """The folder is not a readable git repository."""


@dataclass
class GitObject:
    """One git object, already decompressed (and de-deltified)."""

    sha: str
    kind: str  # commit | tree | blob | tag
    data: bytes
    where: str = "loose"  # "loose" or "pack:<file name>"


def object_sha(kind: str, data: bytes) -> str:
    """An object's name: the SHA-1 of "<type> <size>\\0<content>"."""
    header = f"{kind} {len(data)}".encode() + b"\x00"
    # SHA-1 here is git's content addressing, not a security decision.
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324


def _split_object(raw: bytes) -> tuple[str, bytes]:
    """Split the stored form into (type, content)."""
    head, _, body = raw.partition(b"\x00")
    parts = head.split(b" ")
    if len(parts) != 2:
        raise GitError(f"malformed object header {head[:40]!r}")
    return parts[0].decode("ascii", "replace"), body


# ---------------------------------------------------------------------------
# Loose objects
# ---------------------------------------------------------------------------


def read_loose(objects_dir: Path) -> list[GitObject]:
    """Every `.git/objects/ab/cdef...` file, decompressed."""
    found: list[GitObject] = []
    for bucket in sorted(objects_dir.iterdir()):
        if not bucket.is_dir() or len(bucket.name) != 2:
            continue
        for item in sorted(bucket.iterdir()):
            if not item.is_file() or len(item.name) != 38:
                continue
            try:
                raw = zlib.decompress(item.read_bytes())
            except (zlib.error, OSError):
                continue  # a corrupt object must not stop the rest
            try:
                kind, body = _split_object(raw)
            except GitError:
                continue
            found.append(GitObject(bucket.name + item.name, kind, body, "loose"))
            if len(found) >= MAX_OBJECTS:
                return found
    return found


# ---------------------------------------------------------------------------
# Packs
# ---------------------------------------------------------------------------


def _read_size_header(data: bytes, position: int) -> tuple[int, int, int]:
    """A pack object header: (type, uncompressed size, new position)."""
    byte = data[position]
    position += 1
    kind = (byte >> 4) & 0x07
    size = byte & 0x0F
    shift = 4
    while byte & 0x80:
        byte = data[position]
        position += 1
        size |= (byte & 0x7F) << shift
        shift += 7
    return kind, size, position


def _read_little_varint(data: bytes, position: int) -> tuple[int, int]:
    """The LEB128 little-endian varint used inside a delta."""
    result = 0
    shift = 0
    while True:
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, position


def apply_delta(base: bytes, delta: bytes) -> bytes:
    """Rebuild an object from its base plus a delta's copy/insert instructions."""
    _source_size, position = _read_little_varint(delta, 0)
    target_size, position = _read_little_varint(delta, position)
    out = bytearray()
    while position < len(delta):
        opcode = delta[position]
        position += 1
        if opcode & 0x80:
            # Copy from the base. The low bits say which offset/size bytes follow.
            offset = 0
            size = 0
            for index in range(4):
                if opcode & (1 << index):
                    offset |= delta[position] << (index * 8)
                    position += 1
            for index in range(3):
                if opcode & (1 << (4 + index)):
                    size |= delta[position] << (index * 8)
                    position += 1
            if size == 0:
                size = 0x10000  # a size of zero means 64 KiB
            out += base[offset : offset + size]
        elif opcode:
            out += delta[position : position + opcode]
            position += opcode
        else:
            raise GitError("delta opcode 0 is reserved")
    if len(out) != target_size:
        raise GitError(f"delta produced {len(out)} bytes, expected {target_size}")
    return bytes(out)


def read_pack(path: Path) -> list[GitObject]:
    """Every object in a packfile, with deltas applied.

    The pack is walked straight through rather than through its .idx: the objects
    sit back to back, and zlib tells us where each one ends. A delta's base always
    appears earlier in the pack, so one forward pass is enough - with a second one
    for any REF_DELTA whose base came later.
    """
    data = path.read_bytes()
    if data[:4] != PACK_MAGIC or len(data) < 12:
        raise GitError(f"{path.name} is not a packfile")
    count = int.from_bytes(data[8:12], "big")
    position = 12
    by_offset: dict[int, GitObject] = {}
    found: list[GitObject] = []
    pending: list[tuple[int, str, bytes]] = []  # (offset, base sha, delta) for REF_DELTA
    label = f"pack:{path.name}"

    for _ in range(min(count, MAX_OBJECTS)):
        if position >= len(data):
            break
        start = position
        kind, _size, position = _read_size_header(data, position)
        base_offset = 0
        base_sha = ""
        if kind == OBJ_OFS_DELTA:
            byte = data[position]
            position += 1
            distance = byte & 0x7F
            while byte & 0x80:
                byte = data[position]
                position += 1
                distance = ((distance + 1) << 7) | (byte & 0x7F)
            base_offset = start - distance
        elif kind == OBJ_REF_DELTA:
            base_sha = data[position : position + 20].hex()
            position += 20
        decompressor = zlib.decompressobj()
        try:
            body = decompressor.decompress(data[position:], MAX_OBJECT)
        except zlib.error as exc:
            raise GitError(f"{path.name}: object at {start} does not inflate: {exc}") from exc
        position = len(data) - len(decompressor.unused_data)

        if kind in TYPE_NAMES:
            obj = GitObject(object_sha(TYPE_NAMES[kind], body), TYPE_NAMES[kind], body, label)
            by_offset[start] = obj
            found.append(obj)
        elif kind == OBJ_OFS_DELTA:
            base = by_offset.get(base_offset)
            if base is None:
                continue  # a base we could not read: skip rather than guess
            rebuilt = apply_delta(base.data, body)
            obj = GitObject(object_sha(base.kind, rebuilt), base.kind, rebuilt, label)
            by_offset[start] = obj
            found.append(obj)
        elif kind == OBJ_REF_DELTA:
            pending.append((start, base_sha, body))

    # REF_DELTA bases may be anywhere, so resolve those once everything else is in.
    known = {obj.sha: obj for obj in found}
    for start, base_sha, body in pending:
        base = known.get(base_sha)
        if base is None:
            continue
        rebuilt = apply_delta(base.data, body)
        obj = GitObject(object_sha(base.kind, rebuilt), base.kind, rebuilt, label)
        by_offset[start] = obj
        found.append(obj)
    return found


# ---------------------------------------------------------------------------
# The object graph
# ---------------------------------------------------------------------------


def parse_tree(data: bytes) -> list[tuple[str, str, str]]:
    """A tree's entries as (mode, name, sha)."""
    entries = []
    position = 0
    while position < len(data):
        space = data.find(b" ", position)
        nul = data.find(b"\x00", space + 1)
        if space == -1 or nul == -1 or nul + 20 > len(data):
            break
        mode = data[position:space].decode("ascii", "replace")
        name = data[space + 1 : nul].decode("utf-8", "replace")
        sha = data[nul + 1 : nul + 21].hex()
        entries.append((mode, name, sha))
        position = nul + 21
    return entries


def commit_parents(data: bytes) -> list[str]:
    text = data.split(b"\n\n", 1)[0].decode("utf-8", "replace")
    return [line.split()[1] for line in text.splitlines() if line.startswith("parent ")]


def commit_tree(data: bytes) -> str:
    text = data.split(b"\n\n", 1)[0].decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("tree "):
            return line.split()[1]
    return ""


def read_refs(git_dir: Path) -> dict[str, str]:
    """Every ref name -> commit SHA, from refs/, packed-refs and HEAD."""
    refs: dict[str, str] = {}
    refs_dir = git_dir / "refs"
    if refs_dir.is_dir():
        for item in refs_dir.rglob("*"):
            if not item.is_file():
                continue
            try:
                value = item.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeDecodeError):
                continue
            if SHA_PATTERN.fullmatch(value):
                refs[str(item.relative_to(git_dir))] = value
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("#") or line.startswith("^"):
                continue
            parts = line.split()
            if len(parts) == 2 and SHA_PATTERN.fullmatch(parts[0]):
                refs[parts[1]] = parts[0]
    head = git_dir / "HEAD"
    if head.is_file():
        value = head.read_text(encoding="utf-8", errors="replace").strip()
        if SHA_PATTERN.fullmatch(value):
            refs["HEAD"] = value  # a detached HEAD points straight at a commit
    return refs


def read_reflog(git_dir: Path) -> list[str]:
    """Commit SHAs mentioned in the reflogs, including ones no ref points at now."""
    shas: list[str] = []
    logs = git_dir / "logs"
    if not logs.is_dir():
        return shas
    for item in logs.rglob("*"):
        if not item.is_file():
            continue
        text = item.read_text(encoding="utf-8", errors="replace")
        for sha in SHA_PATTERN.findall(text):
            if sha not in shas and sha != "0" * 40:
                shas.append(sha)
    return shas


def _tree_blobs(tree_sha: str, objects: dict[str, GitObject], depth: int = 0) -> set[str]:
    """Every blob SHA inside a tree, following subdirectories."""
    if depth > 40 or tree_sha not in objects:
        return set()
    tree = objects[tree_sha]
    if tree.kind != "tree":
        return set()
    blobs: set[str] = set()
    for mode, _name, sha in parse_tree(tree.data):
        if mode.startswith("160"):
            continue  # a submodule: the commit it names is not in this repository
        if sha in objects and objects[sha].kind == "tree":
            blobs |= _tree_blobs(sha, objects, depth + 1)
        else:
            blobs.add(sha)
    return blobs


def reachable_from(roots: list[str], objects: dict[str, GitObject]) -> set[str]:
    """Every object reachable by walking commits -> trees -> blobs from `roots`."""
    seen: set[str] = set()
    stack = [sha for sha in roots if sha in objects]
    while stack:
        sha = stack.pop()
        if sha in seen:
            continue
        seen.add(sha)
        obj = objects.get(sha)
        if obj is None:
            continue
        if obj.kind == "commit":
            tree = commit_tree(obj.data)
            if tree:
                stack.append(tree)
            stack += commit_parents(obj.data)
        elif obj.kind == "tree":
            stack += [sha for _mode, _name, sha in parse_tree(obj.data)]
        elif obj.kind == "tag":
            text = obj.data.split(b"\n\n", 1)[0].decode("utf-8", "replace")
            for line in text.splitlines():
                if line.startswith("object "):
                    stack.append(line.split()[1])
    return seen


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


@dataclass
class LostBlob:
    """A blob that is in the history but not in the files you can see.

    Two quite different things end up here, and `why` says which:

    - **removed**: the commit that added it is still an ancestor of a branch, so
      git considers it perfectly reachable - it is simply not in the current tree
      any more. This is the usual "committed the secret, removed it next commit"
      case, and `git fsck` says nothing about it.
    - **unreachable**: no ref reaches it at all, which is what `reset --hard`
      or an abandoned branch leaves behind.
    """

    sha: str
    size: int
    data: bytes
    names: list[str] = field(default_factory=list)  # names any tree gave it
    why: str = ""
    kind: str = "removed"  # "removed" | "unreachable"
    commits: list[str] = field(default_factory=list)  # commits whose tree held it
    flags: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


@dataclass
class GitReport:
    """What the repository still holds."""

    git_dir: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    refs: dict[str, str] = field(default_factory=dict)
    lost: list[LostBlob] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "git_dir": self.git_dir,
            "counts": dict(self.counts),
            "refs": dict(self.refs),
            "lost": [
                {
                    "sha": blob.sha,
                    "size": blob.size,
                    "names": list(blob.names),
                    "why": blob.why,
                    "flags": list(blob.flags),
                    "secrets": list(blob.secrets),
                    "preview": blob.data[:400].decode("utf-8", "replace"),
                }
                for blob in self.lost
            ],
            "notes": list(self.notes),
        }


def find_git_dir(path: Path) -> Path:
    """Accept the repository root, the `.git` folder itself, or a bare repo."""
    if (path / "objects").is_dir() and (path / "refs").is_dir():
        return path
    if (path / ".git").is_dir():
        return path / ".git"
    raise GitError(
        f"{path} is not a git repository: expected a .git folder inside it, "
        "or the .git folder itself"
    )


def read_objects(git_dir: Path, problems: list[str] | None = None) -> dict[str, GitObject]:
    """Every object in the repository, loose and packed.

    One unreadable pack must not lose the rest, so a failure is recorded in
    `problems` and skipped - but it is recorded, because silently reading fewer
    objects than exist would make "nothing was removed" a lie.
    """
    objects: dict[str, GitObject] = {}
    objects_dir = git_dir / "objects"
    if not objects_dir.is_dir():
        raise GitError(f"no objects directory in {git_dir}")
    for obj in read_loose(objects_dir):
        objects[obj.sha] = obj
    pack_dir = objects_dir / "pack"
    if pack_dir.is_dir():
        for pack in sorted(pack_dir.glob("*.pack")):
            try:
                for obj in read_pack(pack):
                    objects.setdefault(obj.sha, obj)
            except (GitError, OSError, zlib.error) as exc:
                if problems is not None:
                    problems.append(f"{pack.name} could not be read ({exc}): it was skipped")
    return objects


def analyse(path: Path, flagset=None) -> GitReport:
    """Read the repository and report the blobs its branches no longer reach."""
    from ctfc.core import secrets as secrets_module
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    git_dir = find_git_dir(Path(path))
    problems: list[str] = []
    objects = read_objects(git_dir, problems)
    report = GitReport(git_dir=str(git_dir))
    report.notes += problems
    for obj in objects.values():
        report.counts[obj.kind] = report.counts.get(obj.kind, 0) + 1
    if not objects:
        report.notes.append("no object found: the .git folder is empty or unreadable")
        return report

    report.refs = read_refs(git_dir)
    live = reachable_from(list(report.refs.values()), objects)
    # A commit only the reflog remembers is exactly what `reset --hard` leaves
    # behind, so note it separately rather than calling it merely unreachable.
    reflog_shas = [sha for sha in read_reflog(git_dir) if sha in objects and sha not in live]
    from_reflog = reachable_from(reflog_shas, objects)

    # Names are only known from trees, so collect them for every blob first.
    names: dict[str, list[str]] = {}
    for obj in objects.values():
        if obj.kind != "tree":
            continue
        for _mode, name, sha in parse_tree(obj.data):
            names.setdefault(sha, [])
            if name not in names[sha]:
                names[sha].append(name)

    # What the branches' *current* trees hold. A blob removed in a later commit is
    # still reachable through history, so "unreachable" alone would miss it - which
    # is exactly why `git fsck` is silent about the usual CTF case.
    current: set[str] = set()
    for sha in report.refs.values():
        obj = objects.get(sha)
        if obj is None or obj.kind != "commit":
            continue
        current |= _tree_blobs(commit_tree(obj.data), objects)

    # Which commits' trees held each blob, so the report can say when it existed.
    held_by: dict[str, list[str]] = {}
    for obj in objects.values():
        if obj.kind != "commit":
            continue
        for blob_sha in _tree_blobs(commit_tree(obj.data), objects):
            held_by.setdefault(blob_sha, []).append(obj.sha[:10])

    for obj in objects.values():
        if obj.kind != "blob" or obj.sha in current:
            continue
        if obj.sha not in live:
            kind = "unreachable"
            why = (
                "reachable only from the reflog: a commit that was reset or amended away"
                if obj.sha in from_reflog
                else "no branch, tag or HEAD reaches it: a dropped commit or an orphan object"
            )
        else:
            kind = "removed"
            why = (
                "in the history but not in any branch's current tree: it was removed or "
                "replaced by a later commit (`git fsck` does not report this)"
            )
        report.lost.append(
            LostBlob(
                sha=obj.sha,
                size=len(obj.data),
                data=obj.data,
                names=names.get(obj.sha, []),
                why=why,
                kind=kind,
                commits=held_by.get(obj.sha, []),
                flags=[hit.text for hit in find_flags(obj.data, flagset)],
                secrets=[
                    f"{secret.name} = {secret.value}"
                    for secret in secrets_module.find_secrets(obj.data)
                ],
            )
        )

    # The ones that actually carry something go first.
    report.lost.sort(key=lambda blob: (not blob.flags, not blob.secrets, -blob.size))
    removed = sum(1 for blob in report.lost if blob.kind == "removed")
    orphaned = sum(1 for blob in report.lost if blob.kind == "unreachable")
    if removed:
        report.notes.append(
            f"{removed} blob(s) in the history but not in the current tree: this is where a "
            "secret that was committed and then removed still lives"
        )
    if orphaned:
        report.notes.append(
            f"{orphaned} blob(s) no ref reaches at all (what `git fsck --lost-found` finds)"
        )
    if not report.lost:
        report.notes.append(
            "every blob is still in a current tree: nothing was removed by a later commit. "
            "Look at the files themselves (`ctfc scan`), or at the commit messages"
        )
    if reflog_shas:
        report.notes.append(
            f"{len(reflog_shas)} commit(s) only the reflog remembers: "
            "`git log --walk-reflogs` or `git fsck --lost-found` in a real checkout"
        )
    return report
