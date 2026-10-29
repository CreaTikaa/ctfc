"""Tests for reading a .git directory (core/gitrepo.py)."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from ctfc.core import gitrepo

# ---------------------------------------------------------------------------
# Building a repository by hand, so the tests do not need the git binary
# ---------------------------------------------------------------------------


def store(git_dir: Path, kind: str, body: bytes) -> str:
    """Write a loose object the way git does and return its SHA."""
    raw = f"{kind} {len(body)}".encode() + b"\x00" + body
    sha = hashlib.sha1(raw).hexdigest()  # noqa: S324 - git's content addressing
    target = git_dir / "objects" / sha[:2] / sha[2:]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(zlib.compress(raw))
    return sha


def tree_entry(mode: str, name: str, sha: str) -> bytes:
    return f"{mode} {name}".encode() + b"\x00" + bytes.fromhex(sha)


def commit_object(tree: str, message: str, parent: str | None = None) -> bytes:
    lines = [f"tree {tree}"]
    if parent:
        lines.append(f"parent {parent}")
    lines.append("author t <t@t> 0 +0000")
    lines.append("committer t <t@t> 0 +0000")
    return ("\n".join(lines) + f"\n\n{message}\n").encode()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo where a secret was committed and then removed in a later commit."""
    git_dir = tmp_path / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "objects").mkdir()

    secret = store(git_dir, "blob", b"CYBN{hand_built_secret}\n")
    readme = store(git_dir, "blob", b"a readme\n")
    first_tree = store(
        git_dir,
        "tree",
        tree_entry("100644", "readme.md", readme) + tree_entry("100644", "secret.txt", secret),
    )
    first = store(git_dir, "commit", commit_object(first_tree, "add both"))
    second_tree = store(git_dir, "tree", tree_entry("100644", "readme.md", readme))
    second = store(git_dir, "commit", commit_object(second_tree, "remove the secret", first))

    (git_dir / "refs" / "heads" / "main").write_text(second + "\n")
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    return tmp_path


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------


def test_object_sha_matches_gits_rule():
    """The name is the SHA-1 of "<type> <size>\\0<content>"."""
    assert gitrepo.object_sha("blob", b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_a_folder_without_a_git_is_refused(tmp_path):
    with pytest.raises(gitrepo.GitError, match="not a git repository"):
        gitrepo.analyse(tmp_path)


def test_the_git_folder_itself_is_accepted(repo):
    assert gitrepo.analyse(repo / ".git").lost


def test_trees_are_parsed_into_mode_name_sha():
    sha = "ce013625030ba8dba906f756967f9e9ca394464a"
    entries = gitrepo.parse_tree(tree_entry("100644", "a.txt", sha))
    assert entries == [("100644", "a.txt", sha)]


def test_commit_fields_are_read():
    body = commit_object("t" * 40, "msg", parent="p" * 40)
    assert gitrepo.commit_tree(body) == "t" * 40
    assert gitrepo.commit_parents(body) == ["p" * 40]


# ---------------------------------------------------------------------------
# The thing the tool exists for
# ---------------------------------------------------------------------------


def test_a_removed_secret_is_found_even_though_git_fsck_would_not(repo):
    """The commit that added it is still an ancestor, so it is NOT unreachable."""
    report = gitrepo.analyse(repo)
    secret = next(blob for blob in report.lost if "secret.txt" in blob.names)
    assert secret.kind == "removed"
    assert secret.flags == ["CYBN{hand_built_secret}"]
    assert secret.commits, "the commit that held it should be named"
    assert "not in any branch's current tree" in secret.why


def test_a_blob_still_in_the_current_tree_is_not_reported(repo):
    report = gitrepo.analyse(repo)
    assert all("readme.md" not in blob.names for blob in report.lost)


def test_a_blob_no_ref_reaches_is_called_unreachable(repo):
    """An orphan object, as `reset --hard` leaves behind."""
    store(repo / ".git", "blob", b"CYBN{orphan}\n")
    report = gitrepo.analyse(repo)
    orphan = next(blob for blob in report.lost if blob.flags == ["CYBN{orphan}"])
    assert orphan.kind == "unreachable"
    assert any("fsck --lost-found" in note for note in report.notes)


def test_blobs_carrying_a_flag_are_ranked_first(repo):
    store(repo / ".git", "blob", b"x" * 5000)  # bigger, but boring
    report = gitrepo.analyse(repo)
    assert report.lost[0].flags == ["CYBN{hand_built_secret}"]


def test_credentials_in_a_removed_blob_are_surfaced(tmp_path):
    git_dir = tmp_path / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "objects").mkdir()
    config = store(git_dir, "blob", b"db_password = sup3rs3cret\nhost = localhost\n")
    tree = store(git_dir, "tree", tree_entry("100644", "settings.ini", config))
    first = store(git_dir, "commit", commit_object(tree, "add config"))
    empty = store(git_dir, "tree", b"")
    second = store(git_dir, "commit", commit_object(empty, "drop config", first))
    (git_dir / "refs" / "heads" / "main").write_text(second + "\n")
    report = gitrepo.analyse(tmp_path)
    blob = next(blob for blob in report.lost if "settings.ini" in blob.names)
    assert any("sup3rs3cret" in secret for secret in blob.secrets)


def test_a_clean_repository_says_so(tmp_path):
    git_dir = tmp_path / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "objects").mkdir()
    blob = store(git_dir, "blob", b"only file\n")
    tree = store(git_dir, "tree", tree_entry("100644", "a.txt", blob))
    commit = store(git_dir, "commit", commit_object(tree, "one"))
    (git_dir / "refs" / "heads" / "main").write_text(commit + "\n")
    report = gitrepo.analyse(tmp_path)
    assert report.lost == []
    assert any("nothing was removed" in note for note in report.notes)


def test_a_submodule_entry_is_not_mistaken_for_a_blob(tmp_path):
    """Mode 160000 names a commit in another repository, which we do not have."""
    git_dir = tmp_path / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "objects").mkdir()
    blob = store(git_dir, "blob", b"file\n")
    tree = store(
        git_dir,
        "tree",
        tree_entry("100644", "a.txt", blob) + tree_entry("160000", "vendor", "ab" * 20),
    )
    commit = store(git_dir, "commit", commit_object(tree, "with submodule"))
    (git_dir / "refs" / "heads" / "main").write_text(commit + "\n")
    gitrepo.analyse(tmp_path)  # must not raise


# ---------------------------------------------------------------------------
# Packs
# ---------------------------------------------------------------------------


def pack_object(kind: int, body: bytes, extra: bytes = b"") -> bytes:
    """One pack entry: type/size header, any delta base reference, then zlib body."""
    size = len(body)
    first = (kind << 4) | (size & 0x0F)
    size >>= 4
    out = bytearray()
    while size:
        out.append(first | 0x80)
        first = size & 0x7F
        size >>= 7
    out.append(first)
    return bytes(out) + extra + zlib.compress(body)


def make_delta(base: bytes, copy_length: int, tail: bytes) -> bytes:
    """A delta that copies `copy_length` bytes from the start of the base, then
    inserts `tail`. Opcode 0x90 = copy, with one size byte and no offset byte
    (bits 0-3 clear means offset 0)."""
    target_size = copy_length + len(tail)
    return bytes([len(base), target_size, 0x90, copy_length, len(tail)]) + tail


def build_pack(entries: list[bytes]) -> bytes:
    header = b"PACK" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    body = header + b"".join(entries)
    return body + hashlib.sha1(body).digest()  # noqa: S324 - pack trailer


def test_a_pack_is_read(tmp_path):
    pack_dir = tmp_path / "objects" / "pack"
    pack_dir.mkdir(parents=True)
    (tmp_path / "refs").mkdir()
    content = b"packed content\n"
    (pack_dir / "pack-test.pack").write_bytes(build_pack([pack_object(gitrepo.OBJ_BLOB, content)]))
    objects = gitrepo.read_objects(tmp_path)
    assert [obj.data for obj in objects.values()] == [content]
    assert next(iter(objects.values())).where == "pack:pack-test.pack"


def test_apply_delta_copies_and_inserts():
    base = b"the quick brown fox"
    # copy "the quick " (10 bytes) from the base, then insert "red fox"
    assert gitrepo.apply_delta(base, make_delta(base, 10, b"red fox")) == b"the quick red fox"


def test_a_delta_that_does_not_fill_its_target_is_refused():
    """A target size that does not match what the instructions produce is corrupt."""
    with pytest.raises(gitrepo.GitError, match="expected"):
        gitrepo.apply_delta(b"abcdef", bytes([6, 99, 0x90, 2]))


def test_an_ofs_delta_in_a_pack_is_resolved(tmp_path):
    """The real reason a pack cannot just be decompressed."""
    pack_dir = tmp_path / "objects" / "pack"
    pack_dir.mkdir(parents=True)
    (tmp_path / "refs").mkdir()
    base = b"the quick brown fox jumps\n"
    base_entry = pack_object(gitrepo.OBJ_BLOB, base)
    # Rebuild "the quick brown fox sleeps\n": copy the first 20 bytes, insert the rest.
    delta_body = make_delta(base, 20, b"sleeps\n")
    # An OFS_DELTA says how far BACK its base entry starts, not an absolute offset.
    distance = len(base_entry)
    delta_entry = pack_object(gitrepo.OBJ_OFS_DELTA, delta_body, extra=bytes([distance & 0x7F]))
    (pack_dir / "pack-delta.pack").write_bytes(build_pack([base_entry, delta_entry]))
    contents = {obj.data for obj in gitrepo.read_objects(tmp_path).values()}
    assert base in contents
    assert b"the quick brown fox sleeps\n" in contents


# ---------------------------------------------------------------------------
# Against the real git, when it is installed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_matches_a_repository_real_git_made(tmp_path):
    """Build it with git itself, including a `git gc` so everything is packed."""

    def run(*args: str) -> None:
        subprocess.run(  # noqa: S603 - our own fixed arguments
            ["git", *args], cwd=tmp_path, check=True, capture_output=True
        )

    run("init", "-q", ".")
    run("config", "user.email", "t@t")
    run("config", "user.name", "t")
    (tmp_path / "keep.txt").write_text("kept\n")
    (tmp_path / "secret.txt").write_text("CYBN{real_git_secret}\n")
    run("add", "-A")
    run("commit", "-qm", "add both")
    run("rm", "-q", "secret.txt")
    run("commit", "-qm", "remove the secret")

    loose = gitrepo.analyse(tmp_path)
    assert any(blob.flags == ["CYBN{real_git_secret}"] for blob in loose.lost)

    run("gc", "-q")
    assert not list((tmp_path / ".git" / "objects").glob("??")), "gc should have packed everything"
    packed = gitrepo.analyse(tmp_path)
    assert any(blob.flags == ["CYBN{real_git_secret}"] for blob in packed.lost)
    # Same answer whether the objects were loose or in a pack.
    assert {blob.sha for blob in loose.lost} == {blob.sha for blob in packed.lost}
