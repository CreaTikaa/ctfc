"""Load the files in ctfc/data/ (signatures, constants, word list).

Results are cached: each file is read once per process.
"""

from __future__ import annotations

import tomllib
from functools import cache, lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@cache
def load_toml(name: str) -> dict:
    """Parse ctfc/data/<name> (a TOML file) and return it as a dict."""
    with open(DATA_DIR / name, "rb") as handle:
        return tomllib.load(handle)


@lru_cache(maxsize=1)
def load_passwords() -> tuple[bytes, ...]:
    """The embedded password list, in order (most common first).

    Used to try passphrases offline on `openssl enc` files and KDFs. It is data,
    not a cracker: the list is small and the tries run under a budget.
    """
    lines = (DATA_DIR / "passwords.txt").read_text(encoding="utf-8").splitlines()
    return tuple(line.encode() for line in lines if line and not line.startswith("#"))


def load_wordlist(path: str | Path, limit: int = 100_000) -> tuple[tuple[bytes, ...], str]:
    """The first `limit` entries of a password file on disk, and a note about it.

    `ctfc` is not a cracker - that is what the hashcat command every hash report
    prints is for - so a 14-million-line rockyou.txt is read up to a cap rather
    than loaded whole. The note says exactly how much was used, because a search
    that silently looked at 0.7% of a list would be worse than no search.

    Duplicates and blank lines are dropped, order is kept (a real list is sorted
    by how common the password is, and that order is the whole value of it).
    """
    file = Path(path)
    if not file.is_file():
        raise FileNotFoundError(f"{file} is not a file")
    seen: set[bytes] = set()
    words: list[bytes] = []
    total = 0
    with file.open("rb") as handle:
        for line in handle:
            total += 1
            word = line.rstrip(b"\r\n")
            if not word or word in seen:
                continue
            if len(words) < limit:
                seen.add(word)
                words.append(word)
    note = f"{file.name}: {len(words)} password(s) used"
    if len(words) >= limit:
        note += (
            f" - the first {limit} unique of {total} line(s). "
            "Raise --wordlist-limit, or use hashcat for the whole list"
        )
    elif total > len(words):
        note += f" ({total} line(s), duplicates and blanks dropped)"
    return tuple(words), note


@lru_cache(maxsize=1)
def load_words() -> frozenset[str]:
    """Return the EN+FR word list used to recognise natural language."""
    words: set[str] = set()
    for line in (DATA_DIR / "words_en_fr.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        words.update(word.lower() for word in line.split())
    return frozenset(words)


def load_cheatsheet() -> str:
    """The one-page decision tree (ctfc/data/cheatsheet.md), as Markdown text."""
    return (DATA_DIR / "cheatsheet.md").read_text(encoding="utf-8")


# The documents that ship *inside* the package, so that they are readable on the
# day of the CTF with no network and no copy of the repository. `docs/` keeps a
# one-paragraph pointer to each, which is why they live here and not there.
DOCS: tuple[tuple[str, str, str], ...] = (
    ("cheatsheet", "Cheat sheet", "cheatsheet.md"),
    ("how-it-works", "How it works", "how-it-works.md"),
    ("day-of-the-ctf", "Day of the CTF", "day-of-the-ctf.md"),
)


def list_docs() -> list[dict]:
    """The documents available, for a menu."""
    return [
        {"id": name, "title": title}
        for name, title, filename in DOCS
        if (DATA_DIR / filename).is_file()
    ]


def load_doc(name: str) -> str:
    """One document, as Markdown text. Raises KeyError for an unknown name."""
    for identifier, _title, filename in DOCS:
        if identifier == name:
            return (DATA_DIR / filename).read_text(encoding="utf-8")
    raise KeyError(name)


def load_volatility() -> dict:
    """The Volatility cheat sheet (ctfc/data/volatility.toml) for the web UI.

    Reference data only: ctfc never runs Volatility, it shows the commands.
    """
    return load_toml("volatility.toml")
