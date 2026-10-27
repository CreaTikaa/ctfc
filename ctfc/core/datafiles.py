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


@lru_cache(maxsize=1)
def load_words() -> frozenset[str]:
    """Return the EN+FR word list used to recognise natural language."""
    words: set[str] = set()
    for line in (DATA_DIR / "words_en_fr.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        words.update(word.lower() for word in line.split())
    return frozenset(words)
