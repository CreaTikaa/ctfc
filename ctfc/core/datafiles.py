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
def load_words() -> frozenset[str]:
    """Return the EN+FR word list used to recognise natural language."""
    words: set[str] = set()
    for line in (DATA_DIR / "words_en_fr.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        words.update(word.lower() for word in line.split())
    return frozenset(words)
