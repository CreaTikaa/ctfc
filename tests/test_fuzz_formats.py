"""A short, fixed-seed fuzz sweep over the format readers, inside `make test`.

The harness lives in `tests/fuzz_formats.py`; this file is what makes it run
without anyone remembering to. The sweep is deliberately small so the suite
stays quick - `make fuzz` is the long one. A failure here prints the seed, the
fixture and the mutation, which reproduces it exactly:

    python tests/fuzz_formats.py --rounds 600 --seed 3 --reader stego
"""

from __future__ import annotations

import pytest
from fuzz_formats import READERS, fuzz

ROUNDS = 30  # per reader; the long sweep is `make fuzz`


@pytest.mark.parametrize("reader", READERS, ids=lambda reader: reader.name)
def test_reader_survives_broken_files(reader):
    """Any bytes in: a report out, or this reader's own error. Nothing else."""
    result = fuzz(rounds=ROUNDS, seed=0, readers=[reader], stop_after=1)
    assert not result.failures, "\n" + result.failures[0].report()


def test_every_reader_has_something_to_chew_on():
    """A reader with no corpus is silently untested: catch that here."""
    result = fuzz(rounds=1, seed=0)
    assert not result.skipped, f"no seed input for: {', '.join(result.skipped)}"
