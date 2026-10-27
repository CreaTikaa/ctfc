"""Shared test helpers."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_bytes():
    """Return a function that reads tests/fixtures/<name>."""

    def read(name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    return read
