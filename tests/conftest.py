"""Shared test helpers."""

import os
import tempfile
from pathlib import Path

import pytest

# Sessions written by the tests (and by the CLI subprocesses they start, which
# inherit the environment) go to a throwaway folder, never ~/.ctfc/sessions.
os.environ["CTFC_SESSIONS_DIR"] = tempfile.mkdtemp(prefix="ctfc-test-sessions-")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_bytes():
    """Return a function that reads tests/fixtures/<name>."""

    def read(name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    return read
