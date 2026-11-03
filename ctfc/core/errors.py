"""The one base class every format reader's error inherits from.

Each reader in `ctfc.core` raises its own error - `PdfError`, `ZipError`,
`SevenZipError` - so that a caller can tell which reader refused the bytes, and
so that the fuzzing harness can insist a reader never raises anything else.

They all inherit from `FormatError`, and `FormatError` inherits from
`ValueError`, which is the honest description of what happened: you handed a
function a value it cannot work with. It also has a practical consequence worth
knowing about. The CLI and the web API both already turn a `ValueError` into a
clean one-line message, so a reader's error reaches the user as

    error: not a tar, 7z, RAR or cabinet. A ZIP goes to `ctfc zip` [...]

instead of a traceback. That is the whole reason for this file: in the middle of
a timed CTF, a stack trace for "wrong file type" is a waste of twenty seconds.
"""

from __future__ import annotations


class FormatError(ValueError):
    """These bytes are not the format the reader was asked to read."""
