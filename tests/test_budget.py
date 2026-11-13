"""The budget guard: `ctfc solve` must keep its time budget, never hang (lot P).

A 227 MB EDR log (IrisCTF 2025 Tracem 1) made `solve` run ~20 s for an 8 s
budget: the per-piece flag search (`hunt`) decoded every base64 run and
assembled split fragments over the whole file, outside the budget. Above
`MAX_DEEP_HUNT`, `hunt` now does the direct search only. The direct search still
finds a plain flag and a base64 of the configured prefix anywhere in the file;
only the costly, low-yield extras (decode every run, fragment assembly) are
skipped. The real enemy on CTF day is a hang, not a missed layered flag in a
227 MB log.
"""

from __future__ import annotations

import time

from ctfc.core.flags import MAX_DEEP_HUNT, hunt

BIG = MAX_DEEP_HUNT + 1_000_000  # just over the deep-hunt threshold


def test_a_plain_flag_is_found_in_a_big_file_and_fast():
    data = b"\x00" * BIG + b"CYBN{plain_in_a_huge_file}" + b"\x00" * 1000
    started = time.monotonic()
    flags = [hit.text for hit in hunt(data).flags]
    assert "CYBN{plain_in_a_huge_file}" in flags
    assert time.monotonic() - started < 5  # a single scan, not a per-run decode storm


def test_a_base64_of_the_prefix_is_still_found_in_a_big_file():
    import base64

    token = base64.b64encode(b"CYBN{base64_of_the_prefix}")
    data = b"z" * BIG + b" " + token + b" "
    # find_flags runs even above the threshold, and it decodes base64 runs that
    # carry the configured prefix - so this is NOT lost.
    assert "CYBN{base64_of_the_prefix}" in [hit.text for hit in hunt(data).flags]


def test_the_deep_extras_are_skipped_above_the_threshold():
    fragment = b" CYBN{an_open_fragment_no_close "
    small = b"noise " * 4 + fragment + b" tail" * 4
    big = b"z" * BIG + fragment + b" tail"
    # Below the threshold the open fragment is reported; above it, the fragment
    # assembly is skipped (that is the work that blew the budget).
    assert any("an_open_fragment" in f.text for f in hunt(small).fragments)
    assert hunt(big).fragments == []
