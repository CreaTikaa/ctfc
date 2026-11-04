"""A short, fixed-seed fuzz sweep over the web API, inside `make test`.

The harness lives in `tests/fuzz_web.py`. This file is what makes it run
without anyone remembering to, and it is deliberately small: `make fuzz-web`
is the long sweep. A failure prints the route, the seed and the body, which
reproduces it exactly:

    python tests/fuzz_web.py --rounds 3000 --seed 7 --route /api/sym
"""

from __future__ import annotations

from fuzz_web import ALLOWED, fuzz

ROUNDS = 60  # the long sweep is `make fuzz-web`


def test_no_route_answers_5xx_to_a_hostile_body():
    """Any body at all: a JSON answer with a 2xx or 4xx. Never a 500."""
    result = fuzz(rounds=ROUNDS, seed=0)
    assert result.routes, "no route was found to fuzz"
    assert not result.failures, "\n\n".join(failure.report() for failure in result.failures[:3])


def test_the_traversal_pass_finds_no_system_file():
    """`..` and friends in a path parameter must not hand back /etc/passwd."""
    result = fuzz(rounds=1, seed=0)
    leaks = [failure for failure in result.failures if "traversal" in failure.detail]
    assert not leaks, "\n".join(failure.report() for failure in leaks)


def test_the_allowed_statuses_do_not_include_server_errors():
    """The rule this file enforces, asserted rather than assumed."""
    assert not any(status >= 500 for status in ALLOWED)
