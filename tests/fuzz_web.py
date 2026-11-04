"""Throw random JSON at every web route and insist the answer is never a 500.

`tests/fuzz_formats.py` stops at the reader: it proves that `pdf.analyse` on
broken bytes raises `PdfError` rather than `IndexError`. But the page is the
part a stranger's file reaches **through Flask**, and between the socket and
the reader there is a layer of its own - the body has to be a JSON object, an
input string has to parse, an option has to be hex when the code assumes hex,
a session name ends up in a path. Each of those is a place where a 500 can
appear even though every reader behaves.

So the rule here is about the *answer*, not the exception:

    any body at all -> a JSON response with a 4xx or 2xx status. Never 5xx.

The bodies are built by a seeded RNG from the keys the API really uses, filled
with values chosen to break assumptions: a mutated fixture, a huge number, a
list where an object is expected, an input string with a `hex:` prefix and
non-hex after it, `null`, an empty string, a 1 MB blob. Non-JSON bodies and
malformed JSON go in too, since a stranger's browser is not obliged to be
polite.

**Path traversal gets its own pass**, because `CLAUDE.md` rule 5 says the
server sanitises paths: the names in `/api/docs/<name>`,
`/api/sessions/<name>/report` and the static route are probed with `..`,
absolute paths, URL-encoded separators and NUL bytes, and a reply that both
succeeds *and* contains the start of a real `/etc/passwd` line is a failure.

Run it:

    python tests/fuzz_web.py                   # 300 rounds, seed 0
    python tests/fuzz_web.py --rounds 3000 --seed 7 --route /api/sym
    make fuzz-web
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # so it runs as a plain script too
    sys.path.insert(0, str(ROOT))

from ctfc.config import Config  # noqa: E402
from ctfc.web.app import create_app  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"

# A status that means "I understood you and I refuse", or "here you are".
# Anything 5xx is the bug this file hunts. 405/404 happen when a route is
# called the wrong way, which is a correct answer too.
ALLOWED = {200, 201, 204, 400, 401, 403, 404, 405, 409, 413, 415, 422, 429}

# The keys the API actually reads, so the random bodies look like real ones.
KEYS = (
    "input",
    "data_b64",
    "name",
    "format",
    "options",
    "token",
    "value",
    "hash",
    "pattern",
    "cipher",
    "mode",
    "key",
    "iv",
    "blob",
    "passphrase",
    "secret",
    "recipe",
    "steps",
    "source",
    "language",
    "filename",
    "reader",
    "against",
    "length",
    "seconds",
    "wordlist",
    "id",
    "tool",
    "args",
    "flag",
    "note",
    "query",
    "title",
)

# The names probed against every route that takes one in its path.
NASTY_NAMES = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "%00etc/passwd",
    "cheatsheet\x00.md",
    "nul",
    "." * 300,
    "a/b/c",
    "-",
    "",
    "CON",
    "sessions/../../secret",
)


@dataclass
class Failure:
    """One request that was answered with something it should not have been."""

    route: str
    status: int
    seed: int
    body: str
    detail: str

    def report(self) -> str:
        return (
            f"{self.route} answered {self.status}\n"
            f"  seed {self.seed}\n"
            f"  body {self.body[:400]}\n"
            f"  {self.detail[:600]}"
        )


@dataclass
class Result:
    rounds: int = 0
    failures: list[Failure] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)


def corpus() -> list[bytes]:
    """A few fixtures, as the raw material for the random bodies."""
    names = (
        "png_with_zip.png",
        "layers_b64_zlib_hex.txt",
        "audit_malicious.pdf",
        "compound_message.msg",
        "audio_lsb.wav",
        "exif_photo.jpg",
        "lens_webshell.php",
        "audit_notes.sqlite",
    )
    out = []
    for name in names:
        path = FIXTURES / name
        if path.is_file():
            out.append(path.read_bytes()[:200_000])
    return out or [b"ctfc"]


def random_value(rng: random.Random, blobs: list[bytes], depth: int = 0):
    """One value for a JSON body: usually plausible, sometimes hostile."""
    choice = rng.randrange(14)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice([True, False])
    if choice == 2:
        return rng.choice([0, -1, 1, 2**31, 2**63, -(2**63), 10**30])
    if choice == 3:
        return rng.choice(["", " ", "\x00", "\n", "0x", "hex:zz", "b64:!!!!", "text:"])
    if choice == 4:
        blob = blobs[rng.randrange(len(blobs))]
        return "b64:" + base64.b64encode(blob[: rng.randrange(1, 4000)]).decode()
    if choice == 5:
        blob = blobs[rng.randrange(len(blobs))]
        return base64.b64encode(blob[: rng.randrange(1, 4000)]).decode()
    if choice == 6:
        return "hex:" + blobs[0][: rng.randrange(1, 64)].hex()
    if choice == 7:
        return rng.choice(["aes", "des", "rc4", "nope", "AES-256-CBC", "cbc", "ecb", "???"])
    if choice == 8:
        return "A" * rng.choice([1, 100, 10_000, 200_000])
    if choice == 9:
        return rng.choice(list(NASTY_NAMES))
    if choice == 10 and depth < 2:
        return [random_value(rng, blobs, depth + 1) for _ in range(rng.randrange(4))]
    if choice == 11 and depth < 2:
        return {
            rng.choice(KEYS): random_value(rng, blobs, depth + 1) for _ in range(rng.randrange(4))
        }
    if choice == 12:
        return rng.choice(["../../etc/passwd", "file:///etc/passwd", "http://127.0.0.1:1/"])
    return rng.choice(["CYBN{x}", "ctfc", "1337", "-1.5", "{}", "[]"])


def random_body(rng: random.Random, blobs: list[bytes]):
    """A whole request body. One in eight is not an object at all."""
    shape = rng.randrange(8)
    if shape == 0:
        return random_value(rng, blobs)  # a scalar or a list where a dict is expected
    body = {}
    for _ in range(rng.randrange(1, 6)):
        body[rng.choice(KEYS)] = random_value(rng, blobs)
    if rng.randrange(3) == 0:
        body["options"] = {
            rng.choice(KEYS): random_value(rng, blobs, 1) for _ in range(rng.randrange(3))
        }
    return body


def routes_of(app) -> list[tuple[str, str]]:
    """Every (method, url) worth calling, with the path parameters filled in."""
    found: list[tuple[str, str]] = []
    for rule in app.url_map.iter_rules():
        if "static" in (rule.endpoint or ""):
            continue
        url = str(rule)
        if "<path:filename>" in url:
            continue  # the static catch-all: covered by the traversal pass
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            filled = (
                url.replace("<name>", "fuzz")
                .replace("<kind>", "auto")
                .replace("<job_id>", "0" * 32)
            )
            if "<" in filled:
                continue  # a parameter we do not know how to fill
            found.append((method, filled))
    return sorted(set(found))


def check(client, method: str, url: str, body, seed: int) -> Failure | None:
    """Send one request and judge the answer."""
    try:
        if method == "GET":
            response = client.get(url)
        elif isinstance(body, (bytes, str)):
            response = client.post(url, data=body, content_type="application/json")
        else:
            response = client.post(url, json=body)
    except Exception as error:  # noqa: BLE001 - an exception escaping Flask is the bug
        frames = traceback.extract_tb(error.__traceback__)
        where = f"{frames[-1].filename.split('/')[-1]}:{frames[-1].lineno}" if frames else "?"
        return Failure(
            route=f"{method} {url}",
            status=0,
            seed=seed,
            body=json.dumps(body, default=str)[:400],
            detail=f"{type(error).__name__}: {error} at {where}",
        )
    if response.status_code in ALLOWED:
        return None
    return Failure(
        route=f"{method} {url}",
        status=response.status_code,
        seed=seed,
        body=json.dumps(body, default=str)[:400],
        detail=response.get_data(as_text=True)[:600],
    )


def leaked(response) -> bool:
    """Did a traversal attempt actually hand back a system file?"""
    if response.status_code != 200:
        return False
    text = response.get_data(as_text=True)[:4000]
    return "root:x:0:0" in text or "/bin/bash\n" in text and ":x:" in text


def fuzz(rounds: int = 300, seed: int = 0, route: str = "") -> Result:
    """Random bodies at every route, plus the traversal pass. Deterministic."""
    app = create_app(Config(max_upload_mb=4))
    app.testing = False  # we want Flask's own 500, not a re-raised exception
    client = app.test_client()
    blobs = corpus()
    result = Result()

    targets = [item for item in routes_of(app) if not route or route in item[1]]
    result.routes = [f"{method} {url}" for method, url in targets]

    for round_number in range(rounds):
        round_seed = seed * 1_000_003 + round_number
        rng = random.Random(round_seed)
        method, url = targets[rng.randrange(len(targets))]
        if method == "GET":
            body = None
        elif rng.randrange(10) == 0:
            # Not JSON at all: raw bytes, or JSON that does not parse.
            body = rng.choice([b"\x00\x01\x02", b"{", b"[1,", b"not json", bytes(1000)])
        else:
            body = random_body(rng, blobs)
        result.rounds += 1
        failure = check(client, method, url, body, round_seed)
        if failure is not None:
            result.failures.append(failure)

    # The traversal pass: every route that takes a name, plus the static route.
    for name in NASTY_NAMES:
        for url in (
            f"/api/docs/{name}",
            f"/api/sessions/{name}/report",
            f"/api/sessions/{name}/replay",
            f"/{name}",
        ):
            result.rounds += 1
            try:
                response = client.get(url)
            except Exception as error:  # noqa: BLE001
                result.failures.append(
                    Failure(route=f"GET {url}", status=0, seed=-1, body="", detail=str(error))
                )
                continue
            if response.status_code not in ALLOWED:
                result.failures.append(
                    Failure(
                        route=f"GET {url}",
                        status=response.status_code,
                        seed=-1,
                        body="",
                        detail=response.get_data(as_text=True)[:400],
                    )
                )
            elif leaked(response):
                result.failures.append(
                    Failure(
                        route=f"GET {url}",
                        status=response.status_code,
                        seed=-1,
                        body="",
                        detail="the answer contains a system file: path traversal",
                    )
                )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--route", default="", help="only the routes whose URL contains this")
    args = parser.parse_args(argv)

    result = fuzz(rounds=args.rounds, seed=args.seed, route=args.route)
    print(f"{len(result.routes)} route(s), {result.rounds} request(s)")
    for failure in result.failures:
        print("\n" + failure.report())
    if result.failures:
        print(f"\n{len(result.failures)} bad answer(s)")
        return 1
    print("every answer was a 2xx or a 4xx")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
