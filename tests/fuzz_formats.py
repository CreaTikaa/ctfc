"""Throw broken files at every format reader and insist they fail politely.

About a dozen modules in `ctfc/core` chew on bytes that came from a challenge,
which is to say from a stranger. They are written defensively - but
"defensively" is a claim, and this is the proof. The rule each reader has to
obey is simple:

    given any bytes at all, either return a report, or raise *its own* error.

Never `IndexError`, never `struct.error`, never `KeyError`, never a MemoryError
from a length field that said four gigabytes, and never a hang. Anything else
means the web UI answers 500 instead of "this is not a PDF", and the terminal
prints a traceback at the worst possible moment of a CTF.

The fixtures are the seed corpus, because they are already the right shapes;
each round picks one, mutates it with a seeded RNG, and calls the reader. The
mutations are the ones that actually break parsers: flip a byte, cut the file
short, blow a length field up to 0xffffffff, duplicate or swap a chunk.

Run it:

    python tests/fuzz_formats.py                 # 200 rounds, seed 0
    python tests/fuzz_formats.py --rounds 5000 --seed 7
    make fuzz                                    # the longer sweep

`tests/test_fuzz_formats.py` runs a short fixed-seed sweep inside `make test`,
so a regression is caught without waiting for anyone to remember this file.
Every failure prints the seed, the fixture and the mutation, which is all that
is needed to reproduce it.
"""

from __future__ import annotations

import argparse
import random
import signal
import struct
import sys
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # so it runs as a plain script too
    sys.path.insert(0, str(ROOT))

from ctfc.core import (  # noqa: E402
    cfb,
    detect,
    evtx,
    hive,
    luks,
    mail,
    office,
    pcap,
    pdf,
    pe,
    protobuf,
    radius,
    repair,
    sqlitedb,
    stego,
    timestamps,
    zipinfo,
)
from ctfc.core.budget import Budget  # noqa: E402
from ctfc.core.jwt import JwtError  # noqa: E402
from ctfc.core.jwt import analyse as jwt_analyse  # noqa: E402

if str(Path(__file__).parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent))
from test_hive import simple_hive  # noqa: E402
from test_stego import make_bmp  # noqa: E402


def tiny_bmp() -> bytes:
    """A 4x4 24-bit BMP: there is no .bmp among the fixtures to mutate."""
    return make_bmp(4, 4, [bytes(range(12)) for _ in range(4)])


FIXTURES = Path(__file__).parent / "fixtures"

# A reader must not spend the whole afternoon on one broken file either.
TIMEOUT_SECONDS = 10


class FuzzTimeout(Exception):
    """The reader did not come back in time: a hang is a bug like any other."""


@dataclass(frozen=True)
class Reader:
    """One entry point under test, and what it is allowed to raise."""

    name: str
    call: Callable[[bytes], object]
    allowed: tuple[type[BaseException], ...]
    patterns: tuple[str, ...] = ()  # fixture globs that make a useful seed corpus
    builders: tuple[Callable[[], bytes], ...] = ()  # seeds built in memory

    def corpus(self) -> list[tuple[str, bytes]]:
        """The seed inputs, as (label, bytes). Labels name the failing case."""
        found: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for pattern in self.patterns:
            for path in sorted(FIXTURES.glob(pattern)):
                if path.is_file() and path.name not in seen:
                    seen.add(path.name)
                    found.append((path.name, path.read_bytes()))
        for builder in self.builders:
            found.append((f"{builder.__name__}()", builder()))
        return found


def _tiny_budget() -> Budget:
    """Searches inside a reader get a short leash: we are testing parsing."""
    return Budget(max_attempts=20_000, max_seconds=2)


READERS: tuple[Reader, ...] = (
    Reader("cfb", cfb.read, (cfb.CfbError,), ("*.doc", "audit_macro.doc")),
    Reader("office", office.analyse, (office.OfficeError,), ("*.doc", "*.docm")),
    Reader("pdf", pdf.analyse, (pdf.PdfError,), ("*.pdf", "*.pdf.secured")),
    Reader(
        "stego",
        lambda data: stego.analyse(data, budget=_tiny_budget()),
        (stego.StegoError,),
        ("*.png", "*.bmp"),
        builders=(tiny_bmp,),
    ),
    Reader(
        "zipinfo",
        lambda data: zipinfo.analyse(data, budget=_tiny_budget()),
        (zipinfo.ZipError,),
        ("*.zip", "png_with_zip.png"),
    ),
    Reader("sqlitedb", sqlitedb.analyse, (sqlitedb.SqliteError,), ("*.sqlite",)),
    # No real hive on this machine: the seed is the one tests/test_hive.py builds
    # from the regf structures.
    Reader("hive", hive.analyse, (hive.HiveError,), builders=(simple_hive,)),
    Reader("pe", pe.analyse, (pe.PeError,), ("*.exe", "*.dll", "*.bin")),
    Reader("evtx", evtx.analyse, (evtx.EvtxError,), ("*.evtx",)),
    Reader("protobuf", protobuf.parse, (protobuf.ProtobufError,), ("*.pb",)),
    Reader("protobuf_text", protobuf.decode_to_text, (protobuf.ProtobufError,), ("*.pb",)),
    Reader("pcap", pcap.analyse, (pcap.PcapError,), ("*.pcap", "*.pcapng")),
    Reader("mail", mail.extract, (), ("audit_mail_imap.pcap", "*.txt")),
    Reader("luks", luks.parse_header, (), ("*.raw", "audit_luks_mem.raw")),
    Reader("radius", radius.parse_access_request, (), ("*.pcap",)),
    Reader("repair", repair.repair, (), ("*.fun", "*.png", "*.bin", "*.zip")),
    Reader("timestamps", timestamps.from_bytes, (), ("*.bin",)),
    # detect is the one that is *always* handed unknown bytes, so it is the one
    # that must never raise at all.
    Reader("detect", detect.detect, (), ("*",)),
    Reader(
        "jwt",
        lambda data: jwt_analyse(data.decode("utf-8", "replace"), try_secrets=False),
        (JwtError,),
        ("jwt.txt",),
    ),
)


# --- mutations ---------------------------------------------------------------


def flip_bytes(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Change a few bytes: the plain "this file is slightly corrupt" case."""
    if not data:
        return data, "flip (empty)"
    out = bytearray(data)
    count = rng.randint(1, max(1, len(out) // 50))
    places = [rng.randrange(len(out)) for _ in range(count)]
    for place in places:
        out[place] = rng.randrange(256)
    return bytes(out), f"flip {count} byte(s) at {places[:5]}"


def truncate(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Cut the file short: the reader that trusts a header walks off the end."""
    if not data:
        return data, "truncate (empty)"
    keep = rng.randrange(len(data))
    return data[:keep], f"truncate to {keep} of {len(data)} bytes"


def tiny_prefix(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Only a magic number and nothing behind it."""
    keep = rng.randint(0, min(32, len(data)))
    return data[:keep], f"keep only the first {keep} bytes"


def blow_up_a_length(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Set a 32-bit field to a huge value: the classic allocation bomb."""
    if len(data) < 8:
        return data, "length field (too short)"
    out = bytearray(data)
    place = rng.randrange(0, len(out) - 4)
    value = rng.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x10000000, 0xFFFFFF00])
    struct.pack_into("<I", out, place, value)
    return bytes(out), f"length field at {place} set to {value:#x}"


def zero_region(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    if not data:
        return data, "zero (empty)"
    out = bytearray(data)
    start = rng.randrange(len(out))
    length = rng.randint(1, min(512, len(out) - start))
    out[start : start + length] = b"\x00" * length
    return bytes(out), f"zero {length} bytes at {start}"


def duplicate_chunk(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """A repeated structure: offsets that point backwards, loops that do not end."""
    if len(data) < 16:
        return data, "duplicate (too short)"
    start = rng.randrange(len(data) - 8)
    length = rng.randint(4, min(1024, len(data) - start))
    chunk = data[start : start + length]
    return data[:start] + chunk + chunk + data[start + length :], (
        f"duplicate {length} bytes at {start}"
    )


def swap_chunks(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    if len(data) < 32:
        return data, "swap (too short)"
    size = rng.randint(4, min(256, len(data) // 4))
    first = rng.randrange(0, len(data) - 2 * size)
    second = rng.randrange(first + size, len(data) - size)
    out = bytearray(data)
    out[first : first + size], out[second : second + size] = (
        data[second : second + size],
        data[first : first + size],
    )
    return bytes(out), f"swap {size} bytes at {first} and {second}"


def splice_random(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Insert noise in the middle: a parser that counts has to notice."""
    place = rng.randrange(len(data) + 1) if data else 0
    noise = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    return data[:place] + noise + data[place:], f"insert {len(noise)} random bytes at {place}"


MUTATIONS: tuple[Callable[[bytes, random.Random], tuple[bytes, str]], ...] = (
    flip_bytes,
    truncate,
    tiny_prefix,
    blow_up_a_length,
    zero_region,
    duplicate_chunk,
    swap_chunks,
    splice_random,
)


# --- the harness -------------------------------------------------------------


@dataclass
class Failure:
    """One reader, one input, one exception that should not have happened."""

    reader: str
    fixture: str
    mutation: str
    seed: int
    error: str
    where: str

    def report(self) -> str:
        return (
            f"{self.reader}: {self.error}\n"
            f"  fixture  {self.fixture}\n"
            f"  mutation {self.mutation}\n"
            f"  seed     {self.seed}\n"
            f"  at       {self.where}"
        )


@dataclass
class Result:
    rounds: int = 0
    failures: list[Failure] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _timeout_handler(_signum, _frame):
    raise FuzzTimeout(f"no answer after {TIMEOUT_SECONDS} seconds")


def call_reader(reader: Reader, data: bytes) -> BaseException | None:
    """Call one reader under a wall-clock alarm. Returns the exception, if any."""
    previous = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        reader.call(data)
        return None
    except BaseException as error:  # noqa: BLE001 - that is the whole point
        return error
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def is_acceptable(reader: Reader, error: BaseException) -> bool:
    """A reader may raise its own error, and nothing else."""
    return isinstance(error, reader.allowed) if reader.allowed else False


def fuzz(
    rounds: int = 200,
    seed: int = 0,
    readers: Sequence[Reader] = READERS,
    *,
    stop_after: int | None = None,
) -> Result:
    """Run `rounds` mutations per reader. Deterministic for a given seed."""
    result = Result()
    for reader in readers:
        corpus = reader.corpus()
        if not corpus:
            result.skipped.append(reader.name)
            continue
        for round_number in range(rounds):
            # One RNG per round, seeded from the round: a failure is reproducible
            # from the printed seed alone.
            round_seed = seed * 1_000_003 + round_number
            rng = random.Random(round_seed)
            label, original = corpus[rng.randrange(len(corpus))]
            mutate = MUTATIONS[rng.randrange(len(MUTATIONS))]
            data, description = mutate(original, rng)
            result.rounds += 1
            error = call_reader(reader, data)
            if error is None or is_acceptable(reader, error):
                continue
            frames = traceback.extract_tb(error.__traceback__)
            where = f"{frames[-1].filename.split('/')[-1]}:{frames[-1].lineno}" if frames else "?"
            result.failures.append(
                Failure(
                    reader=reader.name,
                    fixture=label,
                    mutation=description,
                    seed=round_seed,
                    error=f"{type(error).__name__}: {error}"[:200],
                    where=where,
                )
            )
            if stop_after is not None and len(result.failures) >= stop_after:
                return result
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--rounds", type=int, default=200, help="mutations per reader")
    parser.add_argument("--seed", type=int, default=0, help="base seed (same seed, same run)")
    parser.add_argument("--reader", action="append", help="only this reader (repeatable)")
    args = parser.parse_args(argv)

    chosen = READERS
    if args.reader:
        wanted = set(args.reader)
        chosen = tuple(reader for reader in READERS if reader.name in wanted)
        if not chosen:
            names = ", ".join(reader.name for reader in READERS)
            print(f"no such reader; known: {names}")
            return 2

    result = fuzz(rounds=args.rounds, seed=args.seed, readers=chosen)
    print(f"{result.rounds} rounds over {len(chosen) - len(result.skipped)} reader(s)")
    if result.skipped:
        print(f"no corpus, skipped: {', '.join(result.skipped)}")
    for failure in result.failures:
        print()
        print(failure.report())
    print()
    print(f"{len(result.failures)} failure(s)")
    return 1 if result.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
