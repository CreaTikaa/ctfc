"""Replay the local challenge corpus and guard against two kinds of harm:

1. a REGRESSION - a flag `ctfc solve` used to find and no longer does;
2. a BUDGET violation - a file whose wall-clock runs far past the time budget
   (a hang or a perf cliff: the real enemy when the CTF clock is running).

The corpus (`corpus/challenges/`, gitignored) and the baseline it records
(`corpus/regression-baseline.json`, also gitignored) stay on this machine: they
hold real public-CTF flags, which are never committed. The first run records the
baseline; later runs compare against it.

    python tests/regression.py                 # compare against the baseline
    python tests/regression.py --update        # record the current result as the baseline
    python tests/regression.py --seconds 20    # a longer budget per file

Exit code is non-zero when a flag was lost or a file blew the budget, so this can
gate a change. It is NOT part of `make test` (it needs the local corpus); run it
with `make regression` before trusting a change for the day of the CTF.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus" / "challenges"
BASELINE = ROOT / "corpus" / "regression-baseline.json"
PYTHON = ROOT / ".venv" / "bin" / "python"
# A file may legitimately spend a little longer than the budget (reading the
# file, one flag scan over it). Past this much over, it is a cliff worth fixing.
OVERHEAD_OK = 12.0


def solve(path: Path, seconds: int) -> tuple[list[str], float, bool]:
    """Run `ctfc solve --json` on one file: (flags, wall seconds, timed_out)."""
    hard = seconds + 120  # a generous kill: a real hang is what we are hunting
    started = time.time()
    try:
        done = subprocess.run(
            [str(PYTHON), "-m", "ctfc", "solve", str(path), "--json", "--seconds", str(seconds)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=hard,
        )
    except subprocess.TimeoutExpired:
        return [], time.time() - started, True
    wall = time.time() - started
    try:
        report = json.loads(done.stdout)
    except json.JSONDecodeError:
        return [], wall, False
    return sorted(hit["text"] for hit in report.get("flags", [])), wall, False


def run(seconds: int) -> dict[str, dict]:
    """Solve every corpus file and return {relpath: {flags, wall}}."""
    result: dict[str, dict] = {}
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file() and p.name != "README.md")
    for path in files:
        if path.stat().st_size == 0:
            continue
        flags, wall, timed_out = solve(path, seconds)
        rel = str(path.relative_to(CORPUS))
        result[rel] = {"flags": flags, "wall": round(wall, 1), "timed_out": timed_out}
        marker = "HANG" if timed_out else (f"{len(flags)} flag" if flags else "-")
        print(f"  {wall:6.1f}s  {marker:8}  {rel}", flush=True)
    return result


def compare(baseline: dict, current: dict, seconds: int) -> int:
    """Report lost/gained flags and budget violations. Returns an exit code."""
    problems = 0
    for rel, was in baseline.items():
        now = current.get(rel)
        if now is None:
            print(f"GONE from corpus (not run): {rel}")
            continue
        lost = set(was["flags"]) - set(now["flags"])
        if lost:
            problems += 1
            print(f"REGRESSION {rel}: lost {sorted(lost)}")
    for rel, now in current.items():
        gained = set(now["flags"]) - set(baseline.get(rel, {}).get("flags", []))
        if gained:
            print(f"gained {rel}: {sorted(gained)}")
        if now["timed_out"]:
            problems += 1
            print(f"HANG {rel}: killed before it finished")
        elif now["wall"] > seconds + OVERHEAD_OK:
            problems += 1
            print(f"BUDGET {rel}: {now['wall']}s wall for a {seconds}s budget")
    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=15, help="time budget per file")
    parser.add_argument("--update", action="store_true", help="record the baseline, do not compare")
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    args = parser.parse_args()

    if not CORPUS.is_dir():
        print(f"no corpus at {CORPUS}: nothing to replay (this is normal on a fresh clone)")
        return 0

    print(f"replaying {CORPUS} with a {args.seconds}s budget...")
    current = run(args.seconds)

    if args.update or not args.baseline.exists():
        args.baseline.write_text(json.dumps(current, indent=1, sort_keys=True))
        total = sum(len(v["flags"]) for v in current.values())
        print(f"\nbaseline written to {args.baseline}: {len(current)} files, {total} flag(s)")
        return 0

    baseline = json.loads(args.baseline.read_text())
    code = compare(baseline, current, args.seconds)
    print("\nregression: FAIL (see above)" if code else "\nregression: OK (no flag lost, no hang)")
    return code


if __name__ == "__main__":
    sys.exit(main())
