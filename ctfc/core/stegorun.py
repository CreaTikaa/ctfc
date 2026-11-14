"""Run the installed stego / forensic tools on a media file and read the result.

ctfc already *names* the right external tool for a flagless image or sound
(zsteg, steghide, zbarimg, exiftool, multimon-ng - see `readers._open_stego`,
`_open_exif`, `_open_wav`). When the tool is installed there is no reason to make
the user copy-paste the command and read the output by hand: ctfc runs it and
reads the output back, so a flag that zsteg pulls out of the pixels, or a QR
code zbarimg decodes, or a passphrase-less steghide payload, is reported like
any other flag - and when nothing is a flag, the interesting lines become a lead
to follow (`ctfc auto` on a decoded QR, the Morse that multimon-ng transcribed).

The rules are the same three as `core/tools.py`:

- **argument lists only** (hard rule 4): every command is built here as a list
  and run with `subprocess.run([...])`, `shell=False`. The file path only ever
  lands in a list slot, never in a shell string.
- **offline**: every tool in the table runs entirely on the local file; nothing
  is sent anywhere.
- **the file is analysed, never executed** (hard rule 3): zsteg, steghide,
  exiftool, zbarimg and multimon-ng are readers - the same category as the
  `binwalk` entry already in `tools.toml`. They parse the bytes; they do not run
  them.

Only tools that are actually installed are run (a missing one is silently
skipped), under a per-tool timeout, with their output written into a throwaway
temp directory that is deleted at the end.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core.flags import (
    WEAK_GENERIC_STRENGTH,
    FlagHit,
    FlagSet,
    default_flagset,
    find_flags,
)
from ctfc.core.tools import program_argv

# A single tool must not hold up the whole solve: zsteg -a on a big PNG is the
# slow one, so it gets its own budget, shorter than the solve's.
TOOL_TIMEOUT = 45
# How much of a tool's output is kept and scanned (zsteg -a is very chatty).
OUTPUT_LIMIT = 200_000
# A steghide / stegseek payload bigger than this is a file, not a flag line: it
# is surfaced as a lead to run `ctfc solve` on, not decoded inline here.
PAYLOAD_PREVIEW = 400


@dataclass
class ToolLead:
    """A tool ran, found no outright flag, but produced something worth a look."""

    tool: str  # "zsteg", "zbarimg"...
    summary: str  # one line: what it is and what to do with it
    command: str  # the ctfc command to follow it up (often `ctfc auto` on a file)
    preview: str = ""  # the decoded text / the interesting lines
    score: float = 0.62  # above the generic 0.55 lead: a real tool decoded something


@dataclass
class MediaToolRun:
    """Everything the stego tools made of one media file."""

    flags: list[FlagHit] = field(default_factory=list)
    leads: list[ToolLead] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)  # tool ids that actually ran
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# One runner per tool
# ---------------------------------------------------------------------------
#
# A runner says, for one external tool: which readers it applies to, how to
# build its argument list (given the input file, a scratch folder and an
# optional wordlist), and how to read its result into flags + leads. Returning
# `None` from `argv` means "not applicable this time" (e.g. stegseek with no
# wordlist), and the tool is skipped.


@dataclass(frozen=True)
class Runner:
    """How to run one external tool and interpret it, safely."""

    id: str
    program: str  # the executable name (resolved via config tool_paths / PATH)
    readers: tuple[str, ...]  # the reader names this applies to ("stego", "wav"...)
    argv: Callable[[Path, Path, str], list[str] | None]
    interpret: Callable[[RunContext], None]


@dataclass
class RunContext:
    """Passed to a runner's `interpret`: the raw result and where to put findings."""

    tool: str
    returncode: int
    stdout: str
    stderr: str
    infile: Path
    outdir: Path
    flagset: FlagSet
    run: MediaToolRun

    @property
    def text(self) -> str:
        return self.stdout + "\n" + self.stderr

    def scan(self, data: bytes | str, how: str) -> list[FlagHit]:
        """Keep the flags in `data` that are strong enough to trust from a tool.

        A tool's output is noisy (zsteg -a tries dozens of channels), so a flag
        is only promoted when it rates above the weak-generic bar - exactly the
        gate `solve` applies to a reader's own flags. The configured prefix and
        a wordy/hash body clear it; a chance `{...}` shape does not.
        """
        raw = data if isinstance(data, bytes) else data.encode("utf-8", "replace")
        kept = []
        for hit in find_flags(raw, self.flagset):
            if hit.how == "base64-prefix":
                continue
            if hit.strength <= WEAK_GENERIC_STRENGTH:
                continue
            tagged = FlagHit(
                hit.text, f"{self.tool}: {how}", hit.strength, hit.pattern, hit.encoded
            )
            if not any(existing.text == hit.text for existing in self.run.flags):
                self.run.flags.append(tagged)
            kept.append(tagged)
        return kept


def _interpret_zsteg(ctx: RunContext) -> None:
    """zsteg -a prints one line per channel order / bit plane it tried.

    A hidden message shows up as `b1,rgb,lsb,xy .. text: "the flag"` or
    `.. file: <something>`. Scan the whole thing for a flag; when there is none
    but zsteg still saw readable text or an embedded file, keep those lines as a
    lead (zsteg found *something* in the low bits - worth a human's eye)."""
    if ctx.scan(ctx.stdout, "LSB channel scan (-a)"):
        return
    interesting = [
        line.strip()
        for line in ctx.stdout.splitlines()
        if ("text:" in line or "file:" in line) and "..." not in line.split(":", 1)[-1][:6]
    ]
    # Drop zsteg's "nothing here" filler lines (all dots, or a lone byte value).
    interesting = [line for line in interesting if len(line) > 12][:6]
    if interesting:
        ctx.run.leads.append(
            ToolLead(
                tool="zsteg",
                summary="zsteg found readable data in the low bits (no flag shape): read these",
                command=f"zsteg -a {ctx.infile.name}",
                preview="\n".join(interesting)[:PAYLOAD_PREVIEW],
            )
        )


def _interpret_zbar(ctx: RunContext) -> None:
    """zbarimg prints `QR-Code:<payload>` (or `CODE-128:...`) per symbol it reads.

    The payload is often the flag itself, or a URL / a further-encoded string.
    Strip the `TYPE:` prefix, promote a flag, otherwise hand the decoded text on
    as a strong lead - a QR that decoded is a genuine next step, not a guess."""
    payloads = []
    for line in ctx.stdout.splitlines():
        if ":" in line and line.split(":", 1)[0].replace("-", "").isalnum():
            payload = line.split(":", 1)[1].strip()
            if payload:
                payloads.append(payload)
    if not payloads:
        return
    joined = "\n".join(payloads)
    if ctx.scan(joined, "decoded QR/barcode"):
        return
    ctx.run.leads.append(
        ToolLead(
            tool="zbarimg",
            summary=f"decoded a QR/barcode: {len(payloads)} symbol(s) - decode/follow the content",
            command=f"ctfc auto text:{payloads[0][:80]}",
            preview=joined[:PAYLOAD_PREVIEW],
        )
    )


def _interpret_steghide(ctx: RunContext) -> None:
    """steghide extracted with an empty passphrase, if the data had one.

    When it works, the payload file is in the scratch folder: hunt it for a flag
    and otherwise surface it as a file to solve. A non-zero exit just means no
    empty-passphrase payload - common, and not an error."""
    payload = ctx.outdir / "steghide.out"
    if ctx.returncode != 0 or not payload.is_file():
        return
    data = payload.read_bytes()
    if not data:
        return
    if ctx.scan(data, "steghide payload (empty passphrase)"):
        return
    preview = data[:PAYLOAD_PREVIEW].decode("utf-8", "replace")
    ctx.run.leads.append(
        ToolLead(
            tool="steghide",
            summary=f"steghide extracted a {len(data)}-byte payload with an empty passphrase",
            command="ctfc solve <the extracted payload>",
            preview=preview,
            score=0.72,
        )
    )


def _interpret_stegseek(ctx: RunContext) -> None:
    """stegseek cracked the steghide passphrase from the wordlist, if it is in there.

    It writes `<outdir>/stegseek.out` and prints the passphrase. Read the payload
    the same way as steghide; the passphrase itself goes in the note."""
    payload = ctx.outdir / "stegseek.out"
    if not payload.is_file():
        return
    data = payload.read_bytes()
    if not data:
        return
    passphrase = ""
    for line in ctx.text.splitlines():
        if "passphrase" in line.lower() and '"' in line:
            passphrase = line.split('"')[1]
            break
    note = f" (passphrase {passphrase!r})" if passphrase else ""
    if ctx.scan(data, f"stegseek payload{note}"):
        return
    ctx.run.leads.append(
        ToolLead(
            tool="stegseek",
            summary=f"stegseek cracked steghide{note}: {len(data)}-byte payload",
            command="ctfc solve <the extracted payload>",
            preview=data[:PAYLOAD_PREVIEW].decode("utf-8", "replace"),
            score=0.75,
        )
    )


def _interpret_exiftool(ctx: RunContext) -> None:
    """exiftool reads the thousand vendor tags ctfc's own EXIF reader does not.

    A flag hidden in a Comment / UserComment / Description field shows up here;
    promote it. No lead otherwise - the metadata dump itself is not a next step."""
    ctx.scan(ctx.stdout, "metadata field")


def _interpret_multimon(ctx: RunContext) -> None:
    """multimon-ng transcribes a tone code in the audio (Morse / DTMF / AFSK).

    Its lines are `MORSE: ...`, `DTMF: ...`. Morse carries no case or braces, so
    the transcript is usually a lead a human finishes (THEFLAGIS...), but scan it
    anyway in case the decode is already a whole flag."""
    lines = [
        line.strip()
        for line in ctx.text.splitlines()
        if line.split(":", 1)[0] in ("MORSE", "DTMF", "AFSK1200", "POCSAG", "FLEX")
    ]
    if not lines:
        return
    transcript = "\n".join(lines)
    if ctx.scan(transcript, "decoded tone code"):
        return
    ctx.run.leads.append(
        ToolLead(
            tool="multimon-ng",
            summary="multimon-ng transcribed a tone code (Morse/DTMF): read it as the flag",
            command="(read the transcript below)",
            preview=transcript[:PAYLOAD_PREVIEW],
            score=0.7,
        )
    )


def _argv_zsteg(infile: Path, outdir: Path, wordlist: str) -> list[str]:
    return ["zsteg", "-a", str(infile)]


def _argv_zbar(infile: Path, outdir: Path, wordlist: str) -> list[str]:
    # Enable the common symbologies; -q keeps the "scanned N" noise off stderr.
    return [
        "zbarimg", "--quiet", "-Sdisable",
        "-Sqrcode.enable", "-Scode128.enable", "-Scode39.enable", "-Sean13.enable",
        str(infile),
    ]


def _argv_steghide(infile: Path, outdir: Path, wordlist: str) -> list[str]:
    out = outdir / "steghide.out"
    # -p "" is the empty passphrase, -f overwrites the output file if present.
    return ["steghide", "extract", "-sf", str(infile), "-p", "", "-xf", str(out), "-f"]


def _argv_stegseek(infile: Path, outdir: Path, wordlist: str) -> list[str] | None:
    if not wordlist or not Path(wordlist).is_file():
        return None
    out = outdir / "stegseek.out"
    return ["stegseek", "--quiet", str(infile), wordlist, str(out)]


def _argv_exiftool(infile: Path, outdir: Path, wordlist: str) -> list[str]:
    return ["exiftool", "-s", "-G", str(infile)]


def _argv_multimon(infile: Path, outdir: Path, wordlist: str) -> list[str] | None:
    # multimon-ng wants 22050 Hz mono signed-16 raw; resample with sox first (a
    # separate process, no shell pipe). Without sox there is nothing reliable to
    # feed it, so the tool is skipped and its command stays a named lead.
    raw = outdir / "audio.raw"
    if not raw.is_file():
        return None
    return [
        "multimon-ng", "-t", "raw", "-a", "MORSE_CW", "-a", "DTMF", "-a", "AFSK1200", str(raw)
    ]


RUNNERS: tuple[Runner, ...] = (
    Runner("exiftool", "exiftool", ("stego", "exif", "wav"), _argv_exiftool, _interpret_exiftool),
    Runner("zsteg", "zsteg", ("stego",), _argv_zsteg, _interpret_zsteg),
    Runner("zbarimg", "zbarimg", ("stego", "exif"), _argv_zbar, _interpret_zbar),
    Runner("steghide", "steghide", ("exif", "wav", "stego"), _argv_steghide, _interpret_steghide),
    Runner("stegseek", "stegseek", ("exif", "wav", "stego"), _argv_stegseek, _interpret_stegseek),
    Runner("multimon-ng", "multimon-ng", ("wav",), _argv_multimon, _interpret_multimon),
)


def _resample_for_multimon(infile: Path, outdir: Path, tool_paths: dict | None) -> bool:
    """sox <wav> -> 22050 Hz mono signed-16 raw, so multimon-ng can read it.

    Returns True when the raw file was written. A separate process, argument
    list only - never a shell pipe."""
    sox = program_argv("sox", tool_paths)
    if sox is None:
        return False
    raw = outdir / "audio.raw"
    argv = [*sox, str(infile), "-r", "22050", "-c", "1", "-b", "16",
            "-e", "signed-integer", "-t", "raw", str(raw)]
    try:
        subprocess.run(  # noqa: S603 - argument list, our own
            argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=TOOL_TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return raw.is_file() and raw.stat().st_size > 0


def run_media_tools(
    data: bytes,
    name: str,
    reader: str,
    flagset: FlagSet | None = None,
    offline: bool = False,
    tool_paths: dict | None = None,
    wordlist: str = "",
    timeout: int = TOOL_TIMEOUT,
) -> MediaToolRun:
    """Run the installed stego tools that fit `reader`, and read their output.

    `reader` is the name `readers.sniff` returned ("stego", "wav", "exif").
    `offline` is accepted for symmetry with the rest of the pipeline; every tool
    here is offline anyway, so it changes nothing. Missing tools are skipped.
    The input and every tool's output live in a throwaway temp directory.
    """
    flagset = flagset or default_flagset()
    run = MediaToolRun()
    applicable = [r for r in RUNNERS if reader in r.readers]
    if not applicable:
        return run
    # Nothing to do if not one of them is installed: skip the temp file entirely.
    if not any(program_argv(r.program, tool_paths) for r in applicable):
        return run

    workdir = Path(tempfile.mkdtemp(prefix="ctfc-stego-"))
    try:
        default_suffix = {"stego": ".png", "wav": ".wav", "exif": ".jpg"}.get(reader, "")
        suffix = Path(name).suffix or default_suffix
        infile = workdir / (("input" + suffix) if suffix else "input")
        infile.write_bytes(data)

        if reader == "wav":
            _resample_for_multimon(infile, workdir, tool_paths)

        for runner in applicable:
            program = program_argv(runner.program, tool_paths)
            if program is None:
                continue
            argv = runner.argv(infile, workdir, wordlist)
            if argv is None:
                continue
            resolved = [*program, *argv[1:]]
            try:
                completed = subprocess.run(  # noqa: S603 - argument list from our table
                    resolved,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                run.notes.append(f"{runner.id} could not run: {exc}")
                continue
            run.ran.append(runner.id)
            ctx = RunContext(
                tool=runner.id,
                returncode=completed.returncode,
                stdout=completed.stdout.decode("utf-8", "replace")[:OUTPUT_LIMIT],
                stderr=completed.stderr.decode("utf-8", "replace")[:OUTPUT_LIMIT],
                infile=infile,
                outdir=workdir,
                flagset=flagset,
                run=run,
            )
            runner.interpret(ctx)
            if run.flags:
                # A flag is the answer: no need to keep running the slower tools.
                break
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return run


def tools_available_for(reader: str, tool_paths: dict | None = None) -> list[str]:
    """Which stego tools are installed and apply to this reader (for messages)."""
    return [
        r.id
        for r in RUNNERS
        if reader in r.readers and program_argv(r.program, tool_paths) is not None
    ]
