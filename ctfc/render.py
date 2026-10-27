"""Terminal display with `rich`: tables of candidates, detect reports, hexdumps.

Only formatting lives here. Data always goes through `safe()` before printing, so
bytes from a sample can never inject rich markup or terminal escape sequences.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ctfc.core.detect import DetectReport
from ctfc.core.types import Candidate, Input


def safe(text: str, limit: int = 0) -> str:
    """Replace control characters with '.', cut to `limit` chars, escape rich markup."""
    cleaned = "".join(ch if ch.isprintable() or ch == " " else "." for ch in text)
    if limit and len(cleaned) > limit:
        cleaned = cleaned[: limit - 3] + "..."
    return escape(cleaned)


def safe_block(text: str, limit: int = 2000) -> str:
    """Like safe(), but keeps newlines and tabs (for multi-line outputs)."""
    lines = text[:limit].split("\n")
    return "\n".join(safe(line.replace("\t", "    ")) for line in lines)


def preview(data: bytes, limit: int = 60) -> str:
    """Short one-line view of bytes: text if it is mostly readable, otherwise hex."""
    text = data.decode("utf-8", errors="replace")
    readable = sum(ch.isprintable() or ch in "\n\t" for ch in text) / max(len(text), 1)
    if readable >= 0.85:
        return safe(text.replace("\n", " "), limit)
    return escape("hex:" + data[: limit // 2].hex() + ("..." if len(data) > limit // 2 else ""))


def hexdump(data: bytes, limit: int = 256) -> str:
    """Classic hexdump: offset, 16 hex bytes, ASCII column."""
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > limit:
        lines.append(f"... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def score_style(score: float) -> str:
    if score >= 0.85:
        return "bold green"
    if score >= 0.5:
        return "yellow"
    return "dim"


def print_input_notes(console: Console, inp: Input) -> None:
    for note in inp.notes:
        console.print(f"[cyan]note:[/] {escape(note)}")


def print_notes(console: Console, notes: list[str]) -> None:
    """Lines about the search itself (what was detected, what was tried, limits)."""
    for note in notes:
        console.print(f"[cyan]*[/] {safe(note)}")


def print_candidates(
    console: Console,
    candidates: list[Candidate],
    show_code: bool = False,
    title: str = "Candidates",
) -> None:
    """Ranked table, then the details of the best candidate."""
    if not candidates:
        console.print("[yellow]No convincing result.[/] Try `ctfc detect` for hints.")
        return

    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("score", justify="right", width=6)
    table.add_column("how", ratio=2)
    table.add_column("output", ratio=3)
    table.add_column("why", ratio=3)
    for index, candidate in enumerate(candidates, start=1):
        style = score_style(candidate.score)
        table.add_row(
            str(index),
            f"[{style}]{candidate.score:.2f}[/]",
            safe(candidate.label, 60),
            preview(candidate.data),
            safe("; ".join(candidate.reasons[1:3] or candidate.reasons[:1]), 90),
        )
    console.print(table)
    print_candidate_details(console, candidates[0], show_code)


def print_candidate_details(console: Console, candidate: Candidate, show_code: bool) -> None:
    lines = [f"[bold]{safe(candidate.label)}[/]  score {candidate.score:.2f}", ""]
    lines += [f"  - {safe(reason)}" for reason in candidate.reasons]
    lines.append("")
    text = candidate.data.decode("utf-8", errors="replace")
    if sum(ch.isprintable() or ch in "\n\t" for ch in text) / max(len(text), 1) >= 0.85:
        lines.append(safe_block(text))
    else:
        lines.append(escape(hexdump(candidate.data)))
    if candidate.cyberchef:
        lines += ["", f"[dim]CyberChef recipe:[/] {escape(candidate.cyberchef)}"]
    console.print(Panel("\n".join(lines), title="best candidate", expand=True))
    if show_code and candidate.python:
        console.print(Syntax(candidate.python, "python", theme="monokai", word_wrap=True))
    elif candidate.python:
        console.print("[dim]Add --show-code to print the Python script that reproduces it.[/]")


def print_key_lengths(console: Console, lengths: list) -> None:
    """Table of the most likely repeating-key lengths (from xor.guess_key_lengths)."""
    table = Table(title="likely key lengths", expand=False)
    table.add_column("length", justify="right")
    table.add_column("Hamming bits/byte", justify="right")
    table.add_column("coincidence ratio", justify="right")
    for guess in lengths:
        table.add_row(str(guess.length), f"{guess.hamming:.2f}", f"{guess.ratio:.1f}")
    console.print(table)
    console.print(
        "[dim]Hamming: lower is better (random ~ 4.0). Coincidence ratio: higher is "
        "better (1 = no signal).[/]"
    )


def print_lens(console: Console, report, show_code: bool = False) -> None:
    """Code Lens: the summary, then the operations, artifacts and behaviours."""
    lines = [f"[bold]language:[/] {escape(report.language)}", ""]
    lines += [f"  - {safe(line, 200)}" for line in report.summary] or ["  (nothing recognised)"]
    console.print(Panel("\n".join(lines), title="what this script does", expand=True))

    if report.peeled:
        table = Table(title="peeled blobs (the chain applied to each one)", expand=True)
        table.add_column("score", justify="right", width=6)
        table.add_column("line", justify="right", width=5)
        table.add_column("chain", ratio=1)
        table.add_column("output", ratio=4)
        for peeled in report.peeled:
            table.add_row(
                f"[{score_style(peeled.score)}]{peeled.score:.2f}[/]",
                str(peeled.line),
                safe(peeled.label, 30),
                preview(peeled.data, 90),
            )
        console.print(table)

    if report.operations:
        table = Table(title="operations, in order", expand=True)
        table.add_column("#", justify="right", width=3)
        table.add_column("line", justify="right", width=5)
        table.add_column("step", width=10)
        table.add_column("what", ratio=3)
        table.add_column("rule", width=18)
        for index, operation in enumerate(report.operations, start=1):
            table.add_row(
                str(index),
                str(operation.line),
                operation.kind or "-",
                safe(operation.label, 80),
                safe(operation.rule),
            )
        console.print(table)

    if report.artifacts:
        table = Table(title="extracted values", expand=True)
        table.add_column("kind", width=9)
        table.add_column("line", justify="right", width=5)
        table.add_column("name", width=12)
        table.add_column("value", ratio=3)
        table.add_column("how", ratio=1)
        for artifact in report.artifacts:
            table.add_row(
                artifact.kind,
                str(artifact.line),
                safe(artifact.name or "-", 12),
                safe(artifact.preview(70)),
                safe(artifact.how, 30),
            )
        console.print(table)

    if report.behaviours:
        table = Table(title="behaviour", expand=False)
        table.add_column("kind", width=12)
        table.add_column("line", justify="right", width=5)
        table.add_column("what", ratio=3)
        for behaviour in report.behaviours:
            table.add_row(behaviour.kind, str(behaviour.line), safe(behaviour.label, 90))
        console.print(table)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")

    if report.recovery is None:
        console.print("[yellow]No recovery script:[/] no embedded blob and chain to replay.")
        return
    state = "complete" if report.recovery.complete else "PARTIAL, check it"
    console.print(
        f"[bold]recovery script[/] ({escape(report.recovery.label)}) - {state}, "
        f"{len(report.recovery.blob)} bytes of input"
    )
    if show_code:
        console.print(Syntax(report.recovery.python, "python", theme="monokai", word_wrap=True))
    else:
        console.print("[dim]Add --show-code to print it.[/]")


def print_detect(console: Console, report: DetectReport) -> None:
    facts = Table(title="Facts", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    for name, value in report.facts:
        facts.add_row(name, escape(value))
    console.print(facts)

    if not report.guesses:
        console.print("[yellow]No specific guess.[/] Try `ctfc auto`.")
        return
    table = Table(title="Ranked guesses", expand=True, show_lines=True)
    table.add_column("conf", justify="right", width=5)
    table.add_column("guess", ratio=3)
    table.add_column("why", ratio=4)
    table.add_column("next step", ratio=3)
    for guess in report.guesses:
        style = score_style(guess.confidence)
        table.add_row(
            f"[{style}]{guess.confidence:.2f}[/]",
            safe(guess.label) + f"\n[dim]{escape(guess.rule)}[/]",
            "\n".join(safe(reason, 150) for reason in guess.reasons),
            safe(guess.next_step),
        )
    console.print(table)


def print_key_comparison(console: Console, first, second, same: bool, why: str) -> None:
    """`ctfc rsa --check`: do these two keys belong together?"""
    style = "bold green" if same else "yellow"
    console.print(f"[{style}]{'MATCH' if same else 'NO MATCH'}[/]: {escape(why)}")
    table = Table(show_header=True, expand=False)
    table.add_column("")
    table.add_column("first key")
    table.add_column("second key")
    table.add_row("kind", _kind(first), _kind(second))
    table.add_row("size", f"{first.bits} bits", f"{second.bits} bits")
    table.add_row("n", _tail(first.n), _tail(second.n))
    table.add_row("e", str(first.e), str(second.e))
    console.print(table)


def _kind(key) -> str:
    return "private" if key.is_private else "public"


def _tail(number: int, keep: int = 20) -> str:
    text = str(number)
    return text if len(text) <= keep else "..." + text[-keep:]


def print_rsa(console: Console, report, show_code: bool = False) -> None:
    """`ctfc rsa`: the key, what the attacks tried, then the decryptions."""
    if report.key is not None:
        table = Table(title="the key", show_header=False, expand=False)
        table.add_column("name", style="cyan")
        table.add_column("value")
        for name, value in report.key.facts():
            table.add_row(name, safe(value, 160))
        console.print(table)

    if report.attacks is not None:
        attacks = report.attacks
        console.print("[bold]attacks tried:[/] " + safe(", ".join(attacks.tried)))
        if attacks.factorisation is not None:
            found = attacks.factorisation
            lines = [
                f"[bold green]n factored[/] by {escape(found.method)}",
                "",
                f"  {safe(found.explanation)}",
                "",
                f"  p = {_tail(found.p, 40)}",
                f"  q = {_tail(found.q, 40)}",
            ]
            console.print(Panel("\n".join(lines), title="weakness found", expand=True))
            if show_code and found.python:
                console.print(Syntax(found.python, "python", theme="monokai", word_wrap=True))
        elif attacks.private_exponent is not None:
            found = attacks.private_exponent
            console.print(
                Panel(
                    f"[bold green]d recovered[/] by {escape(found.method)}\n\n"
                    f"  {safe(found.explanation)}\n\n  d = {_tail(found.d, 40)}",
                    title="weakness found",
                    expand=True,
                )
            )
        for note in attacks.notes:
            console.print(f"[yellow]*[/] {safe(note)}")

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")

    if report.candidates:
        print_candidates(console, report.candidates, show_code=show_code, title="RSA decryption")


def print_hash(console: Console, report) -> None:
    """`ctfc hash`: what the string is, and the command that cracks it."""
    facts = Table(title="Facts", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    for name, value in report.facts:
        facts.add_row(name, safe(value, 120))
    console.print(facts)

    if report.matches:
        table = Table(title="possible formats", expand=True, show_lines=True)
        table.add_column("conf", justify="right", width=5)
        table.add_column("format", ratio=2)
        table.add_column("mode", width=12)
        table.add_column("command / notes", ratio=4)
        for match in report.matches:
            modes = []
            if match.format.hashcat is not None:
                modes.append(f"hashcat -m {match.format.hashcat}")
            if match.format.john:
                modes.append(f"john {match.format.john}")
            details = []
            if match.cracked:
                details.append(f"[bold green]password: {safe(match.cracked)}[/]")
            command = match.format.hashcat_command() or match.format.john_command()
            if command:
                details.append(escape(command))
            if match.format.notes:
                details.append(f"[dim]{safe(match.format.notes, 200)}[/]")
            table.add_row(
                f"[{score_style(match.confidence)}]{match.confidence:.2f}[/]",
                safe(match.format.name),
                "\n".join(modes) or "-",
                "\n".join(details),
            )
        console.print(table)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
