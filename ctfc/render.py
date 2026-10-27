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
