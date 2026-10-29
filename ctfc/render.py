"""Terminal display with `rich`: tables of candidates, detect reports, hexdumps.

Only formatting lives here. Data always goes through `safe()` before printing, so
bytes from a sample can never inject rich markup or terminal escape sequences.
"""

from __future__ import annotations

import json

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


def print_scan(
    console: Console, report, min_interest: float = 0.4, show_code: bool = False
) -> None:
    """`ctfc scan`: the ranked folder, then the details of the best file."""
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")

    interesting = report.interesting(min_interest)
    if not interesting:
        console.print(
            f"[yellow]Nothing above {min_interest:.2f}[/] in {len(report.files)} file(s). "
            "Lower --min-interest, or look at the kinds below."
        )
    shown = interesting or report.files[:10]
    table = Table(title=f"{report.root} ({len(report.files)} files scanned)", expand=True)
    table.add_column("score", justify="right", width=6)
    table.add_column("file", ratio=2)
    table.add_column("size", justify="right", width=9)
    table.add_column("kind", ratio=1)
    table.add_column("why", ratio=3)
    for result in shown:
        # Show the path relative to the folder being scanned: the absolute one is
        # long, identical for every row, and pushes the useful columns off screen.
        try:
            shown_path = str(result.path.relative_to(report.root))
        except ValueError:
            shown_path = str(result.path)
        table.add_row(
            f"[{score_style(result.interest)}]{result.interest:.2f}[/]",
            safe(shown_path, 60),
            str(result.size),
            safe(result.kind, 24),
            safe("; ".join(result.reasons[:2]) or result.error, 90),
        )
    console.print(table)
    if report.budget_summary:
        console.print(f"[dim]{report.budget_summary}[/]")

    best = shown[0] if shown else None
    if best is not None and best.best is not None:
        console.print(f"[bold]best file:[/] {escape(str(best.path))}")
        print_candidate_details(console, best.best, show_code)


def print_pcap(
    console: Console, report, findings, saved: list[str], show_code: bool = False
) -> None:
    """`ctfc pcap`: what was in the capture, ranked by how promising it is."""
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    if not findings:
        console.print("[yellow]Nothing to extract.[/] Encrypted traffic, or only handshakes.")
        return

    table = Table(title=f"{len(findings)} object(s) extracted", expand=True)
    table.add_column("score", justify="right", width=6)
    table.add_column("kind", width=13)
    table.add_column("where", ratio=2)
    table.add_column("size", justify="right", width=7)
    table.add_column("what came out", ratio=4)
    for finding in findings:
        item = finding.extracted
        if finding.best is not None:
            decoded = preview(finding.best.data, 50)
            outcome = f"{item.description} -> {finding.best.label}: {decoded}"
        else:
            outcome = f"{item.description}: {preview(item.data, 50)}"
        table.add_row(
            f"[{score_style(finding.score)}]{finding.score:.2f}[/]",
            item.kind,
            safe(item.source or "-", 40),
            str(len(item.data)),
            safe(outcome, 120),
        )
    console.print(table)

    if saved:
        console.print(f"[green]saved {len(saved)} object(s)[/]; next: ctfc scan <that folder>")

    best = findings[0]
    if best.best is not None:
        console.print(f"[bold]best object:[/] {escape(best.extracted.name)}")
        print_candidate_details(console, best.best, show_code)


def print_office(console: Console, report) -> None:
    """`ctfc office`: what the document holds, and the macro source itself."""
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    if report.indicators:
        table = Table(title="what the macro does", expand=True)
        table.add_column("indicator", ratio=3)
        for line in report.indicators:
            table.add_row(safe(line, 160))
        console.print(table)
    for macro in report.macros:
        console.print(f"[bold]{escape(macro.module)}[/] [dim](at offset {macro.offset})[/]")
        console.print(Panel(escape(macro.code[:4000]), border_style="dim"))
    if not report.macros:
        console.print(f"[yellow]No VBA macro.[/] {len(report.streams)} stream(s)/part(s) inside.")


def print_pdf(console: Console, report, saved: list[str]) -> None:
    """`ctfc pdf`: what the document would do, and what it carries."""
    facts = Table(title="PDF", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("version", report.version)
    facts.add_row("objects", str(len(report.objects)))
    facts.add_row("revisions", str(report.revisions))
    facts.add_row("streams decoded", str(sum(1 for obj in report.objects if obj.filters)))
    facts.add_row("encrypted", "yes" if report.encrypted else "no")
    console.print(facts)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    if report.indicators:
        table = Table(title="what it would do", expand=True)
        table.add_column("indicator", ratio=3)
        for line in report.indicators:
            table.add_row(safe(line, 160))
        console.print(table)
    for name, blob in report.embedded:
        console.print(
            f"[bold]embedded file[/] {escape(name)} ({len(blob)} bytes): {preview(blob, 60)}"
        )
    for number, code in report.javascript:
        console.print(f"[bold]JavaScript[/] in object {number}:")
        console.print(Panel(escape(code[:3000]), border_style="dim"))
    if saved:
        console.print(f"[green]saved {len(saved)} file(s)[/]; next: ctfc scan <that folder>")


def print_stego(console: Console, report, show_code: bool = False) -> None:
    """`ctfc stego`: the image, its metadata, and what the low bits spell out."""
    facts = Table(title="image", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("format", report.kind)
    facts.add_row("size", f"{report.width}x{report.height}")
    facts.add_row("channels", str(report.channels))
    console.print(facts)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    print_candidates(
        console, report.candidates, show_code=show_code, title="hidden in the low bits"
    )


def print_git(console: Console, report, saved: list[str]) -> None:
    """`ctfc git`: the blobs the current files no longer show."""
    facts = Table(title="repository", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("git dir", report.git_dir)
    facts.add_row("objects", ", ".join(f"{count} {kind}" for kind, count in report.counts.items()))
    facts.add_row("refs", ", ".join(report.refs) or "none")
    console.print(facts)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    if not report.lost:
        return
    table = Table(title="in the history, not in the current files", expand=True, show_lines=True)
    table.add_column("state", width=12)
    table.add_column("name", ratio=2)
    table.add_column("size", justify="right", width=7)
    table.add_column("what is in it", ratio=4)
    for blob in report.lost:
        found = []
        if blob.flags:
            found.append("[bold green]" + safe(", ".join(blob.flags), 90) + "[/]")
        if blob.secrets:
            found.append("[bold]" + safe("; ".join(blob.secrets), 90) + "[/]")
        if not found:
            found.append(preview(blob.data, 70))
        if blob.commits:
            found.append(f"[dim]in commit(s) {', '.join(blob.commits[:3])}[/]")
        table.add_row(
            blob.kind,
            safe(", ".join(blob.names) or blob.sha[:10], 40),
            str(blob.size),
            "\n".join(found),
        )
    console.print(table)
    if saved:
        console.print(f"[green]saved {len(saved)} blob(s)[/]; next: ctfc scan <that folder>")


def print_sqlite(console: Console, report) -> None:
    """`ctfc sqlite`: the live tables, then the rows carved out of free space."""
    facts = Table(title="database", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("page size", str(report.page_size))
    facts.add_row("pages", str(report.pages))
    facts.add_row("freelist pages", ", ".join(str(number) for number in report.freelist) or "none")
    facts.add_row(
        "live tables",
        ", ".join(f"{name} ({count} rows)" for name, count in report.tables.items()) or "none read",
    )
    console.print(facts)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    if not report.deleted:
        return
    table = Table(title="rows carved out of free space", expand=True)
    table.add_column("rowid", justify="right", width=7)
    table.add_column("where", width=24)
    table.add_column("values", ratio=4)
    for row in report.deleted:
        text = safe(row.text, 150)
        if row.flags:
            text = "[bold green]" + safe(", ".join(row.flags), 90) + "[/] " + text
        elif row.secrets:
            text = "[bold]" + safe("; ".join(row.secrets), 90) + "[/] " + text
        table.add_row("" if row.rowid is None else str(row.rowid), safe(row.where, 24), text)
    console.print(table)


def print_jwt(console: Console, report, show_code: bool = False) -> None:
    """`ctfc jwt`: the decoded parts, then what can be done with the token."""
    facts = Table(title="token", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("algorithm", report.algorithm or "(none)")
    facts.add_row("signature", f"{report.signature_bytes} bytes")
    if report.secret is not None:
        facts.add_row("secret", f"[bold green]{safe(report.secret.decode('utf-8', 'replace'))}[/]")
    console.print(facts)

    if report.findings:
        table = Table(title="what is wrong with it", expand=True, show_lines=True)
        table.add_column("", width=6)
        table.add_column("rule", width=20)
        table.add_column("what it means", ratio=4)
        for finding in report.findings:
            style = {"high": "bold red", "medium": "yellow", "info": "dim"}[finding.severity]
            cell = safe(finding.what, 200)
            if finding.next_step:
                cell += f"\n[green]-> {safe(finding.next_step, 200)}[/]"
            table.add_row(f"[{style}]{finding.severity}[/]", finding.rule, cell)
        console.print(table)

    for title, value in (("header", report.header), ("payload", report.payload)):
        console.print(f"[bold]{title}[/]")
        console.print(Panel(escape(json.dumps(value, indent=2)[:3000]), border_style="dim"))
    for line in report.times:
        console.print(f"[cyan]*[/] {safe(line)}")
    if report.flags:
        console.print(f"[bold green]flag in the payload:[/] {safe(', '.join(report.flags))}")
    if report.forged:
        console.print("[bold]a token you can send instead[/] (payload + admin:true)")
        console.print(Panel(escape(report.forged), border_style="green"))
    if show_code and report.python:
        console.print(Syntax(report.python, "python", theme="ansi_dark", word_wrap=True))


def print_prng(console: Console, report, show_code: bool = False) -> None:
    """`ctfc prng`: what was recovered, then the values before and after the capture."""
    facts = Table(title="generator", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("cloned", f"[bold green]{report.generator}[/]")
    facts.add_row("values used", str(report.used))
    if report.confirmed:
        facts.add_row("confirmed on", f"{report.confirmed} further value(s)")
    if report.seed is not None:
        facts.add_row("seed", f"[bold green]{report.seed}[/]")
    console.print(facts)

    sections = (
        ("the values it will hand out next", report.next_values),
        ("the values it handed out before the capture (most recent first)", report.previous_values),
    )
    for title, values in sections:
        if not values:
            continue
        table = Table(title=title, expand=True)
        table.add_column("#", width=4, justify="right")
        table.add_column("decimal", ratio=2)
        table.add_column("hex", ratio=2)
        for index, value in enumerate(values, start=1):
            table.add_row(str(index), str(value), f"{value & 0xFFFFFFFF:08x}")
        console.print(table)

    if report.next_floats:
        joined = ", ".join(f"{value:.17g}" for value in report.next_floats)
        console.print(f"[bold]random() instead:[/] {safe(joined, 300)}")
    print_notes(console, report.notes)
    if show_code and report.python:
        console.print(Syntax(report.python, "python", theme="ansi_dark", word_wrap=True))


def print_timestamps(console: Console, groups) -> None:
    """`ctfc time`: every plausible reading of the number, with its epoch named."""
    for label, readings in groups:
        table = Table(title=f"readings of {label}", expand=True)
        table.add_column("epoch", ratio=2)
        table.add_column("date", width=24)
        table.add_column("note", ratio=3)
        for reading in readings:
            table.add_row(reading.epoch, reading.text, safe(reading.note, 90))
        console.print(table)


def print_zip(console: Console, report) -> None:
    """`ctfc zip`: the entries, then what to do about the encryption."""
    table = Table(title=f"{len(report.entries)} entry/entries", expand=True)
    table.add_column("name", ratio=3)
    table.add_column("method", ratio=2)
    table.add_column("size", justify="right", width=9)
    table.add_column("crc", width=9)
    table.add_column("notes", ratio=3)
    for entry in report.entries:
        notes = []
        if entry.recovered is not None:
            notes.append("[bold green]" + safe(repr(entry.recovered), 60) + "[/]")
        notes += ["[red]" + safe(problem, 90) + "[/]" for problem in entry.problems]
        table.add_row(
            safe(entry.name, 50),
            ("[yellow]" if entry.encrypted else "") + safe(entry.method_name, 30),
            str(entry.uncompressed_size),
            f"{entry.crc:08x}",
            "\n".join(notes),
        )
    console.print(table)
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    for command in report.commands:
        console.print(f"[green]$[/] {escape(command)}")


def print_hive(console: Console, report) -> None:
    """`ctfc hive`: which hive it is, the keys that matter, and the boot key."""
    facts = Table(title="registry hive", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("file name inside", report.name)
    facts.add_row("looks like", report.kind)
    facts.add_row("keys", str(report.keys))
    if report.boot_key is not None:
        facts.add_row("boot key", f"[bold green]{report.boot_key.hex()}[/]")
    console.print(facts)

    for path, why, values in report.found:
        console.print(f"[bold]{escape(path)}[/] [dim]{safe(why, 70)}[/]")
        for line in values:
            console.print(f"   {safe(line, 200)}")
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")
    for command in report.commands:
        console.print(f"[green]$[/] {escape(command)}")


def print_pe(console: Console, report) -> None:
    """`ctfc pe`: what the executable is, its sections, and what its APIs say."""
    facts = Table(title="executable", show_header=False, expand=False)
    facts.add_column("name", style="cyan")
    facts.add_column("value")
    facts.add_row("format", "PE32+" if report.bits == 64 else "PE32")
    facts.add_row("machine", report.machine)
    facts.add_row(
        "kind", ("DLL" if report.is_dll else "EXE") + (" / .NET" if report.is_dotnet else "")
    )
    facts.add_row("subsystem", report.subsystem)
    facts.add_row("built", report.timestamp_text or "(not a date)")
    facts.add_row("entry point", f"{report.entry_point:#x}")
    facts.add_row("imports", f"{report.import_count} from {len(report.imports)} DLL(s)")
    if report.exports:
        facts.add_row("exports", str(len(report.exports)))
    console.print(facts)

    table = Table(title="sections", expand=True)
    table.add_column("name", width=12)
    table.add_column("flags", width=6)
    table.add_column("virtual", justify="right", width=10)
    table.add_column("on disk", justify="right", width=10)
    table.add_column("entropy", justify="right", width=8)
    for section in report.sections:
        style = "bold red" if section.writable_and_executable else ""
        table.add_row(
            f"[{style}]{safe(section.name, 12)}[/]" if style else safe(section.name, 12),
            section.flags,
            str(section.virtual_size),
            str(section.raw_size),
            f"{section.entropy:.2f}",
        )
    console.print(table)

    if report.notable:
        notable = Table(title="what its API calls say it does", expand=True)
        notable.add_column("import", ratio=2)
        notable.add_column("meaning", ratio=3)
        for line in report.notable:
            name, _, meaning = line.partition(": ")
            notable.add_row(safe(name, 60), safe(meaning, 120))
        console.print(notable)

    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")


def print_evtx(console: Console, report, show_all: bool = False) -> None:
    """`ctfc evtx`: the records worth reading, then all of them with --all."""
    console.print(f"[cyan]*[/] {report.chunks} chunk(s), {len(report.records)} record(s)")
    shown = report.records if show_all else report.interesting
    if shown:
        table = Table(
            title="every record" if show_all else "records holding something",
            expand=True,
            show_lines=True,
        )
        table.add_column("#", justify="right", width=7)
        table.add_column("when", width=22)
        table.add_column("what is in it", ratio=5)
        for record in shown:
            lines = []
            if record.flags:
                lines.append("[bold green]" + safe(", ".join(record.flags), 90) + "[/]")
            if record.secrets:
                lines.append("[bold]" + safe("; ".join(record.secrets), 90) + "[/]")
            if record.command:
                lines.append("[yellow]decoded command:[/] " + safe(record.command, 300))
            lines.append("[dim]" + safe(record.text, 200) + "[/]")
            table.add_row(str(record.number), record.when, "\n".join(lines))
        console.print(table)
    elif not show_all:
        console.print("[yellow]No record holds a flag, a credential or an encoded command.[/]")
        console.print("Use --all to list every record and read them yourself.")
    for note in report.notes:
        console.print(f"[cyan]*[/] {safe(note)}")


def print_radius(console: Console, found, had_secret: bool) -> None:
    """`ctfc radius`: the shared secret(s) that decrypted the PAP password."""
    if not found:
        if had_secret:
            console.print("[yellow]That shared secret did not give a readable password.[/]")
        else:
            console.print(
                "[yellow]No common shared secret worked.[/] "
                "Pass --secret if you know it (it may be in a config from the same box)."
            )
        return
    table = Table(title="recovered RADIUS PAP password", expand=True, show_lines=True)
    table.add_column("shared secret", ratio=2)
    table.add_column("password", ratio=3)
    table.add_column("flag?", width=6)
    for item in found[:10]:
        secret = item.secret.decode("utf-8", "replace")
        password = item.password.decode("utf-8", "replace")
        table.add_row(
            safe(secret), f"[bold green]{safe(password)}[/]", "yes" if item.is_flag else ""
        )
    console.print(table)


def print_recipe(console: Console, result, show_code: bool = False) -> None:
    """`ctfc recipe run`: every step with its own output, then the final result."""
    for note in result.notes:
        console.print(f"[cyan]*[/] {safe(note)}")

    table = Table(title=f"recipe {result.name}", expand=True, show_lines=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("step", ratio=2)
    table.add_column("bytes", justify="right", width=7)
    table.add_column("score", justify="right", width=6)
    table.add_column("output", ratio=4)
    for entry in result.steps:
        if entry.error:
            output = f"[red]{safe(entry.error, 90)}[/]"
            score_cell = "-"
        else:
            output = preview(entry.data, 90)
            score_cell = f"[{score_style(entry.score)}]{entry.score:.2f}[/]"
        table.add_row(
            str(entry.index),
            safe(entry.label, 40),
            str(len(entry.data)),
            score_cell,
            output,
        )
    console.print(table)

    if result.ok:
        text = result.output.decode("utf-8", errors="replace")
        readable = sum(ch.isprintable() or ch in "\n\t" for ch in text) / max(len(text), 1)
        body = safe_block(text) if readable >= 0.85 else escape(hexdump(result.output))
        console.print(Panel(body, title="final output", expand=True))
    if result.cyberchef:
        console.print(f"[dim]CyberChef recipe:[/] {escape(result.cyberchef)}")
    if show_code and result.python:
        console.print(Syntax(result.python, "python", theme="monokai", word_wrap=True))
    elif result.python:
        console.print("[dim]Add --show-code to print the Python script.[/]")


def print_tools(console: Console, suggestions, public_url: str = "", offline: bool = False) -> None:
    """`ctfc tools`: at most three tools, each with the reason and the command."""
    if not suggestions:
        console.print(
            "[yellow]No tool suggested.[/] Nothing fired confidently enough "
            "(see suggest_threshold in the config). `ctfc tools <input> --list` "
            "shows everything ctfc knows about."
        )
        return
    for item in suggestions:
        if item.tool.kind == "local":
            state = "[green]installed[/]" if item.available else "[yellow]not installed[/]"
        elif item.tool.kind == "embedded":
            state = "[green]served from this machine[/]"
        else:
            state = "[cyan]online[/]"
        lines = [f"[bold]{safe(item.tool.name)}[/] ({state})", ""]
        lines.append(f"  why: {safe(item.reason)}")
        if item.tool.notes:
            lines.append(f"  {safe(item.tool.notes)}")
        if item.command:
            lines.append("")
            lines.append("  " + escape(" ".join(item.command)))
        if item.placeholders:
            lines.append(f"  [dim]fill in: {escape(', '.join(item.placeholders))}[/]")
        if not item.available and item.tool.install:
            lines.append(f"  [dim]install: {safe(item.tool.install)}[/]")
        if item.warning:
            lines.append(f"  [yellow]warning: {safe(item.warning)}[/]")
        console.print(Panel("\n".join(lines), expand=True))
        if item.url:
            # Outside the panel and never wrapped: a URL cut over two lines is
            # neither clickable nor copyable.
            console.print(item.url, soft_wrap=True, markup=False, highlight=False)
    if offline:
        console.print("[dim]offline mode: tools that would send data anywhere are hidden.[/]")


def print_tool_list(console: Console, entries) -> None:
    """`ctfc tools <input> --list`: the whole registry and what is installed."""
    table = Table(title="external tools ctfc knows about", expand=True)
    table.add_column("id", width=17)
    table.add_column("kind", width=9)
    table.add_column("here?", width=8)
    table.add_column("fires on", ratio=2)
    table.add_column("notes", ratio=3)
    for tool, available in entries:
        if tool.kind == "local":
            here = "[green]yes[/]" if available else "[yellow]no[/]"
        else:
            here = "[cyan]n/a[/]"
        table.add_row(
            tool.id,
            tool.kind,
            here,
            safe(", ".join(tool.suggest_when), 40),
            safe(tool.notes, 80),
        )
    console.print(table)


def print_tool_run(console: Console, tool, result) -> None:
    """`ctfc tools <input> --run <id>`: the command, then its output."""
    console.print(f"[bold]{safe(tool.name)}[/]: {escape(' '.join(result.command))}")
    if result.error:
        console.print(f"[red]{safe(result.error)}[/]")
        return
    console.print(f"[dim]exit code {result.returncode}[/]")
    if result.stdout:
        console.print(Panel(safe_block(result.stdout, 8000), title="stdout", expand=True))
    if result.stderr:
        console.print(Panel(safe_block(result.stderr, 2000), title="stderr", expand=True))


def _key_view(key: bytes, limit: int = 40) -> str:
    """A key as text when it is plain printable ASCII, otherwise as hex."""
    if key and all(32 <= b < 127 for b in key):
        return safe(key.decode("ascii"), limit)
    text = key.hex()
    return escape(text if len(text) <= limit else text[: limit - 3] + "...")


def print_key_hunt(console: Console, report, show_code: bool = False, limit: int = 15) -> None:
    """`ctfc keys`: the candidate keys found in the dump, then what decrypted."""
    print_notes(console, report.notes)
    if report.candidates:
        table = Table(title="candidate keys (strongest first)", expand=True)
        table.add_column("offset", width=10)
        table.add_column("kind", width=20)
        table.add_column("len", justify="right", width=4)
        table.add_column("key", ratio=2)
        table.add_column("how", ratio=3)
        for candidate in report.candidates[:limit]:
            marker = " [bold green]<- works[/]" if candidate is report.winner else ""
            table.add_row(
                f"0x{candidate.offset:x}",
                candidate.kind.replace("_", " ")
                + (f" ({candidate.role})" if candidate.role != "key" else ""),
                str(len(candidate.key)),
                _key_view(candidate.key),
                safe(candidate.how) + marker,
            )
        console.print(table)
        if len(report.candidates) > limit:
            console.print(
                f"[dim]... and {len(report.candidates) - limit} more (--json lists them all)[/]"
            )
    if report.results:
        print_candidates(console, report.results, show_code=show_code, title="decryptions")
    if report.luks:
        luks = report.luks
        console.print(
            f"[bold green]LUKS master key confirmed[/] ({luks['key_bits']} bits, "
            f"{safe(luks['cipher'])}): {safe(luks['built_from'])}"
        )
        console.print(luks["master_key_hex"], markup=False, highlight=False, soft_wrap=True)
        console.print("[bold]To open the volume[/] (root needed to map it):")
        for line in luks["commands"]:
            console.print(line, markup=False, highlight=False, soft_wrap=True)
    if report.budget_summary:
        console.print(f"[dim]{report.budget_summary}[/]")


def print_session(console: Console, session) -> None:
    """`ctfc session show`: what the session holds, in order."""
    meta = session.meta()
    head = [f"[bold]{safe(meta.display_title())}[/]  ({safe(session.name)})"]
    for label, value in (("CTF", meta.ctf), ("category", meta.category), ("flag", meta.flag)):
        if value:
            head.append(f"{label}: {safe(value)}")
    if meta.description:
        head.append(safe(meta.description, 300))
    head.append(f"[dim]{escape(str(session.folder))}[/]")
    console.print(Panel("\n".join(head), expand=True))
    table = Table(expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("what", ratio=3)
    table.add_column("result", ratio=4)
    for number, entry in enumerate(session.entries(), start=1):
        if entry.kind == "note":
            table.add_row(str(number), "[cyan]note[/]", safe(entry.text, 200))
            continue
        result = entry.result
        found = (
            f"{result.get('score', 0):.2f} {result.get('label', '')}" if result.get("label") else ""
        )
        found = found or "; ".join(result.get("summary", [])[:2])
        table.add_row(str(number), safe(entry.command, 120), safe(found, 160))
    console.print(table)
    console.print("[dim]ctfc report " + escape(session.name) + " --lang fr  -> the write-up[/]")


def print_repair(console: Console, report, source: str, written: list) -> None:
    """`ctfc repair`: what was wrong, the fixes (with the commands), what came out."""
    print_notes(console, report.notes)
    path = source if source and not source.startswith(("hex:", "b64:", "text:")) else "<file>"
    if report.fixes:
        table = Table(title="fixes", expand=True)
        table.add_column("offset", width=8)
        table.add_column("was", width=14)
        table.add_column("becomes", width=14)
        table.add_column("why", ratio=3)
        for fix in report.fixes:
            table.add_row(f"0x{fix.offset:x}", fix.old.hex(), fix.new.hex(), safe(fix.why))
        console.print(table)
    if report.carved:
        table = Table(title="hidden inside", expand=True)
        table.add_column("offset", width=8)
        table.add_column("what", ratio=2)
        table.add_column("size", justify="right", width=8)
        table.add_column("why", ratio=3)
        for item in report.carved:
            table.add_row(
                f"0x{item.offset:x}", safe(item.name), str(len(item.data)), safe(item.why)
            )
        console.print(table)
    if report.fixes or report.carved:
        console.print("[bold]By hand[/] (on a copy):")
        console.print(f"cp {path} fixed", markup=False, highlight=False, soft_wrap=True)
        for fix in report.fixes:
            console.print(fix.command("fixed"), markup=False, highlight=False, soft_wrap=True)
        for index, item in enumerate(report.carved, start=1):
            name = item.filename(index)
            console.print(
                f"dd if=fixed of={name} bs=1 skip={item.offset}",
                markup=False,
                highlight=False,
                soft_wrap=True,
            )
    if written:
        console.print("[bold]Written[/]:")
        for target, nxt in written:
            line = f"  {target}" + (f"   ->  {nxt}" if nxt else "")
            console.print(line, markup=False, highlight=False, soft_wrap=True)
    elif report.carved or report.fixes:
        console.print("[dim]Add --out <folder> to write the repaired file and the pieces.[/]")
