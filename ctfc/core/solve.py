"""`ctfc solve`: the cheat sheet, executed.

Every other command here answers a question you already know how to ask:
`ctfc archive` when you know it is a tar, `ctfc auto` when you know it is a
payload. At two in the morning with twenty minutes left, the question is
simply **"what is in this file?"** - and the answer usually needs five commands
in a row, each one on something the previous one produced.

This module runs that chain:

1. look for the flag in the bytes as they are - cheapest test there is;
2. ask `core/readers.py` which reader claims the file, run it, and take
   everything it hands back that is itself a file (archive members, a mail's
   attachments, a capture's objects, an executable's overlay, a Docker layer);
3. for anything no reader claims, run the decoding chains (`auto`) - and if a
   chain produces something a reader *does* claim (base64 -> zlib -> a tar),
   push that back into step 2;
4. carve what is hidden after the end of a file, for the polyglots;
5. stop at the first flag, and otherwise print the three most interesting
   things that came out, each with the exact command to go further.

Three rules keep this from becoming "`auto` with extra steps":

- **nothing new is brute-forced.** Only operations that are already
  deterministic are chained. A password or a key is never guessed here; that is
  what `ctfc sym`, `ctfc keys` and `ctfc zip --passwords` are for, and `solve`
  prints the command instead of running it.
- **one budget for the whole walk**, shared by every piece, so a 60 MB image
  cannot turn one command into four minutes. The report says what it did not
  get to.
- **every piece carries the commands that reproduce it**, so the output is also
  a recipe: extract here, decode there, look at that.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ctfc.core import readers
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.magic import match_signature
from ctfc.core.scoring import score

# A piece bigger than this is fingerprinted and opened, but not pushed through
# the decoding chains: `auto` is for payloads, not for disk images.
AUTO_SIZE_LIMIT = 2 * 1024 * 1024
# How deep the walk goes. A tar inside a Docker layer inside a tar is depth 3;
# past that it is nearly always the same bytes under another name.
MAX_DEPTH = 5
# How many pieces are looked at in one run, whatever the budget allows.
MAX_PIECES = 400
# Below this an `auto` chain is noise, not a lead.
LEAD_SCORE = 0.45
# Readers whose files often carry something appended after their own end, so
# the carver runs on them too (a PNG with a ZIP behind it is the stock trick).
CARVE_ALSO = {"stego", "pdf"}
# Plain readable text is the weakest finding: cap it, like `ctfc scan` does.
PLAIN_TEXT_CAP = 0.5


def safe_name(name: str, fallback: str = "piece.bin") -> str:
    """The name a piece gets on disk, sanitised the way the --extract flags do."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name.strip().split("/")[-1])
    return cleaned.lstrip(".") or fallback


@dataclass
class Piece:
    """One thing `solve` looked at: the file itself, or something it produced."""

    name: str  # "chal.tar > secret.bin"
    origin: str  # how it was produced ("tar member", "decoded: base64 -> zlib")
    data: bytes = field(repr=False, default=b"")
    depth: int = 0
    # The commands that reproduce this piece from the original file, in order.
    trail: list[str] = field(default_factory=list)
    # Where this piece lands if the trail is actually run (used by the children).
    disk: str = ""

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class FlagFound:
    """A flag, and everything needed to believe it."""

    text: str
    where: str  # the piece it was in
    how: str  # how that piece was obtained
    strength: float
    trail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "where": self.where,
            "how": self.how,
            "strength": round(self.strength, 3),
            "trail": list(self.trail),
        }


@dataclass
class Lead:
    """Something worth a look when no flag came out."""

    title: str  # "chal.tar > notes.txt.gz"
    why: str  # "base64 -> gzip, scores 0.78: readable English"
    score: float
    command: str  # the one command to run next
    preview: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "why": self.why,
            "score": round(self.score, 3),
            "command": self.command,
            "preview": self.preview,
        }


@dataclass
class SolveReport:
    """What the walk found, in the order a human wants to read it."""

    path: str = ""
    size: int = 0
    read_as: str = ""  # the reader that claimed the original file
    flags: list[FlagFound] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)  # the walk, one line per piece
    notes: list[str] = field(default_factory=list)
    pieces: int = 0
    budget: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "read_as": self.read_as,
            "flags": [flag.to_dict() for flag in self.flags],
            "leads": [lead.to_dict() for lead in self.leads],
            "steps": list(self.steps),
            "notes": list(self.notes),
            "pieces": self.pieces,
            "budget": self.budget,
        }


def _preview(data: bytes, limit: int = 120) -> str:
    """A short, printable look at a piece - text if it is text, hex if it is not."""
    head = data[:limit]
    printable = sum(1 for byte in head if 32 <= byte < 127 or byte in (9, 10, 13))
    if head and printable / len(head) > 0.85:
        return head.decode("utf-8", "replace").replace("\n", " ")
    return head[:32].hex()


def _describe(data: bytes) -> str:
    """What this piece looks like, for the walk log."""
    signature = match_signature(data)
    if signature is not None:
        return signature.name
    return "unknown"


def solve(
    data: bytes,
    path: str = "file",
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    max_depth: int = MAX_DEPTH,
    top_leads: int = 3,
) -> SolveReport:
    """Walk a file to the bottom and report the flag, or the best three leads."""
    budget = budget or Budget(max_attempts=200_000, max_seconds=20)
    report = SolveReport(path=path, size=len(data))

    root = Piece(name=safe_name(path, "input"), origin="the file itself", data=data, disk=path)
    queue: list[Piece] = [root]
    seen: set[bytes] = {hashlib.sha256(data).digest()}
    leads: list[Lead] = []

    while queue:
        if report.pieces >= MAX_PIECES:
            report.notes.append(
                f"stopped after {MAX_PIECES} pieces: run the commands above on the one you want"
            )
            break
        if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
            report.notes.append(
                f"budget spent with {len(queue)} piece(s) still to look at "
                "(raise --seconds, or run the command of a lead below)"
            )
            break

        piece = queue.pop(0)
        report.pieces += 1
        reader_name = readers.sniff(piece.data)
        if piece.depth == 0 and reader_name:
            report.read_as = readers.READERS_BY_NAME[reader_name].label

        # 1. Is the flag simply in there? This is the whole point of the walk.
        hits = find_flags(piece.data, flagset)
        for hit in hits:
            if any(found.text == hit.text for found in report.flags):
                continue
            report.flags.append(
                FlagFound(
                    text=hit.text,
                    where=piece.name,
                    how=piece.origin,
                    strength=hit.strength,
                    trail=list(piece.trail),
                )
            )
        if report.flags:
            report.steps.append(f"{piece.name}: the flag is in there ({piece.origin})")
            break

        # 2. What does that reader hand back?
        # (child, how to put it on disk, what to run when it cannot be).
        children: list[tuple[readers.Child, str, str]] = []
        if reader_name:
            opened = readers.open_with(reader_name, piece.data, flagset, piece.disk)
            if piece.depth == 0 and opened.detail:
                report.read_as = f"{opened.label} ({opened.detail})"
            budget.spend(10)
            step = f"{piece.name}: read as {reader_name}"
            if opened.detail:
                step += f" - {opened.detail}"
            if opened.error:
                step += f" - could not be read: {opened.error}"
            if opened.children:
                step += f", {len(opened.children)} piece(s) came out"
            report.steps.append(step)
            for text in opened.flags:
                if not any(found.text == text for found in report.flags):
                    report.flags.append(
                        FlagFound(
                            text=text,
                            where=piece.name,
                            how=f"{reader_name} reader",
                            strength=1.0,
                            trail=[*piece.trail, opened.command.format(file=piece.disk)],
                        )
                    )
            if report.flags:
                break
            # A reader that found nothing to hand over still has advice: an
            # encrypted entry, a password-protected archive, a hash to crack.
            for command in opened.commands[:2]:
                leads.append(
                    Lead(
                        title=piece.name,
                        # The reader's own note says why it suggests this; the
                        # generic sentence is only the fallback.
                        why=(opened.notes[0][:200] if opened.notes else "")
                        or f"{reader_name}: what the reader suggests next",
                        score=0.55,
                        command=command.replace("{file}", piece.disk),
                    )
                )
            children += [
                (child, child.extract or opened.extract, opened.command)
                for child in opened.children
            ]
        else:
            report.steps.append(f"{piece.name}: {_describe(piece.data)}, no reader claims it")

        # 3. The carver, for what is hidden after the end of a file.
        if not reader_name or reader_name in CARVE_ALSO:
            carved = readers.open_with("repair", piece.data, flagset, piece.disk)
            budget.spend(5)
            fresh = [child for child in carved.children if not child.name.startswith("repaired")]
            if fresh:
                report.steps.append(
                    f"{piece.name}: {len(fresh)} file(s) carved out of it ({carved.detail})"
                )
                children += [(child, carved.extract, carved.command) for child in fresh]

        # 4. The decoding chains, for anything no reader claimed.
        if not reader_name and piece.size <= AUTO_SIZE_LIMIT:
            slice_budget = Budget(
                max_attempts=2000,
                max_seconds=max(0.5, min(4.0, budget.max_seconds - budget.elapsed())),
                cancel_event=budget.cancel_event,
            )
            candidates = auto_decode(piece.data, flagset=flagset, budget=slice_budget, top_n=2)
            budget.spend(slice_budget.attempts)
            for candidate in candidates[:2]:
                if candidate.score < LEAD_SCORE:
                    continue
                report.steps.append(
                    f"{piece.name}: {candidate.label} (score {candidate.score:.2f})"
                )
                leads.append(
                    Lead(
                        title=f"{piece.name}: {candidate.label}",
                        why="; ".join(candidate.reasons[:2]) or "the chains found something",
                        score=candidate.score,
                        command=f"ctfc auto {piece.disk} --show-code",
                        preview=_preview(candidate.data),
                    )
                )
                # A chain that produced a file (base64 -> gzip -> a tar) is
                # followed: that is where the next container usually hides.
                children.append(
                    (
                        readers.Child(
                            name=f"decoded: {candidate.label}",
                            origin=f"decoded: {candidate.label}",
                            data=candidate.data,
                        ),
                        "",
                        "ctfc auto {file}",
                    )
                )
            if not candidates:
                # Nothing decoded: is it at least readable on its own?
                plain, reasons = score(piece.data, flagset)
                if plain >= 0.4:
                    leads.append(
                        Lead(
                            title=piece.name,
                            why="readable as it is: " + "; ".join(reasons[:2]),
                            score=min(plain, PLAIN_TEXT_CAP),
                            command=f"ctfc detect {piece.disk}",
                            preview=_preview(piece.data),
                        )
                    )

        # 5. Queue what came out, once each, and remember how to get at it.
        if piece.depth >= max_depth:
            continue
        out_dir = f"out{piece.depth + 1}"
        for child, extract, shown in children:
            digest = hashlib.sha256(child.data).digest()
            if digest in seen:
                continue
            seen.add(digest)
            if extract:
                # It can be written to disk, so it gets the name it will land
                # under, and the command that puts it there.
                name = safe_name(child.name)
                trail = [*piece.trail, extract.format(file=piece.disk, dir=out_dir)]
                disk = f"{out_dir}/{name}"
            else:
                # Produced in memory (a decoding chain, a mail body): the command
                # that shows it is the one that made it, and the piece keeps its
                # parent's path so the next command still points somewhere real.
                name = child.name
                trail = [*piece.trail, shown.format(file=piece.disk)]
                disk = piece.disk
            queue.append(
                Piece(
                    name=f"{piece.name} > {name}",
                    origin=child.origin,
                    data=child.data,
                    depth=piece.depth + 1,
                    trail=trail,
                    disk=disk,
                )
            )

    report.flags = _dedupe_flags(report.flags)
    report.budget = budget.summary()
    if not report.flags:
        leads.sort(key=lambda lead: lead.score, reverse=True)
        report.leads = _dedupe_leads(leads)[:top_leads]
        if not report.leads:
            report.notes.append(
                "nothing came out: try `ctfc detect` for the fingerprint, "
                "`ctfc keys` if you have a dump to hunt keys in, and the Files tab "
                "of `ctfc serve` to run a reader by hand"
            )
    return report


def _dedupe_flags(flags: list[FlagFound]) -> list[FlagFound]:
    """Drop a hit that is only a longer reading of another one.

    The generic flag regex matches everything up to the brace, so a file holding
    `flag.txtCYBN{x}` yields both `CYBN{x}` and `txtCYBN{x}`. They are one flag,
    and the shorter reading is the one that starts at a known prefix.
    """
    kept: list[FlagFound] = []
    for flag in flags:
        if any(other is not flag and flag.text.endswith(other.text) for other in flags):
            continue
        kept.append(flag)
    return kept


def _dedupe_leads(leads: list[Lead]) -> list[Lead]:
    """One lead per command: the best one. Two chains on the same file are one lead."""
    best: dict[str, Lead] = {}
    for lead in leads:
        current = best.get(lead.command)
        if current is None or lead.score > current.score:
            best[lead.command] = lead
    return sorted(best.values(), key=lambda lead: lead.score, reverse=True)
