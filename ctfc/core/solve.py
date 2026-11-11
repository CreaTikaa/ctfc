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
from ctfc.core.flags import (
    ASSEMBLED_STRENGTH,
    DECODE_RUN_RE,
    WEAK_GENERIC_STRENGTH,
    FlagSet,
    Fragment,
    assemble,
    decode_run,
    hunt,
)
from ctfc.core.magic import match_signature
from ctfc.core.scoring import printable_ratio, score

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
# Embedded blobs: a base64 / hex string at least this long inside a text piece
# is decoded, and followed when it turns into readable text or a known file.
BLOB_MIN_CHARS = 64
MAX_BLOBS = 10
TEXT_PIECE = 0.85  # printable ratio above which a piece is "a text"
# A flag-shaped string that may be chance: shown first among the leads.
WEAK_FLAG_LEAD = 0.6
# The base64 of the flag prefix, with no whole flag behind it.
PREFIX_LEAD = 0.7


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
class FragmentFound:
    """Part of a flag, and the piece it was in."""

    fragment: Fragment
    where: str
    trail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {**self.fragment.to_dict(), "where": self.where, "trail": list(self.trail)}


@dataclass
class SolveReport:
    """What the walk found, in the order a human wants to read it."""

    path: str = ""
    size: int = 0
    read_as: str = ""  # the reader that claimed the original file
    flags: list[FlagFound] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    # Parts of a flag seen along the way ("CYBN{half_one", "half_two}"), with
    # the piece each came from. They never stop the walk on their own.
    fragments: list[FragmentFound] = field(default_factory=list)
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
            "fragments": [fragment.to_dict() for fragment in self.fragments],
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


@dataclass
class Visit:
    """One piece, and everything the walk learned about it.

    This is what `walk()` yields. `ctfc solve` turns a visit into flags and
    leads; `ctfc workspace` turns the same visit into secrets, keys and
    ciphertexts. Neither of them re-opens anything.
    """

    piece: Piece
    reader: str = ""  # which reader claimed it, "" when none did
    opened: readers.Opened | None = None  # what that reader found
    carved: readers.Opened | None = None  # what the carver pulled out of it
    candidates: list = field(default_factory=list)  # `auto` results, best first


def walk(
    data: bytes,
    path: str = "file",
    flagset: FlagSet | None = None,
    budget: Budget | None = None,
    max_depth: int = MAX_DEPTH,
    max_pieces: int = MAX_PIECES,
    decode: bool = True,
    notes: list[str] | None = None,
):
    """Yield every piece of a file, breadth first, under one shared budget.

    One file is rarely one thing: it holds members, attachments, streams, an
    overlay, a layer, or a payload behind a decoding chain. This generator is
    the part that goes and gets them, and it is deliberately free of any
    opinion about what matters - the caller decides that.

    Stop early simply by not asking for the next piece: `for visit in walk(...):
    ... break` leaves the rest unread, which is exactly what `solve` does when
    it finds the flag.

    `notes` is appended to (rather than returned) when the walk stops short, so
    that a caller which breaks out early still has the reason.
    """
    budget = budget or Budget(max_attempts=200_000, max_seconds=20)
    notes = notes if notes is not None else []

    root = Piece(name=safe_name(path, "input"), origin="the file itself", data=data, disk=path)
    queue: list[Piece] = [root]
    seen: set[bytes] = {hashlib.sha256(data).digest()}
    count = 0

    while queue:
        if count >= max_pieces:
            notes.append(f"stopped after {max_pieces} pieces in {path}")
            return
        if budget.stopped_reason or budget.elapsed() >= budget.max_seconds:
            notes.append(
                f"budget spent with {len(queue)} piece(s) of {path} still to look at "
                "(raise --seconds)"
            )
            return

        piece = queue.pop(0)
        count += 1
        visit = Visit(piece=piece, reader=readers.sniff(piece.data))
        # (child, how to put it on disk, what to run when it cannot be).
        children: list[tuple[readers.Child, str, str]] = []

        if visit.reader:
            visit.opened = readers.open_with(visit.reader, piece.data, flagset, piece.disk)
            budget.spend(10)
            children += [
                (child, child.extract or visit.opened.extract, visit.opened.command)
                for child in visit.opened.children
            ]

        # The carver, for what hides after the end of a file. It runs on the
        # formats that are routinely used as a wrapper too, not only on the
        # files no reader claimed: a ZIP behind a PNG is the stock trick, and
        # the PNG reader is perfectly happy with the PNG.
        if not visit.reader or visit.reader in CARVE_ALSO:
            carved = readers.open_with("repair", piece.data, flagset, piece.disk)
            budget.spend(5)
            fresh = [child for child in carved.children if not child.name.startswith("repaired")]
            if fresh:
                carved.children = fresh
                visit.carved = carved
                children += [(child, carved.extract, carved.command) for child in fresh]

        # The decoding chains, for anything no reader claimed.
        if decode and not visit.reader and piece.size <= AUTO_SIZE_LIMIT:
            slice_budget = Budget(
                max_attempts=2000,
                max_seconds=max(0.5, min(4.0, budget.max_seconds - budget.elapsed())),
                cancel_event=budget.cancel_event,
            )
            visit.candidates = auto_decode(
                piece.data, flagset=flagset, budget=slice_budget, top_n=2
            )
            budget.spend(slice_budget.attempts)
            for candidate in visit.candidates[:2]:
                if candidate.score < LEAD_SCORE:
                    continue
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

        # Blobs written inside a text (a script's `$payload = "<base64>"`, a
        # config value): the decoding chains above only see the text as a
        # whole, so each long string is decoded on its own.
        if decode and not visit.reader and piece.size <= AUTO_SIZE_LIMIT:
            for name, decoded in embedded_blobs(piece.data):
                children.append(
                    (readers.Child(name=name, origin=name, data=decoded), "", "ctfc auto {file}")
                )

        yield visit

        # Queue what came out, once each, and remember how to get at it.
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


def embedded_blobs(data: bytes) -> list[tuple[str, bytes]]:
    """Long base64 / hex strings inside a text that decode to something real.

    "Something real" is readable text (the next stage of a dropper) or bytes
    that start with a known file signature (a ZIP, a PE, a gzip stream). Random
    decodings of words that happen to be base64-shaped are neither, so they are
    dropped here rather than followed.

    Returns [(label, decoded bytes)], at most MAX_BLOBS, longest first.
    """
    if printable_ratio(data[:4096])[0] < TEXT_PIECE:
        return []
    text = data.decode("latin-1")
    runs = sorted(
        (match for match in DECODE_RUN_RE.finditer(text) if len(match.group(0)) >= BLOB_MIN_CHARS),
        key=lambda match: len(match.group(0)),
        reverse=True,
    )
    found: list[tuple[str, bytes]] = []
    for match in runs:
        if len(found) >= MAX_BLOBS:
            break
        if match.start() == 0 and match.end() == len(text.rstrip()):
            continue  # the whole piece is the blob: the decoding chains have it
        for how, decoded_text in decode_run(match.group(0)):
            decoded = decoded_text.encode("latin-1")
            readable = len(decoded) >= 32 and printable_ratio(decoded)[0] >= 0.9
            if readable or match_signature(decoded) is not None:
                found.append((f"{how} string at offset {match.start()}", decoded))
                break
    return found


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
    leads: list[Lead] = []

    for visit in walk(
        data,
        path,
        flagset=flagset,
        budget=budget,
        max_depth=max_depth,
        notes=report.notes,
    ):
        piece, opened = visit.piece, visit.opened
        report.pieces += 1
        if piece.depth == 0 and visit.reader:
            label = readers.READERS_BY_NAME[visit.reader].label
            detail = opened.detail if opened else ""
            report.read_as = f"{label} ({detail})" if detail else label

        # 1. Is the flag in there - as it is, or one layer down (a hex or
        #    base64 string, UTF-16, backwards)? This is the whole point of the walk.
        found = hunt(piece.data, flagset)
        for fragment in found.fragments:
            if not any(seen.fragment.text == fragment.text for seen in report.fragments):
                report.fragments.append(FragmentFound(fragment, piece.name, list(piece.trail)))
        for hit in found.flags:
            if hit.how == "base64-prefix":
                # "CYBN{" seen in base64, the rest not decoded into a whole flag:
                # a part of a flag (the fragments above have it when it decodes),
                # so the walk goes on - it may find the other part.
                leads.append(
                    Lead(
                        title=f"{piece.name}: base64 of a flag prefix",
                        why=hit.text,
                        score=PREFIX_LEAD,
                        command=f"ctfc auto {piece.disk}",
                        preview=hit.encoded[:120],
                    )
                )
                continue
            if hit.strength <= WEAK_GENERIC_STRENGTH:
                # "W1{!Tgxk3b}": flag-shaped, but as likely chance. Worth a look,
                # not worth stopping the walk for.
                leads.append(
                    Lead(
                        title=f"{piece.name}: flag-shaped {hit.text[:60]}",
                        why="has the XXX{...} shape, but a short body and no known prefix",
                        score=WEAK_FLAG_LEAD,
                        command=f"ctfc detect {piece.disk}",
                        preview=hit.text[:120],
                    )
                )
                continue
            if not any(found.text == hit.text for found in report.flags):
                report.flags.append(
                    FlagFound(
                        text=hit.text,
                        where=piece.name,
                        how=piece.origin if hit.how == "plain" else f"{piece.origin}; {hit.how}",
                        strength=hit.strength,
                        trail=list(piece.trail),
                    )
                )
        if report.flags:
            report.steps.append(f"{piece.name}: the flag is in there ({piece.origin})")
            break

        # 2. What the reader made of it - including the flags it found itself,
        #    in places raw bytes do not show (a UTF-16 mail body, a registry
        #    value, a .NET literal).
        if opened is not None:
            step = f"{piece.name}: read as {visit.reader}"
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
                            how=f"{visit.reader} reader",
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
                        or f"{visit.reader}: what the reader suggests next",
                        score=0.55,
                        command=command.replace("{file}", piece.disk),
                    )
                )
        else:
            report.steps.append(f"{piece.name}: {_describe(piece.data)}, no reader claims it")

        if visit.carved is not None:
            report.steps.append(
                f"{piece.name}: {len(visit.carved.children)} file(s) carved out of it "
                f"({visit.carved.detail})"
            )

        # 3. The decoding chains.
        for candidate in visit.candidates[:2]:
            if candidate.score < LEAD_SCORE:
                continue
            report.steps.append(f"{piece.name}: {candidate.label} (score {candidate.score:.2f})")
            leads.append(
                Lead(
                    title=f"{piece.name}: {candidate.label}",
                    why="; ".join(candidate.reasons[:2]) or "the chains found something",
                    score=candidate.score,
                    command=f"ctfc auto {piece.disk} --show-code",
                    preview=_preview(candidate.data),
                )
            )
        if not visit.reader and not visit.candidates and piece.size <= AUTO_SIZE_LIMIT:
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

    if not report.flags:
        report.flags = _assembled(report.fragments, flagset)
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


def _assembled(fragments: list[FragmentFound], flagset: FlagSet | None) -> list[FlagFound]:
    """The flag two fragments make together, when the walk found no whole one.

    Challenges split the flag ("half of it in the SSH key comment, backwards,
    the other half in base64 in a crontab"). When an opening and a closing
    fragment join into something that passes the flag check, that is the
    answer - reported with where both halves were, and a lower strength than a
    flag found whole.
    """
    by_text = {found.fragment.text: found for found in fragments}
    flags = []
    for flag in assemble([found.fragment for found in fragments], flagset):
        halves = [found for text, found in by_text.items() if flag.startswith(text)]
        halves += [found for text, found in by_text.items() if flag.endswith(text)]
        where = " + ".join(dict.fromkeys(half.where for half in halves))
        how = " + ".join(f"{half.fragment.side}: {half.fragment.how}" for half in halves)
        trail = [command for half in halves for command in half.trail]
        flags.append(
            FlagFound(
                text=flag,
                where=where,
                how=f"assembled from two fragments ({how})",
                strength=ASSEMBLED_STRENGTH,
                trail=list(dict.fromkeys(trail)),
            )
        )
    return flags


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
