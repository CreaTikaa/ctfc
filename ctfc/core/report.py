"""Turn a session into a Markdown write-up.

The layout follows the user's own write-ups (github.com/CreaTikaa/CTFs-Writeups):

    # Challenge name
    ### The statement
    **CTF:** ... · **Category:** ...

    ## Step 1: Recon
    your notes
    ```bash
    ctfc detect map.pdf.secured
    ```
    what ctfc found, why, the output,
    the Python script to redo it by hand, the CyberChef recipe

    ## Flag
    **Flag:** `CYBN{...}`
    GGs !

It is a *draft*: the steps and the code are exact, the story around them is
yours. Notes taken with `ctfc session note` land where you wrote them. Steps
that led nowhere (nothing scored) are left out unless `include_all` is set.
English or French (`lang`), the phrases live in strings.py.
"""

from __future__ import annotations

import re

from ctfc.core.session import Entry, Session
from ctfc.strings import REPORT_TEXT

KEEP_SCORE = 0.5  # a step whose best result scores less is a dead end
OUTPUT_LIMIT = 1500  # characters of output shown per step
REASONS_SHOWN = 5


def fence(text: str, language: str = "") -> str:
    """A Markdown code block that the text itself cannot close.

    Sample output may contain ``` itself: the fence is made one backtick longer
    than the longest run of backticks in the text.
    """
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{language}\n{text.rstrip()}\n{ticks}"


def clean(text: str) -> str:
    """Keep output readable in Markdown: control characters become '.'."""
    return "".join(ch if ch.isprintable() or ch in "\n\t" else "." for ch in text)


def _keep(entry: Entry, following_note: bool, include_all: bool) -> bool:
    if include_all or following_note:
        return True
    if entry.result.get("summary"):
        return True
    return entry.result.get("score", 0) >= KEEP_SCORE


def _dedupe(entries: list[Entry]) -> list[Entry]:
    """The same command run twice in a row (a retry) appears once: the last run."""
    kept: list[Entry] = []
    for entry in entries:
        if (
            kept
            and entry.kind == "step"
            and kept[-1].kind == "step"
            and kept[-1].command == entry.command
        ):
            kept[-1] = entry
        else:
            kept.append(entry)
    return kept


def build_report(session: Session, lang: str = "en", include_all: bool = False) -> str:
    """The write-up of a session, as Markdown text."""
    words = REPORT_TEXT.get(lang, REPORT_TEXT["en"])
    meta = session.meta()
    entries = _dedupe(session.entries())
    out: list[str] = [f"# {meta.display_title()}"]
    if meta.description:
        out.append(f"### {meta.description.strip()}")
    facts = []
    colon = words["colon"]
    if meta.ctf:
        facts.append(f"**{words['ctf']}{colon}** {meta.ctf}")
    if meta.category:
        facts.append(f"**{words['category']}{colon}** {meta.category}")
    if facts:
        out.append(" · ".join(facts))

    number = 0
    for index, entry in enumerate(entries):
        if entry.kind == "note":
            out.append(entry.text)
            continue
        following_note = index + 1 < len(entries) and entries[index + 1].kind == "note"
        if not _keep(entry, following_note, include_all):
            continue
        number += 1
        out.append(_step(entry, number, words))

    flags = session.flags()
    out.append(f"## {words['flag']}")
    if flags:
        out.append(f"**{words['flag']}{words['colon']}** `{flags[0]}`")
    else:
        out.append(words["no_flag"])
    out.append(words["outro"])
    out.append(f"<!-- {words['generated']} (ctfc report {session.name}). {words['check']} -->")
    return "\n\n".join(part for part in out if part) + "\n"


def _step(entry: Entry, number: int, words: dict) -> str:
    """One `## Step N` section."""
    heading = words["tools"].get(entry.tool, entry.tool or words["step"])
    parts = [f"## {words['step']} {number}: {heading}"]
    if entry.command:
        parts.append(fence(entry.command, "bash"))
    result = entry.result
    # What the command saw (detect's guesses, what a script does) comes first.
    if result.get("summary"):
        parts.append("\n".join(f"- {clean(line)}" for line in result["summary"]))
    if result.get("label"):
        parts.append(
            words["found"].format(label=result["label"].strip(), score=result.get("score", 0))
        )
        reasons = [f"- {clean(reason)}" for reason in result.get("reasons", [])[:REASONS_SHOWN]]
        if reasons:
            parts.append("\n".join(reasons))
        if result.get("binary"):
            parts.append(words["binary"].format(length=result.get("length", 0)))
        elif result.get("preview"):
            preview = clean(result["preview"])
            if len(preview) > OUTPUT_LIMIT:
                preview = preview[:OUTPUT_LIMIT] + "\n[...]"
            parts.append(fence(preview, "text"))
        if result.get("python"):
            parts.append(words["by_hand"])
            parts.append(fence(result["python"], "python"))
        if result.get("cyberchef"):
            parts.append(words["cyberchef"])
            parts.append(fence(result["cyberchef"]))
    if not result:
        parts.append(words["nothing"])
    return "\n\n".join(parts)
