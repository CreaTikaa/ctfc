"""Next steps: what to do when `ctfc solve` found no flag.

A "no flag" answer is not useless: the walk *saw* things - a WAV with nothing
in its low bits, a Wi-Fi capture with a WPA handshake, 4 KB of random-looking
bytes with no header. Each of those has a usual meaning in a CTF and a usual
next tool. This module turns what was seen into that advice.

It works in two steps, both deterministic (no ML, hard rule 1):

1. **facts.** For every piece, `observe()` writes down a few short strings:
   `reader:wav`, `magic:jpg`, `entropy:high`, `detect:xor.repeating`,
   `pcap:tls`... (the full list is at the top of `data/leads.toml`).
2. **rules.** `plan()` runs the table in `data/leads.toml` over the facts. A
   rule that matches becomes one `NextStep`: what was found, what it usually
   means, the ctfc commands to try, and the external tools from
   `data/tools.toml` with their command already filled in - installed or not,
   and how to install them.

Adding a case is adding a block to `leads.toml`; this file only matches.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ctfc.core import tools as toolbox
from ctfc.core.datafiles import load_toml
from ctfc.core.magic import match_signature
from ctfc.core.scoring import printable_ratio, shannon_entropy

# A piece above this entropy (bits per byte) with no known header "looks random".
HIGH_ENTROPY = 7.2
# Too short to tell random from not: 64 bytes of English can score 5.5.
ENTROPY_MIN_SIZE = 64
# Text above this printable ratio is "a text".
TEXT_RATIO = 0.9
# `ctfc detect` is run on pieces up to this size (it is cheap, but not free).
DETECT_LIMIT = 256 * 1024
# A detect rule must be at least this sure to count as a fact.
DETECT_CONFIDENCE = 0.7  # the same bar as the tool suggestions (suggest_threshold)
# No reader, no signature, and bigger than this: probably a raw dump.
BIG_RAW = 64 * 1024 * 1024
# How many steps a report shows, and how many tools per step.
MAX_STEPS = 4
MAX_TOOLS = 5
# An MP3 with no ID3 tag starts straight on a frame header: 11 set bits, then
# MPEG version + layer bits. The magic table has no entry (2 bytes is too weak to
# scan for), so it is checked here, at offset 0 only, and twice: two frames.
MP3_SYNC = re.compile(rb"\xff[\xe2-\xff]")
# Two TLS record headers (handshake, TLS 1.0-1.3 version) make "there is TLS".
TLS_RECORD = re.compile(rb"\x16\x03[\x01-\x04]..[\x01\x02]", re.DOTALL)


@dataclass(frozen=True)
class LeadRule:
    """One block of data/leads.toml."""

    id: str
    when: tuple[str, ...]
    found: str
    meaning: str
    ctfc: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    by_hand: tuple[str, ...] = ()
    notes: str = ""  # a regex a reader note must also match ("" = no condition)
    unless: tuple[str, ...] = ()  # patterns that stop the rule (a WAV is RIFF, not video)
    weight: float = 0.5

    def matches(self, facts: set[str], notes: list[str]) -> bool:
        """Does this rule fire on a piece with these facts and reader notes?"""
        hit = any(fnmatch.fnmatch(fact, pattern) for pattern in self.when for fact in facts)
        if not hit:
            return False
        if any(fnmatch.fnmatch(fact, pattern) for pattern in self.unless for fact in facts):
            return False
        if self.notes:
            return any(re.search(self.notes, note) for note in notes)
        return True


@lru_cache(maxsize=1)
def load_rules() -> tuple[LeadRule, ...]:
    """Parse data/leads.toml once per process."""
    rules = []
    for row in load_toml("leads.toml")["lead"]:
        rules.append(
            LeadRule(
                id=row["id"],
                when=tuple(row.get("when", [])),
                found=row["found"],
                meaning=row["meaning"],
                ctfc=tuple(row.get("ctfc", [])),
                tools=tuple(row.get("tools", [])),
                by_hand=tuple(row.get("by_hand", [])),
                notes=row.get("notes", ""),
                unless=tuple(row.get("unless", [])),
                weight=float(row.get("weight", 0.5)),
            )
        )
    return tuple(rules)


@dataclass
class Observation:
    """What the walk saw of one piece: the input of the rules."""

    piece: str  # "chal.zip > song.wav"
    disk: str  # where the piece is on disk once the trail has been run
    trail: list[str] = field(default_factory=list)  # the commands that put it there
    detail: str = ""  # the reader's one-line summary ("2 channel(s), 16-bit, ...")
    facts: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)  # the reader's notes
    depth: int = 0

    def to_dict(self) -> dict:
        return {
            "piece": self.piece,
            "disk": self.disk,
            "detail": self.detail,
            "facts": sorted(self.facts),
        }


@dataclass
class NextStep:
    """One piece of advice: what was found, what it means, what to run."""

    rule: str  # the leads.toml id
    found: str  # "a sound file (2 channel(s), 16-bit, 11050 Hz, 16.5 s)"
    meaning: str
    piece: str  # the piece it is about
    disk: str  # that piece on disk
    trail: list[str] = field(default_factory=list)  # how to get that piece first
    ctfc: list[str] = field(default_factory=list)
    tools: list[toolbox.Suggestion] = field(default_factory=list)
    by_hand: list[str] = field(default_factory=list)
    weight: float = 0.5
    also: list[str] = field(default_factory=list)  # other pieces the same rule fired on
    # True when the piece IS the input: the web page can then run a tool on it.
    on_input: bool = False

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "found": self.found,
            "meaning": self.meaning,
            "piece": self.piece,
            "disk": self.disk,
            "trail": list(self.trail),
            "ctfc": list(self.ctfc),
            "tools": [tool.to_dict() for tool in self.tools],
            "by_hand": list(self.by_hand),
            "weight": round(self.weight, 3),
            "also": list(self.also),
            "on_input": self.on_input,
        }


# ---------------------------------------------------------------------------
# 1. Facts
# ---------------------------------------------------------------------------


def observe(
    data: bytes,
    piece: str,
    disk: str,
    trail: list[str] | None = None,
    reader: str = "",
    detail: str = "",
    error: str = "",
    notes: list[str] | None = None,
    decoded: bool = False,
    depth: int = 0,
    flagset=None,
) -> Observation:
    """Write down the facts the rules need about one piece.

    `decoded` is True when a decoding chain already turned the piece into
    something (then it is not "unknown"). Every check is cheap: the slowest is
    `ctfc detect`, run only on small pieces nobody claimed.
    """
    facts: set[str] = set()
    if reader:
        facts.add(f"reader:{reader}")
        if error:
            facts.add(f"reader-error:{reader}")
    signature = match_signature(data)
    known = signature is not None  # a format we can name: not "unknown", not "random"
    if signature is not None:
        facts.add(f"magic:{signature.ext}")
    if signature is None and MP3_SYNC.match(data[:2]) and _second_mp3_frame(data):
        facts.add("magic:mp3")
        known = True
    if data[:4] == b"\x7fELF" and data[16:18] in (b"\x04\x00", b"\x00\x04"):
        facts.add("kind:core")  # an ELF *core* file: a process's memory, not a program
    if data[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in data[:65536] + data[-65536:]:
        facts.add("kind:apk")
    if reader == "pcap" and len(TLS_RECORD.findall(data[:8_000_000], 0)) >= 2:
        facts.add("pcap:tls")

    if not reader and not known and not decoded:
        head = data[: 1 << 20]
        ratio, _utf8 = printable_ratio(head) if head else (0.0, False)
        if len(data) >= BIG_RAW:
            facts.add("kind:bigraw")
        elif len(data) >= ENTROPY_MIN_SIZE and shannon_entropy(head) >= HIGH_ENTROPY:
            facts.add("entropy:high")
        elif ratio >= TEXT_RATIO and data.strip():
            facts.add("kind:text")
            if _trailing_whitespace(head):
                facts.add("kind:whitespace")
        else:
            facts.add("kind:unknown")
        if len(data) <= DETECT_LIMIT:
            facts |= _detect_facts(data, flagset)

    if not detail and signature is not None:
        detail = signature.name  # no reader: the signature is the best summary
    return Observation(
        piece=piece,
        disk=disk,
        trail=list(trail or []),
        detail=detail,
        facts=facts,
        notes=list(notes or []),
        depth=depth,
    )


def _trailing_whitespace(text: bytes) -> bool:
    """Do several lines end with spaces or tabs (SNOW / whitespace stego)?

    A tab at a line end is never typed by accident, and three or more lines
    with trailing blanks, a quarter of the lines at least, is not an editor's
    leftover.
    """
    lines = text.split(b"\n")
    padded = [line for line in lines if line.rstrip(b"\r") != line.rstrip(b"\r").rstrip(b" \t")]
    return len(padded) >= 3 and len(padded) * 4 >= len(lines)


def _second_mp3_frame(data: bytes) -> bool:
    """Is there a second MPEG audio frame where the first header says it ends?

    One `ff fb` at offset 0 is a coincidence one time in a few hundred; a
    second frame header exactly one frame later is not.
    """
    bitrates = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)
    rates = (44100, 48000, 32000)
    if len(data) < 4 or data[1] & 0xFE != 0xFA:  # MPEG-1 Layer III only: the common case
        return False
    bitrate_index, rate_index = data[2] >> 4, (data[2] >> 2) & 3
    if not 0 < bitrate_index < 15 or rate_index == 3:
        return False
    padding = (data[2] >> 1) & 1
    length = 144 * bitrates[bitrate_index] * 1000 // rates[rate_index] + padding
    return data[length : length + 1] == b"\xff" and bool(MP3_SYNC.match(data[length : length + 2]))


def _detect_facts(data: bytes, flagset) -> set[str]:
    """`detect:<rule>` for every detect guess that is sure enough."""
    from ctfc.core.detect import detect

    try:
        report = detect(data, flagset)
    except Exception:  # noqa: BLE001 - advice must never break the solve
        return set()
    return {
        f"detect:{guess.rule}"
        for guess in report.guesses
        if guess.confidence >= DETECT_CONFIDENCE and guess.rule != "flag"
    }


# ---------------------------------------------------------------------------
# 2. Rules
# ---------------------------------------------------------------------------


def plan(
    observations: list[Observation],
    input_path: str = "",
    offline: bool = False,
    tool_paths: dict | None = None,
    wordlist: str = "",
    cyberchef_url: str = "",
    limit: int = MAX_STEPS,
) -> list[NextStep]:
    """Turn the observations of a walk into at most `limit` next steps.

    One step per rule: when the same rule fires on several pieces (ten PNGs in
    a ZIP), the step is about the first one met - the shallowest - and lists
    the others in `also`. The most specific rules (highest weight) come first.
    """
    steps: dict[str, NextStep] = {}
    for seen in observations:
        for rule in load_rules():
            if not rule.matches(seen.facts, seen.notes):
                continue
            if rule.id in steps:
                if seen.piece not in steps[rule.id].also and len(steps[rule.id].also) < 10:
                    steps[rule.id].also.append(seen.piece)
                continue
            steps[rule.id] = _step(
                rule, seen, input_path, offline, tool_paths, wordlist, cyberchef_url
            )
    ranked = sorted(steps.values(), key=lambda step: -step.weight)
    # A generic rule says nothing new next to a specific one on the same piece
    # ("a capture" after "a Wi-Fi capture with WPA"): keep the specific one.
    kept: list[NextStep] = []
    for step in ranked:
        specific = GENERIC_OF.get(step.rule, set())
        if any(
            other.piece == step.piece and ("*" in specific or other.rule in specific)
            for other in kept
        ):
            continue
        kept.append(step)
    return kept[:limit]


# Generic rule -> the specific rules that make it redundant on the same piece.
GENERIC_OF = {
    "pcap": {"pcap.wpa", "pcap.usb"},
    "unknown": {"encrypted.blob", "xor", "classical", "hash", "embedded"},
    "text": {"classical", "hash", "rsa", "zero.width", "xor", "whitespace"},
    # "the reader failed" adds nothing when another rule already speaks of that piece.
    "reader.failed": {"*"},
    "windows.logs": {"windows.sam"},
}


def _step(
    rule: LeadRule,
    seen: Observation,
    input_path: str,
    offline: bool,
    tool_paths: dict | None,
    wordlist: str,
    cyberchef_url: str,
) -> NextStep:
    """Fill one rule in for one piece: the texts, the commands, the tools."""
    disk = seen.disk or input_path or "<file>"
    values: dict = {"input": disk, "output": f"{disk}.out"}
    if wordlist:
        values["wordlist"] = wordlist
    if cyberchef_url:
        values["cyberchef_url"] = cyberchef_url
    found = rule.found.replace("{detail}", seen.detail or "no detail")
    if seen.piece and seen.depth:
        found = f"{seen.piece}: {found}"
    return NextStep(
        rule=rule.id,
        found=found,
        meaning=rule.meaning,
        piece=seen.piece,
        disk=disk,
        trail=list(seen.trail),
        ctfc=[_fill_text(command, disk, wordlist) for command in rule.ctfc],
        tools=_tools(rule.tools, values, offline, tool_paths),
        by_hand=[_fill_text(text, disk, wordlist) for text in rule.by_hand],
        weight=rule.weight,
        on_input=seen.depth == 0,
    )


def _fill_text(text: str, disk: str, wordlist: str) -> str:
    """A ctfc command or a by-hand line with the piece (and the wordlist) put in."""
    text = text.replace("{file}", disk)
    if wordlist:
        text = text.replace("<wordlist>", wordlist)
    return text


def _tools(
    ids: tuple[str, ...], values: dict, offline: bool, tool_paths: dict | None
) -> list[toolbox.Suggestion]:
    """The tools of one rule, as Suggestions with their command filled in."""
    registry = {tool.id: tool for tool in toolbox.load_tools()}
    picked: list[toolbox.Suggestion] = []
    chosen = [registry[tool_id] for tool_id in ids if tool_id in registry]
    # The embedded CyberChef, when it was fetched, replaces the public one.
    replaced = {
        other
        for tool in chosen
        if tool.prefer_over and toolbox.tool_available(tool, tool_paths)
        for other in tool.prefer_over
    }
    for tool in chosen:
        if tool.id in replaced:
            continue
        if offline and not tool.offline_safe:
            continue
        if tool.kind == "embedded" and not tool.available:
            continue  # a link to a copy that was never fetched would be dead
        command, missing = ([], [])
        url = ""
        if tool.command_template:
            command, missing = toolbox.fill(tool.command_template, values)
            argv = toolbox.program_argv(tool.command_template[0], tool_paths)
            if argv is not None and len(argv) > 1:
                # A program behind tool_paths: show what will really run.
                command = [*argv, *command[1:]]
        if tool.url_template:
            url, url_missing = toolbox.build_url(tool, values)
            missing += url_missing
        picked.append(
            toolbox.Suggestion(
                tool=tool,
                reason="",
                command=command,
                url=url,
                available=toolbox.tool_available(tool, tool_paths),
                warning=toolbox.THIRD_PARTY_WARNING if not tool.offline_safe else "",
                placeholders=sorted(set(missing)),
            )
        )
        if len(picked) >= MAX_TOOLS:
            break
    return picked
