"""Regex rules for the languages we do not parse: PowerShell, JavaScript, bash, VBS.

Python gets a real parser (`lens_python.py`). For the others, writing a parser
would be a project of its own, so we use a **table of rules** kept in
`ctfc/data/lens_rules.toml`: one regex, one explanation, and what the captured
group means. Adding support for a new API is then one TOML entry, not code.

What you lose compared to a parser: the exact order of operations. A regex only
knows where it matched, so operations are ordered **by position in the file**,
which is right for the linear scripts droppers are made of, and wrong for code
that defines a function at the bottom and calls it at the top. The report says so.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from functools import lru_cache

from ctfc.core.datafiles import load_toml
from ctfc.core.lens import Artifact, Behaviour, LensReport, Operation

MIN_BLOB = 16  # a captured "blob" shorter than this is not worth reporting


@dataclass(frozen=True)
class Rule:
    """One row of data/lens_rules.toml (see that file for the field meanings)."""

    id: str
    languages: tuple[str, ...]
    regex: re.Pattern[str]
    explain: str
    operation: str = ""
    direction: str = "both"
    capture: str = ""
    capture_as: str = "text"
    behaviour: str = ""
    cipher: str = ""
    mode: str = ""


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    """Parse and compile the rule table once per process."""
    rules = []
    for row in load_toml("lens_rules.toml")["rule"]:
        rules.append(
            Rule(
                id=row["id"],
                languages=tuple(row["languages"]),
                regex=re.compile(row["regex"]),
                explain=row["explain"],
                operation=row.get("operation", ""),
                direction=row.get("direction", "both"),
                capture=row.get("capture", ""),
                capture_as=row.get("capture_as", "text"),
                behaviour=row.get("behaviour", ""),
                cipher=row.get("cipher", ""),
                mode=row.get("mode", ""),
            )
        )
    return tuple(rules)


def rules_for(language: str) -> list[Rule]:
    return [rule for rule in load_rules() if language in rule.languages]


# ---------------------------------------------------------------------------
# Reading a captured group
# ---------------------------------------------------------------------------


def read_capture(text: str, how: str) -> bytes | None:
    """Turn a captured string into the bytes the script would really use."""
    cleaned = text.strip()
    if how == "text":
        return cleaned.encode("utf-8", errors="replace")
    if how == "hex":
        try:
            return bytes.fromhex(re.sub(r"\s", "", cleaned))
        except ValueError:
            return None
    if how == "base64":
        try:
            return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
    if how == "number":
        try:
            value = int(cleaned, 16) if cleaned.lower().startswith(("0x", "&h")) else int(cleaned)
        except ValueError:
            # "&H5A" style, already handled above; anything else is not a number
            try:
                value = int(cleaned.lstrip("&Hh"), 16)
            except ValueError:
                return None
        return bytes([value & 0xFF])
    if how == "charcodes":
        # "0x41, 0x42, 67" -> b"ABC"
        numbers = []
        for piece in re.split(r"[,\s]+", cleaned):
            piece = piece.strip()
            if not piece:
                continue
            try:
                number = int(piece, 16) if piece.lower().startswith("0x") else int(piece)
            except ValueError:
                return None
            numbers.append(number & 0xFF)
        return bytes(numbers) if numbers else None
    if how == "utf16le_b64":
        raw = read_capture(cleaned, "base64")
        return raw.decode("utf-16-le", errors="replace").encode() if raw else None
    return cleaned.encode("utf-8", errors="replace")


def line_of(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def context_of(source: str, position: int) -> str:
    start = source.rfind("\n", 0, position) + 1
    end = source.find("\n", position)
    line = source[start:] if end == -1 else source[start:end]
    return line.strip()[:200]


# ---------------------------------------------------------------------------
# Applying the rules
# ---------------------------------------------------------------------------


def apply_rules(source: str, language: str, report: LensReport) -> None:
    """Run every rule of `language` over `source` and fill `report`.

    Operations are sorted by where they matched, which is execution order for the
    straight-line scripts this is meant for.
    """
    rules = rules_for(language)
    if not rules:
        report.notes.append(
            f"no rule for {language}: add one in ctfc/data/lens_rules.toml "
            "(id, regex, explanation) - it is a table, not code"
        )
        return

    found: list[tuple[int, Operation]] = []
    seen_artifacts: set[tuple[str, bytes]] = set()
    seen_behaviours: set[tuple[str, str]] = set()
    seen_operations: dict[tuple[str, int], int] = {}  # (kind, line) -> index in `found`
    # Source spans already captured. The same piece of text must be reported once,
    # by the most specific rule that matched it: a hex payload also matches the
    # base64 rule (hex digits are base64 too), and a `.Key = @(0x..)` array also
    # matches the generic "string hidden as byte values" rule.
    seen_spans: set[tuple[int, int]] = set()

    for rule in rules:
        for match in rule.regex.finditer(source):
            position = match.start()
            line = line_of(source, position)

            # Read the captured group first: when the same rule captures a key,
            # that key belongs to this very operation (same place in the code),
            # so it is not a guess and `_attach_keys` must not be involved.
            captured_value: bytes | None = None
            if rule.capture and match.groups() and match.group(1) is not None:
                captured_value = read_capture(match.group(1), rule.capture_as)

            if rule.operation:
                params: dict = {}
                if rule.cipher:
                    params["cipher"] = rule.cipher
                    params["mode"] = rule.mode or "cbc"
                if captured_value and rule.capture in ("key", "iv", "nonce"):
                    params[rule.capture] = captured_value
                operation = Operation(
                    kind=rule.operation,
                    label=rule.explain,
                    line=line,
                    direction=rule.direction,
                    rule=rule.id,
                    params=params,
                )
                # Two rules often describe the same operation (a generic one and a
                # precise one that also captures the key). Keep one per place, and
                # prefer the one that knows the key, whatever order the file is in.
                where = (rule.operation, line)
                if where not in seen_operations:
                    seen_operations[where] = len(found)
                    found.append((position, operation))
                else:
                    index = seen_operations[where]
                    old_position, old_operation = found[index]
                    if params.get("key") and not old_operation.params.get("key"):
                        found[index] = (old_position, operation)

            if rule.behaviour and (rule.behaviour, rule.id) not in seen_behaviours:
                seen_behaviours.add((rule.behaviour, rule.id))
                report.behaviours.append(
                    Behaviour(
                        kind=rule.behaviour,
                        label=rule.explain,
                        line=line,
                        context=context_of(source, position),
                    )
                )

            if rule.capture and captured_value:
                value = captured_value
                kind = rule.capture
                if kind == "blob" and len(value) < MIN_BLOB:
                    continue
                span = (match.start(1), match.end(1))
                if (kind, value) in seen_artifacts or span in seen_spans:
                    continue
                seen_artifacts.add((kind, value))
                seen_spans.add(span)
                report.artifacts.append(
                    Artifact(
                        kind=kind,
                        value=value,
                        how=f"{rule.capture_as} ({rule.id})",
                        line=line,
                        context=context_of(source, position),
                    )
                )

    # A rule with a captured blob and a generic one both fire: keep the specific
    # operation and drop the generic duplicate of the same kind on the same line.
    found.sort(key=lambda item: item[0])
    report.operations += [operation for _, operation in found]

    # Follow `-bxor $k` back to `$k = 0x3b`, then attach keys to the operations.
    _resolve_variable_keys(source, language, report)
    _attach_keys(report)
    if report.operations:
        report.notes.append(
            "operations are ordered by position in the file (regex rules cannot "
            "follow calls), so check the order against the source"
        )


# Per language: how an XOR names its key, and how that name is assigned a value.
# `{name}` is replaced by the variable name found by the first pattern.
XOR_VARIABLE: dict[str, tuple[str, str]] = {
    "powershell": (
        r"-bxor\s*\$(\w+)",
        r"\${name}\s*=\s*(0x[0-9a-fA-F]{{1,2}}|\d{{1,3}}|'[^'\n]{{1,64}}'|\"[^\"\n]{{1,64}}\")",
    ),
    "javascript": (
        r"\^\s*(?:(\w+)\[|(\w+)\b)",
        r"(?:var|let|const)\s+{name}\s*=\s*(0x[0-9a-fA-F]{{1,2}}|\d{{1,3}}|'[^'\n]{{1,64}}'"
        r"|\"[^\"\n]{{1,64}}\")",
    ),
    "vbs": (
        r"\bXor\s+(\w+)\b",
        r"\b{name}\s*=\s*(\d{{1,3}}|&H[0-9A-Fa-f]{{1,2}}|\"[^\"\n]{{1,64}}\")",
    ),
}


def _resolve_variable_keys(source: str, language: str, report: LensReport) -> None:
    """Find the value of an XOR key that the script keeps in a variable.

    A regex cannot do this on its own: one match sees `-bxor $k`, another sees
    `$k = 0x3b`, and nothing ties them together. So we look up the name.
    """
    patterns = XOR_VARIABLE.get(language)
    if patterns is None:
        return
    use_pattern, assign_template = patterns
    for index, operation in enumerate(report.operations):
        if operation.kind != "xor" or operation.params.get("key"):
            continue
        for use in re.finditer(use_pattern, source):
            name = next((group for group in use.groups() if group), None)
            if not name:
                continue
            assignment = re.search(assign_template.format(name=re.escape(name)), source)
            if assignment is None:
                continue
            literal = assignment.group(1)
            if literal[0] in "'\"":
                key = literal[1:-1].encode("utf-8", errors="replace")
                how = "text"
            else:
                key = read_capture(literal, "number") or b""
                how = "number"
            if not key:
                continue
            # A single byte reads better as hex: "0x3b" rather than ";".
            if len(key) == 1:
                readable = f"0x{key[0]:02x}"
            elif all(32 <= byte < 127 for byte in key):
                readable = key.decode("ascii")
            else:
                readable = "0x" + key.hex()
            params = dict(operation.params)
            params["key"] = key
            report.operations[index] = Operation(
                kind="xor",
                label=f"{operation.label}, key from the variable {name} = {readable}",
                line=operation.line,
                direction=operation.direction,
                rule=operation.rule,
                params=params,
            )
            report.artifacts.append(
                Artifact(
                    kind="key",
                    value=key,
                    how=f"{how}, from the variable {name}",
                    line=line_of(source, assignment.start()),
                    name=name,
                    context=context_of(source, assignment.start()),
                )
            )
            break


def _attach_keys(report: LensReport) -> None:
    """Give the XOR and cipher operations the key / IV found elsewhere in the file.

    A regex rule matches `-bxor $k` without knowing what `$k` is; the key usually
    sits in its own rule match a few lines above.
    """
    keys = report.artifacts_of("key")
    ivs = report.artifacts_of("iv")
    if not keys:
        return
    for index, operation in enumerate(report.operations):
        if operation.kind not in ("xor", "cipher") or operation.params.get("key"):
            continue
        # Prefer a key whose size fits the operation.
        if operation.kind == "cipher":
            fitting = [key for key in keys if len(key.value) in (16, 24, 32)]
        else:
            fitting = keys
        if not fitting:
            continue
        params = dict(operation.params)
        params["key"] = fitting[0].value
        # This key was matched by size, not by following the data: say so, so the
        # recovery script is offered as "check this" rather than as the answer.
        params["key_guessed"] = True
        if operation.kind == "cipher" and ivs and not params.get("iv"):
            params["iv"] = ivs[0].value
        report.operations[index] = Operation(
            kind=operation.kind,
            label=operation.label,
            line=operation.line,
            direction=operation.direction,
            rule=operation.rule,
            params=params,
        )
