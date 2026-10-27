"""Point at the right external tool, and run it safely when it is installed.

ctfc is not trying to replace xortool, hashcat or Detect It Easy. It reimplements
the ideas it needs so that it works on its own, and when a better tool is
installed it hands over - with the exact command, already filled in.

Three rules, from `CLAUDE.md`:

- **Only when confident.** A tool is suggested when a detect/lens rule fired
  above `suggest_threshold` (default 0.7), at most `max_suggestions` of them
  (default 3), each with the reason. An unsure guess shows nothing: a wall of
  "you could also try..." is noise during a timed CTF.
- **No `shell=True`, ever.** Commands come from `data/tools.toml` as argument
  lists and are run with `subprocess.run([...])`. The user's input only ever
  lands in a placeholder, never in a shell string.
- **Offline-first.** Anything that talks to a third party is marked
  `offline_safe = false`, carries a warning, and disappears when `offline = true`
  in the config or `--offline` was passed.
"""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ctfc.core.datafiles import load_toml

RUN_TIMEOUT = 120  # a tool that hangs must not hang ctfc
THIRD_PARTY_WARNING = "this sends your data to a third party"
OUTPUT_LIMIT = 200_000  # characters of output kept


@dataclass(frozen=True)
class Tool:
    """One entry of data/tools.toml."""

    id: str
    name: str
    kind: str  # "online" | "local" | "embedded"
    suggest_when: tuple[str, ...]
    offline_safe: bool
    command_template: tuple[str, ...] = ()
    url_template: str = ""
    install: str = ""
    notes: str = ""

    def matches(self, rule: str) -> bool:
        """Does this tool apply to a rule id? Patterns may use `*` (`hash.*`)."""
        return any(fnmatch.fnmatch(rule, pattern) for pattern in self.suggest_when)

    @property
    def available(self) -> bool:
        """For a local tool: is the program on the PATH?"""
        if self.kind != "local" or not self.command_template:
            return True
        return shutil.which(self.command_template[0]) is not None


@dataclass
class Suggestion:
    """A tool worth running here, with the command and the reason."""

    tool: Tool
    reason: str  # "repeating pattern with period 6 (0.70)"
    command: list[str] = field(default_factory=list)
    url: str = ""
    available: bool = True
    warning: str = ""
    placeholders: list[str] = field(default_factory=list)  # fields still to fill in

    def to_dict(self) -> dict:
        return {
            "id": self.tool.id,
            "name": self.tool.name,
            "kind": self.tool.kind,
            "reason": self.reason,
            "command": list(self.command),
            "command_line": " ".join(self.command),
            "url": self.url,
            "available": self.available,
            "offline_safe": self.tool.offline_safe,
            "install": self.tool.install,
            "notes": self.tool.notes,
            "warning": self.warning,
            "placeholders": list(self.placeholders),
        }


@lru_cache(maxsize=1)
def load_tools() -> tuple[Tool, ...]:
    """Parse data/tools.toml once per process."""
    tools = []
    for row in load_toml("tools.toml")["tool"]:
        tools.append(
            Tool(
                id=row["id"],
                name=row["name"],
                kind=row["kind"],
                suggest_when=tuple(row.get("suggest_when", [])),
                offline_safe=bool(row.get("offline_safe", False)),
                command_template=tuple(row.get("command_template", [])),
                url_template=row.get("url_template", ""),
                install=row.get("install", ""),
                notes=row.get("notes", ""),
            )
        )
    return tuple(tools)


def tool_by_id(tool_id: str) -> Tool:
    for tool in load_tools():
        if tool.id == tool_id:
            return tool
    known = ", ".join(tool.id for tool in load_tools())
    raise ValueError(f"unknown tool {tool_id!r}; known: {known}")


# ---------------------------------------------------------------------------
# Filling in a command
# ---------------------------------------------------------------------------

PLACEHOLDER_HINTS = {
    "{input}": "the file to work on",
    "{recipe}": "a recipe to open it with (run detect/auto first)",
    "{wordlist}": "a wordlist, e.g. /usr/share/wordlists/rockyou.txt",
    "{output}": "an output folder",
    "{keylen}": "the key length",
    "{hashcat_mode}": "the hashcat mode number",
    "{john_format}": "the john format name",
    "{modulus}": "the RSA modulus",
}


def fill(template: tuple[str, ...] | str, values: dict) -> tuple[list[str], list[str]]:
    """Replace {placeholders} in a command (or URL). Returns (filled, still missing).

    Values are substituted as whole arguments, never concatenated into a shell
    string: `["xortool", "-l", "6", "/path/with spaces"]` stays four arguments.
    """
    pieces = [template] if isinstance(template, str) else list(template)
    filled = []
    missing = []
    for piece in pieces:
        out = piece
        for name, value in values.items():
            out = out.replace("{" + name + "}", str(value))
        for hint in PLACEHOLDER_HINTS:
            if hint in out and hint.strip("{}") not in values:
                missing.append(hint)
        filled.append(out)
    return filled, missing


def build_url(tool: Tool, values: dict) -> tuple[str, list[str]]:
    """The link for an online/embedded tool.

    CyberChef is not plain templating: the recipe and the data have to be encoded
    the way CyberChef itself does it (see `core/cyberchef.py`, verified against
    the real source). Everything else is a simple substitution.
    """
    if tool.id.startswith("cyberchef"):
        from ctfc.core.cyberchef import PUBLIC_URL, deep_link

        base = values.get("cyberchef_url") if tool.kind == "embedded" else PUBLIC_URL
        if not base:
            base = PUBLIC_URL
        recipe = values.get("cyberchef_recipe") or ""
        data = values.get("cyberchef_data")
        url = deep_link(recipe, data if isinstance(data, bytes) else None, str(base))
        missing = [] if recipe else ["{recipe}"]
        return url, missing
    filled, missing = fill(tool.url_template, values)
    return filled[0], missing


def suggest(
    rules: list[tuple[str, float]],
    values: dict | None = None,
    offline: bool = False,
    threshold: float = 0.7,
    limit: int = 3,
) -> list[Suggestion]:
    """Which tools are worth suggesting for these (rule id, confidence) pairs.

    Only rules above `threshold` are considered, the best first, and each tool is
    suggested once. `values` fills the placeholders that are known (the input
    path, a key length, a hashcat mode...).
    """
    values = values or {}
    ranked = sorted(
        [(rule, confidence) for rule, confidence in rules if confidence >= threshold],
        key=lambda item: -item[1],
    )
    suggestions: list[Suggestion] = []
    seen: set[str] = set()
    for rule, confidence in ranked:
        for tool in load_tools():
            if tool.id in seen or not tool.matches(rule):
                continue
            if offline and not tool.offline_safe:
                continue
            seen.add(tool.id)
            command, missing = ([], [])
            url = ""
            if tool.command_template:
                command, missing = fill(tool.command_template, values)
            if tool.url_template:
                url, url_missing = build_url(tool, values)
                missing += url_missing
            suggestions.append(
                Suggestion(
                    tool=tool,
                    reason=f"{rule} fired with confidence {confidence:.2f}",
                    command=command,
                    url=url,
                    available=tool.available,
                    warning=THIRD_PARTY_WARNING if not tool.offline_safe else "",
                    placeholders=sorted(set(missing)),
                )
            )
            if len(suggestions) >= limit:
                return suggestions
    return suggestions


def suggest_for_report(
    report,
    values: dict | None = None,
    offline: bool = False,
    threshold: float = 0.7,
    limit: int = 3,
) -> list[Suggestion]:
    """Suggestions for a `detect` report: its guesses are already (rule, confidence)."""
    rules = [(guess.rule, guess.confidence) for guess in report.guesses]
    return suggest(rules, values, offline, threshold, limit)


# ---------------------------------------------------------------------------
# Running one
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """What a tool printed."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "command_line": " ".join(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


def run_tool(tool: Tool, values: dict, timeout: int = RUN_TIMEOUT) -> RunResult:
    """Run a local tool with an argument list. Never a shell, never an online tool."""
    if tool.kind != "local":
        return RunResult([], -1, "", "", f"{tool.name} is not a local program: nothing to run")
    if not tool.command_template:
        return RunResult([], -1, "", "", f"{tool.name} has no command in tools.toml")
    command, missing = fill(tool.command_template, values)
    if missing:
        return RunResult(
            command,
            -1,
            "",
            "",
            "still missing: "
            + ", ".join(f"{name} ({PLACEHOLDER_HINTS.get(name, '?')})" for name in missing),
        )
    program = shutil.which(command[0])
    if program is None:
        return RunResult(command, -1, "", "", f"{command[0]} is not installed. {tool.install}")
    try:
        # shell=False (the default) is the point: the argument list is passed as is.
        completed = subprocess.run(  # noqa: S603 - argument list from our own registry
            [program, *command[1:]],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RunResult(command, -1, "", "", f"could not run it: {exc}")
    if isinstance(completed.stdout, bytes):
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
    else:  # pragma: no cover - only if text=True is ever passed
        out, err = completed.stdout, completed.stderr
    return RunResult(command, completed.returncode, out[:OUTPUT_LIMIT], err[:OUTPUT_LIMIT])


def installed_tools() -> list[tuple[Tool, bool]]:
    """Every registered tool and whether it is available here (for `ctfc tools --list`)."""
    return [(tool, tool.available) for tool in load_tools()]


def write_input(data: bytes, folder: Path, name: str = "input.bin") -> Path:
    """Write the data where a local tool can read it (tools work on files)."""
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    target.write_bytes(data)
    return target
