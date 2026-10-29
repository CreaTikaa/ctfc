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
# Where scripts/fetch_vendor.sh puts the embedded CyberChef.
VENDOR_CYBERCHEF = Path(__file__).resolve().parent.parent / "web/static/vendor/cyberchef/index.html"
# Bytes of the input put in a CyberChef link (a URL cannot carry a whole dump).
CYBERCHEF_DATA_LIMIT = 4096
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
    # When this tool is available, these ids are not suggested next to it
    # (the embedded CyberChef makes the public one pointless, and safer).
    prefer_over: tuple[str, ...] = ()

    def matches(self, rule: str) -> bool:
        """Does this tool apply to a rule id? Patterns may use `*` (`hash.*`)."""
        return any(fnmatch.fnmatch(rule, pattern) for pattern in self.suggest_when)

    @property
    def available(self) -> bool:
        """Local tool: is the program on the PATH? Embedded: was it fetched?"""
        if self.kind == "embedded":
            return embedded_cyberchef_installed()
        if self.kind != "local" or not self.command_template:
            return True
        return shutil.which(self.command_template[0]) is not None


@dataclass(frozen=True)
class Signal:
    """Something we noticed about the input, that may make a tool relevant.

    `rule` is a detect / hash rule id ("xor.repeating", "hash.md5"),
    `confidence` is 0..1, `why` is shown to the user (default: the rule id).
    """

    rule: str
    confidence: float
    why: str = ""


def embedded_cyberchef_installed() -> bool:
    """Has scripts/fetch_vendor.sh been run on this machine?"""
    return VENDOR_CYBERCHEF.is_file()


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
                prefer_over=tuple(row.get("prefer_over", [])),
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
    "{password}": "the passphrase (ctfc sym --passwords may find it first)",
    "{zip_entry}": "the encrypted entry inside the ZIP",
    "{bkcrack_offset}": "the offset of the known plaintext in the ciphertext",
    "{bkcrack_plaintext}": "the known plaintext bytes, as hex",
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
    signals: list[Signal],
    values: dict | None = None,
    offline: bool = False,
    threshold: float = 0.7,
    limit: int = 3,
) -> list[Suggestion]:
    """Which tools are worth suggesting for these signals.

    Only signals above `threshold` are considered, the most confident first, and
    each tool is suggested once. `values` fills the placeholders that are known
    (the input path, a key length, a hashcat mode...).
    """
    values = values or {}
    ranked = sorted(
        [signal for signal in signals if signal.confidence >= threshold],
        key=lambda signal: -signal.confidence,
    )
    tools = load_tools()
    # Tools pushed aside by a better alternative that is available here.
    replaced = {
        other for tool in tools if tool.prefer_over and tool.available for other in tool.prefer_over
    }
    suggestions: list[Suggestion] = []
    seen: set[str] = set()
    for signal in ranked:
        for tool in tools:
            if tool.id in seen or tool.id in replaced or not tool.matches(signal.rule):
                continue
            if offline and not tool.offline_safe:
                continue
            if tool.kind == "embedded" and not tool.available:
                continue  # a link to a copy that was never fetched would be dead
            seen.add(tool.id)
            command, missing = ([], [])
            url = ""
            if tool.command_template:
                command, missing = fill(tool.command_template, values)
            if tool.url_template:
                url, url_missing = build_url(tool, values)
                missing += url_missing
            why = signal.why or signal.rule
            suggestions.append(
                Suggestion(
                    tool=tool,
                    reason=f"{why} (confidence {signal.confidence:.2f})",
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


# ---------------------------------------------------------------------------
# Working out the signals and values for an input
# ---------------------------------------------------------------------------


def gather(data: bytes, input_path: str | None, flagset=None) -> tuple[list[Signal], dict]:
    """Run the cheap analyses ctfc already has and collect what the tools need.

    Returns (signals, values): the detect guesses (plus "this is a hash" from
    the hash identifier), and the placeholder values we could work out - the
    input path, a key length, a hashcat mode, a CyberChef recipe.
    `input_path` is None when the data is not a file on disk (pasted text):
    {input} then stays a placeholder, since the tools only read files.
    """
    from ctfc.core.auto import auto_decode
    from ctfc.core.detect import detect
    from ctfc.core.hashes import identify
    from ctfc.core.xor import guess_key_lengths

    report = detect(data, flagset)
    signals = [Signal(guess.rule, guess.confidence, guess.label) for guess in report.guesses]
    values: dict = {"input": input_path} if input_path else {}

    lengths = guess_key_lengths(data)
    if lengths:
        values["keylen"] = lengths[0].length

    # A 32-hex-digit string is surely *a* hash, even when MD5 vs NTLM is a
    # coin toss: hashcat is the right tool either way, so the signal adds the
    # candidates' confidences up and the mode is the most likely one.
    text = data.decode("utf-8", errors="replace").strip()
    matches = identify(text, try_passwords=False).matches if len(text) < 4096 else []
    if matches:
        best = matches[0].format
        if best.hashcat is not None:
            values["hashcat_mode"] = best.hashcat
        if best.john:
            values["john_format"] = best.john
        total = min(0.95, sum(match.confidence for match in matches))
        names = ", ".join(f"{m.format.name} {m.confidence:.2f}" for m in matches[:3])
        signals.append(Signal(f"hash.{best.id}", total, f"looks like a hash ({names})"))

    # A ZipCrypto archive whose encrypted entry we can guess the plaintext for:
    # bkcrack can break it, and we can fill its three fiddly arguments ourselves.
    from ctfc.core.repair import zipcrypto_known_plaintext

    plan = zipcrypto_known_plaintext(data)
    if plan is not None:
        values["zip_entry"] = plan.entry
        values["bkcrack_offset"] = plan.offset
        values["bkcrack_plaintext"] = plan.plaintext_hex
        how = "stored" if plan.method == 0 else "deflated"
        signals.append(
            Signal(
                "zip.known_plaintext",
                0.9,
                f"encrypted entry {plan.entry!r} ({how}): its {len(plan.plaintext)}-byte "
                f"magic is known plaintext at offset {plan.offset}",
            )
        )

    candidates = auto_decode(data, flagset=flagset, top_n=1)
    if candidates and candidates[0].cyberchef:
        values["cyberchef_recipe"] = candidates[0].cyberchef
    values["cyberchef_data"] = data[:CYBERCHEF_DATA_LIMIT]
    return signals, values


def cyberchef_target(config_url: str, offline: bool, for_web: bool) -> tuple[str, str]:
    """Which CyberChef to open a result in: (base URL, note for the user).

    The base URL is "" when nothing is allowed (offline, and no embedded copy).
    Preference: the embedded copy, then the configured server, then - only when
    not offline, and with a warning - the public instance.
    """
    from ctfc.core.cyberchef import PUBLIC_URL, is_public

    if config_url.startswith("/"):  # the default: the embedded copy
        if embedded_cyberchef_installed():
            return cyberchef_base(config_url, for_web), ""
        missing = "the embedded CyberChef is not installed (run scripts/fetch_vendor.sh)"
        if offline:
            return "", missing + " and offline mode forbids the public instance"
        return PUBLIC_URL, f"{missing}: using the public instance - {THIRD_PARTY_WARNING}"
    if is_public(config_url):
        if offline:
            return "", "offline mode: the configured cyberchef_url is a public server"
        return config_url, THIRD_PARTY_WARNING
    return config_url, ""


def cyberchef_base(config_url: str, for_web: bool) -> str:
    """The address of the embedded CyberChef, as the caller can open it.

    The default `cyberchef_url` is relative ("/vendor/cyberchef/index.html"): fine
    in the web UI, which serves it, but meaningless in a terminal - there the
    vendored file is opened directly (CyberChef works from file://).
    """
    if for_web or not config_url.startswith("/"):
        return config_url
    return VENDOR_CYBERCHEF.as_uri()


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
    for piece in tool.command_template:
        # A value that *is* a whole argument and starts with "-" would be read by
        # the tool as an option ("--outfile=~/.bashrc" given as a wordlist).
        name = piece.strip("{}")
        if piece == "{" + name + "}" and str(values.get(name, "")).startswith("-"):
            return RunResult(
                command,
                -1,
                "",
                "",
                f"{piece} starts with '-': the tool would read it as an option, so ctfc "
                "refuses it (write ./name for a file whose name starts with '-')",
            )
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
            # A tool that asks a question (openssl without -pass prompts for a
            # password) must fail at once, not wait for a keyboard nobody uses.
            stdin=subprocess.DEVNULL,
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
