"""User configuration, read from ~/.ctfc/config.toml (optional).

Example config.toml:

    offline = true
    flag_regexes = ['BZHCTF\\{.*?\\}', 'STHACK\\{.*?\\}']   # added to the defaults
    flag_prefixes = ["BZHCTF{"]                             # also searched in base64 form
    cyberchef_url = "http://127.0.0.1:8137/vendor/cyberchef/index.html"
    wordlist = "~/Documents/rockyou.txt"     # printed into hashcat / stegseek commands

    [tool_paths]                             # programs behind a shell alias
    vol = ["python3", "/home/me/volatility3/vol.py"]
    stegsolve = ["java", "-jar", "/home/me/stegsolve.jar"]

Every key is optional. Unknown keys are reported as warnings, not errors.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".ctfc" / "config.toml"

# Generic "XXX{...}" flag shape, plus the team's usual format.
# The body is capped at 120 characters (a longer one is never kept as a flag,
# see flags.looks_like_flag): unbounded, the search turned quadratic on binary
# output with many "{" and no "}" or newline - 8 s per 400 KB XOR guess.
DEFAULT_FLAG_REGEXES = [
    r"[A-Za-z0-9_]{2,15}\{[^}\n]{4,120}\}",
    r"CYBN\{[^}\n]*\}",
]

# Flag prefixes that are also looked for in base64 form (e.g. "Q1lCTn" = base64 of "CYBN").
DEFAULT_FLAG_PREFIXES = ["CYBN{"]


class ConfigError(ValueError):
    """Raised when the config file is invalid. The message says what to fix."""


@dataclass
class Config:
    """All settings, with their defaults. See the module docstring for the file format."""

    offline: bool = False  # True: never contact a third party (CyberChef/dcode/factordb)
    flag_regexes: list[str] = field(default_factory=lambda: list(DEFAULT_FLAG_REGEXES))
    flag_prefixes: list[str] = field(default_factory=lambda: list(DEFAULT_FLAG_PREFIXES))
    cyberchef_url: str = "/vendor/cyberchef/index.html"  # embedded copy by default
    suggest_threshold: float = 0.7  # external tools are suggested only above this confidence
    max_suggestions: int = 3
    max_upload_mb: int = 50  # web UI upload cap
    web_host: str = "127.0.0.1"
    web_port: int = 8137
    auto_max_depth: int = 6  # how many decoding layers `ctfc auto` peels at most
    auto_budget: int = 2000  # how many decode attempts `ctfc auto` may make
    top_n: int = 10  # how many candidates are shown
    sessions_dir: str = ""  # where sessions live (default ~/.ctfc/sessions)
    # The wordlist printed into the hashcat / stegseek / aircrack commands.
    # "" = the first of WORDLIST_GUESSES that exists on this machine.
    wordlist: str = ""
    # Programs that are not on the PATH under their own name (a shell alias is
    # invisible to ctfc): program -> the argument list that starts it, e.g.
    # vol = ["python3", "/home/me/volatility3/vol.py"]
    tool_paths: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)  # filled by load_config


# Keys that may appear in config.toml, with the type they must have.
_KEY_TYPES: dict[str, type] = {
    "offline": bool,
    "flag_regexes": list,
    "flag_prefixes": list,
    "cyberchef_url": str,
    "suggest_threshold": float,
    "max_suggestions": int,
    "max_upload_mb": int,
    "web_host": str,
    "web_port": int,
    "auto_max_depth": int,
    "auto_budget": int,
    "top_n": int,
    "sessions_dir": str,
    "wordlist": str,
    "tool_paths": dict,
}

# Where a wordlist usually lives, tried in order when `wordlist` is not set.
WORDLIST_GUESSES = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "~/rockyou.txt",
    "~/Documents/rockyou.txt",
    "~/wordlists/rockyou.txt",
)


def find_wordlist(config: Config) -> str:
    """The wordlist to print in commands: the configured one, or the first found, or ""."""
    for candidate in ([config.wordlist] if config.wordlist else []) + list(WORDLIST_GUESSES):
        path = Path(candidate).expanduser()
        if path.is_file():
            return str(path)
    return ""


def load_config(path: Path | None = None) -> Config:
    """Read the config file if it exists, otherwise return the defaults."""
    config = Config()
    path = path or DEFAULT_CONFIG_PATH
    if not path.is_file():
        return config

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML ({exc})") from exc

    for key, value in raw.items():
        expected = _KEY_TYPES.get(key)
        if expected is None:
            config.warnings.append(f"{path}: unknown key '{key}' ignored")
            continue
        if expected is float and isinstance(value, int):
            value = float(value)
        if not isinstance(value, expected):
            raise ConfigError(f"{path}: '{key}' must be a {expected.__name__}, got {value!r}")
        if key == "flag_regexes":
            # User regexes are added to the defaults, not replacing them.
            config.flag_regexes = _unique(config.flag_regexes + [str(v) for v in value])
        elif key == "flag_prefixes":
            config.flag_prefixes = _unique(config.flag_prefixes + [str(v) for v in value])
        elif key == "tool_paths":
            for program, argv in value.items():
                if isinstance(argv, str):
                    argv = [argv]
                if not isinstance(argv, list) or not argv:
                    raise ConfigError(
                        f"{path}: tool_paths.{program} must be a list of arguments, "
                        f'e.g. ["python3", "/path/to/vol.py"]'
                    )
                config.tool_paths[str(program)] = [str(part) for part in argv]
        else:
            setattr(config, key, value)

    for pattern in config.flag_regexes:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"{path}: flag regex {pattern!r} is invalid ({exc})") from exc
    return config


def _unique(items: list[str]) -> list[str]:
    """Remove duplicates while keeping the order."""
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


# ---------------------------------------------------------------------------
# Writing the config back (stdlib reads TOML but does not write it)
# ---------------------------------------------------------------------------
#
# `ctfc config` edits the file for the user (add the CTF's flag format, point at
# a wordlist) rather than making him hand-write TOML under time pressure. Only the
# few scalar / list / string->list-table shapes this project uses are serialised;
# anything else raises rather than writing something it cannot read back.


def _toml_str(value: str) -> str:
    """One TOML string. A literal '...' when it can hold the value (no single
    quote, no newline) - which keeps regex backslashes untouched - else a basic
    "..." with the two characters that must be escaped."""
    if "'" not in value and "\n" not in value:
        return f"'{value}'"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_value(value: object) -> str:
    """A scalar or a list of strings, as TOML. Tables are handled separately."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _toml_str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_str(str(item)) for item in value) + "]"
    raise ConfigError(f"cannot serialise {value!r} to TOML")


def dumps_config(data: dict) -> str:
    """Serialise a config dict to TOML text, tables (e.g. tool_paths) last."""
    lines = ["# ctfc configuration - see ctfc/config.py for every key.", ""]
    for key, value in data.items():
        if not isinstance(value, dict):
            lines.append(f"{key} = {_toml_value(value)}")
    for key, value in data.items():
        if isinstance(value, dict):
            lines += ["", f"[{key}]"]
            for name, argv in value.items():
                lines.append(f"{name} = {_toml_value(argv)}")
    return "\n".join(lines) + "\n"


def read_raw_config(path: Path | None = None) -> dict:
    """The config file as a plain dict (the user's own keys), or {} if absent."""
    path = path or DEFAULT_CONFIG_PATH
    if not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML ({exc})") from exc


def write_raw_config(data: dict, path: Path | None = None) -> Path:
    """Write a config dict back to the file, creating ~/.ctfc/ if needed."""
    path = path or DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_config(data), encoding="utf-8")
    return path


def flag_to_prefix_and_regex(flag: str) -> tuple[str, str]:
    """From "SHARKY{" (or "SHARKY", or "SHARKY{...}") -> ("SHARKY{", regex).

    The regex matches that prefix with any one-line body, and the prefix is what
    is also searched in base64 form. The name is escaped so odd characters in it
    (a dash, a dot) cannot break the pattern."""
    name = flag.strip()
    if "{" in name:
        name = name[: name.index("{")]
    name = name.strip()
    if not name:
        raise ConfigError("a flag format needs a name, e.g. SHARKY{ or SHARKY")
    prefix = name + "{"
    regex = re.escape(name) + r"\{[^}\n]{1,120}\}"
    return prefix, regex
