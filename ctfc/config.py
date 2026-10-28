"""User configuration, read from ~/.ctfc/config.toml (optional).

Example config.toml:

    offline = true
    flag_regexes = ['BZHCTF\\{.*?\\}', 'STHACK\\{.*?\\}']   # added to the defaults
    flag_prefixes = ["BZHCTF{"]                             # also searched in base64 form
    cyberchef_url = "http://127.0.0.1:8137/vendor/cyberchef/index.html"

Every key is optional. Unknown keys are reported as warnings, not errors.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".ctfc" / "config.toml"

# Generic "XXX{...}" flag shape, plus the team's usual format.
DEFAULT_FLAG_REGEXES = [
    r"[A-Za-z0-9_]{2,15}\{[^}\n]{4,}\}",
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
}


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
