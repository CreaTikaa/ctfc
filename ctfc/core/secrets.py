"""Point at the credentials written in clear in a config, a script or a dump.

Decoding a backup often ends on a config file - a pfSense XML, an `.env`, a JSON,
an `ini` - where one value out of hundreds of lines is the answer: a shared
secret, an API key, a password. This module finds those values by the name that
sits next to them, in the shapes configs actually use:

    password = hunter2            api_key: 4f2ad91c
    <secret>Y3t4plBar</secret>    "aws_secret_key": "wJalrXUtn..."
    RADIUS_SECRET="s3cr3t"        token  :  eyJhbGci...

It only reads. Nothing is decoded, tried or sent anywhere.

One deduction is made, because challenge authors lean on it: when the text around
a secret mentions a rotation (the words rotation / rotate / rot13 / caesar /
shift), the ROT13 of each short alphabetic secret is shown beside it. That is how
the pfSense challenge hid its RADIUS secret - "rotation policy" in a comment, the
real secret ROT13'd.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Names that announce a credential (matched case-insensitively, as a whole word).
NAME = (
    r"(?:[a-z0-9_]*_)?"  # an optional prefix: aws_, radius_, db_...
    r"(?:secret|password|passwd|pass|passphrase|api[_-]?key|apikey|auth[_-]?token|"
    r"token|access[_-]?key|private[_-]?key|credential|client[_-]?secret|key)"
)
# A value: a quoted string, an XML text node, or a bare run up to whitespace/comment.
VALUE = r"""(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"'<>#;]{3,256}))"""

# key = value  |  key: value   (ini, env, yaml, properties, shell)
ASSIGN_RE = re.compile(rf"(?im)^[ \t]*({NAME})[ \t]*[:=][ \t]*{VALUE}")
# <key>value</key>  (XML / HTML config)
XML_RE = re.compile(rf"(?is)<({NAME})>\s*([^<\n]{{1,256}}?)\s*</\1>")
# "key": "value"  (JSON, also matched by ASSIGN_RE but this keeps JSON clean)
JSON_RE = re.compile(rf'(?i)"({NAME})"\s*:\s*"([^"\n]{{1,256}})"')

# Words that say "I rotated the real value".
ROTATION_RE = re.compile(r"(?i)\brot(?:ation|ate|13)?\b|\bcaesar\b|\bshift(?:ed)?\b")
# Placeholders that are not real secrets: don't cry wolf.
PLACEHOLDERS = {
    "password",
    "changeme",
    "example",
    "your_password",
    "your-secret",
    "xxx",
    "none",
    "null",
    "true",
    "false",
    "enabled",
    "disabled",
    "yes",
    "no",
    "redacted",
    "<password>",
    "...",
    "secret",
    "todo",
    "placeholder",
}

_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


@dataclass
class Secret:
    """One credential found in the text, with its name and where it is."""

    name: str
    value: str
    line: int
    kind: str  # "assignment", "xml", "json"
    rot13: str = ""  # the ROT13 reading, when the text hints at a rotation

    def to_dict(self) -> dict:
        data = {"name": self.name, "value": self.value, "line": self.line, "kind": self.kind}
        if self.rot13:
            data["rot13"] = self.rot13
        return data


def _plausible(value: str) -> bool:
    """A real-looking secret: not a placeholder, not an obvious non-secret."""
    stripped = value.strip()
    if len(stripped) < 3 or len(stripped) > 256:
        return False
    if stripped.lower() in PLACEHOLDERS:
        return False
    if stripped.isdigit():  # a port, a timeout, a count
        return False
    return True


def _line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def find_secrets(data: bytes) -> list[Secret]:
    """Every credential written in clear in `data`, in order, without duplicates.

    `data` is the already-decoded text (a config, a script). Binary input yields
    nothing: this is meant to run on what came *out* of a decoding chain.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    # A config is text; refuse to scan a binary blob that merely contains a word.
    printable = sum(32 <= ord(ch) < 127 or ch in "\t\n\r" for ch in text[:4096])
    if not text or printable < 0.9 * len(text[:4096]):
        return []

    rotates = bool(ROTATION_RE.search(text))
    found: list[Secret] = []
    seen: set[tuple[str, str]] = set()

    def keep(name: str, value: str, position: int, kind: str) -> None:
        value = value.strip()
        if not _plausible(value) or (name.lower(), value) in seen:
            return
        seen.add((name.lower(), value))
        secret = Secret(name=name, value=value, line=_line_of(text, position), kind=kind)
        if rotates and value.isascii() and any(ch.isalpha() for ch in value):
            rotated = value.translate(_ROT13)
            if rotated != value:
                secret.rot13 = rotated
        found.append(secret)

    for match in XML_RE.finditer(text):
        keep(match.group(1), match.group(2), match.start(), "xml")
    for match in JSON_RE.finditer(text):
        keep(match.group(1), match.group(2), match.start(), "json")
    for match in ASSIGN_RE.finditer(text):
        value = next(group for group in match.groups()[1:] if group is not None)
        keep(match.group(1), value, match.start(), "assignment")

    found.sort(key=lambda secret: secret.line)
    return found
