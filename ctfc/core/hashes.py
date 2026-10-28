"""Identify a hash, then print the command that cracks it.

ctfc deliberately does **not** crack hashes (CLAUDE.md section 2): hashcat and
john are far better at it than anything that could be written here. What is
genuinely useful during a CTF is the step before: *which format is this, and what
is the hashcat mode number?*

Identification uses three signals, from strongest to weakest:

1. a **prefix** (`$2y$`, `$6$`, `$krb5tgs$`, `{SSHA}`): nearly certain,
2. a **full-shape regex** (`$mysqlna$<40 hex>*<40 hex>`, `user::domain:...`),
3. the **length and charset** alone: 32 hex characters is MD5, but also NTLM,
   MD4, MD2 and RIPEMD-128. There is no way to tell them apart from the string,
   so ctfc lists them all, ranked, and says why.

The table lives in `ctfc/data/hashcat_modes.toml` - one entry per format, easy to
extend. The only "cracking" done here is a tiny offline dictionary check against
the embedded password list, for the unsalted formats where that is instant.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache

from ctfc.core.datafiles import load_passwords, load_toml

# Unsalted formats we can test against the embedded password list ourselves.
# Anything salted or iterated is left to hashcat: that is the whole point.
INSTANT_FORMATS: dict[str, object] = {
    "md5": lambda password: hashlib.md5(password).hexdigest(),
    "sha1": lambda password: hashlib.sha1(password).hexdigest(),
    "sha224": lambda password: hashlib.sha224(password).hexdigest(),
    "sha256": lambda password: hashlib.sha256(password).hexdigest(),
    "sha384": lambda password: hashlib.sha384(password).hexdigest(),
    "sha512": lambda password: hashlib.sha512(password).hexdigest(),
    "md4": lambda password: _try_hash("md4", password),
    "ntlm": lambda password: _try_hash("md4", password.decode().encode("utf-16-le")),
    "sha3_256": lambda password: hashlib.sha3_256(password).hexdigest(),
    "ripemd160": lambda password: _try_hash("ripemd160", password),
    "whirlpool": lambda password: _try_hash("whirlpool", password),
}

CHARSETS = {
    "hex": re.compile(r"^[0-9a-f]+$"),
    "hex_upper": re.compile(r"^[0-9A-F]+$"),
    "base64": re.compile(r"^[A-Za-z0-9+/]+={0,2}$"),
    "any": re.compile(r"^.+$", re.DOTALL),
}


def _try_hash(name: str, data: bytes) -> str | None:
    """Hash with an algorithm OpenSSL may or may not provide (md4, whirlpool)."""
    try:
        return hashlib.new(name, data).hexdigest()
    except ValueError:
        return None


@dataclass(frozen=True)
class HashFormat:
    """One row of data/hashcat_modes.toml."""

    id: str
    name: str
    confidence: float
    hashcat: int | None = None
    john: str | None = None
    prefix: str = ""
    regex: re.Pattern[str] | None = None
    length: int | None = None
    charset: str = "any"
    notes: str = ""
    example: str = ""

    def hashcat_command(self, filename: str = "hash.txt") -> str | None:
        if self.hashcat is None:
            return None
        return (
            f"hashcat -m {self.hashcat} -a 0 {filename} /usr/share/wordlists/rockyou.txt "
            "-O --status"
        )

    def john_command(self, filename: str = "hash.txt") -> str | None:
        if not self.john:
            return None
        return f"john --format={self.john} --wordlist=/usr/share/wordlists/rockyou.txt {filename}"


@dataclass
class Match:
    """One possible format for the hash we were given."""

    format: HashFormat
    confidence: float
    reasons: list[str] = field(default_factory=list)
    cracked: str | None = None  # filled when the embedded list happens to contain it

    def to_dict(self) -> dict:
        return {
            "id": self.format.id,
            "name": self.format.name,
            "confidence": round(self.confidence, 3),
            "hashcat_mode": self.format.hashcat,
            "john_format": self.format.john,
            "hashcat": self.format.hashcat_command(),
            "john": self.format.john_command(),
            "notes": self.format.notes,
            "reasons": list(self.reasons),
            "cracked": self.cracked,
        }


@dataclass
class HashReport:
    """What ctfc thinks this string is."""

    value: str
    matches: list[Match] = field(default_factory=list)
    facts: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "matches": [match.to_dict() for match in self.matches],
            "facts": self.facts,
            "notes": list(self.notes),
        }


@lru_cache(maxsize=1)
def load_formats() -> tuple[HashFormat, ...]:
    """Parse and compile the format table once per process."""
    formats = []
    for row in load_toml("hashcat_modes.toml")["hash"]:
        pattern = row.get("regex")
        formats.append(
            HashFormat(
                id=row["id"],
                name=row["name"],
                confidence=float(row["confidence"]),
                hashcat=row.get("hashcat"),
                john=row.get("john"),
                prefix=row.get("prefix", ""),
                regex=re.compile(pattern) if pattern else None,
                length=row.get("length"),
                charset=row.get("charset", "any"),
                notes=row.get("notes", ""),
                example=row.get("example", ""),
            )
        )
    return tuple(formats)


def identify(value: str, try_passwords: bool = True) -> HashReport:
    """Identify `value` and rank the possible formats, best first."""
    cleaned = value.strip()
    report = HashReport(value=cleaned)
    if not cleaned:
        report.notes.append("nothing to identify: the input is empty")
        return report

    charset = _charset_of(cleaned)
    report.facts = [
        ("length", f"{len(cleaned)} characters"),
        ("charset", charset),
    ]
    if ":" in cleaned:
        report.facts.append(("contains ':'", "maybe hash:salt, or a dump line (user:hash:...)"))
    if cleaned.startswith("$"):
        fields = cleaned.split("$")
        report.facts.append(("$ fields", f"{len(fields) - 1}: {'$'.join(fields[:2])}$..."))

    for candidate in load_formats():
        match = _match_format(cleaned, candidate, charset)
        if match is not None:
            report.matches.append(match)

    report.matches.sort(key=lambda match: -match.confidence)

    if not report.matches:
        report.notes.append(
            "no known format matches. Is it really a hash? Try `ctfc detect` (it may "
            "be base64 or hex of something else), and check hashcat's example list: "
            "https://hashcat.net/wiki/doku.php?id=example_hashes"
        )
    elif len({match.format.length for match in report.matches}) == 1 and len(report.matches) > 1:
        report.notes.append(
            "several formats have exactly this shape: the string alone cannot tell "
            "them apart, so the context decides (where did you find it?)"
        )

    _explain_dump_line(report)
    if try_passwords:
        _try_the_password_list(report)
    return report


# The LM / NT hash of an empty password: seen on every disabled account.
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _explain_dump_line(report: HashReport) -> None:
    """A `user:rid:lm:nt:::` line holds the hash to crack in its 4th field."""
    if not any(match.format.id == "pwdump" for match in report.matches):
        return
    user, rid, lm, nt = report.value.split(":")[:4]
    report.facts.append(("user", f"{user or '(no name)'} (RID {rid})"))
    report.facts.append(("NT hash", nt))
    report.notes.append(f"the hash to crack is the 4th field: {nt}")
    if nt.lower() == EMPTY_NT:
        report.notes.append(
            "that NT hash is the hash of an EMPTY password: this account has no "
            "password, nothing to crack (a deleted or disabled account, usually)"
        )
    if lm.lower() != EMPTY_LM:
        report.notes.append(
            f"the LM half is not the empty placeholder ({lm}): LM is much weaker, "
            "crack it first with hashcat -m 3000"
        )


def _charset_of(value: str) -> str:
    for name in ("hex", "hex_upper", "base64"):
        if CHARSETS[name].match(value):
            return name
    return "mixed/other"


def _match_format(value: str, candidate: HashFormat, charset: str) -> Match | None:
    """Does `value` look like this format? Returns the match with its reasons."""
    reasons: list[str] = []
    confidence = candidate.confidence

    if candidate.prefix:
        if not value.startswith(candidate.prefix):
            return None
        reasons.append(f"starts with {candidate.prefix!r}, which is specific to this format")
        return Match(format=candidate, confidence=confidence, reasons=reasons)

    if candidate.regex is not None:
        if not candidate.regex.fullmatch(value):
            return None
        reasons.append("the whole string matches this format's shape")
        return Match(format=candidate, confidence=confidence, reasons=reasons)

    if candidate.length is not None:
        if len(value) != candidate.length:
            return None
        expected = CHARSETS.get(candidate.charset, CHARSETS["any"])
        if not expected.match(value):
            return None
        reasons.append(f"{candidate.length} characters of {candidate.charset}")
        return Match(format=candidate, confidence=confidence, reasons=reasons)

    return None


def _try_the_password_list(report: HashReport) -> None:
    """A free try: is it one of the 10000 embedded passwords?

    Only for unsalted formats, where one hash per password is enough. This is not
    a cracker, it is the thirty-second check you would do by hand anyway.
    """
    targets = {
        match.format.id: match for match in report.matches if match.format.id in INSTANT_FORMATS
    }
    if not targets:
        return
    lowered = report.value.lower()
    for password in load_passwords():
        for format_id, match in targets.items():
            compute = INSTANT_FORMATS[format_id]
            try:
                digest = compute(password)  # type: ignore[operator]
            except (ValueError, UnicodeDecodeError):
                continue
            if digest is not None and digest == lowered:
                match.cracked = password.decode("utf-8", errors="replace")
                match.confidence = 1.0
                match.reasons.insert(
                    0,
                    f'found in the embedded password list: the password is "{match.cracked}"',
                )
                report.matches.sort(key=lambda item: -item.confidence)
                report.notes.append(
                    f"cracked offline with the embedded list ({match.format.name}): "
                    f'"{match.cracked}"'
                )
                return
