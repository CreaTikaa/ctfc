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
    if name == "md4":
        # Modern OpenSSL drops MD4, which would leave NTLM (the SAM-dump hash)
        # identifiable but never crackable. Our own MD4 needs no OpenSSL.
        from ctfc.core.md4 import md4

        return md4(data).hex()
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
    # What the password opened, for the hashes that carry the encrypted data
    # itself (zip2john's $pkzip2$): the file, and the flags found in it.
    recovered: bytes | None = None
    recovered_name: str = ""
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        answer = {
            "value": self.value,
            "matches": [match.to_dict() for match in self.matches],
            "facts": self.facts,
            "notes": list(self.notes),
            "flags": list(self.flags),
        }
        if self.recovered is not None:
            answer["recovered_name"] = self.recovered_name
            answer["recovered_hex"] = self.recovered.hex()
            answer["recovered_text"] = self.recovered.decode("utf-8", errors="replace")
        return answer


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


def identify(
    value: str, try_passwords: bool = True, passwords: tuple[bytes, ...] | None = None
) -> HashReport:
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
    _note_length_extension(report)
    _explain_pkzip(report, passwords if try_passwords else ())
    if try_passwords:
        _try_the_password_list(report, passwords)
    return report


def _explain_pkzip(report: HashReport, passwords: tuple[bytes, ...] | None) -> None:
    """A zip2john line: read its fields, try the passwords, decrypt the file from it.

    The only "hash" that is cracked here beyond the instant ones: each try costs
    12 decrypted bytes (see `zipcrypto.py`), about 100000 passwords a second,
    and a hit gives the file itself - not just a password to type somewhere.
    """
    match = next((match for match in report.matches if match.format.id == "pkzip2"), None)
    if match is None:
        return
    from ctfc.core import pkzip2
    from ctfc.core.flags import find_flags

    parsed = pkzip2.parse(report.value)
    if parsed is None:
        report.notes.append("it starts like a zip2john line but its fields do not parse")
        return
    entry = parsed.entries[0]
    report.facts.append(("entry", parsed.name))
    report.facts.append(("entries in the line", str(len(parsed.entries))))
    report.facts.append(("compression", {0: "stored", 8: "deflate"}.get(entry.compression, "?")))
    if entry.full:
        report.facts.append(("CRC-32 / size", f"{entry.crc:08x} / {entry.size} bytes"))
    mode = pkzip2.hashcat_mode(parsed)
    report.notes.append(
        f"hashcat mode for this line: -m {mode}; hashcat wants only the part from "
        "$pkzip2$ to $/pkzip2$ (`cut -d: -f2 hash.txt > h`)"
    )
    report.notes.extend(parsed.notes)
    if any(e.full for e in parsed.entries):
        report.notes.append(
            "the whole encrypted entry is in the line: the ZIP can be rebuilt from it "
            "(`ctfc hash <file> --out rebuilt.zip`), no archive needed"
        )
    if passwords is not None and not passwords:
        return  # --no-passwords
    from ctfc.core.datafiles import load_passwords

    source = "your wordlist" if passwords else "the embedded password list"
    found = pkzip2.crack(parsed, passwords or load_passwords())
    if found is None:
        report.notes.append(
            f"not in {source}: try `--wordlist rockyou.txt --wordlist-limit 20000000` "
            f"(about 100000 a second here) or hashcat -m {mode}"
        )
        return
    password = found.password.decode("utf-8", errors="replace")
    match.cracked = password
    match.confidence = 1.0
    match.reasons.insert(0, f'found in {source}: the password is "{password}"')
    if found.plaintext is None:
        report.notes.append(
            f'"{password}" passes the header check (1 wrong password in 256 does too: '
            "confirm it on the real archive)"
        )
        return
    report.recovered = found.plaintext
    report.recovered_name = parsed.name
    report.flags = [hit.text for hit in find_flags(found.plaintext) if hit.strength > 0.45]
    report.notes.append(
        f'cracked with {source} after {found.tried} tries: "{password}" decrypts '
        f"{parsed.name} and its CRC-32 checks out"
    )


# A plain Merkle-Damgard digest can be *extended*, which beats cracking it when the
# hash is used as a signature: H(secret || message) is forgeable without the secret.
EXTENDABLE = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}


def _note_length_extension(report: HashReport) -> None:
    """Point at `ctfc extend` when the hash is one that length extension breaks."""
    names = {match.format.id for match in report.matches}
    for algo, length in EXTENDABLE.items():
        if algo in names and len(report.value) == length:
            report.notes.append(
                f"if this digest signs a message (a MAC of the form {algo}(secret || data), "
                "a token, a cookie), do not crack it: extend it. "
                f"`ctfc extend {report.value[:8]}... --data <message> --append <what you want>` "
                "forges a valid digest for a longer message without the secret"
            )
            return


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


def _try_the_password_list(report: HashReport, passwords: tuple[bytes, ...] | None = None) -> None:
    """A free try: is it one of the 10000 embedded passwords (or a given list)?

    Only for unsalted formats, where one hash per password is enough. This is not
    a cracker, it is the thirty-second check you would do by hand anyway - and
    `--wordlist` only widens that check, which is why the report still prints
    the hashcat command either way.
    """
    targets = {
        match.format.id: match for match in report.matches if match.format.id in INSTANT_FORMATS
    }
    if not targets:
        return
    lowered = report.value.lower()
    # Say which list it was: "the embedded list" for a password that came from
    # the user's own rockyou would send them looking in the wrong place.
    source = "your wordlist" if passwords else "the embedded password list"
    for password in passwords or load_passwords():
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
                    f'found in {source}: the password is "{match.cracked}"',
                )
                report.matches.sort(key=lambda item: -item.confidence)
                report.notes.append(
                    f'cracked offline with {source} ({match.format.name}): "{match.cracked}"'
                )
                return
