"""Read a JWT, and say what is wrong with it.

A JSON Web Token is three base64url pieces joined by dots:

    eyJhbGciOiJIUzI1NiJ9 . eyJ1c2VyIjoiYm9iIn0 . 3sPc8y...
    \\_____ header _____/   \\____ payload ____/   \\_ signature _/

The header and the payload are **not encrypted** - base64 is not encryption - so
reading them needs no key at all. Everything interesting is therefore about the
signature, and the mistakes are always the same handful:

- **`alg: none`**: the token says it is unsigned, and a library that believes the
  token rather than its own configuration will accept anything. Change the
  payload, drop the signature, done.
- **a guessable HMAC secret**: `HS256` signs with a shared string, and that string
  is routinely `secret`, `password` or the app's name. Once it is known, any
  payload can be re-signed, so the token is fully forgeable.
- **a header that points at the key**: `jwk` carries a key *inside the token*,
  and `jku`/`x5u` fetch one over the network. A verifier that trusts either lets
  the attacker choose the key.
- **`kid` path traversal**: the key id is sometimes used as a file name.
- **RS256 / HS256 confusion**: if the server picks the algorithm from the header,
  an RSA-signed token can be replaced by an HMAC one signed with the *public* key.

So this module decodes the parts, tries the embedded password list against an
HMAC signature, and reports each of the above with the reason. It never contacts
anything and never runs any of the token's content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ctfc.core.datafiles import load_passwords

# A JWT is three dot-separated base64url groups; the signature may be empty.
TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$")
# The HMAC algorithms, and which hash each one means.
HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
# Claims that hold a time, and what they mean.
TIME_CLAIMS = {
    "exp": "expires at",
    "iat": "issued at",
    "nbf": "not valid before",
    "auth_time": "authenticated at",
}
MAX_SECRETS = 20_000


class JwtError(Exception):
    """The string is not a JWT we can read."""


def b64url_decode(text: str) -> bytes:
    """base64url without padding, as every JWT field is written."""
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise JwtError(f"{text[:20]}... is not valid base64url: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def looks_like_jwt(text: str) -> bool:
    return bool(TOKEN_SHAPE.match(text.strip()))


@dataclass
class Jwt:
    """A parsed token."""

    header: dict
    payload: dict
    signature: bytes
    signing_input: bytes  # exactly the bytes that were signed: "header.payload"
    raw: str

    @property
    def algorithm(self) -> str:
        return str(self.header.get("alg", "")).strip()


def parse(token: str) -> Jwt:
    """Split a token and decode its header and payload."""
    text = token.strip()
    parts = text.split(".")
    if len(parts) != 3:
        raise JwtError(
            f"a JWT has three dot-separated parts, this has {len(parts)} "
            "(a JWE has five, and cannot be read without the key)"
        )
    header_raw, payload_raw, signature_raw = parts
    try:
        header = json.loads(b64url_decode(header_raw))
        payload = json.loads(b64url_decode(payload_raw))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Three base64url groups is a shape many strings fit by accident, so a
        # failure here usually means it was never a JWT.
        raise JwtError(f"the header or payload is not JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("the header and payload must both be JSON objects")
    return Jwt(
        header=header,
        payload=payload,
        signature=b64url_decode(signature_raw) if signature_raw else b"",
        signing_input=f"{header_raw}.{payload_raw}".encode(),
        raw=text,
    )


def sign(signing_input: bytes, secret: bytes, algorithm: str) -> bytes:
    """The HMAC signature a token with this algorithm should carry."""
    digest = HMAC_HASHES.get(algorithm.upper())
    if digest is None:
        raise JwtError(f"{algorithm} is not an HMAC algorithm")
    return hmac.new(secret, signing_input, digest).digest()


def crack_hmac(token: Jwt, secrets=None) -> bytes | None:
    """Find the shared secret by trying a list of candidates against the signature.

    This is a verification, not a guess: the recomputed HMAC either equals the
    token's own signature or it does not, so a hit is certain.
    """
    if token.algorithm.upper() not in HMAC_HASHES or not token.signature:
        return None
    candidates = list(secrets) if secrets is not None else list(load_passwords())
    for secret in candidates[:MAX_SECRETS]:
        if hmac.compare_digest(sign(token.signing_input, secret, token.algorithm), token.signature):
            return secret
    return None


def forge(token: Jwt, payload: dict, secret: bytes | None = None) -> str:
    """Build a token with a new payload: unsigned, or re-signed with `secret`."""
    header = dict(token.header)
    if secret is None:
        header["alg"] = "none"
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    head = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    signing_input = f"{b64url_encode(head)}.{b64url_encode(body)}".encode()
    if secret is None:
        return signing_input.decode() + "."
    signature = sign(signing_input, secret, header.get("alg", "HS256"))
    return f"{signing_input.decode()}.{b64url_encode(signature)}"


@dataclass
class Finding:
    """One thing worth knowing about the token."""

    rule: str
    what: str
    severity: str  # "high" | "medium" | "info"
    next_step: str = ""


@dataclass
class JwtReport:
    """What the token says and what can be done with it."""

    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    algorithm: str = ""
    signature_bytes: int = 0
    secret: bytes | None = None
    forged: str = ""
    times: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    python: str = ""

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "payload": self.payload,
            "algorithm": self.algorithm,
            "signature_bytes": self.signature_bytes,
            "secret": None if self.secret is None else self.secret.decode("utf-8", "replace"),
            "forged": self.forged,
            "times": list(self.times),
            "findings": [
                {
                    "rule": finding.rule,
                    "what": finding.what,
                    "severity": finding.severity,
                    "next_step": finding.next_step,
                }
                for finding in self.findings
            ],
            "flags": list(self.flags),
            "python": self.python,
        }


def _readable_time(value: object) -> str | None:
    """A numeric claim read as a Unix timestamp, or None if it is not one."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    # Anything outside 2001..2286 is not a seconds-since-epoch claim.
    if not 1_000_000_000 <= value <= 9_999_999_999:
        return None
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def analyse(token: str, flagset=None, secrets=None, try_secrets: bool = True) -> JwtReport:
    """Read the token and report the weaknesses it carries."""
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    parsed = parse(token)
    report = JwtReport(
        header=parsed.header,
        payload=parsed.payload,
        algorithm=parsed.algorithm,
        signature_bytes=len(parsed.signature),
    )

    algorithm = parsed.algorithm.upper()
    if algorithm in ("NONE", "") or not parsed.signature:
        report.findings.append(
            Finding(
                rule="jwt.alg_none",
                what=(
                    f"alg is {parsed.algorithm!r} and the signature is "
                    f"{len(parsed.signature)} bytes: the token is unsigned"
                ),
                severity="high",
                next_step="change the payload and send it with an empty third part",
            )
        )
        report.forged = forge(parsed, {**parsed.payload, "admin": True})
    elif algorithm in HMAC_HASHES:
        report.findings.append(
            Finding(
                rule="jwt.hmac",
                what=f"{parsed.algorithm} signs with a shared secret, so the secret is guessable",
                severity="info",
                next_step="if the secret is weak, any payload can be re-signed",
            )
        )
        if try_secrets:
            found = crack_hmac(parsed, secrets)
            if found is not None:
                report.secret = found
                report.findings.append(
                    Finding(
                        rule="jwt.weak_secret",
                        what=f"the signing secret is {found.decode('utf-8', 'replace')!r}",
                        severity="high",
                        next_step="the token is now fully forgeable: re-sign any payload",
                    )
                )
                report.forged = forge(parsed, {**parsed.payload, "admin": True}, found)
    elif algorithm.startswith(("RS", "ES", "PS")):
        report.findings.append(
            Finding(
                rule="jwt.asymmetric",
                what=f"{parsed.algorithm} is signed with a private key, which we do not have",
                severity="info",
                next_step=(
                    "if the server picks the algorithm from the header, try the HS256 "
                    "confusion: re-sign with alg=HS256 using the PUBLIC key as the HMAC secret"
                ),
            )
        )

    # Header fields that let the token choose its own key.
    if "jwk" in parsed.header:
        report.findings.append(
            Finding(
                rule="jwt.jwk_in_header",
                what="the header carries a jwk: the token supplies its own verification key",
                severity="high",
                next_step="replace the jwk with your own key pair and re-sign",
            )
        )
    for field_name in ("jku", "x5u"):
        if field_name in parsed.header:
            report.findings.append(
                Finding(
                    rule=f"jwt.{field_name}",
                    what=f"the header's {field_name} points at a key to fetch over the network",
                    severity="high",
                    next_step="host your own key set there if the server fetches it",
                )
            )
    kid = parsed.header.get("kid")
    if isinstance(kid, str) and ("/" in kid or ".." in kid or "\\" in kid):
        report.findings.append(
            Finding(
                rule="jwt.kid_path",
                what=f"kid looks like a path ({kid!r}): it may be read as a file name",
                severity="high",
                next_step="try kid=/dev/null with an empty secret, or a path traversal",
            )
        )

    for claim, meaning in TIME_CLAIMS.items():
        readable = _readable_time(parsed.payload.get(claim))
        if readable:
            report.times.append(f"{claim} ({meaning}): {readable}")
    expiry = parsed.payload.get("exp")
    if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
        if expiry < datetime.now(UTC).timestamp():
            report.findings.append(
                Finding(
                    rule="jwt.expired",
                    what="exp is in the past: this token has expired",
                    severity="info",
                    next_step="push exp forward once you can re-sign",
                )
            )

    body = json.dumps(parsed.payload).encode()
    report.flags = [hit.text for hit in find_flags(body, flagset)]
    report.python = _snippet(parsed, report.secret)
    report.findings.sort(key=lambda finding: {"high": 0, "medium": 1, "info": 2}[finding.severity])
    return report


def _snippet(token: Jwt, secret: bytes | None) -> str:
    """A standalone script that re-signs a changed payload (teaching layer)."""
    if secret is None:
        return (
            "# alg=none: there is nothing to sign. Keep the third part empty.\n"
            "import base64, json\n"
            "\n"
            "def b64(data):\n"
            '    return base64.urlsafe_b64encode(data).decode().rstrip("=")\n'
            "\n"
            'header = {"alg": "none", "typ": "JWT"}\n'
            f"payload = {token.payload!r}\n"
            'payload["admin"] = True\n'
            'dump = lambda value: json.dumps(value, separators=(",", ":")).encode()\n'
            'print(b64(dump(header)) + "." + b64(dump(payload)) + ".")\n'
        )
    return (
        "# The secret is known, so any payload can be signed.\n"
        "import base64, hashlib, hmac, json\n"
        "\n"
        "def b64(data):\n"
        '    return base64.urlsafe_b64encode(data).decode().rstrip("=")\n'
        "\n"
        f"secret = {secret!r}\n"
        f"header = {token.header!r}\n"
        f"payload = {token.payload!r}\n"
        'payload["admin"] = True\n'
        'dump = lambda value: json.dumps(value, separators=(",", ":")).encode()\n'
        'signing_input = (b64(dump(header)) + "." + b64(dump(payload))).encode()\n'
        "signature = hmac.new(secret, signing_input, hashlib.sha256).digest()\n"
        'print(signing_input.decode() + "." + b64(signature))\n'
    )
