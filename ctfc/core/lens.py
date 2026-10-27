"""Code Lens: read a script and say what it does to the data, without running it.

This is the most useful tool of the whole project for forensics: when you have
the encryptor (a dropper, an obfuscated script, a "crypter"), you do not have to
guess the cipher or the key layout. You mirror what the code does.

**Nothing here ever executes the analysed file** (CLAUDE.md hard rule 3). No
`eval`, no `exec`, no `pickle`, no import of the sample. Python is read with the
standard `ast` module; the other languages with a table of regex rules
(`data/lens_rules.toml`). Values are recovered by *constant folding*: we rebuild
`"ab" + "cd"` or `bytes([0x41, 0x42])` ourselves, by hand, the way a human reads
them.

What comes out:

- the **language** and a plain summary: "decodes a base64 blob, inflates it with
  zlib, XORs it with 'Upd4t3r!', then runs it with exec()",
- the **operations** in the order they happen (innermost call first),
- the **artifacts**: keys, IVs, salts, passwords, blobs, URLs, file paths, with
  the line they came from,
- a **recovery script**: a standalone Python program that redoes the decoding
  chain on the embedded blob, so you can read the payload instead of running it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core.codegen import Step, chain_label, chain_snippet
from ctfc.core.flags import FlagSet
from ctfc.core.magic import match_signature
from ctfc.core.scoring import score

# What an artifact can be. Order matters: it is the order of the report table.
ARTIFACT_KINDS = (
    "key",
    "iv",
    "nonce",
    "salt",
    "password",
    "blob",
    "url",
    "path",
    "command",
    "flag",
)


@dataclass(frozen=True)
class Artifact:
    """One interesting value found in the script, and where it was found."""

    kind: str  # one of ARTIFACT_KINDS
    value: bytes  # the bytes as the script would use them
    how: str  # "literal", "hex string", "base64 string", "char codes"...
    line: int
    name: str = ""  # the variable name, when the script gave one
    context: str = ""  # the source line, trimmed

    def preview(self, limit: int = 60) -> str:
        """Readable one-line view: text when printable, hex otherwise.

        A single byte always reads as hex: "0x3b" is clearer than ";".
        """
        if len(self.value) == 1:
            text = f"0x{self.value[0]:02x}"
        elif self.value and all(32 <= byte < 127 for byte in self.value):
            text = self.value.decode("ascii")
        else:
            text = "hex:" + self.value.hex()
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "how": self.how,
            "line": self.line,
            "preview": self.preview(200),
            "value_hex": self.value.hex(),
            "length": len(self.value),
            "context": self.context,
        }


@dataclass(frozen=True)
class Operation:
    """One thing the script does to the data, in execution order."""

    kind: str  # a codegen step name ("base64", "zlib", "xor", "cipher") or ""
    label: str  # "decode base64", "AES-256-CBC decrypt"
    line: int
    direction: str  # "decode" (undoes) | "encode" (applies) | "both"
    rule: str  # "ast" or the rule id it came from
    params: dict = field(default_factory=dict)  # for codegen: key/iv/mode...

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "line": self.line,
            "direction": self.direction,
            "rule": self.rule,
            "params": {
                name: (value.hex() if isinstance(value, bytes) else value)
                for name, value in self.params.items()
            },
        }


@dataclass(frozen=True)
class Behaviour:
    """Something the script does besides transforming data (run, download, write)."""

    kind: str  # "execute", "network", "filesystem", "persistence", "process"
    label: str
    line: int
    context: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "line": self.line, "context": self.context}


@dataclass
class Recovery:
    """A runnable chain that recovers what the script hides."""

    blob: bytes
    steps: list[Step]
    python: str
    label: str
    complete: bool = True  # False when a key or a step is missing

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "complete": self.complete,
            "blob_length": len(self.blob),
            "steps": [step.to_dict() for step in self.steps],
            "python": self.python,
        }


@dataclass
class Peeled:
    """One embedded blob with the script's own chain applied to it, statically."""

    line: int
    name: str
    label: str  # the chain that was applied
    data: bytes
    score: float
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "name": self.name,
            "label": self.label,
            "score": round(self.score, 3),
            "reasons": list(self.reasons),
            "data_text": self.data.decode("utf-8", errors="replace"),
            "data_hex": self.data.hex(),
            "length": len(self.data),
        }


@dataclass
class LensReport:
    """Everything Code Lens found in one script."""

    language: str
    summary: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    behaviours: list[Behaviour] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    recovery: Recovery | None = None
    peeled: list[Peeled] = field(default_factory=list)

    def artifacts_of(self, kind: str) -> list[Artifact]:
        return [artifact for artifact in self.artifacts if artifact.kind == kind]

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "summary": list(self.summary),
            "operations": [operation.to_dict() for operation in self.operations],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "behaviours": [behaviour.to_dict() for behaviour in self.behaviours],
            "notes": list(self.notes),
            "recovery": self.recovery.to_dict() if self.recovery else None,
            "peeled": [peeled.to_dict() for peeled in self.peeled],
        }


# ---------------------------------------------------------------------------
# Which language is this?
# ---------------------------------------------------------------------------

EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".sh": "bash",
    ".bash": "bash",
    ".vbs": "vbs",
    ".vbe": "vbs",
}

# (language, regex-free marker, points). Simple and readable on purpose.
MARKERS: tuple[tuple[str, str, int], ...] = (
    ("python", "import ", 2),
    ("python", "def ", 2),
    ("python", "print(", 1),
    ("python", "__name__", 3),
    ("python", "b64decode", 2),
    ("powershell", "$", 1),
    ("powershell", "-bxor", 3),
    ("powershell", "FromBase64String", 3),
    ("powershell", "New-Object", 3),
    ("powershell", "Write-Host", 3),
    ("powershell", "powershell", 2),
    ("powershell", "Get-", 2),
    ("javascript", "function(", 2),
    ("javascript", "function (", 2),
    ("javascript", "=>", 1),
    ("javascript", "var ", 2),
    ("javascript", "const ", 2),
    ("javascript", "let ", 2),
    ("javascript", "atob(", 3),
    ("javascript", "charCodeAt", 3),
    ("javascript", "require(", 2),
    ("bash", "#!/bin/sh", 4),
    ("bash", "#!/bin/bash", 4),
    ("bash", "openssl ", 2),
    ("bash", "echo ", 1),
    ("bash", "base64 -d", 3),
    ("bash", "$(", 2),
    ("vbs", "Dim ", 3),
    ("vbs", "Set ", 2),
    ("vbs", "CreateObject", 3),
    ("vbs", "WScript", 4),
    ("vbs", "End Function", 3),
    ("vbs", "End Sub", 3),
)


def detect_language(source: str, filename: str = "") -> tuple[str, str]:
    """Return (language, why). The file extension wins; otherwise count markers."""
    suffix = Path(filename).suffix.lower()
    if suffix in EXTENSIONS:
        return EXTENSIONS[suffix], f"the file extension {suffix} says so"

    scores: dict[str, int] = {}
    for language, marker, points in MARKERS:
        if marker in source:
            scores[language] = scores.get(language, 0) + points
    if not scores:
        return "unknown", "no marker of a known language was found"
    best = max(scores, key=lambda language: scores[language])
    others = ", ".join(f"{name} {value}" for name, value in sorted(scores.items()))
    return best, f"markers point to {best} (scores: {others})"


# ---------------------------------------------------------------------------
# The recovery script
# ---------------------------------------------------------------------------

# Operations whose codegen step takes no parameter.
PLAIN_STEPS = {
    "base64",
    "base64url",
    "base32",
    "base58",
    "base85",
    "ascii85",
    "hex",
    "url",
    "html",
    "quoted_printable",
    "binary",
    "decimal",
    "reverse",
    "rot13",
    "rot47",
    "utf16le",
    "zlib",
    "gzip",
    "bz2",
    "lzma",
    "deflate",
}


def build_recovery(report: LensReport) -> Recovery | None:
    """Turn the operations into a standalone script that undoes them.

    The chain starts from the biggest embedded blob. A script that *decodes*
    something (the usual dropper) is replayed in the same order; a script that
    *encodes* is undone in reverse order.
    """
    blobs = report.artifacts_of("blob")
    if not blobs:
        return None
    blob = max(blobs, key=lambda artifact: len(artifact.value))

    fernet = _fernet_recovery(report, blobs)
    if fernet is not None:
        return fernet

    usable = [operation for operation in report.operations if operation.kind]
    if not usable:
        return None

    encoding = sum(1 for operation in usable if operation.direction == "encode")
    decoding = sum(1 for operation in usable if operation.direction == "decode")
    reverse = encoding > decoding
    ordered = list(reversed(usable)) if reverse else usable

    steps: list[Step] = []
    complete = True
    for operation in ordered:
        if operation.params.get("key_guessed"):
            # The key was matched by size, not by following the data, so the rest
            # of the chain is a guess. Stop here: a short script that works beats
            # a long one that crashes. The note tells the user what was left out.
            report.notes.append(
                f'the recovery script stops before "{operation.label}" (line '
                f"{operation.line}): its key was matched by size, not by following "
                "the data, so it may not belong to this chain at all"
            )
            complete = False
            break
        if operation.kind in PLAIN_STEPS:
            steps.append(Step(operation.kind))
        elif operation.kind == "xor":
            key = operation.params.get("key")
            if not key:
                complete = False
                continue
            steps.append(Step("xor", {"key": key.hex() if isinstance(key, bytes) else key}))
        elif operation.kind == "cipher":
            if not operation.params.get("key"):
                complete = False
                continue
            steps.append(Step("cipher", _cipher_step_params(operation.params)))
        else:
            complete = False
    if not steps:
        return None

    # The blob itself may already be the base64 text the first step decodes.
    label = chain_label(steps)
    return Recovery(
        blob=blob.value,
        steps=steps,
        python=chain_snippet(blob.value, steps),
        label=label,
        complete=complete,
    )


def apply_chain(data: bytes, steps: list[Step]) -> bytes | None:
    """Run the chain ourselves, in this process, on `data`.

    This is the "peel the layers" view CLAUDE.md asks for: the *data* is decoded,
    the script is still never executed. Returns None as soon as a step fails,
    because a half-applied chain would only be misleading.
    """
    from ctfc.core.encodings import DECODERS_BY_NAME, DecodeError
    from ctfc.core.xor import xor_with_key

    current = data
    for step in steps:
        try:
            if step.name == "xor":
                current = xor_with_key(current, bytes.fromhex(step.params["key"]))
            elif step.name == "cipher":
                current = _apply_cipher(current, step.params)
            else:
                current = DECODERS_BY_NAME[step.name].decode(current)
        except (DecodeError, ValueError, KeyError, UnicodeError, OverflowError):
            return None
        if not current:
            return None
    return current


def _apply_cipher(data: bytes, params: dict) -> bytes:
    """One cipher step of a peeled chain (reuses the M3 code)."""
    from ctfc.core.symmetric import CIPHERS, decrypt_raw, strip_padding

    spec = CIPHERS[params["cipher"]]
    key = bytes.fromhex(params["key"])
    iv = bytes.fromhex(params["iv"]) if params.get("iv") else None
    raw = decrypt_raw(spec, params["mode"], key, iv, data)
    if params.get("unpad") == "pkcs7":
        plain, _ = strip_padding(raw, spec.block_size)
        return plain
    return raw


def peel_blobs(report: LensReport, flagset: FlagSet | None = None) -> None:
    """Apply the script's own chain to every embedded blob and score the results.

    A dropper often hides several strings the same way (a URL here, a flag there).
    The recovery script only covers one of them, so we decode them all and rank
    what came out - that is usually where the answer is.
    """
    if report.recovery is None or not report.recovery.steps:
        return
    steps = report.recovery.steps
    label = chain_label(steps)
    seen: set[bytes] = set()
    for artifact in report.artifacts_of("blob"):
        output = apply_chain(artifact.value, steps)
        if output is None or output in seen:
            continue
        seen.add(output)
        value, reasons = score(output, flagset)
        report.peeled.append(
            Peeled(
                line=artifact.line,
                name=artifact.name,
                label=label,
                data=output,
                score=value,
                reasons=reasons,
            )
        )
    report.peeled.sort(key=lambda peeled: -peeled.score)


def _fernet_recovery(report: LensReport, blobs: list[Artifact]) -> Recovery | None:
    """A Fernet token plus its key: reuse the snippet symmetric.py already writes."""
    if not any("Fernet" in operation.label for operation in report.operations):
        return None
    tokens = [artifact for artifact in blobs if artifact.value.startswith(b"gAAAA")]
    keys = report.artifacts_of("key")
    if not tokens or not keys:
        return None
    from ctfc.core.symmetric import _fernet_snippet, decoded_forms

    for key in keys:
        for form in decoded_forms(key.value, "fernet key"):
            if len(form.data) == 32:
                return Recovery(
                    blob=tokens[0].value,
                    steps=[],
                    python=_fernet_snippet(tokens[0].value, form.data),
                    label="Fernet token with the key found in the script",
                )
    return None


def _cipher_step_params(params: dict) -> dict:
    """Shape a cipher operation's parameters for codegen.cipher_step_code."""
    from ctfc.core.symmetric import CIPHERS, cipher_label

    key = params["key"]
    cipher = params.get("cipher", "aes")
    mode = params.get("mode", "cbc")
    out = {"cipher": cipher, "mode": mode, "key": key.hex()}
    iv = params.get("iv")
    if iv:
        out["iv"] = iv.hex()
        out["iv_size"] = len(iv)
    # Only strip the padding if the script itself does: a script that keeps it
    # would otherwise get a recovery snippet that crashes on a valid result.
    if params.get("unpad") and CIPHERS[cipher].block_size > 1 and mode in ("cbc", "ecb"):
        out["unpad"] = "pkcs7"
    out["label"] = cipher_label(CIPHERS[cipher], key, mode)
    return out


# ---------------------------------------------------------------------------
# The summary, in plain words
# ---------------------------------------------------------------------------


def build_summary(report: LensReport) -> list[str]:
    """ "This script does X, then Y": one readable line per step, then behaviours."""
    lines: list[str] = []
    operations = report.operations
    if operations:
        chain = " -> ".join(operation.label for operation in operations)
        lines.append(f"data path: {chain}")
    for behaviour in report.behaviours:
        lines.append(f"{behaviour.kind}: {behaviour.label}")

    for kind in ("key", "iv", "nonce", "salt", "password"):
        for artifact in report.artifacts_of(kind):
            name = f" ({artifact.name})" if artifact.name else ""
            size = len(artifact.value)
            lines.append(
                f"hardcoded {kind}{name}: {artifact.preview()} "
                f"[{size} byte{'s' if size != 1 else ''}, {artifact.how}, line {artifact.line}]"
            )
    for artifact in report.artifacts_of("blob"):
        signature = match_signature(artifact.value)
        extra = f", looks like {signature.name}" if signature else ""
        lines.append(
            f"embedded blob of {len(artifact.value)} bytes "
            f"({artifact.how}, line {artifact.line}{extra})"
        )
    for peeled in report.peeled:
        text = peeled.data.decode("utf-8", errors="replace").replace("\n", " ")
        preview = text if len(text) <= 90 else text[:87] + "..."
        where = f" (line {peeled.line})" if peeled.line else ""
        lines.append(f"peeled{where}: {preview}")
    return lines


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _suggest_next_command(report: LensReport) -> None:
    """When the script hides a password instead of a key, say which ctfc command finishes the job.

    A `openssl enc -pass pass:xxx` or a CryptoJS passphrase does not give us a key
    directly: the key comes out of a KDF, and trying the KDF layouts is exactly
    what `ctfc sym` does. So we hand over instead of guessing here.
    """
    needs_password = any(
        operation.kind == "cipher" and not operation.params.get("key")
        for operation in report.operations
    )
    if not needs_password:
        return
    passwords = report.artifacts_of("password")
    blobs = report.artifacts_of("blob")
    if passwords and blobs:
        report.notes.append(
            "the cipher uses a passphrase, not a raw key: save the blob to a file and run "
            f'`ctfc sym <file> --pass "{passwords[0].value.decode("utf-8", errors="replace")}"` '
            "(ctfc will try the KDF layouts, openssl included)"
        )
    elif blobs:
        report.notes.append(
            "a cipher was found but no key: save the blob to a file and run "
            "`ctfc sym <file> --passwords` (or pass the key with --key)"
        )


def analyse(source: bytes | str, filename: str = "", flagset: FlagSet | None = None) -> LensReport:
    """Analyse one script statically. `filename` only helps guess the language."""
    if isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    else:
        text = source

    language, why = detect_language(text, filename)
    report = LensReport(language=language)
    report.notes.append(f"language: {language} ({why})")

    if language == "python":
        from ctfc.core.lens_python import analyse_python

        analyse_python(text, report)
        if not report.operations and not report.artifacts:
            # Decompiled or truncated Python often does not parse: fall back.
            from ctfc.core.lens_rules import apply_rules

            apply_rules(text, "python", report)
    else:
        from ctfc.core.lens_rules import apply_rules

        apply_rules(text, language, report)

    report.artifacts.sort(key=lambda artifact: (ARTIFACT_KINDS.index(artifact.kind), artifact.line))
    report.recovery = build_recovery(report)
    peel_blobs(report, flagset)
    report.summary = build_summary(report)
    _suggest_next_command(report)
    if not report.operations:
        report.notes.append(
            "no data transformation recognised: the script may use an API ctfc does "
            "not know yet (add a rule in ctfc/data/lens_rules.toml), or hide it at runtime"
        )
    return report
