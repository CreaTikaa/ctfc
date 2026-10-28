"""Recipes: an ordered list of operations, applied one after the other.

This is the manual counterpart of `auto`. When you already know what to do -
"base64, then zlib, then XOR with this key" - you do not want a search, you want
exactly those three steps, with the intermediate output of each one visible so
you can see where it goes wrong.

A recipe is plain JSON, so it can be saved, edited by hand and shared:

    {
      "name": "stage1",
      "steps": [
        {"op": "base64"},
        {"op": "zlib"},
        {"op": "xor", "args": {"key": "4b3379e21"}},
        {"op": "cipher", "args": {"cipher": "aes", "mode": "cbc", "key": "...", "iv": "..."}}
      ]
    }

The operation names are the same ones `auto` and Code Lens use (the decoders of
`encodings.py`, plus `xor`, `cipher` and `base64_custom`), so a chain found
automatically can be saved as a recipe, edited, and replayed - and exported as a
Python script or a CyberChef recipe, because they all go through `codegen`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core.codegen import Step, chain_cyberchef, chain_label, chain_snippet, step_code
from ctfc.core.encodings import DECODERS_BY_NAME, DecodeError
from ctfc.core.flags import FlagSet
from ctfc.core.scoring import has_valid_pkcs7, score

# Operations that take arguments; everything else is a decoder name.
PARAMETRISED = {"xor", "cipher", "base64_custom"}


class RecipeError(ValueError):
    """Raised when a recipe cannot be read or applied. The message says what to fix."""


@dataclass
class StepResult:
    """What one step did: its output, and whether it worked."""

    index: int
    step: Step
    label: str
    comment: str
    data: bytes = b""
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "op": self.step.name,
            "label": self.label,
            "comment": self.comment,
            "length": len(self.data),
            "score": round(self.score, 3),
            "reasons": list(self.reasons),
            "data_hex": self.data.hex(),
            "data_text": self.data.decode("utf-8", errors="replace"),
            "error": self.error,
        }


@dataclass
class RecipeResult:
    """The whole run: one entry per step, plus the final output."""

    name: str
    steps: list[StepResult] = field(default_factory=list)
    output: bytes = b""
    python: str = ""
    cyberchef: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and not any(result.error for result in self.steps)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "steps": [result.to_dict() for result in self.steps],
            "output_hex": self.output.hex(),
            "output_text": self.output.decode("utf-8", errors="replace"),
            "python": self.python,
            "cyberchef": self.cyberchef,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Reading and writing recipes
# ---------------------------------------------------------------------------


def parse_steps(raw: list) -> list[Step]:
    """Turn the JSON "steps" list into codegen Steps, checking as we go."""
    steps = []
    for position, entry in enumerate(raw, start=1):
        if isinstance(entry, str):  # a bare name is allowed: "base64"
            entry = {"op": entry}
        if not isinstance(entry, dict) or "op" not in entry:
            raise RecipeError(f'step {position}: expected {{"op": "name", ...}}, got {entry!r}')
        name = str(entry["op"])
        args = entry.get("args") or {}
        if not isinstance(args, dict):
            raise RecipeError(f'step {position} ({name}): "args" must be an object')
        if name not in PARAMETRISED and name not in DECODERS_BY_NAME:
            known = ", ".join(sorted(DECODERS_BY_NAME) + sorted(PARAMETRISED))
            raise RecipeError(f"step {position}: unknown operation {name!r}. Known: {known}")
        if name == "xor" and "key" not in args:
            raise RecipeError(f'step {position}: xor needs args {{"key": "<hex>"}}')
        if name == "cipher":
            if not {"cipher", "key"} <= set(args):
                raise RecipeError(
                    f'step {position}: cipher needs at least {{"cipher": "aes", "key": "<hex>"}}'
                )
            try:
                check_cipher(args)
            except RecipeError as exc:
                raise RecipeError(f"step {position}: {exc}") from exc
        if name == "base64_custom" and "alphabet" not in args:
            raise RecipeError(f'step {position}: base64_custom needs {{"alphabet": "..."}}')
        steps.append(Step(name, dict(args)))
    return steps


def load(path: str | Path) -> tuple[str, list[Step]]:
    """Read a recipe file. Returns (name, steps)."""
    file_path = Path(path)
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RecipeError(f"cannot read {file_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{file_path} is not valid JSON: {exc}") from exc
    if isinstance(raw, list):  # a bare list of steps is accepted
        raw = {"steps": raw}
    if not isinstance(raw, dict) or "steps" not in raw:
        raise RecipeError(f'{file_path}: expected an object with a "steps" list')
    return str(raw.get("name") or file_path.stem), parse_steps(raw["steps"])


def dump(name: str, steps: list[Step], path: str | Path | None = None) -> str:
    """Serialise a recipe to JSON (and write it, when a path is given)."""
    payload = {
        "name": name,
        "steps": [
            {"op": step.name, **({"args": dict(step.params)} if step.params else {})}
            for step in steps
        ],
    }
    text = json.dumps(payload, indent=2) + "\n"
    if path is not None:
        Path(path).write_text(text, encoding="utf-8")
    return text


def from_candidate_steps(steps: list[Step], name: str = "recipe") -> str:
    """Save the chain of an `auto` / Code Lens result as a reusable recipe."""
    return dump(name, steps)


# ---------------------------------------------------------------------------
# Running a recipe
# ---------------------------------------------------------------------------


def apply_step(data: bytes, step: Step) -> bytes:
    """Apply one operation. Raises RecipeError with a readable message on failure."""
    try:
        if step.name == "xor":
            from ctfc.core.xor import xor_with_key

            return xor_with_key(data, bytes.fromhex(step.params["key"]))
        if step.name == "base64_custom":
            from ctfc.core.encodings import decode_custom_base64

            return decode_custom_base64(data, step.params["alphabet"])
        if step.name == "cipher":
            return _apply_cipher(data, step.params)
        return DECODERS_BY_NAME[step.name].decode(data)
    except (DecodeError, ValueError, KeyError, UnicodeError, OverflowError) as exc:
        raise RecipeError(str(exc)) from exc


def check_cipher(params: dict) -> None:
    """Refuse an unknown cipher or mode, with the list of the known ones."""
    from ctfc.core.symmetric import CIPHERS

    name = str(params["cipher"]).lower()
    if name not in CIPHERS:
        raise RecipeError(f"unknown cipher {name!r}; known: {', '.join(sorted(CIPHERS))}")
    spec = CIPHERS[name]
    mode = str(params.get("mode", "cbc")).lower()
    if mode not in spec.modes:
        raise RecipeError(f"{spec.label} has no mode {mode!r}; known: {', '.join(spec.modes)}")


def complete_cipher(params: dict) -> dict:
    """Fill the optional fields of a cipher step, so codegen and the run agree.

    A hand-written recipe may leave out `mode` (CBC is assumed) and `iv_size`
    (the usual size for that cipher: 12 for a GCM or ChaCha20 nonce, 8 for
    Salsa20, the block size otherwise).
    """
    from ctfc.core.symmetric import CIPHERS

    check_cipher(params)
    full = dict(params)
    full["cipher"] = str(params["cipher"]).lower()
    full["mode"] = str(params.get("mode", "cbc")).lower()
    if full.get("iv_from") == "prefix" and not full.get("iv_size"):
        spec = CIPHERS[full["cipher"]]
        if full["mode"] == "gcm" or full["cipher"] == "chacha20":
            full["iv_size"] = 12
        elif full["cipher"] == "salsa20":
            full["iv_size"] = 8
        else:
            full["iv_size"] = spec.block_size
    return full


def _apply_cipher(data: bytes, params: dict) -> bytes:
    """A cipher step, reusing the M3 primitives.

    The optional fields mean exactly what they mean in the generated Python
    (`codegen.cipher_step_code`), so a recipe and its exported script agree:
    `header_skip` drops N bytes first, `iv_from: "prefix"` reads the IV from the
    start of the data (`iv_size` bytes), and `tag` says the data *ends* with that
    16-byte GCM tag (the usual nonce||ct||tag layout).
    """
    from ctfc.core.symmetric import CIPHERS, CryptoError, decrypt_raw

    params = complete_cipher(params)
    spec = CIPHERS[params["cipher"]]
    mode = params["mode"]
    key = bytes.fromhex(params["key"])
    iv = bytes.fromhex(params["iv"]) if params.get("iv") else None
    if params.get("header_skip"):
        data = data[int(params["header_skip"]) :]
    if params.get("iv_from") == "prefix":
        size = int(params["iv_size"])
        iv, data = data[:size], data[size:]
    tag = None
    if params.get("tag"):
        tag, data = data[-16:], data[:-16]
        if tag.hex() != str(params["tag"]).lower():
            raise RecipeError(
                f"the data does not end with the tag {params['tag']} (it ends with "
                f"{tag.hex()}): a recipe expects the tag at the end of the data"
            )
    try:
        raw = decrypt_raw(
            spec,
            mode,
            key,
            iv,
            data,
            endian=str(params.get("endian", "big")),
            counter=int(params.get("counter", 0)),
            ctr_style=str(params.get("ctr_style", "block")),
            tag=tag,
        )
    except CryptoError as exc:
        raise RecipeError(str(exc)) from exc
    # Same behaviour as the exported script: `unpad()` refuses a bad padding.
    if params.get("unpad") == "pkcs7":
        if not has_valid_pkcs7(raw, spec.block_size):
            raise RecipeError(
                "invalid PKCS7 padding after decryption: the key, IV or mode is wrong "
                '(or the data is not padded: drop "unpad")'
            )
        return raw[: -raw[-1]]
    if params.get("unpad") == "zero":
        return raw.rstrip(b"\x00")
    return raw


def run(
    data: bytes,
    steps: list[Step],
    name: str = "recipe",
    flagset: FlagSet | None = None,
) -> RecipeResult:
    """Apply every step in order, keeping each intermediate output.

    A step that fails stops the run: the steps before it keep their output, so you
    can see exactly how far the recipe got and what the data looked like there.
    """
    result = RecipeResult(name=name)
    current = data
    applied: list[Step] = []
    for index, step in enumerate(steps, start=1):
        try:
            if step.name == "cipher":
                step = Step("cipher", complete_cipher(step.params))
            code = step_code(step)
            label, comment = code.label, code.comment
        except (KeyError, ValueError):  # malformed: apply_step explains it below
            label, comment = step.name, ""
        entry = StepResult(index=index, step=step, label=label, comment=comment)
        try:
            current = apply_step(current, step)
        except RecipeError as exc:
            entry.error = str(exc)
            entry.data = b""
            result.steps.append(entry)
            if index == 1:
                where = "the input itself"
            else:
                where = f"the output of step {index - 1} (above)"
            result.notes.append(
                f"step {index} ({label}) failed: {exc}. Check that {where} "
                "is what this step expects."
            )
            break
        entry.data = current
        entry.score, entry.reasons = score(current, flagset)
        result.steps.append(entry)
        applied.append(step)

    if result.ok:
        result.output = current
    elif len(result.steps) > 1:
        # The run stopped: the output of the last step that *worked* is the
        # useful one, because that is where you pick the recipe back up.
        result.output = result.steps[-2].data
    else:
        result.output = data
    if applied:
        result.python = chain_snippet(data, applied)
        result.cyberchef = chain_cyberchef(applied)
        result.notes.insert(0, "chain: " + chain_label(applied))
    return result


def run_file(data: bytes, path: str | Path, flagset: FlagSet | None = None) -> RecipeResult:
    """Load a recipe from disk and run it on `data`."""
    name, steps = load(path)
    return run(data, steps, name, flagset)
