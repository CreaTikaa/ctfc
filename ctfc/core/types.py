"""Shared data types used by every module.

- `Input`: the bytes the user gave us, plus where they came from.
- `Candidate`: one possible answer (a decoded / decrypted output) with its score
  and the reasons behind that score.
- `Recipe`: an ordered list of operations (used by the pipeline, milestone M6).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Input:
    """Raw bytes given by the user and a short description of their origin."""

    data: bytes
    source: str  # "file:<path>", "stdin", "hex", "b64", "text", "auto-hex", ...
    notes: list[str] = field(default_factory=list)  # e.g. "bare hex text auto-detected"


@dataclass
class Candidate:
    """One possible result. Every result must explain itself (hard rule #6)."""

    label: str  # "AES-256-CBC, key=blob[:32], iv=blob[32:]"
    data: bytes  # the output bytes
    score: float  # 0..1, higher is more likely to be the answer
    reasons: list[str]  # "valid PKCS7 padding", "matches flag regex", ...
    params: dict = field(default_factory=dict)  # key / iv / mode / ... (hex strings)
    python: str = ""  # standalone snippet that reproduces this result
    cyberchef: str | None = None  # CyberChef recipe, if expressible

    def to_dict(self) -> dict:
        """JSON-friendly view (bytes become hex + a text preview)."""
        return {
            "label": self.label,
            "score": round(self.score, 3),
            "reasons": list(self.reasons),
            "params": dict(self.params),
            "data_hex": self.data.hex(),
            "data_text": self.data.decode("utf-8", errors="replace"),
            "length": len(self.data),
            "python": self.python,
            "cyberchef": self.cyberchef,
        }


@dataclass
class RecipeStep:
    """One operation of a recipe, e.g. op="from_base64", args={}."""

    op: str
    args: dict = field(default_factory=dict)


@dataclass
class Recipe:
    """An ordered list of operations, applied one after the other."""

    name: str
    steps: list[RecipeStep] = field(default_factory=list)
