"""Static analysis of Python scripts with the standard `ast` module.

Why `ast` and not regex: a parsed tree gives the *order* of operations for free.
In `xor(zlib.decompress(base64.b64decode(BLOB)), KEY)` the innermost call runs
first, and a tree knows that; a regex does not.

Two things happen here:

1. **Constant folding** (`fold`): rebuild the value of an expression made only of
   literals, the way you would read it by hand. `"ab" + "cd"` -> `b"abcd"`,
   `bytes([0x41, 0x42])` -> `b"AB"`, `"...".encode()`, `[::-1]`, `bytes.fromhex`,
   `base64.b64decode("...")`, and variables that were assigned a folded value.
   **Never `eval`** (hard rule 3): when something cannot be folded, we return
   None and say so instead of guessing.

2. **Recognition**: calls that transform data (`b64decode`, `decompress`,
   `AES.new(...).decrypt`, XOR loops) become `Operation`s, and literals that look
   like keys, IVs, salts, passwords, blobs, URLs or paths become `Artifact`s.
"""

from __future__ import annotations

import ast
import base64
import binascii
import re

from ctfc.core.lens import Artifact, Behaviour, LensReport, Operation

# ---------------------------------------------------------------------------
# Tables: which call means which operation
# ---------------------------------------------------------------------------

# (module, function) -> (codegen step name, label, direction)
DATA_CALLS: dict[tuple[str, str], tuple[str, str, str]] = {
    ("base64", "b64decode"): ("base64", "decode base64", "decode"),
    ("base64", "standard_b64decode"): ("base64", "decode base64", "decode"),
    ("base64", "urlsafe_b64decode"): ("base64url", "decode base64url", "decode"),
    ("base64", "b32decode"): ("base32", "decode base32", "decode"),
    ("base64", "b16decode"): ("hex", "decode hex", "decode"),
    ("base64", "b85decode"): ("base85", "decode base85", "decode"),
    ("base64", "a85decode"): ("ascii85", "decode ascii85", "decode"),
    ("base64", "b64encode"): ("base64", "encode to base64", "encode"),
    ("base64", "urlsafe_b64encode"): ("base64url", "encode to base64url", "encode"),
    ("base64", "b32encode"): ("base32", "encode to base32", "encode"),
    ("base64", "b85encode"): ("base85", "encode to base85", "encode"),
    ("base64", "a85encode"): ("ascii85", "encode to ascii85", "encode"),
    ("zlib", "decompress"): ("zlib", "inflate with zlib", "decode"),
    ("zlib", "compress"): ("zlib", "deflate with zlib", "encode"),
    ("gzip", "decompress"): ("gzip", "decompress gzip", "decode"),
    ("gzip", "compress"): ("gzip", "compress with gzip", "encode"),
    ("bz2", "decompress"): ("bz2", "decompress bz2", "decode"),
    ("bz2", "compress"): ("bz2", "compress with bz2", "encode"),
    ("lzma", "decompress"): ("lzma", "decompress lzma", "decode"),
    ("lzma", "compress"): ("lzma", "compress with lzma", "encode"),
    ("binascii", "unhexlify"): ("hex", "decode hex", "decode"),
    ("binascii", "a2b_hex"): ("hex", "decode hex", "decode"),
    ("binascii", "hexlify"): ("hex", "encode to hex", "encode"),
    ("binascii", "a2b_base64"): ("base64", "decode base64", "decode"),
    ("bytes", "fromhex"): ("hex", "decode hex", "decode"),
    ("urllib.parse", "unquote"): ("url", "decode URL escapes", "decode"),
    ("urllib.parse", "unquote_plus"): ("url", "decode URL escapes", "decode"),
    ("html", "unescape"): ("html", "decode HTML entities", "decode"),
}

# pycryptodome cipher modules -> ctfc cipher names (see symmetric.CIPHERS)
CIPHER_MODULES = {
    "AES": "aes",
    "DES": "des",
    "DES3": "3des",
    "Blowfish": "blowfish",
    "ARC4": "rc4",
    "ChaCha20": "chacha20",
    "Salsa20": "salsa20",
}

MODE_CONSTANTS = {
    "MODE_ECB": "ecb",
    "MODE_CBC": "cbc",
    "MODE_CTR": "ctr",
    "MODE_CFB": "cfb",
    "MODE_OFB": "ofb",
    "MODE_GCM": "gcm",
    "MODE_EAX": "eax",
    "MODE_OCB": "ocb",
}

# Hash functions, which are usually a key derivation when the result feeds a cipher.
HASHES = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s")

# Calls that say what the script *does*, beyond transforming bytes.
BEHAVIOUR_CALLS: dict[str, tuple[str, str]] = {
    "exec": ("execute", "runs the decoded result with exec()"),
    "eval": ("execute", "evaluates the decoded result with eval()"),
    "compile": ("execute", "compiles the decoded result"),
    "__import__": ("execute", "imports a module chosen at runtime"),
    "os.system": ("process", "runs a shell command with os.system()"),
    "os.popen": ("process", "runs a shell command with os.popen()"),
    "os.remove": ("filesystem", "deletes a file"),
    "os.unlink": ("filesystem", "deletes a file"),
    "subprocess.run": ("process", "starts a process with subprocess.run()"),
    "subprocess.Popen": ("process", "starts a process with subprocess.Popen()"),
    "subprocess.call": ("process", "starts a process with subprocess.call()"),
    "subprocess.check_output": ("process", "runs a command and reads its output"),
    "urllib.request.urlopen": ("network", "downloads from a URL"),
    "requests.get": ("network", "downloads with requests.get()"),
    "requests.post": ("network", "sends data with requests.post()"),
    "socket.socket": ("network", "opens a raw network socket"),
    "winreg.SetValueEx": ("persistence", "writes a Windows registry value"),
    "winreg.CreateKey": ("persistence", "creates a Windows registry key"),
    "shutil.copy": ("filesystem", "copies a file"),
}

# Variable names that tell us what a value is for.
NAME_HINTS: tuple[tuple[str, str], ...] = (
    ("password", "password"),
    ("passphrase", "password"),
    ("passwd", "password"),
    ("secret", "key"),
    ("nonce", "nonce"),
    ("salt", "salt"),
    ("iv", "iv"),
    ("key", "key"),
    # A "token" is the thing to decrypt (a Fernet token, a JWT), never the key.
    ("token", "blob"),
    ("flag", "flag"),
    ("url", "url"),
    ("path", "path"),
    ("blob", "blob"),
    ("payload", "blob"),
    ("data", "blob"),
    ("enc", "blob"),
    ("cipher", "blob"),
)

URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\|/(?:etc|tmp|var|usr|home|opt)/|%[A-Z]+%|~/)")
# 40+ characters before a string is called a payload by name; the fallback in
# PythonLens.promote_spare_blob uses SHORT_BLOB_RE instead.
BLOB_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]{40,}$")
SHORT_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,}$")
HEX_BLOB_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){16,}$")
MIN_BLOB = 24  # shorter "blobs" are usually keys or noise


# ---------------------------------------------------------------------------
# Constant folding: rebuild a literal value without running anything
# ---------------------------------------------------------------------------


def as_bytes(value: object) -> bytes | None:
    """Turn a folded value into bytes, when that makes sense."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    if isinstance(value, int):
        return bytes([value]) if 0 <= value < 256 else None
    return None


class Folder:
    """Evaluates literal expressions *by hand* (no eval, no exec, no import)."""

    def __init__(self) -> None:
        self.names: dict[str, object] = {}  # variable -> folded value

    def fold(self, node: ast.AST | None, depth: int = 0) -> object | None:
        """Return the value of `node` if it is made of literals only, else None."""
        if node is None or depth > 20:  # depth guard: no runaway recursion
            return None

        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, (str, bytes, int, float)) else None

        if isinstance(node, ast.Name):
            return self.names.get(node.id)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = [self.fold(element, depth + 1) for element in node.elts]
            return None if any(item is None for item in items) else items

        if isinstance(node, ast.JoinedStr):  # f-string of literals only
            pieces = []
            for part in node.values:
                value = self.fold(part, depth + 1)
                if not isinstance(value, str):
                    return None
                pieces.append(value)
            return "".join(pieces)

        if isinstance(node, ast.FormattedValue):
            value = self.fold(node.value, depth + 1)
            return None if value is None else str(value)

        if isinstance(node, ast.BinOp):
            return self._fold_binop(node, depth)

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            value = self.fold(node.operand, depth + 1)
            return -value if isinstance(value, int) else None

        if isinstance(node, ast.Subscript):
            return self._fold_subscript(node, depth)

        if isinstance(node, ast.Call):
            return self._fold_call(node, depth)

        return None

    def _fold_binop(self, node: ast.BinOp, depth: int) -> object | None:
        left = self.fold(node.left, depth + 1)
        right = self.fold(node.right, depth + 1)
        if left is None or right is None:
            return None
        try:
            if isinstance(node.op, ast.Add):
                if isinstance(left, type(right)) or isinstance(right, type(left)):
                    return left + right  # type: ignore[operator]
                return None
            if isinstance(node.op, ast.Mult):
                if isinstance(left, (str, bytes, list)) and isinstance(right, int):
                    return left * min(right, 4096)  # cap: no memory bombs
                if isinstance(right, (str, bytes, list)) and isinstance(left, int):
                    return right * min(left, 4096)
                return None
            if isinstance(node.op, ast.BitXor) and isinstance(left, int) and isinstance(right, int):
                return left ^ right
            if isinstance(node.op, ast.Mod) and isinstance(left, str) and isinstance(right, str):
                return None  # "%s" % x: not worth guessing
        except (TypeError, ValueError, OverflowError):
            return None
        return None

    def _fold_subscript(self, node: ast.Subscript, depth: int) -> object | None:
        value = self.fold(node.value, depth + 1)
        if not isinstance(value, (str, bytes, list)):
            return None
        index = node.slice
        if isinstance(index, ast.Slice):
            lower = self.fold(index.lower, depth + 1)
            upper = self.fold(index.upper, depth + 1)
            step = self.fold(index.step, depth + 1)
            if not all(part is None or isinstance(part, int) for part in (lower, upper, step)):
                return None
            return value[lower:upper:step]  # type: ignore[misc]
        position = self.fold(index, depth + 1)
        if isinstance(position, int) and -len(value) <= position < len(value):
            return value[position]
        return None

    def _fold_call(self, node: ast.Call, depth: int) -> object | None:
        """Fold the handful of calls that only rearrange literals."""
        name = dotted_name(node.func)
        arguments = [self.fold(argument, depth + 1) for argument in node.args]
        first = arguments[0] if arguments else None

        if name in ("bytes", "bytearray"):
            if not node.args:
                return b""  # bytes() really is empty
            if first is None:
                return None  # bytes(<something we cannot read>): do not guess
            if isinstance(first, list) and all(isinstance(item, int) for item in first):
                return bytes(item & 0xFF for item in first)
            if isinstance(first, str):
                return first.encode("utf-8", errors="replace")
            if isinstance(first, bytes):
                return first
            return None
        if name == "str" and isinstance(first, bytes):
            return first.decode("utf-8", errors="replace")
        if name == "chr" and isinstance(first, int):
            return chr(first & 0x10FFFF)
        if name == "ord" and isinstance(first, str) and len(first) == 1:
            return ord(first)
        if name == "bytes.fromhex" and isinstance(first, str):
            return _unhex(first)
        if name in ("binascii.unhexlify", "binascii.a2b_hex", "base64.b16decode"):
            text = first.decode() if isinstance(first, bytes) else first
            return _unhex(text) if isinstance(text, str) else None
        if name in ("base64.b64decode", "base64.standard_b64decode", "binascii.a2b_base64"):
            return _unb64(first)
        if name == "base64.urlsafe_b64decode":
            return _unb64(first, urlsafe=True)
        if name in ("base64.b64encode", "base64.standard_b64encode"):
            raw = as_bytes(first)
            return base64.b64encode(raw) if raw is not None else None
        if name == "list" and isinstance(first, (str, bytes, list)):
            return list(first)

        # Method calls on a folded value: "abc".encode(), b"abc".decode(), "".join([...])
        if isinstance(node.func, ast.Attribute):
            target = self.fold(node.func.value, depth + 1)
            method = node.func.attr
            if target is None:
                return None
            if method == "encode" and isinstance(target, str):
                return target.encode("utf-8", errors="replace")
            if method == "decode" and isinstance(target, bytes):
                return target.decode("utf-8", errors="replace")
            if method == "join" and isinstance(target, (str, bytes)) and isinstance(first, list):
                if all(isinstance(item, type(target)) for item in first):
                    return target.join(first)  # type: ignore[arg-type]
                return None
            if method == "replace" and isinstance(target, (str, bytes)) and len(arguments) >= 2:
                old, new = arguments[0], arguments[1]
                if isinstance(old, type(target)) and isinstance(new, type(target)):
                    return target.replace(old, new)  # type: ignore[arg-type]
                return None
            if method in ("strip", "lstrip", "rstrip") and isinstance(target, (str, bytes)):
                return getattr(target, method)()
            if method == "hex" and isinstance(target, bytes):
                return target.hex()
        return None

    def remember(self, target: ast.AST, value: object) -> None:
        """Record `name = <folded value>` for later lookups."""
        if isinstance(target, ast.Name) and value is not None:
            self.names[target.id] = value


def _unhex(text: str) -> bytes | None:
    cleaned = re.sub(r"\s", "", text)
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _unb64(value: object, urlsafe: bool = False) -> bytes | None:
    raw = as_bytes(value)
    if raw is None:
        return None
    cleaned = re.sub(rb"\s", b"", raw)
    if urlsafe:
        cleaned = cleaned.replace(b"-", b"+").replace(b"_", b"/")
    try:
        return base64.b64decode(cleaned + b"=" * (-len(cleaned) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def dotted_name(node: ast.AST) -> str:
    """ "base64.b64decode" for an Attribute/Name chain, "" for anything else."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):  # AES.new(...).decrypt -> "<call>.decrypt"
        parts.append("<call>")
    else:
        return ""
    return ".".join(reversed(parts))


# ---------------------------------------------------------------------------
# The analyser
# ---------------------------------------------------------------------------


class PythonLens:
    """Walks the tree once, in source order, collecting operations and artifacts."""

    # Variable names whose assignment is key *setup*, not part of the data path:
    # `KEY = bytes.fromhex("...")` must not be reported as "decode hex".
    KEY_MATERIAL = ("key", "iv", "nonce", "salt", "password", "passphrase", "passwd", "secret")

    def __init__(self, source: str, report: LensReport) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.report = report
        self.folder = Folder()
        self.cipher_variables: dict[str, dict] = {}  # variable -> cipher params
        self.cipher_by_node: dict[int, dict] = {}  # id(<X.new(...) call>) -> params
        self.seen_artifacts: set[tuple[str, bytes]] = set()
        self.in_key_setup = False  # True while walking a key-material assignment
        # Literals that were not classified: used as a fallback when a decoding
        # chain was found but no string was long enough to look like the payload.
        self.spare_literals: list[tuple[str, bytes, int]] = []
        # Does the script remove a PKCS7 padding? The recovery script must match.
        self.unpads = "unpad(" in source or "Padding.unpad" in source

    def context(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:200]
        return ""

    # -- artifacts ---------------------------------------------------------

    def add_artifact(self, kind: str, value: bytes, how: str, line: int, name: str = "") -> None:
        if not value or (kind, value) in self.seen_artifacts:
            return
        self.seen_artifacts.add((kind, value))
        self.report.artifacts.append(
            Artifact(
                kind=kind,
                value=value,
                how=how,
                line=line,
                name=name,
                context=self.context(line),
            )
        )

    def classify_value(self, name: str, value: object, line: int) -> None:
        """Decide what a `name = value` assignment is: a key, a blob, a URL..."""
        raw = as_bytes(value)
        if raw is None or not raw:
            return
        lowered = name.lower()
        text = raw.decode("utf-8", errors="replace")

        if isinstance(value, str) and URL_RE.search(value):
            self.add_artifact("url", raw, "literal string", line, name)
            return
        if isinstance(value, str) and PATH_RE.match(value):
            self.add_artifact("path", raw, "literal string", line, name)
            return

        kind = ""
        for marker, hinted in NAME_HINTS:
            if marker in lowered:
                kind = hinted
                break

        # The name wins: a variable called FERNET_KEY is a key, even though its
        # value is a long base64 string that would otherwise look like a payload.
        if kind in ("key", "iv", "nonce", "salt", "password", "flag"):
            how = "literal"
            if isinstance(value, str) and HEX_BLOB_RE.match(text):
                how = "hex string"
            elif isinstance(value, str) and BLOB_RE.match(text):
                how = "base64 string"
            self.add_artifact(kind, raw, how, line, name)
            return

        # Otherwise a long base64/hex string is a blob, whatever it is called.
        if len(raw) >= MIN_BLOB and (BLOB_RE.match(text) or HEX_BLOB_RE.match(text)):
            is_hex = bool(HEX_BLOB_RE.match(text))
            decoded = _unhex(text) if is_hex else _unb64(raw)
            if decoded and len(decoded) >= 8:
                # Keep the *encoded* text as the blob: the chain starts by decoding it.
                how = "hex string" if is_hex else "base64 string"
                self.add_artifact("blob", raw, how, line, name)
                return
        if kind == "blob" and len(raw) >= MIN_BLOB:
            self.add_artifact("blob", raw, "literal", line, name)
            return
        # Nothing matched. Keep it aside: if the script turns out to decode
        # something and we found no payload, a short literal is the best guess.
        if 12 <= len(raw) <= 4096:
            self.spare_literals.append((name, raw, line))

    # -- operations --------------------------------------------------------

    def add_operation(
        self, kind: str, label: str, line: int, direction: str, params: dict | None = None
    ) -> None:
        self.report.operations.append(
            Operation(
                kind=kind,
                label=label,
                line=line,
                direction=direction,
                rule="ast",
                params=params or {},
            )
        )

    def visit_call(self, node: ast.Call) -> None:
        """One call: is it a data transformation, a cipher, or a behaviour?"""
        name = dotted_name(node.func)
        line = getattr(node, "lineno", 0)
        short = name.split(".")[-1]
        module = ".".join(name.split(".")[:-1])

        # data transformations (base64, zlib, hex...), unless this is key setup
        if not self.in_key_setup:
            for (table_module, table_function), (kind, label, direction) in DATA_CALLS.items():
                if short == table_function and (
                    module == table_module
                    or module.endswith("." + table_module)
                    or module == ""
                    or table_module == "bytes"
                ):
                    self.add_operation(kind, label, line, direction)
                    break

        # ciphers: AES.new(key, AES.MODE_CBC, iv)
        if short == "new" and module.split(".")[-1] in CIPHER_MODULES:
            self.read_cipher(node, CIPHER_MODULES[module.split(".")[-1]], line)
        elif short == "Fernet" or name.endswith("Fernet"):
            self.read_fernet(node, line)
        elif short in ("decrypt", "encrypt", "decrypt_and_verify", "encrypt_and_digest"):
            self.read_cipher_use(node, short, line)

        # hashes used as key derivation
        if module.split(".")[-1] == "hashlib" or short in HASHES:
            if short in HASHES:
                argument = self.folder.fold(node.args[0]) if node.args else None
                raw = as_bytes(argument)
                detail = f' of "{raw.decode("utf-8", errors="replace")}"' if raw else ""
                self.add_operation(
                    "", f"derive a key with {short}(){detail}", line, "both", {"hash": short}
                )
        if short in ("PBKDF2", "pbkdf2_hmac"):
            self.add_operation("", f"derive a key with {short}()", line, "both")
        if short == "scrypt":
            self.add_operation("", "derive a key with scrypt()", line, "both")

        # XOR helpers from pycryptodome
        if short == "strxor":
            self.add_operation("xor", "XOR two byte strings (strxor)", line, "both")

        # behaviours
        for call, (kind, label) in BEHAVIOUR_CALLS.items():
            if name == call or (short == call.split(".")[-1] and call.count(".") == 0):
                self.report.behaviours.append(
                    Behaviour(kind=kind, label=label, line=line, context=self.context(line))
                )
                break

        # URLs and paths passed inline
        for argument in node.args:
            value = self.folder.fold(argument)
            if isinstance(value, str):
                if URL_RE.search(value):
                    self.add_artifact("url", value.encode(), "literal string", line)
                elif PATH_RE.match(value):
                    self.add_artifact("path", value.encode(), "literal string", line)

    def read_cipher(self, node: ast.Call, cipher: str, line: int) -> None:
        """`AES.new(key, AES.MODE_CBC, iv)`: this is *setup*, so only record it.

        The operation itself is emitted when `.decrypt()` / `.encrypt()` is called,
        because that is where the data really passes through the cipher. Python
        evaluates `AES.new(...)` before the arguments of `.decrypt(...)`, so
        emitting here would put the cipher before the base64 decode that feeds it.
        """
        params: dict = {"cipher": cipher, "mode": "ecb" if cipher != "rc4" else "stream"}
        if cipher in ("rc4", "chacha20", "salsa20"):
            params["mode"] = "stream"

        positional = list(node.args)
        if positional:
            key = as_bytes(self.folder.fold(positional[0]))
            if key:
                params["key"] = key
                self.add_artifact("key", key, "passed to the cipher", line)
        if len(positional) >= 2:
            mode_name = dotted_name(positional[1]).split(".")[-1]
            if mode_name in MODE_CONSTANTS:
                params["mode"] = MODE_CONSTANTS[mode_name]
        if len(positional) >= 3:
            iv = as_bytes(self.folder.fold(positional[2]))
            if iv:
                params["iv"] = iv
                self.add_artifact("iv", iv, "passed to the cipher", line)
        for keyword in node.keywords:
            value = as_bytes(self.folder.fold(keyword.value))
            if keyword.arg == "key" and value:
                params["key"] = value
                self.add_artifact("key", value, "passed to the cipher", line)
            elif keyword.arg in ("iv", "IV") and value:
                params["iv"] = value
                self.add_artifact("iv", value, "passed to the cipher", line)
            elif keyword.arg == "nonce" and value:
                params["iv"] = value
                self.add_artifact("nonce", value, "passed to the cipher", line)
            elif keyword.arg == "mode":
                mode_name = dotted_name(keyword.value).split(".")[-1]
                if mode_name in MODE_CONSTANTS:
                    params["mode"] = MODE_CONSTANTS[mode_name]

        params["unpad"] = self.unpads
        self.cipher_by_node[id(node)] = params
        self.last_cipher = params

    def read_fernet(self, node: ast.Call, line: int) -> None:
        """`Fernet(key)`: setup too; the operation comes with `.decrypt()`."""
        key = as_bytes(self.folder.fold(node.args[0])) if node.args else None
        params: dict = {"cipher": "fernet"}
        if key:
            params["key"] = key
            self.add_artifact("key", key, "Fernet key (base64 of 32 bytes)", line)
        self.cipher_by_node[id(node)] = params
        self.last_cipher = params

    def read_cipher_use(self, node: ast.Call, method: str, line: int) -> None:
        """`.decrypt(...)` / `.encrypt(...)`: this is the step in the data path."""
        direction = "decode" if method.startswith("decrypt") else "encode"
        params = self.cipher_for(node)
        if params is None:
            return
        cipher = params.get("cipher", "?")
        if cipher == "fernet":
            label = "Fernet (AES-128-CBC + HMAC-SHA256)"
            kind = ""  # the recovery script for Fernet is built by symmetric.py
        else:
            label = f"{cipher.upper()}-{params.get('mode', '?').upper()}"
            if params.get("key"):
                label += f" with a {len(params['key'])}-byte key"
            kind = "cipher"
        verb = " decrypt" if direction == "decode" else " encrypt"
        self.add_operation(kind, label + verb, line, direction, params)

    def cipher_for(self, node: ast.Call) -> dict | None:
        """Find the parameters of the cipher object `.decrypt()` was called on."""
        target = node.func.value if isinstance(node.func, ast.Attribute) else None
        if isinstance(target, ast.Call):  # AES.new(...).decrypt(...)
            return self.cipher_by_node.get(id(target))
        if isinstance(target, ast.Name):  # cipher = AES.new(...) ; cipher.decrypt(...)
            return self.cipher_variables.get(target.id)
        return getattr(self, "last_cipher", None)

    # -- XOR loops ---------------------------------------------------------

    def find_xor(self, node: ast.AST) -> None:
        """Recognise the usual XOR shapes and recover the key when it is a literal.

        Shapes handled:
            bytes(a ^ b for a, b in zip(data, key))
            bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            chr(ord(c) ^ 0x5A) inside a comprehension
            data ^ key                      (ints)
        """
        for inner in ast.walk(node):
            if not isinstance(inner, ast.BinOp) or not isinstance(inner.op, ast.BitXor):
                continue
            line = getattr(inner, "lineno", getattr(node, "lineno", 0))
            key = self.xor_key(inner)
            params = {"key": key} if key else {}
            label = "XOR"
            if key:
                readable = key.decode("ascii") if all(32 <= b < 127 for b in key) else key.hex()
                label = f"XOR with a {len(key)}-byte key ({readable})"
                self.add_artifact("key", key, "XOR key", line)
            self.add_operation("xor", label, line, "both", params)
            return  # one XOR operation per statement is enough

    def xor_key(self, node: ast.BinOp) -> bytes | None:
        """The literal side of `x ^ key`, as bytes, when there is one."""
        for side in (node.right, node.left):
            value = self.folder.fold(side)
            raw = as_bytes(value)
            if raw:
                return raw
            # key[i % len(key)] -> fold `key` itself
            if isinstance(side, ast.Subscript):
                base = as_bytes(self.folder.fold(side.value))
                if base:
                    return base
        return None

    # -- the walk ----------------------------------------------------------

    def run(self) -> None:
        try:
            tree = ast.parse(self.source)
        except (SyntaxError, ValueError) as exc:
            self.report.notes.append(
                f"this file does not parse as Python ({exc}); falling back to regex rules"
            )
            return
        self.walk_body(tree.body)
        self.promote_spare_blob()

    def promote_spare_blob(self) -> None:
        """When a chain was found but no payload, take the best short literal.

        `classify_value` asks for 40+ characters before calling a string a payload,
        to stay quiet on normal code. But a script that clearly decodes something
        must have had *something* to decode, so here the bar is lower.
        """
        decodes = any(operation.kind for operation in self.report.operations)
        if not decodes or self.report.artifacts_of("blob"):
            return
        best: tuple[str, bytes, int] | None = None
        for name, raw, line in self.spare_literals:
            text = raw.decode("utf-8", errors="replace")
            if not (SHORT_BLOB_RE.match(text) or HEX_BLOB_RE.match(text)):
                continue
            is_hex = bool(HEX_BLOB_RE.match(text))
            if (_unhex(text) if is_hex else _unb64(raw)) is None:
                continue
            if best is None or len(raw) > len(best[1]):
                best = (name, raw, line)
        if best is not None:
            name, raw, line = best
            self.add_artifact("blob", raw, "short literal, taken as the payload", line, name)

    def walk_body(self, body: list[ast.stmt]) -> None:
        """Statements in source order; inside one statement, innermost call first."""
        for statement in body:
            self.walk_statement(statement)

    def walk_statement(self, statement: ast.stmt) -> None:
        # Remember assignments so later lines can use the value.
        targets: list[ast.AST] = []
        if isinstance(statement, ast.Assign):
            value = self.folder.fold(statement.value)
            targets = list(statement.targets)
            for target in targets:
                self.folder.remember(target, value)
                if isinstance(target, ast.Name):
                    self.classify_value(target.id, value, statement.lineno)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            value = self.folder.fold(statement.value)
            targets = [statement.target]
            self.folder.remember(statement.target, value)
            if isinstance(statement.target, ast.Name):
                self.classify_value(statement.target.id, value, statement.lineno)

        # Is this line building key material rather than moving the data along?
        self.in_key_setup = any(
            isinstance(target, ast.Name)
            and any(marker in target.id.lower() for marker in self.KEY_MATERIAL)
            for target in targets
        )

        # Expressions: calls innermost first, then the XOR shapes.
        for node in self.expressions(statement):
            for inner in post_order_calls(node):
                self.visit_call(inner)
            if not self.in_key_setup:
                self.find_xor(node)

        # `cipher = AES.new(...)`: remember which variable holds which cipher.
        for target in targets:
            if isinstance(target, ast.Name) and isinstance(statement.value, ast.Call):  # type: ignore[union-attr]
                params = self.cipher_by_node.get(id(statement.value))  # type: ignore[union-attr]
                if params is not None:
                    self.cipher_variables[target.id] = params
        self.in_key_setup = False

        # Then recurse into nested blocks (function bodies, loops, ifs).
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.stmt):
                self.walk_statement(child)
            elif isinstance(child, list):  # pragma: no cover - ast gives stmts directly
                self.walk_body([item for item in child if isinstance(item, ast.stmt)])

    def expressions(self, statement: ast.stmt) -> list[ast.AST]:
        """The expression parts of a statement (not its nested statements)."""
        found: list[ast.AST] = []
        for _field, child in ast.iter_fields(statement):
            if isinstance(child, ast.expr):
                found.append(child)
            elif isinstance(child, list):
                found += [item for item in child if isinstance(item, ast.expr)]
        return found


def post_order_calls(node: ast.AST) -> list[ast.Call]:
    """Every Call inside `node`, innermost first: that is execution order."""
    calls: list[ast.Call] = []

    def walk(current: ast.AST) -> None:
        for child in ast.iter_child_nodes(current):
            if isinstance(child, ast.stmt):
                continue  # nested statements are walked separately, in their own order
            walk(child)
        if isinstance(current, ast.Call):
            calls.append(current)

    walk(node)
    return calls


def analyse_python(source: str, report: LensReport) -> None:
    """Fill `report` with what this Python source does. Never runs it."""
    lens = PythonLens(source, report)
    lens.run()
