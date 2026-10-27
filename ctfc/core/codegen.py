"""Turn a result into a standalone Python script, so it can be redone by hand.

The generated scripts only use the standard library (and pycryptodome for ciphers,
from milestone M3). They are short and commented on purpose: read them!

A result is described as a chain of `Step`s. A step is either a decoder from
encodings.py (no parameters) or an operation with parameters, like
Step("xor", {"key": "6b6579"}).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.encodings import DECODERS_BY_NAME

INLINE_LIMIT = 512  # inputs bigger than this are read from a file in the snippet


@dataclass(frozen=True)
class Step:
    """One operation of a chain: a decoder name, or "xor" with params {"key": hex}."""

    name: str
    params: dict = field(default_factory=dict, hash=False, compare=False)

    def to_dict(self) -> dict:
        return {"name": self.name, "params": dict(self.params)}


@dataclass
class StepCode:
    """What a step needs in a generated script."""

    label: str  # short text shown in chains: "base64", "xor(key='abc')"
    comment: str  # explanation written above the code line
    python: str  # code transforming the variable `data`
    imports: tuple[str, ...] = ()  # module names: "import zlib"
    import_lines: tuple[str, ...] = ()  # full lines: "from Crypto.Cipher import AES"
    helper: str = ""
    cyberchef: str | None = None


# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------


def key_repr(key: bytes) -> str:
    """Show a key as text when it is readable, otherwise as hex."""
    if key and all(32 <= b < 127 for b in key):
        return repr(key.decode())
    return "0x" + key.hex()


def xor_python(key: bytes) -> str:
    """Python line(s) XORing `data` with a (repeating) key."""
    if len(key) == 1:
        return f"data = bytes(b ^ 0x{key[0]:02x} for b in data)"
    literal = repr(key) if all(32 <= b < 127 for b in key) else f'bytes.fromhex("{key.hex()}")'
    return f"key = {literal}\ndata = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))"


def xor_cyberchef(key: bytes) -> str:
    return "XOR({'option':'Hex','string':'" + key.hex() + "'},'Standard',false)"


def xor_step_code(params: dict) -> StepCode:
    """Code for Step("xor", {"key": hex, optional "layers": [base_key_hex, byte_hex]})."""
    key = bytes.fromhex(params["key"])
    layers = params.get("layers")
    if layers:
        # Two layers: repeating key, then one byte. XOR is associative, so both
        # together equal ONE repeating key (base_key XOR byte): we show the layers.
        base_key, single = bytes.fromhex(layers[0]), bytes.fromhex(layers[1])
        return StepCode(
            label=f"xor(key={key_repr(base_key)}) -> xor(0x{single.hex()})",
            comment=f"XOR with the repeating key {key_repr(base_key)}, then with the "
            f"single byte 0x{single.hex()} (same as one key {key_repr(key)})",
            python=xor_python(base_key) + "\n" + xor_python(single),
            cyberchef=xor_cyberchef(base_key) + xor_cyberchef(single),
        )
    kind = "single-byte" if len(key) == 1 else f"repeating {len(key)}-byte"
    return StepCode(
        label=f"xor(key={key_repr(key)})",
        comment=f"XOR with the {kind} key {key_repr(key)}",
        python=xor_python(key),
        cyberchef=xor_cyberchef(key),
    )


# ---------------------------------------------------------------------------
# Symmetric ciphers (milestone M3)
# ---------------------------------------------------------------------------

# pycryptodome module for each cipher name ("from Crypto.Cipher import AES").
CIPHER_MODULES = {
    "aes": "AES",
    "des": "DES",
    "3des": "DES3",
    "blowfish": "Blowfish",
    "rc4": "ARC4",
    "chacha20": "ChaCha20",
    "salsa20": "Salsa20",
}

# CyberChef operation name for each cipher ("Raw" input/output). Ciphers missing
# from this table have no CyberChef equivalent (TEA/XTEA, CTS).
CYBERCHEF_OPS = {
    "aes": "AES_Decrypt",
    "des": "DES_Decrypt",
    "3des": "Triple_DES_Decrypt",
    "blowfish": "Blowfish_Decrypt",
    "rc4": "RC4",
}
CYBERCHEF_MODES = {
    "cbc": "CBC",
    "ecb": "ECB",
    "ctr": "CTR",
    "cfb": "CFB",
    "ofb": "OFB",
    "gcm": "GCM",
}


def _hex_arg(value: bytes) -> str:
    """CyberChef "toggle string" argument in hex form."""
    return "{'option':'Hex','string':'" + value.hex() + "'}"


def cipher_cyberchef(params: dict) -> str | None:
    """CyberChef recipe for one cipher step, or None when it cannot be expressed."""
    operation = CYBERCHEF_OPS.get(params["cipher"])
    mode = CYBERCHEF_MODES.get(params["mode"])
    if operation is None or params.get("iv_from") or params.get("header_skip"):
        # An IV read out of the data, or a header to strip, cannot be expressed
        # as a recipe argument: the user would get a wrong result silently.
        return None
    key = bytes.fromhex(params["key"])
    if operation == "RC4":
        return f"RC4({_hex_arg(key)},'Latin1','Latin1')"
    if mode is None:
        return None
    iv = bytes.fromhex(params.get("iv") or "")
    # CyberChef removes PKCS7 itself in CBC/ECB; "/NoPadding" keeps the raw bytes.
    if mode in ("CBC", "ECB") and params.get("unpad") != "pkcs7":
        mode += "/NoPadding"
    arguments = [_hex_arg(key), _hex_arg(iv), f"'{mode}'", "'Raw'", "'Raw'"]
    if operation == "AES_Decrypt":
        arguments.append(_hex_arg(bytes.fromhex(params.get("tag") or "")))
    return f"{operation}({','.join(arguments)})"


def _cipher_call(params: dict, block_size: int) -> str:
    """The pycryptodome (or helper) call that decrypts `data`."""
    cipher = params["cipher"]
    mode = params["mode"]
    module = CIPHER_MODULES.get(cipher)

    if cipher in ("tea", "xtea"):
        endian = ">" if params.get("endian", "big") == "big" else "<"
        block = f'lambda b, k: {cipher}_decrypt_block(b, k, "{endian}")'
        if mode == "cbc":
            return f"data = cbc_decrypt(data, key, iv, {block}, 8)"
        return f"data = ecb_decrypt(data, key, {block}, 8)"
    if mode in ("cts", "cts3"):
        block = f"lambda b, k: {module}.new(k, {module}.MODE_ECB).decrypt(b)"
        swapped = "True" if mode == "cts3" else "False"
        return (
            f"data = cbc_cts_decrypt(\n"
            f"    data, key, iv, {block}, {block_size}, swapped={swapped}\n"
            f")"
        )
    if mode == "stream":
        if cipher == "rc4":
            return "data = ARC4.new(key).decrypt(data)"
        seek = "\ncipher.seek(64)  # start at block counter 1" if params.get("counter") else ""
        return f"cipher = {module}.new(key=key, nonce=nonce){seek}\ndata = cipher.decrypt(data)"
    if mode == "ecb":
        return f"data = {module}.new(key, {module}.MODE_ECB).decrypt(data)"
    if mode == "cbc":
        return f"data = {module}.new(key, {module}.MODE_CBC, iv).decrypt(data)"
    if mode == "ctr":
        if params.get("ctr_style") == "nonce8":
            return f"data = {module}.new(key, {module}.MODE_CTR, nonce=nonce).decrypt(data)"
        # A full 16-byte counter block (what `openssl enc -aes-256-ctr` uses).
        return (
            f'data = {module}.new(key, {module}.MODE_CTR, nonce=b"", '
            "initial_value=iv).decrypt(data)"
        )
    if mode == "cfb":
        return (
            f"data = {module}.new(key, {module}.MODE_CFB, iv, "
            f"segment_size={block_size * 8}).decrypt(data)"
        )
    if mode == "cfb8":
        return f"data = {module}.new(key, {module}.MODE_CFB, iv).decrypt(data)"
    if mode == "ofb":
        return f"data = {module}.new(key, {module}.MODE_OFB, iv).decrypt(data)"
    if mode == "gcm":
        if params.get("tag"):
            return (
                f"cipher = {module}.new(key, {module}.MODE_GCM, nonce=nonce)\n"
                "data = cipher.decrypt_and_verify(data, tag)  # raises if the key is wrong"
            )
        return f"data = {module}.new(key, {module}.MODE_GCM, nonce=nonce).decrypt(data)"
    raise ValueError(f"no code for mode {mode!r}")


def cipher_step_code(params: dict) -> StepCode:
    """Code for Step("cipher", {...}): see `symmetric.step_params` for the fields."""
    from ctfc.core.blockmodes import CBC_HELPER, CTS_HELPER, ECB_HELPER
    from ctfc.core.kdf import EVP_HELPER
    from ctfc.core.tea import TEA_HELPER, XTEA_HELPER

    cipher, mode = params["cipher"], params["mode"]
    block_size = 8 if cipher in ("tea", "xtea", "des", "3des", "blowfish") else 16
    key = bytes.fromhex(params["key"])
    # Stream ciphers and GCM call it a nonce, block modes call it an IV.
    uses_nonce = mode in ("stream", "gcm") or params.get("ctr_style") == "nonce8"
    nonce_name = "nonce" if uses_nonce else "iv"

    lines: list[str] = []
    imports: list[str] = []
    import_lines: list[str] = []
    helpers: list[str] = []

    # 1. the key: either derived from a passphrase, or a literal
    kdf = params.get("kdf")
    if kdf:
        imports.append("hashlib")
        password = str(kdf["password"])
        if password.isascii() and password.isprintable() and '"' not in password:
            lines.append(f'password = b"{password}"')
        else:
            lines.append(f'password = bytes.fromhex("{password.encode().hex()}")')
        if kdf.get("salt"):
            lines.append(f'salt = bytes.fromhex("{kdf["salt"]}")')
        lines.append(kdf["python"])
        if "evp_bytes_to_key" in kdf["python"]:
            helpers.append(EVP_HELPER)
    else:
        lines.append(f'key = bytes.fromhex("{params["key"]}")')

    # 2. drop a container header (e.g. openssl's "Salted__" + salt)
    if params.get("header_skip"):
        why = params.get("header_why", "header")
        lines.append(f"data = data[{params['header_skip']}:]  # {why}")

    # 3. the IV / nonce, which may be hiding at the start of the ciphertext
    if params.get("iv_from") == "prefix":
        size = params["iv_size"]
        lines.append(f"{nonce_name} = data[:{size}]  # the IV was prepended to the ciphertext")
        lines.append(f"data = data[{size}:]")
    elif kdf and kdf.get("gives_iv"):
        pass  # the KDF derived key *and* iv in one go (openssl enc does this)
    elif params.get("iv"):
        lines.append(f'{nonce_name} = bytes.fromhex("{params["iv"]}")')

    # 4. cut what is not ciphertext either (the GCM tag at the end)
    if params.get("tag"):
        lines.append("tag = data[-16:]  # AES-GCM authentication tag")
        lines.append("data = data[:-16]")

    # 4. the decryption itself
    lines.append(_cipher_call(params, block_size))

    # 5. remove the padding
    if params.get("unpad") == "pkcs7":
        import_lines.append("from Crypto.Util.Padding import unpad")
        lines.append(f"data = unpad(data, {block_size})  # PKCS7")
    elif params.get("unpad") == "zero":
        lines.append('data = data.rstrip(b"\\x00")  # zero padding')

    if cipher in ("tea", "xtea"):
        imports.append("struct")
        helpers.append(TEA_HELPER if cipher == "tea" else XTEA_HELPER)
        helpers.append(CBC_HELPER if mode == "cbc" else ECB_HELPER)
    else:
        import_lines.insert(0, f"from Crypto.Cipher import {CIPHER_MODULES[cipher]}")
    if mode in ("cts", "cts3"):
        helpers += [CBC_HELPER, CTS_HELPER]

    label = params.get("label") or f"{cipher}-{mode}"
    return StepCode(
        label=label,
        comment=label + (f", key {key_repr(key)}" if len(key) <= 32 else ""),
        python="\n".join(lines),
        imports=tuple(imports),
        import_lines=tuple(import_lines),
        helper="\n".join(helpers),
        cyberchef=cipher_cyberchef(params),
    )


# ---------------------------------------------------------------------------
# Generic steps and chains
# ---------------------------------------------------------------------------


def step_code(step: Step) -> StepCode:
    """Look up how to write one step in Python / CyberChef."""
    if step.name == "xor":
        return xor_step_code(step.params)
    if step.name == "cipher":
        return cipher_step_code(step.params)
    decoder = DECODERS_BY_NAME[step.name]
    return StepCode(
        label=decoder.name,
        comment=decoder.label,
        python=decoder.python,
        imports=decoder.imports,
        helper=decoder.helper,
        cyberchef=decoder.cyberchef,
    )


def chain_label(steps: list[Step]) -> str:
    return " -> ".join(step_code(step).label for step in steps)


def input_line(data: bytes) -> str:
    """Python line that defines `data` with the input bytes."""
    if len(data) > INLINE_LIMIT:
        return 'data = open("input.bin", "rb").read()  # <- your input file'
    try:
        text = data.decode("ascii")
        if text.isprintable():
            return f"data = {data!r}"
    except UnicodeDecodeError:
        pass
    return f'data = bytes.fromhex("{data.hex()}")'


def chain_snippet(data: bytes, steps: list[Step]) -> str:
    """Script that applies `steps` in order to `data` and prints the result."""
    codes = [step_code(step) for step in steps]
    imports = sorted({module for code in codes for module in code.imports})
    helpers: list[str] = []
    for code in codes:
        if code.helper and code.helper not in helpers:
            helpers.append(code.helper)

    lines = [f'"""Reproduce: {chain_label(steps)}  (generated by ctfc)"""']
    lines += [f"import {module}" for module in imports]
    extra_imports: list[str] = []
    for code in codes:
        for line in code.import_lines:
            if line not in extra_imports:
                extra_imports.append(line)
    lines += extra_imports
    for helper in helpers:
        lines.append(helper.rstrip())
    lines.append("")
    lines.append(input_line(data))
    for number, code in enumerate(codes, start=1):
        lines.append(f"# step {number}: {code.comment}")
        lines.append(code.python)
    lines.append('print(data.decode("utf-8", errors="replace"))')
    return "\n".join(lines) + "\n"


def chain_cyberchef(steps: list[Step]) -> str | None:
    """CyberChef recipe for the chain, or None if one step has no CyberChef equivalent.

    The format is CyberChef's compact "chef" format: operations written one after
    the other, e.g. From_Base64('A-Za-z0-9+/=',true,false)Zlib_Inflate(...).
    """
    operations = []
    for step in steps:
        operation = step_code(step).cyberchef
        if operation is None:
            return None
        operations.append(operation)
    return "".join(operations)
