"""All user-facing text (CLI help, messages, web labels) lives here.

Why: a French locale can be added later by writing a second dictionary,
without touching the rest of the code.

Usage:
    from ctfc.strings import t
    print(t("not_yet", command="xor", milestone="M2"))
"""

from __future__ import annotations

EN: dict[str, str] = {
    # --- general CLI ---
    "app_description": (
        "ctfc - CTF Crypto Lab. Identify encodings and ciphers, try sensible "
        "combinations, explain why, and print code to reproduce the result."
    ),
    "app_epilog": (
        "Input convention: a file path, '-' for stdin, or hex:..., b64:..., text:... "
        "Bare hex/base64 text is auto-detected."
    ),
    "opt_json": "print machine-readable JSON instead of tables",
    "opt_show_code": "print the Python snippet that reproduces the best result",
    "opt_offline": "never contact a third party (overrides the config file)",
    "opt_config": "path to a config.toml (default: ~/.ctfc/config.toml)",
    "opt_top": "how many candidates to show (default from config)",
    "arg_input": "file path, '-', hex:..., b64:..., text:... (or bare hex/base64)",
    "not_yet": "'{command}' is not implemented yet (planned for milestone {milestone}).",
    "error_prefix": "error",
    "warning_prefix": "warning",
    "note_prefix": "note",
    # --- command help (one line each, plus an example) ---
    "cmd_detect": "fingerprint the input and rank guesses (encoding, cipher, file type)",
    "cmd_detect_ex": "example: ctfc detect b64:U2FsdGVkX1+...  |  ctfc detect dump.bin",
    "cmd_auto": "'magic' mode: try decoding chains until the output looks meaningful",
    "cmd_auto_ex": "example: ctfc auto 'eJzLSM3JyVcozy/KSQEAGgQEXQ=='",
    "cmd_xor": "XOR solver: single byte, repeating key, crib dragging",
    "cmd_xor_ex": "example: ctfc xor secret.bin --keylen 8 --crib 'CYBN{'",
    "cmd_sym": "symmetric ciphers (AES, DES, ...) with the unknown-layout solver",
    "cmd_sym_ex": "example: ctfc sym ct.bin --cipher aes --mode cbc --blob hex:00112233...",
    "cmd_blob": "unknown key/iv blob: test the usual splits against a ciphertext",
    "cmd_blob_ex": "example: ctfc blob keyiv.bin --against ct.bin",
    "cmd_rsa": "RSA: parse keys, decrypt, weak-key attacks",
    "cmd_rsa_ex": "example: ctfc rsa --key priv.pem --decrypt ct.bin",
    "cmd_hash": "identify a hash and print the hashcat/john command",
    "cmd_hash_ex": "example: ctfc hash '$2y$10$...'",
    "cmd_lens": "static crypto analysis of a script + generated inverse script",
    "cmd_lens_ex": "example: ctfc lens dropper.ps1",
    "cmd_keys": "hunt candidate keys in a dump and test them against a ciphertext",
    "cmd_keys_ex": "example: ctfc keys memdump.raw --against ct.bin",
    "cmd_recipe": "run a saved recipe (ordered operations)",
    "cmd_recipe_ex": "example: ctfc recipe run layers.json input.bin",
    "cmd_tools": "external tool suggestions for this input",
    "cmd_tools_ex": "example: ctfc tools sample.bin",
    "cmd_serve": "start the local web UI",
    "cmd_serve_ex": "example: ctfc serve --port 8137  (then open http://127.0.0.1:8137)",
    "opt_port": "port to listen on",
    "opt_host": "address to bind (default 127.0.0.1; anything else exposes the tool)",
    "serve_start": "ctfc web UI on http://{host}:{port}  (Ctrl+C to stop)",
    "serve_exposed": (
        "binding to {host}: the tool will be reachable from other machines. "
        "Only do this on a trusted network."
    ),
    # --- web ---
    "web_title": "ctfc - CTF Crypto Lab",
    "upload_too_big": "upload too large (limit {limit} MB, set max_upload_mb in config)",
}

# The active language table. A French table can be added later: FR = {...}.
_ACTIVE = EN


def t(key: str, **kwargs: object) -> str:
    """Return the text for `key`, with `{placeholders}` filled from kwargs."""
    text = _ACTIVE.get(key, EN.get(key, key))
    return text.format(**kwargs) if kwargs else text
