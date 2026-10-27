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
    # --- web (every key starting with "web_" is sent to the browser) ---
    "web_title": "ctfc - CTF Crypto Lab",
    "web_input": "Input",
    "web_format": "format",
    "web_format_auto": "auto (hex / base64 / text)",
    "web_format_text": "text",
    "web_format_hex": "hex",
    "web_format_b64": "base64",
    "web_placeholder": "Paste text, hex or base64 here, or drop a file below.\n"
    "Prefixes work too: hex:..., b64:..., text:...",
    "web_drop": "Drop a file here, or click to choose one",
    "web_clear": "clear",
    "web_hexdump": "Hexdump (first 512 bytes)",
    "web_run": "Run",
    "web_running": "Running...",
    "web_shortcut": "Ctrl+Enter = run",
    "web_offline": "offline",
    "web_coming": "coming in milestone {milestone}",
    "web_tab_auto": "Auto",
    "web_tab_detect": "Detect",
    "web_tab_pipeline": "Pipeline",
    "web_tab_xor": "XOR",
    "web_tab_sym": "Symmetric",
    "web_tab_rsa": "RSA",
    "web_tab_lens": "Code Lens",
    "web_tab_hash": "Hash",
    "web_tab_keys": "Keys",
    "web_tab_cheatsheet": "Cheatsheet",
    "web_auto_help": "Tries decoding chains (base64, hex, zlib, rot13, ...) and ranks the outputs.",
    "web_detect_help": "Fingerprints the input: entropy, charset, magic bytes, lengths, constants.",
    "web_no_result": "No convincing result. Try the Detect tab for hints.",
    "web_no_guess": "No specific guess. Try the Auto tab.",
    "web_facts": "Facts",
    "web_guesses": "Ranked guesses",
    "web_entropy_chart": "Entropy per 256-byte window (0 to 8 bits/byte)",
    "web_next_step": "next",
    "web_copy": "Copy",
    "web_copied": "Copied",
    "web_show_python": "Show Python",
    "web_hide_python": "Hide Python",
    "web_copy_cyberchef": "Copy CyberChef recipe",
    "web_next_input": "Use as next input",
    "web_view_hex": "hex view",
    "web_view_text": "text view",
    "web_bytes": "bytes",
    "web_empty_input": "The input is empty.",
    "upload_too_big": "upload too large (limit {limit} MB, set max_upload_mb in config)",
}

# The active language table. A French table can be added later: FR = {...}.
_ACTIVE = EN


def t(key: str, **kwargs: object) -> str:
    """Return the text for `key`, with `{placeholders}` filled from kwargs."""
    text = _ACTIVE.get(key, EN.get(key, key))
    return text.format(**kwargs) if kwargs else text
