"""All user-facing text (CLI help, messages, web labels) lives here.

Why: a French locale can be added later by writing a second dictionary,
without touching the rest of the code.

Usage:
    from ctfc.strings import t
    print(t("not_yet", command="lens", milestone="M4"))
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
    "cmd_xor": "XOR solver: single byte, repeating key, known plaintext, crib dragging",
    "cmd_xor_ex": (
        "example: ctfc xor secret.bin  |  ctfc xor secret.bin --keylen 8 --crib 'CYBN{'  |  "
        "ctfc xor secret.bin --key text:s3cr3t  |  ctfc xor c1.bin --with c2.bin --crib 'the '"
    ),
    "opt_xor_key": "decrypt with this key (hex:..., text:..., b64:... or a key file)",
    "opt_xor_keylen": "only try this key length (1 = single byte)",
    "opt_xor_crib": "known plaintext somewhere in the data, e.g. 'CYBN{' or hex:89504e47",
    "opt_xor_with": "XOR with a second input (two messages encrypted with the same key)",
    "opt_xor_hashed": (
        "always try md5/sha of the embedded word list as the key (automatic when "
        "nothing else convinces)"
    ),
    "interrupted": "interrupted (Ctrl+C)",
    "cmd_sym": "symmetric ciphers (AES, DES, ...) with the unknown-layout solver",
    "cmd_sym_ex": (
        "examples: ctfc sym ct.bin --blob keyiv.b64  |  "
        "ctfc sym ct.bin --key hex:00112233... --mode cbc  |  "
        "ctfc sym secret.enc --pass password123  |  ctfc sym secret.enc --passwords"
    ),
    "opt_sym_cipher": (
        "aes, 3des, des, blowfish, chacha20, salsa20, rc4, tea, xtea (default: try them all)"
    ),
    "opt_sym_mode": "ecb, cbc, ctr, gcm, cfb, cfb8, ofb, cts (CS1), cts3 (default: try them)",
    "opt_sym_key": (
        "the key: hex:..., b64:..., text:... or a file (raw and decoded forms are both tried)"
    ),
    "opt_sym_iv": "the IV / nonce (if you do not pass one, the usual places are tried)",
    "opt_sym_blob": "a blob that may hold the key and/or the IV: every usual split is tried",
    "opt_sym_pass": "passphrase: md5/sha, PBKDF2, scrypt and openssl EVP_BytesToKey are tried",
    "opt_sym_passwords": "try the embedded password list (10000 entries, offline) as passphrases",
    "opt_seconds": "time budget for the search, in seconds (default 30)",
    "cmd_blob": "unknown key/iv blob: test the usual splits against a ciphertext",
    "cmd_blob_ex": "example: ctfc blob keyiv.b64 --against ct.bin",
    "opt_blob_against": "the ciphertext to test the splits against (file, hex:..., b64:...)",
    "cmd_rsa": "RSA: inspect keys, compare them, decrypt, attack weak keys",
    "cmd_rsa_ex": (
        "examples: ctfc rsa --key priv.pem --decrypt ct.bin  |  "
        "ctfc rsa --key pub.pem --decrypt ct.bin --attack  |  "
        "ctfc rsa --n 0x... --e 3 --decrypt ct.bin  |  "
        "ctfc rsa --key a.pub --attack --other b.pub  |  ctfc rsa --key priv.pem --check pub.pem"
    ),
    "opt_rsa_key": "a PEM / DER / OpenSSH key file (public or private)",
    "opt_rsa_pass": "passphrase of an encrypted private key",
    "opt_rsa_decrypt": "ciphertext to decrypt (file, hex:..., b64:...)",
    "opt_rsa_attack": "look for a weakness: small primes, Fermat, Wiener, Pollard, shared prime",
    "opt_rsa_other": "another key or modulus to compare with (repeatable): finds a shared prime",
    "opt_rsa_check": "another key: check whether it is the pair of this one (same modulus)",
    "opt_rsa_n": "the modulus n, in decimal or 0x hex",
    "opt_rsa_e": "the public exponent e (default 65537)",
    "opt_rsa_d": "the private exponent d",
    "opt_rsa_p": "the prime p",
    "opt_rsa_q": "the prime q",
    "cmd_hash": "identify a hash and print the hashcat/john command",
    "cmd_hash_ex": (
        "examples: ctfc hash '$2y$10$...'  |  ctfc hash 5f4dcc3b5aa765d61d8327deb882cf99  |  "
        "ctfc hash '$mysqlna$...' --json"
    ),
    "arg_hash": "the hash string (quote it: it often contains $)",
    "opt_hash_no_passwords": "do not try the embedded password list on unsalted formats",
    "cmd_lens": "static crypto analysis of a script + generated recovery script",
    "cmd_lens_ex": (
        "examples: ctfc lens dropper.ps1  |  ctfc lens stage1.py --show-code  |  "
        "ctfc lens obfuscated.js --json"
    ),
    "arg_script": (
        "the script to analyse: a file path, '-' for stdin, or text:... (NEVER executed)"
    ),
    "cmd_keys": "hunt candidate keys in a dump and test them against a ciphertext",
    "cmd_keys_ex": "example: ctfc keys memdump.raw --against ct.bin",
    "cmd_recipe": "run, save or show a recipe (an ordered list of operations)",
    "cmd_recipe_ex": (
        "examples: ctfc recipe run layers.json payload.bin  |  "
        "ctfc recipe save found.json payload.bin  |  ctfc recipe show found.json"
    ),
    "arg_recipe_action": "run (apply it), save (what auto found), show (print the JSON)",
    "arg_recipe": "the recipe file (JSON)",
    "opt_recipe_cyberchef": "also print a CyberChef link for the recipe",
    "recipe_nothing_to_save": "auto found no chain on this input: nothing to save.",
    "cmd_tools": "suggest the external tools that fit this input, and run them",
    "cmd_tools_ex": (
        "examples: ctfc tools sample.bin  |  ctfc tools dump.bin --list  |  "
        "ctfc tools secret.bin --run xortool"
    ),
    "opt_tools_list": "list every tool ctfc knows about and whether it is installed here",
    "opt_tools_run": "run this tool (by id) on the input and show its output",
    "opt_tools_wordlist": "wordlist path, for the tools that need one",
    "opt_tools_password": "passphrase, for the tools that need one (openssl)",
    "tool_offline_refused": "{name} would send your data to a third party, and offline mode is on.",
    "cmd_pcap": "pull HTTP bodies, DNS exfiltration and TCP streams out of a capture",
    "cmd_pcap_ex": (
        "examples: ctfc pcap capture.pcap  |  ctfc pcap traffic.pcapng --extract ./objects  "
        "(then: ctfc scan ./objects)"
    ),
    "opt_pcap_extract": "also save every extracted object into this folder",
    "cmd_scan": "run detect + auto on every file of a folder and rank them",
    "cmd_scan_ex": (
        "examples: ctfc scan _dump.bin.extracted  |  ctfc scan ./objects --seconds 300  |  "
        "ctfc scan ./carved --json"
    ),
    "arg_folder": "the folder to scan (or a single file)",
    "opt_scan_no_recursive": "do not go into subfolders",
    "opt_scan_per_file": "time budget per file, in seconds (default 3)",
    "opt_scan_min": "only report files at least this interesting, 0..1 (default 0.4)",
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
    "web_xor_help": "Single byte, repeating key (length found automatically), file headers, "
    "crib dragging. Every field is optional.",
    "web_xor_key": "key (decrypt with it)",
    "web_xor_key_ph": "text:s3cr3t, hex:41424344, b64:...",
    "web_xor_keylen": "key length",
    "web_xor_keylen_ph": "auto",
    "web_xor_crib": "crib (known plaintext)",
    "web_xor_crib_ph": "CYBN{  or  hex:89504e47",
    "web_xor_other": "second input: XOR the two (same key stream used twice)",
    "web_xor_other_ph": "hex / base64 / text of the other ciphertext",
    "web_xor_hashed": "try md5/sha of common words as the key (automatic if nothing else works)",
    "web_key_lengths": "Likely key lengths (Hamming: lower is better, random ~ 4.0; "
    "coincidence ratio: higher is better)",
    "web_sym_help": "Give what you have (key, IV, blob, passphrase): the rest is guessed. "
    "Valid PKCS7 padding or a GCM tag tells us when the key is right.",
    "web_sym_key": "key",
    "web_sym_key_ph": "hex, base64 or text (both readings are tried)",
    "web_sym_iv": "IV / nonce",
    "web_sym_iv_ph": "empty = try the usual places",
    "web_sym_blob": "blob (key and/or IV)",
    "web_sym_blob_ph": "e.g. 48 bytes = key||iv, every split is tried",
    "web_sym_pass": "passphrase",
    "web_sym_pass_ph": "md5/sha, PBKDF2, scrypt, openssl are tried",
    "web_sym_cipher": "cipher",
    "web_sym_mode": "mode",
    "web_sym_auto": "auto (try them all)",
    "web_sym_seconds": "time budget (s)",
    "web_sym_passwords": "try the embedded password list (10000 entries, offline)",
    "web_lens_help": "Paste or drop a script (Python, PowerShell, JS, bash, VBS). "
    "It is read statically and NEVER executed.",
    "web_lens_language": "language",
    "web_lens_nothing": "Nothing recognised. Is it really a script?",
    "web_lens_peeled": "Layers peeled off the embedded blobs (static, nothing was run)",
    "web_lens_operations": "What it does to the data, in order",
    "web_lens_artifacts": "Extracted values",
    "web_lens_behaviour": "Behaviour (beyond transforming data)",
    "web_lens_recovery": "Recovery script",
    "web_lens_complete": "complete",
    "web_lens_partial": "partial: check it",
    "web_rsa_help": "Ciphertext on the left, key (or n/e) in the options. Tick the box to look "
    "for a weak key. Nothing is sent anywhere.",
    "web_rsa_key": "key (PEM) - paste it, or leave empty and fill n/e below",
    "web_rsa_key_ph": "-----BEGIN PUBLIC KEY----- ...",
    "web_rsa_number_ph": "decimal, or 0x for hex",
    "web_rsa_optional_ph": "optional",
    "web_rsa_n": "n (modulus)",
    "web_rsa_e": "e (exponent)",
    "web_rsa_d": "d (private exponent)",
    "web_rsa_p": "p",
    "web_rsa_q": "q",
    "web_rsa_other": "other keys or moduli (one per line): finds a shared prime",
    "web_rsa_attack": "look for a weakness (small primes, Fermat, Wiener, Pollard)",
    "web_rsa_facts": "The key",
    "web_rsa_tried": "tried",
    "web_rsa_no_weakness": "no weakness found offline",
    "web_hash_help": "Paste a hash. ctfc identifies the format and gives the hashcat / john "
    "command; it does not crack it (except a free try on the embedded list).",
    "web_hash_formats": "Possible formats, best first",
    "web_hash_none": "No known format matches. Try the Detect tab: it may be base64 or hex.",
    "web_hash_no_passwords": "do not try the embedded password list",
    "web_blob_needs_ct": "to test a blob, also give the ciphertext it should decrypt.",
    "web_cancel": "Cancel",
    "web_cancelled": "Cancelled: partial results below.",
    "web_attempts": "attempts",
    "web_no_result": "No convincing result. Try the Detect tab for hints.",
    "web_no_guess": "No specific guess. Try the Auto tab.",
    "web_facts": "Facts",
    "web_guesses": "Ranked guesses",
    "web_entropy_chart": "Entropy per 256-byte window (0 to 8 bits/byte)",
    "web_next_step": "next",
    "web_apply": "Apply in",
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
    # Pipeline tab (M6)
    "web_pipeline_help": "Your own chain of operations, applied in order, with the output of "
    "every step. Ctrl+Enter runs it; Auto results have an 'Open in Pipeline' button.",
    "web_pipeline_recipe": 'recipe (JSON): {"name": ..., "steps": [{"op": "base64"}, ...]}',
    "web_pipeline_add": "add a step:",
    "web_pipeline_load": "Load .json",
    "web_pipeline_save": "Save .json",
    "web_pipeline_clear": "Clear",
    "web_pipeline_step": "step",
    "web_pipeline_failed": "A step failed: the output of the step before it is shown above.",
    "web_pipeline_export": "The whole recipe",
    "web_pipeline_no_cyberchef": "(no CyberChef equivalent for one of the steps)",
    "web_pipeline_bad_json": "The recipe is not valid JSON:",
    "web_pipeline_ask_key": "XOR key, in hex (e.g. 4b337921)",
    "web_open_pipeline": "Open in Pipeline",
    # CyberChef links
    "web_open_cyberchef": "Open in CyberChef",
    "web_no_cyberchef": "No CyberChef link for this result.",
    "web_cyberchef_confirm": "{note}\n\nOpen it anyway?",
    "web_cyberchef_truncated": "CyberChef got the first 4096 bytes only (a URL cannot carry more).",
    # Suggested tools strip
    "web_suggested": "Suggested tools",
    "web_tool_online": "online",
    "web_tool_local": "local copy",
    "web_tool_installed": "installed",
    "web_tool_missing": "not installed",
    "web_tool_install": "install",
    "web_tool_copy_command": "Copy command",
    "web_tool_open": "Open",
    "web_tool_run": "Run",
    "upload_too_big": "upload too large (limit {limit} MB, set max_upload_mb in config)",
}

# The active language table. A French table can be added later: FR = {...}.
_ACTIVE = EN


def t(key: str, **kwargs: object) -> str:
    """Return the text for `key`, with `{placeholders}` filled from kwargs."""
    text = _ACTIVE.get(key, EN.get(key, key))
    return text.format(**kwargs) if kwargs else text
