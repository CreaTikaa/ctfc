# ctfc — CTF Crypto Lab

Crypto helper for forensics CTFs: go from "I found a payload / key / IV / blob" to
"plaintext / flag". Identifies encodings and ciphers, tries sensible combinations,
explains why, and prints Python code to reproduce every result.

- **No AI at runtime**: deterministic heuristics only (usable in CTFs that ban AI).
- **Offline-first**: CLI and web UI work without network.
- **Never executes analysed content**.

## Install

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Or without installing: `python -m ctfc ...` from this folder.

## Use

```sh
ctfc --help              # list commands (each has an example in its --help)
ctfc detect <input>      # fingerprint + ranked guesses
ctfc auto <input>        # try decoding chains until something readable appears
ctfc serve               # web UI on http://127.0.0.1:8137
```

`<input>` is a file path, `-` for stdin, or `hex:...`, `b64:...`, `text:...`.

Examples with the test fixtures:

```sh
ctfc auto tests/fixtures/layers_b64_zlib_hex.txt --show-code   # base64 -> zlib -> hex -> flag
ctfc auto tests/fixtures/powershell_encoded.txt                # PowerShell -enc payload
ctfc detect tests/fixtures/png_with_zip.png                    # ZIP hidden after a PNG
ctfc detect tests/fixtures/xor_repeating.bin                   # XOR key length 6
ctfc detect tests/fixtures/openssl_salted_md5.b64 --json       # openssl enc, as JSON
```

How it works, in plain language: [docs/how-it-works.md](docs/how-it-works.md).

## Develop

```sh
make test    # pytest
make lint    # ruff
```

Optional config: `~/.ctfc/config.toml` (see `ctfc/config.py` for every key).
