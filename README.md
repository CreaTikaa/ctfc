# ctfc ~ ctf crypto helper

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
ctfc xor <input>         # XOR: single byte, repeating key, known plaintext, two inputs
ctfc sym <input>         # AES/DES/ChaCha20/... with whatever key material you have
ctfc lens <script>       # static analysis of a dropper + generated inverse script
ctfc rsa / ctfc hash     # RSA keys and weak-key attacks; hash format + hashcat mode
ctfc classical <input>   # Caesar, affine, Atbash, Vigenère, rail fence
ctfc keys <dump> --against <ct>   # find the key in a memory dump / binary, test it
ctfc lens <script> --against <file>   # mirror the encryptor on the file it produced
ctfc session new <chall>     # record every command; ctfc report --lang fr = the write-up
ctfc cheatsheet              # the one-page decision tree
ctfc recipe run r.json <input>   # your own chain of steps, each output shown
ctfc tools <input>       # which external tool fits (xortool, hashcat, CyberChef...)
ctfc serve               # web UI on http://127.0.0.1:8137
```

Once, with internet: `make vendor` downloads the official CyberChef (v11.5.0,
hash-checked) so that "Open in CyberChef" works offline.

`<input>` is a file path, `-` for stdin, or `hex:...`, `b64:...`, `text:...`.

Examples with the test fixtures:

```sh
ctfc auto tests/fixtures/layers_b64_zlib_hex.txt --show-code   # base64 -> zlib -> hex -> flag
ctfc auto tests/fixtures/powershell_encoded.txt                # PowerShell -enc payload
ctfc detect tests/fixtures/png_with_zip.png                    # ZIP hidden after a PNG
ctfc detect tests/fixtures/xor_repeating.bin                   # XOR key length 6
ctfc detect tests/fixtures/openssl_salted_md5.b64 --json       # openssl enc, as JSON
ctfc xor tests/fixtures/xor_two_layers.bin                     # key 'secret' + byte 0x42
ctfc xor tests/fixtures/xor_png.bin                            # PNG header as known plaintext
ctfc xor tests/fixtures/xor_short_crib.bin --crib 'CYBN{'      # crib dragging
ctfc xor tests/fixtures/two_time_pad_1.bin --with tests/fixtures/two_time_pad_2.bin --crib ' the '
ctfc auto tests/fixtures/powershell_xor.b64                    # base64 -> XOR -> PowerShell
```

**The day of the CTF**: [docs/day-of-the-ctf.md](docs/day-of-the-ctf.md) (sessions,
write-up, `make bundle` for a machine without internet).

How it works, in plain language: [docs/how-it-works.md](docs/how-it-works.md).
The decision tree: `ctfc cheatsheet` ([source](ctfc/data/cheatsheet.md)).

## Develop

```sh
make test    # pytest
make lint    # ruff
```

Optional config: `~/.ctfc/config.toml` (see `ctfc/config.py` for every key).
