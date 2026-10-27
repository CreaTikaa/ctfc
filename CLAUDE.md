# ctfc — CTF Crypto Lab

A terminal + local web tool that helps go from "I found a payload / key / IV / blob" to "plaintext / flag" in forensics CTF challenges, and that points to the right external tool (CyberChef, dcode, xortool, Detect It Easy, hashcat…) when that is the better answer.

## 0. Read this first

- The user is French. **Talk to him in French in chat.** Code, identifiers, docstrings, CLI help and UI strings are in English (route UI strings through one `strings.py` so a French locale can be added later).
- He is strong in forensics/CTF but **not a strong developer**. He must be able to read, understand and modify every file. Prefer boring, explicit, well-commented code over clever code. He is learning from this repo.
- Before starting a milestone: post a short plan (in French) and wait for his OK. After each milestone: run the tests, summarize what works with the exact commands to try it, then commit.
- Ask before adding any dependency that is not listed in section 2.

## 1. The problem being solved

He can usually find the artifacts (XOR key, AES key + IV, RSA key, an encoded blob) but struggles to:
1. **identify** which cipher / mode / encoding / key layout applies,
2. **write correct decoding code** for it.

The tool must identify, try sensible combinations, explain why, and emit reproducible code, so that he can also redo it by hand.

## 2. Hard rules

1. **No LLM / AI / ML at runtime or in dependencies.** The tool will be used in CTFs that ban AI. No API calls to any model provider, no local models, no embeddings. Everything is deterministic heuristics (entropy, statistics, signatures, regex, brute force with scoring). Never add `openai`, `anthropic`, `transformers`, `torch`, `langchain` or similar.
2. **Offline-first.** Core, CLI and web UI must work with no network. Vendor all web assets (no CDN, no npm build step: plain HTML/CSS/JS). Anything that talks to a third party (public CyberChef/dcode links, factordb) is opt-in, shows a "this sends data to a third party" warning, and is disabled when `offline = true` in config or `--offline` is passed.
3. **Never execute analyzed content.** Samples may be malware. Code Lens is static analysis only (Python `ast`, tokenizers/regex for other languages). No `eval`, `exec`, `pickle.loads`, or running pasted scripts.
4. **No `shell=True`.** External tools are launched with argument lists, only those declared in `data/tools.toml`.
5. The web server binds to `127.0.0.1` by default, caps upload size, and sanitizes paths.
6. **Every result is explainable**: what was tried, why it scored well, and a snippet to reproduce it.
7. Allowed runtime dependencies: `pycryptodome`, `flask`, `rich`. Optional extra: `gmpy2` (faster RSA maths). Everything else is stdlib. Dev: `pytest`, `ruff`.

Out of scope: cracking disk containers (VeraCrypt/LUKS/BitLocker), attacking remote targets, anything needing network access to a target. For hashes, identify them and print the ready-to-run hashcat/john command rather than writing a cracker (tiny wordlist / known-plaintext cases are fine).

## 3. Architecture

One core library, two thin front-ends.

```
ctfc/
  core/
    types.py        # Candidate, Input, Recipe dataclasses
    inputs.py       # file / stdin / hex: / b64: / text: parsing, auto-detect hex or base64 text
    scoring.py      # score(bytes) -> (0..1, reasons)
    encodings.py    # hex, base64/32/58/62/85, ascii85, url, html, rot, zlib, gzip, bz2, lzma, quoted-printable
    detect.py       # fingerprinting + ranked guesses (section 4.1)
    xor.py          # section 4.2
    symmetric.py    # AES/DES/3DES/Blowfish/ChaCha20/Salsa20/RC4/TEA/XTEA (section 4.3)
    kdf.py          # EVP_BytesToKey (openssl enc), PBKDF2, scrypt, md5/sha* of a passphrase
    rsa.py          # section 4.5
    hashes.py       # identify + hashcat/john mode table
    classical.py    # caesar, affine, vigenere, atbash, rail fence, (substitution hints)
    lens.py         # static analysis of scripts (section 4.4)
    keyhunt.py      # candidate key extraction from dumps/strings
    pipeline.py     # recipe engine (ordered operations, CyberChef-like)
    codegen.py      # Candidate/Recipe -> standalone Python (pycryptodome) script
    cyberchef.py    # Candidate/Recipe -> CyberChef recipe string + deep link
    tools.py        # external tool registry, suggestion rules, safe launcher
  cli.py
  web/
    app.py          # Flask, JSON API only calls core
    static/         # index.html, app.js, style.css, vendor/
  strings.py
  data/
    magic.toml          # file signatures
    constants.toml      # crypto constants (AES S-box start, MD5/SHA IVs, "expand 32-byte k", TEA delta 0x9e3779b9...)
    hashcat_modes.toml  # hash formats -> hashcat/john modes
    tools.toml          # external tool registry
    words_en_fr.txt     # small word list for plaintext scoring
tests/
docs/
  cheatsheet.md     # one-page decision tree, also shown in the web UI
  how-it-works.md   # plain-language explanation of each module
```

Core functions are pure: `bytes` in, `list[Candidate]` out. No printing, no global state. CLI and web only format and display.

```python
@dataclass
class Candidate:
    label: str             # "AES-256-CBC, key=blob[:32], iv=blob[32:]"
    data: bytes            # output
    score: float           # 0..1
    reasons: list[str]     # "valid PKCS7 padding", "matches flag regex", "PNG magic bytes"
    params: dict           # key / iv / mode / etc. (hex)
    python: str            # standalone snippet that reproduces this result
    cyberchef: str | None  # CyberChef recipe if expressible
```

Brute-force loops take a time/attempt budget, report progress, and can be cancelled.

## 4. Features

### 4.1 Detect (fingerprint)
Given bytes, report and rank guesses with reasons:
- Entropy (whole + per 256-byte window), printable ratio, UTF-8 validity, charset (hex, base64, base32, base58, custom alphabets).
- Length rules: `len % 16 == 0` -> AES-like block; `% 8` -> DES/3DES/Blowfish/TEA; key lengths 16/24/32 -> AES-128/192/256; IV 16 -> CBC/CFB/OFB/CTR; nonce 12 -> GCM/ChaCha20; 48 = 32+16 (key||iv).
- Repeated 16-byte blocks -> ECB. Repeating patterns + partly readable text -> repeating-key XOR.
- Magic bytes (own table in `magic.toml`) and embedded files after a valid end marker (polyglots).
- Prefixes: `Salted__` (openssl enc), `gAAAA` (Fernet), PEM headers, `$mysqlna$`, `$2y$`, JWT shape, etc.
- Crypto constants found in binaries (AES S-box, MD5/SHA IVs, ChaCha "expand 32-byte k", TEA delta, RC4 256-byte init loop).
- Zero-width / invisible Unicode characters in text (U+200B/C/D, U+2060-2064, U+FEFF) -> report and suggest StegCloak-style decoders.

### 4.2 XOR
- Single byte brute force (all 256) with scoring.
- Repeating key: key length via normalized Hamming distance, then per-column single-byte solve using frequency scoring (English + French).
- Known-plaintext / crib: try file headers (`\x89PNG`, `%PDF`, `MZ`, `PK\x03\x04`, `<?xml`, `-----BEGIN`, `http`) and flag prefixes at offset 0 and sliding (crib dragging) to recover key bytes.
- XOR two inputs, XOR with a key from a file, key as hex or text.
- Handle the common "two layers" pattern: repeating key, then a single byte (or the reverse).

### 4.3 Symmetric
Ciphers: AES, DES, 3DES, Blowfish, ChaCha20, Salsa20, RC4, TEA, XTEA. AES modes: ECB, CBC, CTR, CFB, OFB, GCM, plus CBC with ciphertext stealing (CTS) for ciphertexts that are not block-aligned.

The key feature is the **"unknown layout" solver**. Given a ciphertext plus any subset of {key, iv/nonce, blob, passphrase}, the user may leave parts out. Try, in order of likelihood:
- Blob splits: `key||iv`, `iv||key`, key only, 16+16, 24+16, 32+16, 32+12 (nonce).
- Key/IV encodings: raw, hex, base64, ASCII-padded/truncated to 16/24/32.
- IV/nonce prepended to the ciphertext (and `nonce||ct||tag` for GCM), IV = zeros, IV = key prefix.
- Key from passphrase: md5, sha1, sha256, PBKDF2 (common iteration counts), scrypt, openssl `EVP_BytesToKey` with `Salted__` header.
- Padding: PKCS7 (valid padding is a strong signal), zero padding, none.
- Score each plaintext with `scoring.py`; keep the top N with reasons; never print thousands of lines.

Also: Fernet tokens, `openssl enc` files (and print the equivalent `openssl enc -d ...` command).

### 4.4 Code Lens (the highest-value feature for forensics)
Paste or load a script (Python incl. decompiled .pyc, PowerShell, JavaScript, bash, VBS) and get a structured summary, using static analysis only:
- Detect crypto usage: pycryptodome / `cryptography` calls (`AES.new(k, AES.MODE_CBC, iv)`, `Fernet`, `PKCS1_OAEP`), CryptoJS, `openssl enc`, .NET `System.Security.Cryptography`, `ConvertTo-SecureString -Key`, XOR (`-bxor`, `^` in loops, `bxor`), custom loops.
- Extract hardcoded keys, IVs, salts, base64/hex blobs, URLs, file paths, and the order of operations (base64 -> zlib -> XOR ...).
- Output: "this script does X then Y", the extracted parameters, and a **generated inverse script** (Python) that undoes it.
- For layered obfuscation (base64 / zlib / XOR / reversed strings / char-code arrays / string concatenation) offer a safe static "peel the layers" view.
- Python: use `ast`. Others: tokenizer + regex rules kept in a rule table (id, regex, explanation) that is easy to extend.

### 4.5 RSA and hashes
- Parse PEM/DER public and private keys; check that a private key matches a public key (compare modulus); show n, e, bit size.
- Decrypt with a private key (OAEP with SHA-1/256, PKCS#1 v1.5); build a private key from `n,e,p,q` or `n,e,d`.
- Offline attacks on weak keys: small `e` (cube root), shared factors across keys, Fermat, Wiener, small primes. factordb lookup is an opt-in online button.
- Hash identification from length/charset/prefix, with the matching hashcat/john mode and a ready command. Include DB-auth formats seen in forensics (e.g. MySQL native auth `$mysqlna$<salt>*<response>`, NTLM, bcrypt, sha512crypt, Kerberos AS-REP/TGS).

### 4.6 Key hunting
Given a dump / binary / strings output and optionally a ciphertext: extract candidate keys (high-entropy 16/24/32 byte windows, hex/base64 strings of the right length, strings near crypto constants), then test them against the ciphertext with the solver of 4.3 under a visible budget. Report which candidate worked and where it was found (offset).

### 4.7 Pipeline (recipes)
An ordered list of operations (decode, decompress, XOR, AES, RSA, classical...). Save and load as JSON. Each step shows its intermediate output (hexdump + text view). Export as a CyberChef recipe and as a Python script.

### 4.8 External tool bridge
`data/tools.toml` is a registry. Each entry: `id`, `name`, `kind` (`online` | `local` | `embedded`), `url_template` or `command_template`, `suggest_when` (rule ids from detect/lens), `offline_safe` (bool), `notes`.

- Suggest a tool **only when confident** (threshold in config), at most 3 suggestions, each with the reason ("repeating pattern with period 8 -> xortool / CyberChef XOR"). Otherwise show nothing.
- Initial entries: CyberChef, dcode.fr, xortool, Detect It Easy (`diec`), hashcat, john, binwalk, openssl, RsaCtfTool, factordb.
- **CyberChef**: generate a deep link `#recipe=Op(args)...&input=<encoded input>`. Verify the exact URL/input encoding against a real CyberChef build before shipping it. Prefer a local copy: config `cyberchef_url` (default: the embedded copy). The embedded copy is fetched at **build time** by `scripts/fetch_vendor.sh` into `web/static/vendor/cyberchef/` and served locally (check the license and keep the attribution file). Warn before sending data to the public instance.
- **dcode.fr**: online only. Link to the relevant tool page; no embedding; opt-in with warning.
- **Local tools** (xortool, diec, hashcat, john, binwalk, openssl): if `shutil.which` finds them, show the exact command, plus a "Run" button that executes it with an arg list and shows the output. If missing, show the command and the install hint.
- Do not vendor xortool or Detect It Easy. Reimplement the core idea in `xor.py` / `detect.py` ourselves, and call the real tool when installed.

## 5. Terminal interface

Input convention for `<input>`: a file path, `-` for stdin, or `hex:...`, `b64:...`, `text:...`. Bare hex/base64 text is auto-detected, with a note saying so.

```
ctfc detect <input>                 # fingerprint + ranked guesses
ctfc auto <input>                   # "magic": try decoding chains until the output looks meaningful
ctfc xor <input> [--key K] [--keylen N] [--crib TEXT]
ctfc sym <input> [--cipher aes] [--mode cbc] [--key K] [--iv V] [--blob B] [--pass P]
ctfc blob <input>                   # unknown key/iv blob: test the splits
ctfc rsa <args>
ctfc hash <hash>
ctfc lens <script>                  # static crypto analysis + generated inverse script
ctfc keys <dump> --against <ct>     # key hunting
ctfc recipe run <recipe.json>
ctfc tools <input>                  # external tool suggestions for this input
ctfc serve [--port 8137]            # web UI on http://127.0.0.1:8137
```

Terminal output uses `rich`: a ranked table (score, label, short reason), then details for the selected candidate. `--json` on every command. `--show-code` prints the reproduce snippet. Good `--help` with an example per command.

## 6. Web UI

Plain HTML/CSS/JS, dark theme, works offline, usable on a laptop screen during a timed CTF.
- Left: input (paste text/hex/base64, or drag-and-drop a file), with hexdump view and auto-detected format.
- Tabs: **Auto**, **Detect**, **Pipeline**, **XOR**, **Symmetric**, **RSA**, **Code Lens**, **Hash**, **Keys**, **Cheatsheet**.
- Results as ranked cards: score, reasons, output (text + hex), buttons **Copy**, **Show Python**, **Open in CyberChef**, **Use as next input**.
- A "Suggested tools" strip appears only when 4.8 rules fire.
- Keyboard shortcuts (Ctrl+Enter = run). Long jobs stream progress and can be cancelled.
- Optional session workspace in `~/.ctfc/sessions/<name>/` that stores inputs, results and notes, with `ctfc report` exporting a Markdown write-up (added in the last milestone).

## 7. Scoring (`scoring.py`)

Deterministic and documented in `docs/how-it-works.md`. Combine:
- printable-ASCII/UTF-8 ratio and low entropy,
- common-word hit rate (EN + FR word list) and letter-frequency chi-squared,
- magic bytes of known file types (strong), valid PKCS7 padding (strong),
- match against flag regexes (very strong). Flag regexes are configurable in `~/.ctfc/config.toml`, with defaults like `[A-Za-z0-9_]{2,15}\{[^}\n]{4,}\}` plus user-defined ones (e.g. `BZHCTF\{.*?\}`, `STHACK\{.*?\}`).

Every score carries human-readable reasons. Never return a bare number.

## 8. Teaching layer

Because he must be able to redo things by hand when the tool is not at hand:
- Every Candidate has a minimal standalone **pycryptodome snippet** (`python` field). Keep these snippets short and commented.
- `docs/how-it-works.md` explains in plain language: block vs stream ciphers, modes, IV vs nonce, padding, why CBC padding is a good oracle for "did I get the right key", repeating-key XOR key-length detection, RSA/OAEP, KDFs.
- `docs/cheatsheet.md` is the one-page decision tree (code available? -> mirror the encryptor; data only? -> length/entropy/magic; unknown key layout? -> try the splits).

## 9. Tests

`pytest`, with fixtures in `tests/fixtures/` that mirror real challenge shapes (generate them in a `tests/make_fixtures.py` script with known keys; never commit real challenge flags):
- PowerShell-style script obfuscated with a repeating-key XOR plus a single-byte XOR on strings.
- 48-byte `key||iv` blob, AES-256-CBC; and the RSA-OAEP-wrapped variant.
- `openssl enc` file with `Salted__` (md5 and pbkdf2 variants).
- AES-ECB data with repeated blocks; AES-CBC with a non-aligned tail (CTS).
- Fernet token; AES-GCM with `nonce||ct||tag`.
- Multi-layer: base64 -> zlib -> XOR -> text.
- MySQL `$mysqlna$` hash; affine/Caesar with a large shift.
- Text containing zero-width characters.
- Scripts in Python, PowerShell, JS, bash that use each crypto API, for Code Lens.

Ask the user for anonymized samples of his own past challenges and add them as fixtures (with expected outputs). Each core module needs unit tests; a few end-to-end CLI tests too.

## 10. Milestones

Do them in this order. Each ends with passing tests, a demo command, and a commit.

1. **M0 Scaffold**: `pyproject.toml`, package layout, `Candidate`, input parsing, config, CLI skeleton, `ctfc serve` hello page, CI-less local `make test`.
2. **M1 Detect + Auto**: encodings, scoring, magic table, `detect`, `auto` chain, minimal web UI (input + results cards).
3. **M2 XOR**: all of 4.2, with web tab.
4. **M3 Symmetric**: AES first (all modes + layout solver + KDFs + openssl enc), then the other ciphers; codegen snippets.
5. **M4 Code Lens**: Python (`ast`) first, then PowerShell, JS, bash; generated inverse script.
6. **M5 RSA + hashes**.
7. **M6 Pipeline + CyberChef export/deep link + external tool bridge**, embedded CyberChef via `fetch_vendor.sh`.
8. **M7 Key hunting + classical ciphers**.
9. **M8 Sessions + report export + offline bundle + docs polish**: `make bundle` produces a folder with a vendored wheelhouse so it installs on a machine without internet (`pip install --no-index --find-links wheels/ ctfc`), plus a README with a "day of the CTF" quick-start.

## 11. Conventions and commands

- Python 3.11+, type hints everywhere, `ruff` for lint/format, small files, one responsibility each.
- Docstrings say **what the crypto concept is** in one or two lines, not just what the function does.
- No metaprogramming, no plugin frameworks, no async unless needed; Flask sync is fine.
- Errors: clear messages with a suggestion ("ciphertext length 37 is not a multiple of 16: try CTR/CFB/GCM or CTS").
- Keep the repo runnable from a plain folder: `python -m ctfc ...` must work without installation.

```
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check .
ctfc serve        # http://127.0.0.1:8137
```

## 12. First session checklist

1. Read this whole file.
2. Reply in French with a concrete plan for M0 and M1 (files you will create, how you will test), and the questions you need answered (e.g. preferred project folder name, flag formats to add by default, which of the external tools he already has installed).
3. Wait for his OK before writing code.
