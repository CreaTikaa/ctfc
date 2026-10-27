# Handoff notes (for the next agent)

Last update: 2026-10-27, after milestone M4. Read `CLAUDE.md` first, then this file.

## 1. Working agreement with the user

- Chat in **French**. Code, docstrings, CLI help, UI strings in English (UI strings in `ctfc/strings.py`).
- Before each milestone: post a short plan in French and **wait for his OK**. After it: tests, demo
  commands, commit, and **push to GitHub** (`git push origin main`, repo
  https://github.com/CreaTikaa/ctfc, `gh` is logged in as CreaTikaa; pushing is pre-authorized).
- Commit messages end with the `Co-Authored-By` line given by the harness.
- He likes improvement ideas: propose them at the end of a milestone (list in section 6). He said
  the remaining ideas will be done **after M3, once it is functional** - so they are open now.
- Decisions already taken: package name `ctfc` in `~/apps/ctfc`; default flag formats = generic
  regex `[A-Za-z0-9_]{2,15}\{[^}\n]{4,}\}` + `CYBN\{[^}\n]*\}`, and `CYBN{` is also searched in
  base64 (`flag_prefixes`). No anonymized challenge samples yet (he will send some later).

## 2. Status

| Milestone | Commit | Content |
|-----------|--------|---------|
| M0 scaffold | `a8e1937` | pyproject, Makefile, types, inputs, config, strings, argparse CLI, Flask hello |
| M1 detect + auto | `dcd775e` | encodings, scoring, flags, magic, detect, auto, rich CLI, web UI (Auto/Detect) |
| M2 XOR | `369bfef` | xor.py, XOR in auto, `ctfc xor`, web jobs (progress/cancel), XOR tab |
| M3 symmetric | `244a7ae` | symmetric.py, kdf.py, tea.py, blockmodes.py, `ctfc sym`, `ctfc blob`, web Symmetric tab |
| M4 Code Lens | this one | lens.py, lens_python.py, lens_rules.py, data/lens_rules.toml, `ctfc lens`, web Code Lens tab |
| M5 RSA + hashes | - | **next**, plan in section 5 |

240 tests pass (`.venv/bin/python -m pytest -q`, ~9 s), `ruff check .` and `ruff format --check .`
clean.

**The user said on 2026-10-27, for M4: "tu peux directement commencer avec ton plan, pas besoin de
me le présenter".** That waiver was for M4 only. For M5, post the plan in French and wait, unless
he says otherwise again.

## 3. Environment

- Python 3.11.2, virtualenv in `.venv` (`pip install -e ".[dev]"` done). Run `.venv/bin/ctfc ...`
  or `python -m ctfc ...`. **Careful: the bare `python` on PATH is an old build without
  `pathlib`** - always use `.venv/bin/python`.
- External tools: `diec`, `hashcat`, `binwalk`, `openssl` (3.0.22) present; `xortool` and
  `RsaCtfTool` installed with pipx (`~/.local/bin`). **`john` is missing**: needs
  `sudo apt install john`, which only the user can run.
- The user keeps a full `rockyou.txt` in `~/Documents/rockyou.txt` (14.3 M lines). The embedded
  list `ctfc/data/passwords.txt` is its first 10000 entries plus 13 CTF classics
  (`password123`, `infected`, `ctf`, `flag`...), ~80 KB, regenerate with that file if needed.
- Node 24 and `/usr/bin/chromium` exist. The web UI was checked for real with headless Chromium
  driven over the DevTools protocol: launch
  `chromium --headless=new --remote-debugging-port=9333 --no-sandbox about:blank`, open the
  WebSocket from `http://127.0.0.1:9333/json/list`, then `Page.navigate` + `Runtime.evaluate`
  (fill `#input-text`, click a tab, click `#run`, poll until `#run` is enabled, read the cards).
  The script lived in the session scratchpad and is gone; rewrite it when needed, it is ~40 lines.
  `node --check ctfc/web/static/app.js` checks JS syntax.

## 4. Architecture as built (differences from CLAUDE.md section 3)

Added modules (small, one responsibility each):
- `core/budget.py`: `Budget(max_attempts, max_seconds, on_progress, cancel_event)`; loops call
  `budget.spend()`; `summary()` for the user. Used by auto, xor and the M3 solver.
- `core/flags.py`, `core/magic.py`, `core/datafiles.py`, `core/auto.py`, `core/xor.py`: see the
  M2 notes in git history and `docs/how-it-works.md`.
- `core/symmetric.py` (M3): the cipher table (`CIPHERS`), `decrypt_raw()` (one set of parameters
  in, raw plaintext out), the material/attempt generators and `solve_symmetric()` ->
  `SolveReport(candidates, notes, budget_summary)`. `notes` is the "what I detected and tried"
  list that both front-ends display.
- `core/kdf.py` (M3): `OPENSSL_LAYOUTS` = (digest, iterations) pairs, `openssl_derive()`,
  `hash_keys()`, `salted_keys()`, `evp_bytes_to_key()`, and `EVP_HELPER` (source text for
  generated scripts). `Derived` carries `method`, `python` and `openssl_flags`.
- `core/blockmodes.py` (M3): hand-written ECB / CBC / CBC-CTS working on any
  `block_decrypt(block, key, endian)` callable, plus the same code as text for generated scripts.
- `core/tea.py` (M3): TEA and XTEA block functions (both endiannesses) + helper source text.
- `core/lens.py` (M4): the shared types (`Artifact`, `Operation`, `Behaviour`, `Peeled`,
  `Recovery`, `LensReport`), language detection, `analyse()`, `build_recovery()`, `apply_chain()`
  and `peel_blobs()`. `analyse(source, filename, flagset)` is the only entry point front-ends use.
- `core/lens_python.py` (M4): `ast`-based analysis. `Folder.fold()` is the constant folder (the
  thing that replaces `eval`): add a case there to support a new literal shape. `PythonLens`
  walks statements in order and calls innermost-first.
- `core/lens_rules.py` (M4): the regex engine for PowerShell / JS / bash / VBS, plus the two jobs
  a regex cannot do: `_resolve_variable_keys` (follow `-bxor $k` back to `$k = 0x3b`) and
  `_attach_keys` (match a key by size, marking it `key_guessed`).
- `data/lens_rules.toml` (M4): 60 rules. **Adding support for an API is one TOML entry, not code.**
  Fields: id, languages, regex, explain, operation, direction, capture, capture_as, behaviour,
  cipher, mode. `tests/test_lens.py::test_every_rule_is_well_formed` validates them all.
- `render.py`: rich tables; all sample data goes through `safe()`. `print_notes()` added in M3,
  `print_lens()` in M4.
- `web/jobs.py`: background jobs. Kinds handled in `web/app.py::prepare()`: `auto`, `xor`, `sym`,
  `blob`. Sync twins: `/api/auto`, `/api/xor`, `/api/detect`, `/api/sym`, `/api/lens` (Code Lens
  is static analysis, so it is fast enough to answer directly - no job needed).
- `core/codegen.py`: a result chain is a list of `Step(name, params)`; `step_code()` maps a step to
  `StepCode(label, comment, python, imports, import_lines, helper, cyberchef)`. M3 added
  `Step("cipher", params)` (`cipher_step_code`) and the `import_lines` field (for
  `from Crypto.Cipher import AES`, since `imports` only holds module names).

Conventions worth keeping:
- `parse_input(spec, allow_files=True, decode_bare=True)`. The web always passes
  `allow_files=False`. `detect`/`auto` pass `decode_bare=False`. **Key material
  (`--key/--iv/--blob`) is read with `decode_bare=False`**: the solver tries the raw bytes *and*
  their hex/base64 readings itself and says which one worked.
- Every candidate has reasons, a Python snippet and a CyberChef string when possible. The tests
  **run the generated snippets** with `python -I` and check their output: keep doing that.
- Fixtures are generated by `tests/make_fixtures.py` (seed 1337, fake flags `CYBN{fixture_...}`);
  run `make fixtures` after editing it. Fixture files are committed. The M3 generator writes its
  own CTS / Fernet / XTEA encryptors **independently of ctfc**, so the tests do not check the
  code against itself.
- CLI: `PLANNED` in `cli.py` lists commands not built yet (`lens`, `rsa`, `hash`, `recipe`,
  `tools`, `keys`). Remove the entry when implementing one, and drop the matching `(Mx)` hints in
  `core/detect.py`.
- Web: tabs not built have `data-milestone` in `index.html` (disabled). `TOOLS` in `app.js` lists
  built tabs and whether they run `sync` or `job`; `OPTION_PANELS` lists tabs that have an
  `#options-<tab>` panel.

Scoring decisions (tuned against noise, keep the noise tests green):
- `text_score = printable^6 * (0.35 + 0.40*word_rate + 0.25*frequency)`; flag score loses up to
  0.15 if the text around the flag is unreadable.
- auto: `MIN_SCORE 0.2`, `FOUND 0.9`, `ONCE_PER_CHAIN = rot13, rot47, reverse, xor`.
- xor: guessed file headers are masked from the score (`forced=`); near-ties prefer shorter keys.
- symmetric: `MIN_SCORE 0.25`, `PKCS7_BONUS 0.15`, `TAG_BONUS 0.25` (GCM tag / Fernet HMAC),
  `STOP_AT 0.95` = stop the whole search as soon as something scores that high. When nothing
  passes `MIN_SCORE`, the 3 least-bad are shown with a note saying so. Fernet candidates are
  **pinned**: their verdict is always shown, even "the HMAC does NOT verify".

Code Lens decisions (M4), all with a test that pins them:
- An assignment to a name containing key/iv/nonce/salt/password/secret is **setup**, not a data
  step (`PythonLens.KEY_MATERIAL`), so a hex-decoded key is not reported as "decode hex".
- A cipher operation is emitted at `.decrypt()`/`.encrypt()`, never at `.new()`, or the cipher
  would be ordered before the base64 decode that feeds it (Python evaluates the callee first).
- `"token"` means the *ciphertext* (Fernet token, JWT), never a key, in `NAME_HINTS`.
- A key attached by size only is marked `key_guessed`; the recovery script then **stops before
  that step** and a note says so. Better a short script that works than a long one that crashes.
- Blob detection: 40+ characters by name, with a fallback (`promote_spare_blob`) that accepts a
  16+ character literal when a decoding chain was found but no payload - a script that decodes
  must have had something to decode.
- The same source span is reported once, by the most specific rule (hex digits are also valid
  base64, and a `.Key = @(0x..)` array also matches the generic char-code rule).
- `peel_blobs()` applies the chain to *every* blob and ranks by `scoring.py`, so the flag regexes
  fire; the answer is usually the first row.

Conventions **verified against real implementations** in M3 (tests enforce them):
- `openssl enc -aes-256-cfb` = pycryptodome `MODE_CFB, segment_size=128`; our separate `cfb8`
  mode is pycryptodome's default (one segment per byte).
- `openssl enc -aes-256-ctr` = `MODE_CTR, nonce=b"", initial_value=<16-byte iv>`; the solver also
  tries pycryptodome's half-nonce style (`ctr_style="nonce8"`).
- `openssl enc -aes-128-cbc-cts` writes **CS1** (truncated block first); Kerberos/.NET use CS3
  (the last two pieces swapped). Both are tried, labelled `CBC-CTS-CS1` / `CBC-CTS-CS3`.
- `EVP_BytesToKey` matches `openssl enc -md md5 -P -S <salt>` (exact key+iv vector in the tests).
- TEA/XTEA match the published all-zero test vectors (`41ea3a0a94baa940`, `dee9d4d8f7131ed9`).

Known limitations / open points:
- CyberChef operation strings in `encodings.py` / `codegen.py` are **still not verified** against
  a real CyberChef build (CLAUDE.md requires it in M6, with the deep-link format). The cipher
  recipes are skipped (`None`) whenever an IV is read out of the data or a header is stripped,
  because a recipe cannot express that and would silently give a wrong result.
- The solver tries one cipher layer. A ciphertext that is base64 **and** encrypted needs the Auto
  tab first, or `--blob`/`--key` plus a manual decode; chaining auto -> sym is M6 (pipeline).
- `--passwords` tries the 3 cheapest openssl KDF layouts over the whole list (EVP md5, EVP
  sha256, PBKDF2-sha256-10000), KDF-major so one slow KDF cannot eat the budget. It does not try
  `hash_keys`/scrypt over the list (too slow); a given `--pass` does get the full set.
- No XChaCha20 (24-byte nonce), no AES-SIV, no DES degenerate-key handling beyond what
  pycryptodome refuses (caught as `CryptoError` and skipped).
- `docs/cheatsheet.md` does not exist yet (CLAUDE.md puts it in M8 with the web tab).
- Code Lens: a key computed at runtime cannot be recovered statically (the KDF call is reported);
  control flow is not simulated, so a character-by-character loop with arithmetic is not folded
  (the char-code *array* form is); the rule-based languages have no notion of scope.
- `tests/fixtures/*` is excluded from ruff in `pyproject.toml`: the Code Lens samples are data,
  deliberately written in obfuscated dropper style, and must stay byte-for-byte as they are.

## 5. Plan for M5 (RSA + hashes) - post it in French and wait for his OK

CLAUDE.md section 4.5.

1. `core/rsa.py`: parse PEM/DER public and private keys (pycryptodome `RSA.import_key`), print n,
   e, d, p, q, bit size; check that a private key matches a public one (compare moduli); decrypt
   with OAEP (SHA-1/SHA-256) and PKCS#1 v1.5, trying both and scoring the result; build a key from
   `n,e,p,q` or `n,e,d` (`RSA.construct`), including the `d` from `p,q,e` computation.
2. Offline attacks on weak keys, each with a one-line explanation of *why* it works: small `e`
   (integer cube root with `gmpy2` if present, else Newton on ints), shared factors across several
   keys (gcd of moduli), Fermat (p and q close), Wiener (small `d`, continued fractions), trial
   division by small primes, and Hastad for the same message under several keys if cheap.
   factordb is an **opt-in online button** (config `offline`, `--offline`), with the warning.
3. `core/hashes.py` + `data/hashcat_modes.toml`: identify a hash from its length, charset and
   prefix, then print the ready `hashcat -m <mode>` and `john --format=<x>` commands. Include the
   DB/auth formats CLAUDE.md names: MySQL native `$mysqlna$<salt>*<response>` (fixture exists),
   NTLM, bcrypt `$2y$`, sha512crypt `$6$`, Kerberos AS-REP/TGS, plus the plain md5/sha family.
   **No cracker**: identify + hand over (tiny wordlist / known-plaintext cases are fine).
4. CLI `ctfc rsa` (`--key`, `--decrypt`, `--n/--e/--d/--p/--q`, `--attack`) and `ctfc hash <hash>`;
   web RSA and Hash tabs. Remove `rsa`/`hash` from `PLANNED` and the `data-milestone` attributes.
5. Fixtures: an RSA keypair with a known flag (OAEP and PKCS1v15 variants), a small-`e` key, two
   keys sharing a prime, a Fermat-weak key, a Wiener-weak key, the RSA-OAEP-wrapped AES key||iv
   blob CLAUDE.md asks for in section 9, and one hash per format in the table.
6. Docs: a `how-it-works.md` section on RSA (why `e=3` on a short message is a cube root, what
   OAEP padding is for, why sharing a prime breaks both keys), and the hash identification table.

## 6. Improvement ideas (open: he said "on les feras toutes apres si M3 est fonctionnel")

1. "Apply" buttons on Detect guesses that open the right tab pre-filled (e.g. XOR keylen 6,
   openssl `Salted__` -> Symmetric with the passphrase field focused). Now easy: both tabs exist.
2. Custom base64 alphabet decoding: detect already finds the alphabet; feed it to auto.
3. Batch mode `ctfc scan <folder>`: detect + auto on every extracted file, ranked.
4. pcap extraction in stdlib: HTTP bodies, DNS exfiltration reassembly (base32/hex subdomains).
5. ~~Embedded password list~~ **done in M3** (`ctfc/data/passwords.txt`, `--passwords`).
6. History of "Use as next input" steps, undo, export the whole chain as a script/recipe (leads
   into M6 Pipeline).
7. Stego tool suggestions (zsteg, steghide/stegseek, exiftool) through the M6 tool registry.
8. XOR key derived from a hash of common words (md5/sha of a string), common in CTF malware.
   Note: M3 already does this for *cipher* keys (`key_forms` hashes the given key), so the same
   trick in `xor.py` would be a small addition.

## 7. Quick verification commands

```sh
cd ~/apps/ctfc && source .venv/bin/activate
make test && make lint
ctfc auto tests/fixtures/layers_b64_zlib_hex.txt --show-code
ctfc detect tests/fixtures/png_with_zip.png
ctfc xor tests/fixtures/xor_two_layers.bin
ctfc blob tests/fixtures/key_iv_blob.b64 --against tests/fixtures/aes_cbc_keyiv_blob.bin
ctfc sym tests/fixtures/aes_gcm_nonce_ct_tag.bin --key "$(cat tests/fixtures/aes_cbc_iv_prefix.key)" --show-code
ctfc sym tests/fixtures/openssl_salted_pbkdf2.bin --passwords
ctfc sym tests/fixtures/xtea_cbc.bin --pass tiny --cipher xtea
ctfc lens tests/fixtures/lens_dropper.ps1 --show-code
ctfc lens tests/fixtures/lens_layers.py
ctfc serve   # http://127.0.0.1:8137
```
