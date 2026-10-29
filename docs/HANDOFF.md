# Handoff notes (for the next agent)

Last update: 2026-10-28, **M8 done: every milestone of CLAUDE.md is built.** What is left is
listed in section 5ter (open points) - ask the user before starting anything new.
Read `CLAUDE.md` first, then this file.

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
| M4 Code Lens | `c367e69` | lens.py, lens_python.py, lens_rules.py, data/lens_rules.toml, `ctfc lens`, web Code Lens tab |
| M5 RSA + hashes | this one | rsa.py, rsa_attacks.py, hashes.py, data/hashcat_modes.toml, `ctfc rsa`, `ctfc hash`, web RSA + Hash tabs |
| ideas 1 + 8 | `fb74064` | "Apply" buttons in Detect (`Guess.apply`), XOR key from a hash of a common word |
| ideas 2 + 3 + 4 | this one | custom base64 alphabet in auto, `ctfc scan <folder>`, `ctfc pcap` (core/pcap.py) |
| M6 pipeline + CyberChef + tools | `69ae63c`..`78bf9b7` | recipes, verified CyberChef deep links, embedded CyberChef (`make vendor`), tool bridge, web Pipeline tab + Suggested tools strip (section 5) |
| M7 classical + key hunting | `180633d`..`bcdd550` | classical.py, keyhunt.py, `ctfc classical`, `ctfc keys`, web Keys tab (section 5bis) |
| M8 sessions + report + bundle | `5e35985`..this one | write-up lessons (`lens --against`), sessions, `ctfc report`, cheat sheet, `make bundle` (section 5ter) |

643 tests pass, 1 skipped (`.venv/bin/python -m pytest -q`, ~40 s), `ruff check .` and `ruff format --check .`
clean.

**Plan approval: the user waived it twice on 2026-10-27.** For M4: "tu peux directement commencer
avec ton plan, pas besoin de me le présenter". For M5 and the improvement ideas that follow:
"Fais un plan pour M5. Et commence directement sans ma confirmation. Pour les améliorations,
commence directement après avoir validé M5." So: write the plan, post it with the results, do not
wait. Ask again before M6 unless he repeats the waiver.

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
- `core/scan.py` (idea 3): `scan(folder)` runs detect + auto on every file and ranks them by an
  explicit `interest` built from independent signals (a flag in the file, a crypto detect rule, a
  container type, a decoding chain, plain text capped at `PLAIN_TEXT_CAP`). Each file gets its own
  budget slice. Carved *media* is deliberately low-interest; containers (enc/zip/kdbx/pcap) are not.
- `core/pcap.py` (idea 4): pcap **and** pcapng parsing, Ethernet/SLL/raw link layers, IPv4+IPv6,
  TCP reassembly by sequence number (gaps reported, never glued over silently), HTTP request and
  response extraction (chunked + gzip/deflate undone), DNS exfiltration rebuilt from the first
  label of each query, raw TCP/UDP fallback. `solve()` then runs `auto` on every object and ranks
  them. **Checked byte-for-byte against tshark** (packet count, DNS names, exported HTTP objects).
- `core/rsa.py` (M5): `KeyInfo` (n, e, d, p, q + `facts()` which names the weaknesses it can
  see), `parse_key()`, `build_key()` (completes d from p,q,e and p,q from n,e,d), `keys_match()`,
  `decrypt_candidates()` (OAEP-SHA1, OAEP-SHA256, PKCS#1 v1.5, textbook, all scored),
  `small_exponent_candidates()` (the e-th root attack, no key needed) and `solve_rsa()`.
- `core/rsa_attacks.py` (M5): the integer maths, one function per weakness. `run_attacks()` runs
  them **cheapest first with a per-attack slice of the budget** - without that, Pollard rho (which
  can never say "no") starves Fermat. `iroot`/`isqrt` use gmpy2 when installed, else Newton on ints.
- `core/hashes.py` + `data/hashcat_modes.toml` (M5): 42 formats, identification by prefix (strong),
  full-shape regex (strong) or length+charset (weak, every candidate listed). Plus one free offline
  try of the embedded password list on the *unsalted* formats only.
- `render.py`: rich tables; all sample data goes through `safe()`. `print_notes()` added in M3,
  `print_lens()` in M4, `print_rsa()` / `print_hash()` / `print_key_comparison()` in M5.
- `web/jobs.py`: background jobs. Kinds handled in `web/app.py::prepare()`: `auto`, `xor`, `sym`,
  `blob`, `rsa` (an attack can take seconds). Sync twins: `/api/auto`, `/api/xor`, `/api/detect`,
  `/api/sym`, `/api/rsa`, plus `/api/lens` and `/api/hash`, which are fast enough to answer
  directly with no job.
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

RSA and hash decisions (M5):
- Attacks run cheapest-first, each with its own budget slice (see above). If nothing fires, the
  report says plainly that a proper modulus will not be factored here and points at the
  ciphertext instead - never an endless "trying".
- A verified padding (OAEP / PKCS#1 v1.5) adds 0.2 to the score, like PKCS7 in M3: it is
  near-proof the key is right.
- An RSA result of 16/24/32/44/48 unreadable bytes is reported as **key material**, with the
  `ctfc blob` command to run next (test: `test_rsa_wrapping_an_aes_key_hands_over_to_blob`).
- Hash identification never claims certainty from a length alone; every same-shape candidate is
  listed with its mode. `test_every_example_is_recognised_as_its_own_format` is the guard that
  catches a typo in a pattern (it already caught one in phpass).
- The embedded password list is tried only on unsalted formats; anything salted goes to hashcat.

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
- CyberChef operation strings were verified against CyberChef v11.5.0 in M6 (section 5). The
  cipher recipes are skipped (`None`) whenever an IV is read out of the data or a header is stripped,
  because a recipe cannot express that and would silently give a wrong result.
- The solver tries one cipher layer. A ciphertext that is base64 **and** encrypted needs the Auto
  tab first, or `--blob`/`--key` plus a manual decode; chaining auto -> sym is M6 (pipeline).
- `--passwords` tries the 3 cheapest openssl KDF layouts over the whole list (EVP md5, EVP
  sha256, PBKDF2-sha256-10000), KDF-major so one slow KDF cannot eat the budget. It does not try
  `hash_keys`/scrypt over the list (too slow); a given `--pass` does get the full set.
- No XChaCha20 (24-byte nonce), no AES-SIV, no DES degenerate-key handling beyond what
  pycryptodome refuses (caught as `CryptoError` and skipped).
- `docs/cheatsheet.md` does not exist yet (CLAUDE.md puts it in M8 with the web tab).
- RSA: no Hastad (same message under several keys with the same small e), no Franklin-Reiter, no
  partial-key (Coppersmith) attacks - they need lattice work that would mean a new dependency.
  factordb is a link in the M6 tool bridge (`ctfc tools <key.pem>`), hidden when offline.
- `gmpy2` is not installed here, so the pure-Python path is the one that gets exercised.
- Code Lens: a key computed at runtime cannot be recovered statically (the KDF call is reported);
  control flow is not simulated, so a character-by-character loop with arithmetic is not folded
  (the char-code *array* form is); the rule-based languages have no notion of scope.
- `tests/fixtures/*` is excluded from ruff in `pyproject.toml`: the Code Lens samples are data,
  deliberately written in obfuscated dropper style, and must stay byte-for-byte as they are.

## 5. M6 (done): recipes, CyberChef, external tools

Commits `69ae63c` (core + CLI), `5bfad6d` (tests + fixes), `e377b5e` (web), and the
last one (vendor script + docs). Plain-language write-up: `docs/how-it-works.md`
section 10.

- `core/pipeline.py`: JSON recipes. `complete_cipher()` fills the optional cipher
  fields (`mode` = cbc, `iv_size` by cipher) so **the run and the exported Python
  read the same fields the same way** (`iv_from`, `tag` = last 16 bytes of the
  data, `header_skip`). `unpad: pkcs7` is strict like `unpad()`. Tests run the
  exported script and compare.
- `core/cyberchef.py`: deep links. **Verified in the real CyberChef v11.5.0**
  (headless Chromium on the vendored copy, via `ctfc serve` and via `file://`):
  base64 -> zlib -> XOR and AES-256-CBC both give the flag.
  `test_vendored_version_is_the_verified_one` ties `VERIFIED_AGAINST` to
  `VERSION` in `scripts/fetch_vendor.sh`: bump both together, and re-check.
- `scripts/fetch_vendor.sh` / `make vendor`: pinned version + URL + SHA-256 of
  the release zip, checked before unzip; keeps LICENSE, writes ATTRIBUTION.txt and
  VERSION; installs into `ctfc/web/static/vendor/cyberchef/` (gitignored, 80 MB).
  **Already run on this machine.** The zip has no `index.html` (only `.gz`/`.br`),
  so the script copies `CyberChef_v11.5.0.html` to it.
- `core/tools.py`: `Signal(rule, confidence, why)`; `gather(data, path)` builds the
  signals (detect guesses + a "this is a hash" signal = sum of the hash
  candidates' confidences, capped 0.95) and placeholder values; `suggest()`;
  `cyberchef_target()` = embedded copy > configured URL > public (not offline);
  `run_tool()` = argument list, `stdin=DEVNULL` (openssl used to hang 120 s
  waiting for a password), refuses a whole-argument value starting with `-`.
  `prefer_over` in tools.toml: the embedded CyberChef hides the public one; an
  embedded tool that is not installed is never suggested.
- `test_every_suggest_when_pattern_can_fire` checks every `suggest_when` against
  the rule ids ctfc can produce (`FUTURE_RULES` allows `classical.*` until M7:
  **M7 must emit `classical.*` rule ids**, or remove that allowance).
- Web: Pipeline tab (JSON editor, add-step buttons, load/save, one card per step),
  "Open in Pipeline" on Auto cards (idea 6), "Open in CyberChef" on every card
  with a recipe (confirm dialog for the public instance), Suggested tools strip
  after auto/detect/xor/sym/hash, Run button for local tools. Routes:
  `/api/recipe`, `/api/cyberchef`, `/api/tools`, `/api/tools/run`.
- The UI check script (headless Chromium over CDP) is in the session scratchpad
  only; it is ~60 lines of node, rewrite it when needed (section 3).

Not done in M6, on purpose: idea 7 (stego tools) is covered by the registry
entries (zsteg, steghide, stegseek, exiftool) but there is no stego *analysis* in
ctfc. Undo/history of "Use as next input" was replaced by "Open in Pipeline",
which gives the same thing (the whole chain, editable, replayable).

(M7 was then planned in French, approved by the user: "Je valide. Tu peux continuer".)

## 5bis. M7 (done): classical ciphers and key hunting

Plain-language write-up: `docs/how-it-works.md` sections 11 and 12.

Classical (`core/classical.py`, `ctfc classical`):
- Ciphers follow **CyberChef v11.5.0** (read in its source and every fixture's
  recipe opened in the real CyberChef): only ASCII letters change, case kept,
  Vigenère key advances on letters only, rail fence uses CyberChef's offset rule.
  `ROT13(true,true,false,26-shift)`, `Affine_Cipher_Decode(a,b)`,
  `Atbash_Cipher()`, `Vigenère_Decode('key')`, `Rail_Fence_Cipher_Decode(r,o)`.
- Vigenère key length (`vigenere_key_lengths`): column IoC -> keep the best 5 and
  their divisors -> solve each by frequency and measure chi2 -> if the best key
  repeats itself (`key_period`, 60% agreement) its period wins; a divisor with
  chi2 within 1.5x wins too. Ranking needs 12 letters per column
  (`MIN_COLUMN_LETTERS`), the solver looks further (8, `SOLVER_COLUMN_LETTERS`).
  Measured on random keys: 108/111 solved, all 25 Caesar shifts. Misses = keys
  longer than ~1/10 of the letters (information limit).
- Over-fitting guards (each pinned by a test): `refine_vigenere` (letter by
  letter with the full scorer), `reduce_key`, and dropping any Vigenère key that
  repeats a shorter period ("tttthzttt" is Caesar 19). Ranking ties within 0.01
  go to the simpler cipher (`_simplicity`).
- Flag crib (`find_cribs`): a word of a known prefix's length before "{" gives
  the shifts. A prefix in clear is never a crib (`CYBN{` is not a shifted `flag{`).
- Rail fence `trim`: a trailing newline added after encryption is kept out of
  the zigzag (CyberChef: `Remove_whitespace(false,true,true,false,false,false)`
  first). Found because the fixture file ends with "\n" - real files do too.
- `auto` calls the classical solver on text that does not read (own 3 s budget,
  shares the cancel event); `is_text_like` keeps base64/hex out.
- detect rules: `classical.flag_shift`, `.monoalphabetic`, `.vigenere`,
  `.transposition` -> dcode in the tool bridge. Apply button -> Auto tab.

Key hunting (`core/keyhunt.py`, `ctfc keys`, web Keys tab, job kind `keys`):
- AES key schedule scan: vectorised (`_xor3` = XOR of three shifted copies via
  big ints, then `bytes.find(b"\x01\x00\x00")`), 16 MB chunks overlapping by one
  schedule; ~0.5 s for 40 MB. Expansion pinned to the FIPS-197 vectors (128,
  192, 256). detect reports `keys.aes_schedule` (Apply -> Keys tab).
- Other finders: labelled values (key/iv/password...), hex/base64 of key
  lengths (pure hex is never re-read as base64), ASCII strings incl. the end of
  a C string, random windows (AES only, last). Order = `STRENGTH`.
- Each candidate gets `PER_KEY_SECONDS` of `solve_symmetric`; the hunt stops at
  the first score >= 0.9. The result's reasons and Python start with
  "key found at offset 0x...".
- `PLANNED` in cli.py now holds `report` (M8).

## 5ter. M8 (done): the user's write-ups, sessions, report, cheat sheet, bundle

The user pointed at his write-ups (https://github.com/CreaTikaa/CTFs-Writeups) for the
report format **and** as real use-cases. Four challenge shapes were rebuilt as fixtures
(`writeup_*`, new keys, fake flags; never copy real flags) and each one exposed a gap,
all fixed and pinned by `tests/test_writeups.py`:
- Cave Expedition (PowerShell, obfuscated, two base64 keys, `-bxor $a -bxor $b`, base64
  out) -> `core/lens_against.py`, `ctfc lens <script> --against <file>`: the script's
  literals (raw/base64/hex) are tried as the keys of its own operations.
- A new Hire (Python stager) -> `PythonLens.encoded_literal`: for `x = b64decode("...")`
  the blob is the *encoded* literal (the recovery script used to decode twice and crash).
- Ghost in the Dark (.NET AES) -> rule `ps.aes.create` + `_resolve_cipher_variables`
  (`.Key = $k` back to `$k = [Convert]::FromBase64String(...)`, CipherMode read).
- Silent Trap (RC4 over base64) -> `symmetric.decode_text_ciphertext`: base64/hex text
  ciphertext is decoded first (was an M3 limitation), the snippet starts with that step.
- `codegen.chain_snippet(save_as=...)`: binary results are written to a file.

Sessions (`core/session.py`): `~/.ctfc/sessions/<name>/{session.json,steps.jsonl,inputs/}`,
append-only steps, names `[A-Za-z0-9_-]{1,64}` only. `CTFC_SESSIONS_DIR` overrides the
folder; **tests/conftest.py sets it** so the suite never writes into real sessions (keep
that). CLI: `ctfc session new|use|stop|list|show|note|flag`, `--session` on every
command, `remember()` in cli.py is called once per command. `config.sessions_dir` too.
Web: session bar; `record()` in web/app.py, jobs are wrapped in `prepare()`.

Report (`core/report.py`): layout of his write-ups (`# title`, `### statement`, `## Step
N: <heading per tool>`, command, findings, output, "To redo it by hand", CyberChef,
`## Flag`, "GGs !"). Phrases EN/FR in `strings.REPORT_TEXT`. Dead ends dropped unless
followed by a note; retries deduplicated; `fence()` outlasts backticks in the output.

Cheat sheet: `ctfc/data/cheatsheet.md` (packaged; `docs/cheatsheet.md` points to it),
`ctfc cheatsheet`, web tab with a tiny textContent-only Markdown renderer.
`tests/test_cheatsheet.py` checks every `ctfc <cmd> --option` it mentions exists.

Bundle: `make bundle` -> `dist/ctfc-bundle/` (wheels incl. CyberChef inside the ctfc
wheel, `install.sh` with `--no-index`, README-OFFLINE.md = docs/day-of-the-ctf.md).
Verified: installed from a copy with PIP_NO_INDEX=1, commands run outside the repo.

Open points (not started, ask first):
- Keyword substitution solver (hill climbing needs n-gram tables: a data file, no dep).
- `lens --against` for JS/bash/VBS ciphers relies on the same literal search but the
  cipher rules of those languages do not resolve variables like PowerShell now does.
- Bundle wheels are platform-specific (`BUNDLE_PLATFORM` adds another platform's).
- The user dropped two Notion exports in `examples/` (untracked, not read, not
  committed): ask him what they are for.

## 5quater. IN PROGRESS: audit against the user's real challenges

On 2026-10-28 the user put two Notion exports of his challenge notes in `examples/`
(untracked, French + English, mostly Forensics) and asked: **"check the tool covers
every use case in there - I should have been able to flag them just by pasting the
artifacts into ctfc, without an LLM"**. He also said any feature that makes the tool
richer is welcome, as long as it stays fast and **deduces parameters instead of asking
for them**.

The two exports are also saved outside the repo in the session scratchpad; if they are
gone, re-extract `examples/*.zip` (each holds one `Forensics *.md`, the second also two
screenshots).

### Audit method (redo it this way)

`/tmp/.../scratchpad/audit/build.py` and `build2.py` rebuild each case in miniature
(own encryptors, fake `CYBN{...}` flags) into `cases/`, then each one is run through
ctfc. **Those scripts are in the scratchpad and will be deleted** - rewrite them from
the table below, they are ~60 lines each.

### Coverage table (status 2026-10-28, second audit session)

Fixtures for every FIXED case are committed as `tests/fixtures/audit_*` (+ the real
LUKS headers), generated by `write_audit_fixtures()` in make_fixtures.py.

| # | Challenge / step | ctfc | Done? |
|---|---|---|---|
| A | Docker Layers: `openssl enc -aes-256-cbc -iter 10 -pass pass:<sha256>` | `ctfc sym --pass` | **FIXED** (`445f2ec`, `-iter` 10/100 in kdf.py) |
| B | Android SimpleLocker: AES-CBC, key = sha256(password), IV = 16 zero bytes | `ctfc sym --pass` | **FIXED** (`5253c9a`, zero-IV now beats "IV = first block" when the block reads) |
| C | pfSense `gateway.bak`: base64 XML, `<secret>` field, ROT13 hint | `ctfc auto` | **FIXED** (`1015e52`, core/secrets.py: surfaces the `<secret>` + its ROT13 reading) |
| D | RADIUS PAP password in a pcap (password XOR MD5(secret+authenticator)) | `ctfc pcap` / `ctfc radius` | **FIXED** (`bf97adb`, core/radius.py; secret guessed from the common+embedded list) |
| E | Pixel Rehab: PNG magic 0x88, 7z after IEND, PNG header pasted over the 7z magic | `ctfc repair` | **FIXED** (`51a6ee2`, core/repair.py + CLI + detect + tests) |
| F | DNS tunnelling: hex over SEVERAL labels, counter label, junk before the PNG magic | `ctfc pcap` | **FIXED** (`7bd7100`, extract_dns rewritten) |
| G | Encrypted ZIP, known-plaintext with bkcrack (offset 5 for a Deflate-stored PNG) | `ctfc tools` | **FIXED** (`bfa5e46`, repair.zipcrypto_known_plaintext deduces entry/offset/plaintext) |
| H | qcow2 + LUKS, `aeskeyfind`, master key = key1\|\|key2 or key2\|\|key1 | `ctfc keys --against` | **FIXED** (`3b89781`, core/luks.py confirms the master key with the header's PBKDF2 digest) |
| I | SAM/NTDS: `user:rid:lm:nt:::` line | `ctfc hash` | **FIXED** (`445f2ec`, format `pwdump`) |
| J | pdf2john / 7z2john / keepass2john, oleid/olevba, Volatility, ewfexport, WinDefReleaser | `ctfc tools` | **FIXED** (`9a43d2e`, 8 tools.toml entries fired by the file magic; Volatility/ewfexport left out as live-forensics tools, not paste-and-run) |

### Audit complete: all 10 cases covered

Every case from the two Notion exports now has a paste-and-run path in ctfc, no LLM.
The last three were done this session:

- **J** (`tools:` commit): `data/tools.toml` gained zip2john, rar2john, 7z2john, pdf2john,
  keepass2john, office2john, olevba and oleid, each fired by the file's own magic
  (`magic.zip` / `magic.rar` / `magic.7z` / `magic.pdf` / `magic.kdbx` / `magic.doc`). The
  `*2john` ones print a hash you paste into `ctfc hash`; olevba/oleid read VBA macros. None
  are installed here, so ctfc shows the command + the install hint.
- **G** (`bkcrack` commit): `repair.zipcrypto_known_plaintext()` reads the ZIP local headers,
  finds the first ZipCrypto-encrypted entry whose name gives its type (a `.png`...), takes
  that type's magic as the known plaintext, and places it (offset 0 if stored, 5 if deflated
  - the uncompressed-block header). A `zip.known_plaintext` signal fires the bkcrack entry, so
  `ctfc tools secret.zip` prints the exact `bkcrack -C ... -c flag.png -x 5 <magic>` command.
  Fixture `audit_zipcrypto.zip` is a real ZipCrypto archive (make_fixtures.py now implements
  the cipher) that decrypts back to a PNG.
- **D** (`radius` commit): `core/radius.py` undoes RFC 2865 section 5.2 (password XOR a chain
  of MD5(secret + previous block)). The shared secret is guessed from a common list +
  `passwords.txt`, so `ctfc pcap capture.pcap` recovers the password on its own; `ctfc radius
  hex:<User-Password> --authenticator hex:<16 bytes>` is the paste-the-two-blobs path. Fixture
  `audit_radius.pcap` leaks `CYBN{fixture_radius_pap}` at score 0.97.

Earlier this audit (commits): A/I `445f2ec`, E `51a6ee2` (+lint `fde82ec`), F `7bd7100`,
B `5253c9a`, H `3b89781`, C `1015e52`. All verified against the real tools (openssl, 7z,
cryptsetup, zip). `core/repair.py` has content validators (7z start-header CRC32,
xz/png/zip/elf/luks), so a pasted header names ONE format instead of a list.

## 5quinquies. Second audit: against *published* CTF write-ups (2026-10-29)

After the user's own challenges were all covered, he asked to check ctfc against public
forensics write-ups ("HTB, Tales of Eldoria, 0xFun, etc.") and add whatever was missing.
The write-ups reviewed were HTB **Cyber Apocalypse 2025 "Tales from Eldoria"** (all five
forensics challenges) plus the recurring USB-keystroke genre (HTB Cyber Apocalypse 2021
"Key Mission", irisCTF 2025 "deldeldel", UMDCTF 2022, and the HackTricks page on it).

### Tales from Eldoria, challenge by challenge

| Challenge | Artefact | ctfc |
|---|---|---|
| A new Hire | base64 in a `client.py` | already fine (`auto` / `lens`) |
| Cave Expedition | `.evtx` logs + encoded PowerShell + double XOR | script half already had a fixture (`writeup_cave_*`); **the `.evtx` half was the gap** -> `psenc` |
| ToolPie | pcap -> HTTP POST -> bz2 -> marshal -> AES-CBC | already fine (`pcap` + `auto` + the layout solver); the marshal/.pyc step stays out (hard rule 3) |
| Silent Trap | pcap of **IMAP**, ZIP attachment, password in the HTML body, RC4 C2 | RC4 was fine, **mail extraction was the gap** -> `core/mail.py` |
| Stealth Invasion | Windows memory dump + Volatility 3 | **deliberately out of scope** (CLAUDE.md section 2); ctfc identifies and points at the tool |

### What was added (3 commits, all pushed)

1. **USB keystrokes** (`core/usb.py`): the clearest gap of all - ctfc produced *nothing*
   for a USB capture, because a usbmon frame is not Ethernet so the IP/TCP walk found no
   packets at all. Decodes HID boot-protocol reports (8 bytes: modifiers, reserved, six
   usage codes) through the usage table, strips the usbmon 48/64-byte or USBPcap
   self-declaring pseudo-header, applies Backspace as a real deletion, toggles Caps Lock,
   and groups per device. Link types 189/220/249 now take that path in `pcap.analyse()`.
   Fixture `audit_usb_keyboard.pcap` (types a flag with a corrected typo) -> 0.97.
2. **Mail** (`core/mail.py`): IMAP `{N}` literal / SMTP `DATA` / POP3 dot framing, then
   the stdlib `email` package for the MIME tree, decoding every part. **Bodies are kept
   too** - that is where the ZIP password lives. `--extract` reduces an attachment's name
   to a plain basename (the name comes from the sample). Fixture `audit_mail_imap.pcap`.
3. **`psenc` decoder** (`core/encodings.py`): finds `powershell -enc <base64>` in the raw
   bytes *and* in UTF-16LE at both alignments, which is what makes it work on an `.evtx`.
   Keeps a match only if the decoded script is readable **ASCII** (random bytes decode as
   UTF-16LE and hit printable Unicode often enough to fool `str.isprintable()`). Being a
   registry entry it works in `auto`, recipes and codegen for free. Fixture
   `audit_evtx_dropper.evtx` -> `psenc -> extract_base64` -> flag at 0.97. **Note:** this
   changed the expected chain of the old `powershell_encoded.txt` fixture from
   `extract_base64 -> utf16le` to the single `psenc` step, in `tests/test_auto.py`.

Also this session: the **web RADIUS tab** he asked for (`/api/radius` + `#options-radius`,
reusing the generic candidate cards), and section 14 of `docs/how-it-works.md`, which
documents the whole capture side (it was undocumented before).

### Candidates NOT built, and why

- **Volatility / memory dumps**: out of scope by CLAUDE.md section 2. `ctfc keys` and
  `ctfc scan` already get something useful out of a dump; a profile-aware parser is a
  different project. If he ever wants it, it belongs behind a tool-bridge entry.
- **marshal / .pyc loading** (ToolPie step 3): hard rule 3 forbids `pickle.loads` and
  friends on samples. A static `.pyc` *header* reader would be fine; running marshal is not.
- **Mouse-movement drawing** from a USB capture: doable (the reports are 3-5 bytes) but it
  needs a plot to be useful, and it shows up far less often than keyboards.
- **A real `.evtx` parser**: `psenc` gets the command line out without one, which is what
  the challenges actually need. A full parser is a lot of binary XML for little gain.

## 6bis. The improvement ideas (all five done)

Order proposed, cheapest and most useful first. Each one ends with tests, a demo command and a
commit, like a milestone.

All five improvement ideas are now done; what follows is M6. Kept here for the record:

1. ~~**"Apply" buttons in Detect**~~ **done**: `Guess.apply` is `{"tab": ..., "options": {...}}`,
   filled in `detect.py` (`SIG_APPLY`, `PREFIX_APPLY`, and inline for xor/ecb/blob guesses). The
   web UI turns it into a button via `applyGuess()`; the option ids follow `<tab>-<option>`, so a
   new option is pre-fillable as soon as it is named that way. A test checks every table entry
   names a real tab, and another checks the field survives the JSON round trip.
2. ~~**XOR key from a hash of a common word**~~ **done**: `xor.solve_hashed_key()` tries
   md5/sha1/sha256 of the 10000 embedded words, in both the raw-digest and `.hexdigest()` forms
   (60000 keys, ~0.2 s thanks to a `text_points` pre-filter on 256 bytes before real scoring).
   `solve_xor` calls it on its own when nothing else beats `HASHED_FALLBACK = 0.8` - that
   threshold matters: a column solve with one wrong byte scores ~0.55 and must not block it.
   `--hashed-keys` / the XOR tab checkbox force it.
3. ~~**`ctfc scan <folder>`**~~ **done**: `core/scan.py`, `ctfc scan` with `--no-recursive`,
   `--per-file`, `--min-interest`. The ranking rules are in section 4.
4. ~~**Custom base64 alphabet**~~ **done**: `encodings.find_custom_alphabet()` +
   `decode_custom_base64()`, offered by `auto` at every step as `Step("base64_custom")`. The
   fiddly part was *what* to decode: the alphabet holds most letters, so "keep every character it
   knows" swallowed the whole script. It now drops the alphabet declaration and takes the longest
   remaining run, and the generated snippet does the same.
5. ~~**pcap extraction in stdlib**~~ **done**: `core/pcap.py`, `ctfc pcap` with `--extract <dir>`
   which feeds `ctfc scan`. Validated against tshark.

Idea 6 (history of "Use as next input", export the chain) belongs with M6's pipeline, and idea 7
(stego tool suggestions) with M6's tool registry: leave both there.

Done so far: idea 5 (password list, M3), idea 1 and idea 8 (this commit).

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

Ideas 5 (password list) and, in M5, the hash hand-off are done. See section 5 for the order the
remaining ones will be done in.

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
ctfc rsa --key tests/fixtures/rsa_fermat.pub.pem --decrypt tests/fixtures/rsa_fermat.bin --attack
ctfc rsa --key tests/fixtures/rsa_private.pem --check tests/fixtures/rsa_public.pem
ctfc hash 482c811da5d5b4bc6d497ffa98491e38
ctfc pcap tests/fixtures/capture.pcap
ctfc pcap tests/fixtures/capture.pcap --extract /tmp/objs && ctfc scan /tmp/objs
ctfc pcap tests/fixtures/audit_radius.pcap          # recovers the RADIUS PAP password on its own
ctfc pcap tests/fixtures/audit_usb_keyboard.pcap    # reads what was typed on the USB keyboard
ctfc pcap tests/fixtures/audit_mail_imap.pcap       # the e-mail body (ZIP password) + the attachment
ctfc auto tests/fixtures/audit_evtx_dropper.evtx    # PowerShell -enc hidden as UTF-16LE in the log
ctfc radius hex:<User-Password> --authenticator hex:<16 bytes>   # the paste-two-blobs path
ctfc tools tests/fixtures/audit_zipcrypto.zip       # prints the ready-to-run bkcrack command
ctfc scan tests/fixtures --min-interest 0.9
ctfc recipe save /tmp/r.json tests/fixtures/layers_b64_zlib_xor.txt
ctfc recipe run /tmp/r.json tests/fixtures/layers_b64_zlib_xor.txt --cyberchef
ctfc tools text:482c811da5d5b4bc6d497ffa98491e38
ctfc tools tests/fixtures/openssl_salted_md5.bin --run openssl --password password123
ctfc classical tests/fixtures/classical_vigenere.txt
ctfc classical text:'PLOA{fvzcyr_fuvsg}'
ctfc keys tests/fixtures/memdump_aes.bin --against tests/fixtures/memdump_aes_ct.bin
ctfc keys tests/fixtures/strings_dump.txt
ctfc lens tests/fixtures/writeup_cave_ransom.ps1 --against tests/fixtures/writeup_cave_map.pdf.secured --show-code
ctfc session new demo --title "Demo"; ctfc auto tests/fixtures/layers_b64_zlib_xor.txt; ctfc report --lang fr
ctfc session stop
ctfc cheatsheet
make bundle  # dist/ctfc-bundle/, installs without internet
make vendor  # once: embedded CyberChef (already done on this machine)
ctfc serve   # http://127.0.0.1:8137  (Pipeline tab, Open in CyberChef, Suggested tools)
```
