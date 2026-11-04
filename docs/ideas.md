# Ideas for later

Everything in `CLAUDE.md`'s milestones is built, both audits are closed, the
A/B/C feature batches are done, and every section of the *previous* version of
this file has been built (lots D, E, F and G - see `HANDOFF.md` §5septies and
§5octies).

- **Section 1** is what is still open from that list: three things that need a
  real sample before they can be finished honestly, and the things that were
  measured or considered and deliberately not built.
- **Section 2** was the list written at the end of the session that finished the
  old one. **It is now built too** (lot H, 2026-11-04 - `HANDOFF.md` §5nonies);
  each entry below keeps its reasoning, with what actually happened added where
  the plan turned out to be wrong. **Section 2.7 is the fresh list.**
- **Section 3** keeps the reasoning behind what is already done, and section 4
  the questions that do not need reopening.

The rules still apply to anything added later: no LLM, offline-first, nothing
executed, and every feature has to *deduce its parameters* rather than ask for
them.

---

## 1. Still open, and why

### 1.1 Three places that stop short on purpose

Each needs something real to verify against. That condition is the whole entry:
without it, the code would be a guess wearing the clothes of an implementation.

- **SAM hash decryption** (`core/hive.py`). The boot key is already recovered.
  What is missing is the RC4 or AES path over the SAM's `F` and `V` structures
  plus the DES keys derived from each RID. **Condition:** a genuine SAM+SYSTEM
  pair and a known-good `samdump2` output to diff against.
- **EVTX binary XML** (`core/evtx.py`). Templates, the substitution array and
  the per-chunk string table. It would give real element names and the EventID,
  so `4688` and `4104` could be filtered instead of grepped.
  **Condition:** one real `.evtx` and an `evtx_dump` run to compare with.
- **LZXPRESS Huffman**, for MAM-compressed prefetch (`core/winartifact.py`).
  Every Windows 10+ `.pf` is compressed this way, and the reader names the file
  and hands over instead of guessing. **Condition:** a real compressed `.pf`
  plus a known-good decompression (libscca is installed here and does it) to
  diff against. Writing a decompressor that only agrees with itself is exactly
  what this project does not do.

### 1.2 Measured and declined: parallel brute force

`ctfc` searches, measured on this machine (the table is also in
`docs/how-it-works.md` §28):

| search | time |
|---|---|
| `solve_xor` on 289 bytes, hashed-key fallback included | 0.4 s |
| key hunt over a 64 KB memory dump | 0.04 s |
| `ctfc crc` worst case (every searchable length and alphabet) | 4.5 s |
| `ctfc sym --passwords` over the 10000-password list | 8.3 s |

Nothing is felt as slow. The slowest is the password list, and it is slow for
the one honest reason that PBKDF2 is *meant* to be: four cores would turn 8
seconds into 2, bought with process pools, pickling, and re-plumbing progress
and cancellation through `Budget`. A search big enough to need real parallelism
belongs in hashcat, which `ctfc hash` already hands over to. **Condition to
revisit:** a real search in a real CTF that is actually waited on.

### 1.3 The long tail that stays with dcode.fr

`Playfair`, `Bifid`, `Nihilist`, `ADFGVX` and friends all need a key square
typed in by hand. The rule that came out of section 3.3 is that a decoding
belongs in ctfc when it is **deterministic**, so `auto` can simply try it and
let the scoring decide. These are not, so `ctfc tools` links to dcode's page for
them and that is the better answer. The keyless ones (Morse, Bacon, A1Z26,
Polybius, tap code) *are* in, and so are Base45, basE91, Z85 and uuencode.

### 1.4 Other executables not read

**Mach-O** is named and handed to `otool`/`nm`: there is no macOS here to test
against, and a Mach-O challenge is rare enough that `ctfc exe` saying so plainly
is worth more than a half-read header. ELF, PE, Java class/JAR and Android DEX
are all read.

---

## 2. Built on 2026-11-04 (lot H), with what the plan got wrong

Written at the end of the session that finished the previous list, while the
code was still fresh. Ordered by **value against effort**, as before. Each entry
says what it unlocks, roughly what it costs, and the trap to avoid - because the
trap is usually the reason a feature ends up half-useful.

The two at the top are the ones I would actually start with: they are the only
two that change what ctfc *is*, rather than adding another reader to it.

### 2.1 `ctfc solve <file>` - the cheat sheet, executed

**What it is.** One command that runs the decision tree instead of printing it:
fingerprint the file, pick the reader that claims it (the Files tab already
sniffs exactly this), run it, feed everything that came *out* of it - extracted
members, decoded streams, carved files, decompressed layers - back through
`auto` and the flag hunt, and print **only** the answer: the flag if there is
one, otherwise the three most interesting things that came out, each with the
exact command to go further.

**Why it is first.** It is the two-in-the-morning command. With twenty minutes
left nobody wants to remember whether this one is `ctfc archive` or `ctfc zip`,
or that a `.docm` goes to `office` and a `.jar` to `exe`. Everything needed
already exists; what is missing is the thing that puts them in order.

**Cost.** Small to medium. It is a bounded loop over pieces that are all
written: `detect`, `formats.sniff`, every reader, `auto`, `search_flags`. The
only new code is the iterator "what did this reader produce that is itself worth
reading" - and each report already carries it (entries with `data`, `objects`,
`carved`, `extracted`, Docker layers).

**The trap.** Becoming `auto` with extra steps, and burning four minutes on a
64 MB dump. The rule has to be: `solve` only chains things that are already
deterministic, it never brute-forces anything that `auto` would not, it stops at
the first flag, and it reports its budget like every other search here.

### 2.2 A workspace that correlates artefacts

**What it is.** Today ctfc is one file in, one answer out. A real challenge is a
folder: the key is never in the same file as the ciphertext. So:
`ctfc workspace <folder>` (or the session, extended) reads every file once and
keeps three pools -

- **candidate secrets**: every password-shaped string found anywhere - a config
  file, a mail body, a ZIP comment, a registry value, a `.lnk` argument, a
  Docker `ENV`, an MSI string, a literal Code Lens pulled out of a script;
- **candidate keys**: the high-entropy 16/24/32-byte windows and the hex/base64
  strings of the right length (`keyhunt` already finds these, per file);
- **ciphertexts**: everything that is encrypted - `openssl enc` files, encrypted
  ZIP/7z/RAR entries, Fernet tokens, AES-shaped blobs.

Then it tries every secret against every ciphertext under a visible budget and
reports the pairs that worked: *"the password in mail.eml opens backup.7z"*.

**Why.** That cross-product is exactly what he does by hand across a multi-file
challenge, and it is the one step the tool does not do. It is also where a
forensics challenge is actually won.

**Cost.** Medium to large, but mostly glue: `secrets.find_secrets`, `keyhunt`,
`solve_symmetric` and every format reader already produce the three lists.

**The trap.** The combinatorics. 40 secrets x 12 ciphertexts x the layout solver
is a long afternoon, so the budget has to be shared across the whole cross
product rather than per pair, with the cheap tests first (does this ZIP's
password check byte match?) before the expensive ones (PBKDF2). And the report
has to say what it did *not* get to.

### 2.3 PNG surgery: the shrunk height and the bad CRC

**What it is.** The classic: a PNG whose IHDR height was reduced so the bottom
of the image - where the flag is - never gets drawn. The fix is to brute-force
the real height, recompute the IHDR CRC and write the file back out. While in
there: a deliberately wrong chunk CRC, a bit-depth/colour-type pair that no
encoder would emit, and a `zTXt`/`iTXt` holding the answer.

**Why.** It is a stock challenge, it is pure stdlib (zlib and CRC32), and
`ctfc repair` is already the right home for it - it repairs magic bytes and
carves trailing data, so chunk-level surgery is the missing half.

**Cost.** Small. The pixels do not even need decoding: a height is right when
the IDAT stream inflates to exactly `height * (1 + width * channels)` bytes.

**The trap.** Silently "fixing" a file that was never broken. Every change has to
be reported the way `repair` already reports: offset, old bytes, new bytes, why.

### 2.4 `ctfc timeline` - every timestamp in one table

**What it is.** Every reader already pulls times out: prefetch run times, a
shortcut's three, EVTX records, SQLite rows, ZIP and CAB entries, a PE build
stamp, Docker `history`, EXIF. Merge them, sort them, label each with where it
came from, and print one table. `--since` / `--until` to narrow it.

**Why.** A forensics challenge is usually "what happened, in which order" - and
the answer is currently spread over six commands and read by eye.

**Cost.** Medium, nearly all plumbing: `core/timestamps.py` already normalises
every epoch involved.

**The trap.** Time zones and fake stamps. Everything should be printed as UTC
and labelled with its source, and a stamp that is obviously forged (a 2080 build
date, an mtime before the file format existed) should be *kept* and flagged, not
dropped - a forged timestamp is evidence too.

### 2.5 Small, frequent, cheap

Each of these is an afternoon at most, and each has come up in a real challenge:

- **`ctfc mail <file.eml>`**. `core/mail.py` exists but is only reachable
  through a capture. A plain `.eml` or `.mbox` on disk has no command, which is
  a strange gap now that `.msg` has one.
- **An EXIF reader**. The flag, the GPS point or the camera serial in a photo.
  About a hundred lines (TIFF IFDs), no dependency - `exiftool` is suggested
  today but is not always installed, and `ctfc stego` is already the natural
  home.
- **WAV LSB**, with `wave` from the standard library, plus a "this looks like a
  spectrogram puzzle" note that hands over to Audacity or Sonic Visualiser (the
  spectrogram itself needs numpy, which is not an allowed dependency).
- **`--wordlist <path>`** on the password tries of `sym`, `zip` and `jwt`, with
  a budget and progress. He keeps a full `rockyou.txt` in `~/Documents`, and the
  embedded list is only its first 10000 entries.
- **Code Lens: PHP**, which is the one language of the web category that is
  missing, and **string extraction from Go and Rust binaries**, whose strings are
  length-prefixed rather than NUL-terminated - which is precisely why `strings`
  is useless on them and why a small reader would not be.
- **QR codes and barcodes in an image**: suggest `zbarimg` through the tool
  bridge first, and only then consider a minimal decoder for the clean,
  well-aligned case. Reading a damaged QR properly is a project.

### 2.6 Engineering, not features

- **Fuzz the web API** the way the format readers are fuzzed: random JSON bodies
  at every route. The page is the part a stranger's file reaches *through Flask*,
  and `tests/fuzz_formats.py` stops at the reader.
- **A regression corpus from his own past challenges**, anonymized. He offered
  samples long ago and they never arrived; each one becomes a fixture with its
  expected flag, and the suite then proves the tool still solves them. That is
  the only test that measures the thing he actually cares about.
- **`make demo`**: run every command in `HANDOFF.md` §7 and fail if any exits
  non-zero. That list is checked by hand today, which means it is checked when
  someone remembers.

---

## 3. Done, kept for the reasoning

The entries below were the plan; they are built. What each one says about *why*
still holds, and the limits named in them are still the limits.

- ~~**Mersenne Twister state recovery**~~ `ctfc prng`. Highest ratio of
  "challenges solved" to "lines written" of anything on the original list.
  Untempering is exact; the truncated variants (`random()`, `mt_rand()`,
  `getrandbits(k<32)`) are refused on purpose - they need a GF(2) solve over the
  19937-bit state, which is a self-contained addition and must not be bolted
  onto `untemper`.
- ~~**Hash length extension**~~ `ctfc extend`. MD5/SHA-1/SHA-256/SHA-512 with
  the compression functions written out, because hashlib cannot resume from a
  state. SHA-224/384 are refused with the reason: they publish only part of the
  final state.
- ~~**A fuzzing harness**~~ `make fuzz`. It has now found **six** real bugs
  across three sessions, which is six more than "written defensively" was worth
  as a claim.
- ~~**RSA with several messages**~~ `ctfc rsa --also` and `ctfc sig`. Nonce reuse
  was indeed the cheapest and most valuable of the four.
- ~~**Archives beyond ZIP**~~ `ctfc archive`: tar, 7z, RAR 4 and 5, cabinets,
  and a `docker save` image's layers (the whiteout case is one of his own
  challenges). 7z's compressed *and* encrypted header both handled.
- ~~**More containers through the OLE2 reader**~~ `ctfc msg`, `ctfc msi`, and
  ObjectPool objects through `ctfc office --extract`.
- ~~**Windows artefacts**~~ `ctfc winartifact`: `.lnk`, prefetch, jump lists;
  AmCache through `ctfc hive`.
- ~~**CRC32 beyond three bytes**~~ `ctfc crc`: the word lists, a
  meet-in-the-middle search over several alphabets, and a GF(2) solve - with the
  share of the checksum space searched reported, because that number is what
  decides whether a hit is the content or a coincidence.
- ~~**Scoring calibration**~~ `tests/test_scoring_calibration.py`. It found a
  real miscalibration on its first run (every flag found in a sentence was
  quietly docked below `auto.FOUND`), and later a second one (a weak magic
  number was worth exactly `auto.XOR_MIN_SCORE`).
- ~~**ELF triage, Java constant pool, DEX string table, .NET literals**~~
  `ctfc exe`, and `ctfc pe` for the `#US` heap.
- ~~**Watch mode and a solve replay**~~ `ctfc watch` and `ctfc replay`.

---

## 4. Deliberately not doing

Recorded so the question does not have to be reopened each time.

- **Anything with an LLM in it.** Hard rule 1. The whole point is that ctfc works
  in a competition that bans them.
- **Attacking a remote target**: padding oracles, ECB byte-at-a-time, blind
  SQLi. Out of scope per `CLAUDE.md`, and they need a live service, which makes
  them a different tool.
- **Disk container cracking** (VeraCrypt, LUKS passphrase, BitLocker).
  Explicitly out of scope; `ctfc keys` already handles the "the master key is in
  this memory dump" case, which is the part a CTF actually asks.
- **Running or emulating a sample.** Hard rule 3. Static only, always - even
  marshal-loading a `.pyc` is over that line, and so is interpreting a
  Brainfuck program we were handed.
- **Vendoring zsteg, xortool or Detect It Easy.** The idea gets reimplemented
  and the real tool gets called when installed. `core/stego.py`, `core/xor.py`
  and `core/pe.py` are that decision carried out three times.
- **A full memory-forensics engine.** The Volatility tab exists precisely so
  that ctfc can hand that job over well instead of doing it badly.
- **Row-level MSI table decoding.** The string pool answers the same questions
  with a tenth of the code, and `msidump` exists. Stated in the report rather
  than hidden.


---

## 2.7 What is left, and what I would do next (2026-11-04)

Everything in section 2 is built. **The first entry is what he asked for
explicitly at the end of that session**, the second is the one that measures the
thing he actually cares about.

### 2.7.0 Put the rest of lot H in the browser (his stated priority)

He asked whether everything added in lot H is reachable from the web UI. It was
audited by driving the API (`HANDOFF.md` §5nonies, "Web UI coverage"), and three
things are missing, cheapest first:

- **The Go / Rust report does not show.** `ctfc exe` / `ctfc pe` print the
  version, the module, the program's own functions and the exact literals; the
  Files tab's `_exe` / `_pe` adapters show only ELF / segments / sections,
  although `report.toolchain` is right there. One `facts` section and one
  `table` section each, in `ctfc/web/formats.py`. Start here.
- **`ctfc timeline` has no route.** The events already exist on every reader
  (`readers.Opened.events`), so one dropped file is an adapter plus a tab.
- **`ctfc workspace` cannot be reached at all**, because it takes a folder. The
  design decision to make first: accept a **multi-file drop** in the page and
  run the cross product over those files (the pools do not care where the bytes
  came from), or leave it in the terminal beside `scan`, `watch` and `git`,
  which the Docs tab names. If the page is where he works, the drop is the
  answer.
- Then the two small ones: a **`--wordlist` path field** in the Symmetric, Hash
  and JWT tabs (the server is local, so a path works), and
  **`find_prose_secrets`** in the Keys tab as a second list beside the key
  candidates - today it only runs inside `workspace`.

### 2.7.1 A regression corpus from his own challenges (the one that matters)

Still the top of the list, and still blocked on the same thing: **the samples
never arrived**. He said the bar is "j'aurais pu les flag simplement en copiant
les infos dans le tool" - so the test that proves it is his own past challenges,
anonymized, each as a fixture with its expected flag. `tests/demo.py` is now the
frame it would drop into: one line per challenge, the flag as the expected
output. Ask again, and if the answer is "later", `make demo` at least keeps the
62 synthetic cases honest.

### 2.7.2 The three readers that need a real sample

Unchanged from section 1.1: SAM hash decryption, EVTX binary XML, LZXPRESS
Huffman for compressed prefetch. All three would be guesses without something
genuine to diff against, and the project has deliberately not guessed.

### 2.7.3 Smaller, and each an afternoon

- **A Go PE's string literals.** `ctfc pe` reads the function table of a Windows
  Go binary but not its literals, because a PE's string headers hold absolute
  addresses and the reader does not keep the image base. Keeping it is a
  two-line change in `pe.py`; the rest is passing sections into
  `binstrings.slice_strings` with `address = image_base + virtual_address`.
- **Rust literals properly** would mean reading the immediates out of the code,
  which means a disassembler. `capstone` is not an allowed dependency, and a
  hand-written x86-64 length decoder for `lea`/`mov` pairs is a week. The honest
  answer stays: hand over to `objdump -d`.
- **`ctfc solve` in the browser.** The Files tab runs one reader; `solve` is the
  one that chains them, and it is the command a tired person wants. The API
  already returns the shape (`SolveReport.to_dict`), so it is a tab and a
  renderer, not new logic.
- **A `--since`/`--until` on `ctfc workspace`** to narrow a big folder, and a
  `--secrets-from <file>` to add a list of candidate passwords by hand.
- **The `interesting` flag on `AmCache`/`hive`** and the other readers that
  return `notes` but no `events`: `ctfc timeline` would then cover them too
  (registry key last-written times are real evidence).

### 2.7.4 Still deliberately not doing

The spectrogram, DTMF and whistled Morse (an FFT needs numpy), decoding a
damaged QR (`zbarimg` is now suggested and does it in one call), the keyed
classical ciphers that need a key square typed in (dcode.fr), parallel brute
force (measured: the slowest search here is 8.3 s), and Mach-O (no macOS to
check against).
