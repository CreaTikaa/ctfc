# Ideas for later

Everything in `CLAUDE.md`'s milestones is built, both audits are closed, the
A/B/C feature batches are done (`HANDOFF.md` §5sexies), and **section 1 plus
section 2.5 of this file are now done too** (`HANDOFF.md` §5septies):
`ctfc prng`, `ctfc extend`, `make fuzz`, `ctfc rsa --also`, `ctfc sig`. This is
the list of what could come next.

It is ordered by **value against effort**, not by how interesting it is to build.
Each entry says what it unlocks, roughly what it costs, and - where it matters -
what would have to be true before it is worth starting. The same rules still
apply: no LLM, offline-first, nothing executed, and every feature has to *deduce
its parameters* rather than ask for them.

---

## 1. Done (2026-10-30) - kept for the reasoning

The three entries below are built. What they say about *why* still holds, and the
limits named in 1.1 are still the limits.

### 1.1 ~~Mersenne Twister state recovery~~ **done** (`ctfc prng`, commit `6b6424c`)
**Unlocks:** a whole family of challenges. Any target that leaks 624 consecutive
32-bit outputs of Python's `random`, PHP's `mt_rand` or a JS polyfill has its
entire future *and past* output recoverable - tokens, shuffles, "random" keys.
**Cost:** small. Untempering an MT19937 output is four invertible bit operations;
feed 624 of them back into the state array and the generator is cloned. No
dependency, no target needed, completely deterministic.
**Shape:** `ctfc prng mt19937 <numbers>` taking a list of outputs (decimal, hex,
or a file), reporting the recovered state, then the next N and previous N values.
Handle the common variants: outputs truncated to fewer bits (needs 624 full
words, so say clearly when there are not enough), and `random.random()` floats,
which are two outputs combined.
**Why it is first:** highest ratio of "challenges solved" to "lines written" of
anything left, and it fits the existing shape exactly.

### 1.2 ~~Hash length extension~~ **done** (`ctfc extend`, commit `c4082e0`)
**Unlocks:** the classic `MAC = md5(secret || message)` forgery. Given the digest
and the length of the secret, append anything and produce a valid digest without
ever knowing the secret.
**Cost:** small-to-medium. Needs MD5, SHA-1, SHA-256 and SHA-512 compression
functions callable from a chosen state, which means writing the three
compression loops by hand (hashlib will not resume from a state). Each is
~40 lines and well specified.
**Shape:** `ctfc extend --hash <digest> --algo sha256 --append <data>
[--secret-length N | --secret-length 1-64]`. When the length is unknown, emit one
candidate per plausible length - that *is* the deduce-the-parameters behaviour.
Output the forged digest and the exact padded message to send.

### 1.3 ~~A fuzzing harness over the format readers~~ **done** (`make fuzz`, commit `beeb792`: it found three real bugs, see `HANDOFF.md` §5septies)
**Unlocks:** confidence. There are now about a dozen readers chewing on untrusted
bytes - `cfb`, `office`, `pdf`, `stego`, `zipinfo`, `gitrepo`, `sqlitedb`, `hive`,
`pe`, `evtx`, `protobuf`, `pcap`, `usb`, `mail`. They are written defensively and
each has its own error type, but "defensively" is a claim, not a proof.
**Cost:** small. `tests/fuzz_formats.py` walking every fixture, mutating bytes
with a seeded RNG, and asserting that each `analyse()` either returns or raises
*its own* exception type - never `IndexError`, `struct.error`, `MemoryError`, or
a hang. Run it with a fixed seed in `make test` and a longer sweep behind
`make fuzz`.
**Why:** this is the cheapest way to find the bugs that a real challenge file
would find at the worst moment. It is also the kind of thing that only gets
written if it is written down.

---

## 2. Clear value, more work (2.5 is done; the rest is open)

### 2.1 Finish what was deliberately left unfinished
Three places stop short *on purpose*, each because there was nothing real to
verify against. Each is worth finishing the moment that changes:

- **SAM hash decryption** (`core/hive.py`). Needs the boot key - already
  recovered - plus the RC4 or AES path over the SAM's `F` and `V` structures,
  and DES keys derived from each RID. Do this only with a genuine SAM+SYSTEM
  pair in hand and a known-good `samdump2` output to compare against.
- **Full EVTX binary XML** (`core/evtx.py`). Templates, the substitution array
  and the per-chunk string table. Would give real element names and the EventID,
  so `4688` and `4104` could be filtered. Needs one real `.evtx` and an
  `evtx_dump` run to diff against.
- **CRC32 recovery beyond three bytes** (`core/zipinfo.py`). Brute force stops at
  three because 95⁴ is too slow in Python. CRC32 is linear over GF(2), so a
  4-8 byte preimage can be *solved* rather than searched - pick the message
  length, build the 32 equations, and solve. Medium maths, small code, and it
  turns "a short file" into "a short-ish file".

### 2.2 More containers through the OLE2 reader we already have
`core/cfb.py` already reads compound files, and three high-value formats *are*
compound files, so they are mostly report-writing rather than parsing:

- **`.msg` Outlook messages**: headers, body, attachments. Pairs with
  `core/mail.py`, which already handles the MIME side.
- **MSI installers**: the tables are streams; the embedded CAB and the custom
  actions are what matter.
- **OLE2 embedded objects** (`ObjectPool`): `ctfc office` notes when one is
  present but does not extract it yet. That is the "the real payload was an
  embedded object inside the .doc" case.

### 2.3 Archive formats beyond ZIP
`ctfc zip` showed how much is in the headers. The same treatment for **7z, RAR,
tar and CAB**: entry listing, which encryption, and the matching `*2john`
hand-off. 7z's header is itself compressed, which is the only awkward part.

### 2.4 LNK, Prefetch, AmCache, Jump Lists
The Windows artefacts that answer "what was run, and when". All are
well-documented binary structures of moderate size, and all three timestamps
decode through `core/timestamps.py`, which exists now. A `ctfc winartifact
<file>` that sniffs which one it is would cover a lot of forensics ground for one
module's worth of work.

### 2.5 ~~RSA attacks that need more than one message~~ **done** (commit `2d897c9`)
All four are built: common modulus, Håstad broadcast and Franklin-Reiter in
`core/rsa_multi.py` behind `ctfc rsa --also <key>=<ct>`, and ECDSA/DSA nonce
reuse in `core/signatures.py` behind `ctfc sig`. The nonce-reuse one did turn out
to be the cheapest and most valuable of the four, as suspected here.

---

## 3. Worth doing, lower priority

### 3.1 Other executables
**ELF triage** to match `ctfc pe` (sections, dynamic symbols, `RWX` segments,
packers, overlay) - useful but `readelf` is usually installed, which is why it
scores below PE. **Mach-O** likewise. **Java `.class`/JAR** (constant-pool
strings are where keys hide) and **Android DEX** (the SimpleLocker case was
Android) are more distinctive and probably better value than ELF.

### 3.2 .NET IL string extraction
`ctfc pe` says "use dnSpy" for a .NET assembly. Reading the `#Strings` and
`#US` heaps out of the metadata would at least dump every string literal without
leaving ctfc - which is often all that is needed.

### 3.3 Classical and encoding long tail
Playfair, Bifid, Nihilist, Beaufort, ADFGVX, Bacon, tap code, Morse in odd
encodings, Base45/Base91/z85, Brainfuck and friends. Individually small; the
honest question is whether dcode.fr's page (already linked by the tool bridge) is
simply the better answer for most of them. Add the ones that `auto` can try
*automatically* and leave the interactive ones to dcode.

### 3.4 Workflow polish
- **Watch mode**: `ctfc watch <folder>` running `detect`/`auto` on anything new,
  for when a challenge drips files out.
- **A solve replay**: a session already records every step; rendering it as a
  single runnable script would turn a session into a write-up artefact rather
  than a log of one.
- **Parallel brute force**: the XOR, password and CRC searches are embarrassingly
  parallel and currently single-threaded. Only worth it if a real search is
  actually felt as slow - measure before building.

### 3.5 Scoring calibration
`scoring.py` is the judge for every brute-force result, and its thresholds were
chosen by eye. A test that runs it across every fixture plus a pile of noise and
reports the score distribution would show whether the cut-offs are where they
should be - and would catch a regression that makes everything score 0.6.

---

## 4. Deliberately not doing

Recorded so the question does not have to be reopened each time:

- **Anything with an LLM in it.** Hard rule 1. The whole point is that ctfc works
  in a competition that bans them.
- **Attacking a remote target**: padding oracles, ECB byte-at-a-time, blind SQLi.
  Out of scope per `CLAUDE.md`, and they need a live service, which makes them a
  different tool.
- **Disk container cracking** (VeraCrypt, LUKS passphrase, BitLocker). Explicitly
  out of scope; `ctfc keys` already handles the "the master key is in this memory
  dump" case, which is the part a CTF actually asks.
- **Running or emulating a sample.** Hard rule 3. Static only, always - even
  marshal-loading a `.pyc` is over that line.
- **Vendoring zsteg, xortool or Detect It Easy.** The idea gets reimplemented and
  the real tool gets called when installed. `core/stego.py` and `core/xor.py` are
  that decision already carried out twice.
- **A full memory-forensics engine.** The Volatility tab exists precisely so
  that ctfc can hand that job over well instead of doing it badly.
