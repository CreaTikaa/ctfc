# Ideas for later

Everything in `CLAUDE.md`'s milestones is built, both audits are closed, the
A/B/C feature batches are done, and **every section of this file that could be
built has now been built** (lots D, E, F and G - see `HANDOFF.md` §5septies and
§5octies). What is left is listed in section 1: three things that need a real
sample before they can be finished honestly, and the things that were measured
or considered and deliberately not built.

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

## 2. Done, kept for the reasoning

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

## 3. Deliberately not doing

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
