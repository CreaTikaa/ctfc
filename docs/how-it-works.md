# How ctfc works

Plain-language notes on each module, so you can redo everything by hand when the
tool is not available. Sections are added milestone by milestone.

---

## 1. Inputs (`ctfc/core/inputs.py`)

Every command takes the same kind of input:

| You type            | ctfc reads                                  |
|---------------------|---------------------------------------------|
| `path/to/file`      | the raw bytes of the file                   |
| `-`                 | stdin (`cat x | ctfc auto -`)               |
| `hex:41 42 0x43`    | hex; spaces, `0x`, `\x`, `:` are ignored    |
| `b64:QUJD`          | base64, standard or URL-safe, padding optional |
| `text:hello`        | the UTF-8 bytes of the text, nothing decoded |
| `Q1lCTntoaX0=`      | bare text: decoded if it *looks* like hex/base64, with a note |

`detect` and `auto` keep bare text **as text**: they recognise encodings
themselves, and this way the decoding chain they show starts from exactly what
you pasted.

The web UI never reads files on the server: only text you paste or files you drop.

---

## 2. Scoring (`ctfc/core/scoring.py`)

Brute force produces many outputs; scoring decides which ones look like "the
answer". It is a fixed set of rules, no AI:

| Rule | Score | Why |
|------|-------|-----|
| A flag pattern matches (`CYBN{...}`, your own regexes) | 0.97 | Strongest possible signal |
| The generic `XXX{....}` shape, with a CTF-looking prefix (`BZHCTF`, `FCSC`, `flag`...) | 0.90 | |
| The generic shape with any other prefix (`a3g{...}`) | 0.45 | Random bytes and code (`else{ ... }`) match it too |
| A flag whose content is garbled (`CYBN{fi)x~}`) | 0.60 | Typically a half-correct key |
| A flag prefix appears **in base64** (`Q1lCTn...` = `CYBN{`) | 0.90 | One more decode to go |
| Magic bytes of a known file (PNG, ZIP, PDF...) | 0.85 | Random bytes almost never start like that |
| Natural text (see below) | up to ~0.95 | |
| Valid PKCS7 padding (after a block cipher) | +0.15 | Wrong keys rarely produce valid padding |

**Natural text** combines three measurements:

- **printable ratio**: share of readable characters. Encrypted data is ~37% printable
  by chance, text is ~100%.
- **word rate**: share of letters that belong to common English/French words
  (`ctfc/data/words_en_fr.txt`, add your own words there).
- **letter frequency (chi-squared)**: compares how often each letter a..z appears
  with English and French. 0 = identical; normal text gives < 50.

```
text_score = printable⁶ × (0.35 + 0.40 × word_rate + 0.25 × frequency_score)
frequency_score = 1 / (1 + chi² / 60)
```

(printable to the power 6: real text is ~100% printable, so 94% printable is
already suspicious: 0.94⁶ ≈ 0.69.)

A flag inside unreadable text is suspicious too (a half-correct XOR key can
produce `CYBN{fixtuaDp3vz_repeating}` in the middle of garbage). So a flag's score
loses up to 0.15 depending on how readable the *rest* of the output is. A flag
alone is not penalised.

So the order is: flag > file > sentence > base64/hex text > random bytes.

**Entropy** (bits per byte, 0 to 8) measures how "random" bytes look:
English ≈ 4.5, base64 text ≈ 6, compressed or encrypted data ≈ 8. With few bytes
the maximum is lower (`log2(length)`), which is why ctfc prints both.

### Flags in base64

base64 turns 3 bytes into 4 characters. So `CYBN{` has 3 possible encodings,
depending on where it sits inside the encoded data:

```
"CYBN{"   at position 0 mod 3 -> Q1lCTn
          at position 1 mod 3 -> NZQk57
          at position 2 mod 3 -> DWUJOe
```

ctfc searches all three, then decodes the surrounding base64 to show the flag.
Add your own prefixes with `flag_prefixes = ["BZHCTF{"]` in `~/.ctfc/config.toml`.

---

## 3. Detect (`ctfc/core/detect.py`)

`ctfc detect <input>` measures the data, then runs independent checks. Each
check gives *guesses* with a confidence, reasons and a next step.

| Check | What it looks at |
|-------|------------------|
| flags | flag regexes, in clear or base64 |
| magic bytes | `ctfc/data/magic.toml`: file type at offset 0 |
| appended data | bytes after the end marker (PNG `IEND`, ZIP end record, JPEG `FFD9`, PDF `%%EOF`) = polyglot / hidden file |
| embedded files | other signatures later in the data (`binwalk`-like) |
| text prefixes | `U2FsdGVkX1` (base64 of `Salted__`), Fernet `gAAAAA`, PEM, JWT, `$mysqlna$`, bcrypt, Kerberos, NetNTLMv2, PowerShell `-enc`... |
| charset | binary, decimal, hex, base32, base64, base58, base62, base85 |
| zero-width chars | U+200B/C/D, U+2060-2064, U+FEFF hidden in text |
| crypto constants | `ctfc/data/constants.toml`: AES S-box, MD5/SHA init values, ChaCha `expand 32-byte k`, TEA `0x9e3779b9`... as bytes **and** as hex text in source code |
| custom base64 alphabet | a 64-character string with no repeated character |
| entropy | random-looking = encrypted/compressed/key; low but unreadable = simple XOR |
| ECB | equal 16-byte blocks: ECB encrypts equal plaintext blocks to equal ciphertext blocks |
| lengths | 16/24/32 = AES keys, 12 = GCM/ChaCha nonce, 48 = 32-byte key + 16-byte IV... |
| XOR period | see below |

If the input is hex/base64 text, the binary checks also run on the decoded bytes
("after base64 decoding: ...").

### Repeating-key XOR: finding the key length

With a key of length `p`, byte `i` and byte `i + p` were XORed with the **same**
key byte. If the plaintext bytes are equal, the ciphertext bytes are equal too.
In English, two letters picked at random are equal about 6.5% of the time; in
random data, only 0.4%.

So for each distance `k` ctfc counts how often `data[i] == data[i + k]`. Distances
that are multiples of the key length stand out. ctfc picks the `p` whose multiples
stand out most compared to the other distances. Keys with a repeated character
(`s3cr3t`) also create a shorter pseudo-period, so other plausible lengths are listed.

---

## 4. Auto / "magic" (`ctfc/core/auto.py`)

`ctfc auto <input>` peels encoding layers by itself:

1. Start from the input. Try every decoder whose quick test says "maybe"
   (`ctfc/core/encodings.py`).
2. Score each output. Put it in a queue, best score first.
3. Take the best output from the queue and repeat, up to 6 layers deep.
4. Never decode the same output twice; stop when the budget (2000 attempts by
   default) runs out; stop going deeper once a specific flag is found.
5. Report the outputs that score better than the input, with the decoding chain,
   a Python script that redoes it, and the CyberChef recipe.

ROT13, ROT47 and "reverse" may appear only once per chain, otherwise the search
wastes its time on `rot47 -> rot13 -> rot47 -> ...`.

Decoders available: hex, base64, base64url, base32, base58, base62, base85,
ascii85, URL `%XX`, HTML entities, quoted-printable, binary, decimal char codes,
reverse, ROT13, ROT47, UTF-16LE (PowerShell), zero-width bits, JWT, "extract the
longest base64/hex run from a text", zlib, gzip, bzip2, lzma/xz, raw deflate.

Compression and encryption both look random, but compressed data starts with a
header (`78 9C` zlib, `1F 8B` gzip, `BZh` bzip2, `FD 37 7A 58 5A` xz) and
decompresses without error. Decompression is capped at 64 MB (zip bomb protection).

---

## 5. XOR (`ctfc/core/xor.py`)

```
ciphertext = plaintext XOR key        plaintext = ciphertext XOR key
```

The same operation encrypts and decrypts. With a repeating key `abc`, byte 0 is
XORed with `a`, byte 1 with `b`, byte 2 with `c`, byte 3 with `a` again...

`ctfc xor <input>` tries, in this order:

### Single byte

Only 256 possible keys: try them all and keep the most readable outputs. Two
"text models" decide what readable means:
- **prose**: frequent letters (space, e, t, a, o, i, n, s, r, h, l, u) +3, other
  letters +1, printable +1, other bytes -4;
- **binary**: the most frequent byte of a binary file is usually `0x00`, so
  `key = most frequent byte`.

### Repeating key: find the length, then solve column by column

1. **Key length** (two independent tests, combined):
   - *normalized Hamming distance*: cut the data in blocks of L bytes and count the
     differing bits between blocks. With the right L, the key cancels out
     (`(p1^k) ^ (p2^k) = p1 ^ p2`) and two text blocks differ by ~2.5-3.3 bits per
     byte; with a wrong L it looks random: ~4 bits per byte.
   - *coincidence ratio*: see "Repeating-key XOR" in the Detect section.
   ctfc prints the top 5 lengths with both numbers.
2. **Columns**: bytes 0, L, 2L, ... were all XORed with key byte 0. That column
   is a single-byte XOR: solve it with the text models above. Same for column 1,
   2... Three keys are built: *prose*, *printable text / code* (for scripts full of
   `0x2e,0x33,...`) and *binary*.
3. **Clean-up**: a key `abcabc` is shortened to `abc`; a long key is also "folded"
   by majority vote into its divisors (a 9-byte `BBBBUBBBB` becomes `B`): with few
   bytes per column, one column is often solved wrong.

The best result is chosen by the normal scoring, with a tiny bonus for shorter keys.

### Known plaintext (crib)

If you know a piece of the plaintext, then at that position
`key = ciphertext XOR known_plaintext`.

- **File headers at offset 0**: ctfc assumes the plaintext starts with a PNG, PDF,
  ZIP, MZ, ELF, GIF, JPEG, XML, PEM, shebang, HTML, URL or `Salted__` header.
  If the recovered key bytes repeat inside the header (key shorter than the
  header), the key is confirmed. Otherwise the header gives the first key bytes and
  the column solver gives the rest. **The guessed header is not counted in the
  score**, otherwise assuming "PNG" would always "find" a PNG.
- **Crib dragging**: the crib (your `--crib`, plus the flag prefixes like `CYBN{`)
  is slid over every position. For keys up to the crib's length, each position
  gives the whole key: decrypt and score. For longer keys, the crib fixes some key
  bytes and the columns the others.

Limits: with very short data (a few dozen bytes) and a key longer than the crib,
there are too few bytes per column. Give a longer crib or the key length.

### Two layers

"Repeating key, then single byte" is the same as one repeating key, because XOR
is associative: `(p ^ k) ^ b = p ^ (k ^ b)`. ctfc finds `k ^ b` directly, then
tries every `b` to split it back into a readable key: `'1\'!0\'6'` =
`'secret'` XOR `0x42`. Several splits can be valid (`SECRET` XOR `0x62` also
works): the most word-like one is shown.

### Two inputs (two-time pad)

`ctfc xor c1.bin --with c2.bin`: if two messages were encrypted with the same key
stream, `c1 ^ c2 = p1 ^ p2` and the key disappears. With `--crib ' the '`, every
position where one message contains " the " reveals 5 characters of the other one.

### In `auto`

`auto` also tries single-byte and repeating-key XOR on data that is not a known
file or compressed stream and does not already read well. A result is kept only if
it is readable (score >= 0.6), or if the XOR turned unreadable bytes into
fully printable text (scripts). Repeating-key XOR is only tried when the key length
test is convincing.

## 6. Symmetric ciphers (`ctfc/core/symmetric.py`)

### Block or stream?

A **block cipher** (AES, DES, 3DES, Blowfish, TEA, XTEA) transforms a fixed-size
chunk: 16 bytes for AES, 8 bytes for the others. It can only encrypt whole blocks,
so the plaintext has to be *padded* to a multiple of the block size. Consequence
you can use: **an AES ciphertext is almost always a multiple of 16 bytes**.

A **stream cipher** (RC4, ChaCha20, Salsa20) builds a key stream, one byte at a
time, and XORs it with the plaintext. No padding, so **the ciphertext has exactly
the length of the plaintext**. CTR, CFB, OFB and GCM turn a block cipher into a
stream cipher, with the same consequence.

So, from a length alone:

| length | likely |
|---|---|
| multiple of 16 | AES in ECB or CBC |
| multiple of 8, not of 16 | DES / 3DES / Blowfish / TEA / XTEA in ECB or CBC |
| anything else | a stream: CTR, CFB, OFB, GCM, ChaCha20, RC4... or CBC-CTS |

### The modes, and what each one leaks

- **ECB**: each block encrypted on its own. Two identical plaintext blocks give two
  identical ciphertext blocks, which is why `detect` looks for repeated blocks.
  No IV.
- **CBC**: each plaintext block is XORed with the *previous ciphertext block*
  before encryption (the first one with the IV). To decrypt block *n* you need
  ciphertext block *n-1*, which you have — so **a wrong IV only breaks the first
  block**. If your plaintext is readable except for its first 16 bytes, you have
  the right key and the wrong IV.
- **CTR**: encrypts a counter and XORs the result with the data. The ciphertext
  length is the plaintext length. Beware: "the counter" is written differently by
  different libraries (a full 16-byte block, or an 8-byte nonce plus an 8-byte
  counter) — ctfc tries both.
- **CFB / OFB**: two other ways to make a stream out of a block cipher. CFB comes
  in two flavours: one segment per block (what `openssl enc -aes-256-cfb` does) and
  one segment per byte (CFB8, the pycryptodome default). ctfc tries both.
- **GCM**: CTR plus an *authentication tag* (16 bytes, usually glued to the end of
  the ciphertext). The tag is computed from the key, so **if the tag verifies, the
  key is right**. That is the strongest signal this tool can get.
- **CBC-CTS** (ciphertext stealing): CBC for a plaintext whose length is not a
  multiple of the block size, without padding. The short last block steals the
  bytes it lacks from the previous ciphertext block. Two layouts exist (CS1, what
  `openssl enc -aes-128-cbc-cts` writes, and CS3, used by Kerberos and .NET); they
  only differ in the order of the last two pieces, and ctfc tries both.

### IV or nonce?

Same role, different rules. Both make the same plaintext encrypt to different
ciphertexts, and **neither is secret** — that is why it is so often simply glued
to the front of the ciphertext.

- an **IV** (CBC, CFB, OFB) is as long as a block (16 bytes for AES) and should be
  unpredictable;
- a **nonce** (CTR, GCM, ChaCha20: 12 bytes, Salsa20: 8) must only never be used
  twice with the same key. Reusing one is fatal: two messages with the same key
  stream can be XORed together (see section 5, "two inputs").

Where ctfc looks for it, in order: what you passed, the blob you passed, **the
first 8/12/16 bytes of the ciphertext**, all zeros, the start of the key.

### Padding, and why it tells you the key is right

PKCS7 pads with *N* bytes all equal to *N*: one missing byte gives `01`, two give
`02 02`, and a plaintext that already fits gets a whole extra block of `10` x16.
So after a decryption you can simply look at the end:

```
...48 65 6c 6c 6f 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b   -> valid: 11 x 0x0b
```

A **wrong** key produces random bytes, which are valid PKCS7 padding only about
once in 256 tries. That is why `ctfc` adds 0.15 to the score when the padding is
valid and says so in the reasons: it is the cheap oracle that makes the whole
layout search work, even when the plaintext is a binary file with no readable text.

(The same property is what makes a *padding oracle attack* possible against a
server that says "bad padding" out loud — not something this tool does, since it
only works offline.)

### Deriving a key from a passphrase (`ctfc/core/kdf.py`)

When the challenge gives a *password* rather than a key, something turned the one
into the other:

| KDF | what it does | where you meet it |
|---|---|---|
| `md5(password)` / `sha256(password)` | one hash, no salt | hand-written scripts |
| `EVP_BytesToKey` | `D_i = H(D_{i-1} \|\| password \|\| salt)`, concatenated, then cut into key then IV | `openssl enc` without `-pbkdf2` |
| PBKDF2 | HMAC repeated N times (default 10000 for openssl) | `openssl enc -pbkdf2`, most modern code |
| scrypt | PBKDF2 plus a lot of memory | modern code |

An `openssl enc` file is easy to recognise: it starts with the eight bytes
`Salted__` followed by the 8-byte salt (or with `U2FsdGVkX1` when it was written
with `-a`, i.e. base64). ctfc prints the salt, derives key **and** IV from the
password for every layout above, and shows the `openssl enc -d ...` command that
reproduces the result — check it: it is the one you would paste in a write-up.

With `--passwords`, the passphrase is looked for in `ctfc/data/passwords.txt`
(10000 common passwords, offline). The cheap derivations are tried over the whole
list before the slow ones, so the budget is not spent on PBKDF2 for the first few
hundred entries.

### The unknown-layout search

`solve_symmetric()` is a few nested loops, and nothing more clever than that:

```
for cipher in (aes, 3des, des, blowfish, chacha20, salsa20, rc4, tea, xtea):
  for key_size in that cipher's sizes:        # 32, then 16, then 24 for AES
    for material in (the key you gave, the blob splits, the KDFs of your password):
      for mode in that cipher's modes:        # filtered by the ciphertext length
        for iv in (yours, from the blob, from the ciphertext, zeros, the key):
            decrypt, strip the padding, score, keep the reasons
```

- the **key forms** tried for whatever you pass: raw, hex-decoded, base64-decoded,
  cut to size, zero-padded to size (what CryptoJS does), and `md5`/`sha256` of it
  (in case it was really a passphrase);
- the **blob splits**: the whole blob as the key, `key||iv`, `iv||key`,
  `blob[:keysize]`, `blob[-keysize:]`;
- everything runs under a `Budget` (default 30 s) with progress and cancellation,
  identical attempts are skipped, and the search **stops as soon as a result scores
  0.95 or more** (a flag, or a verified tag), so it does not burn the budget after
  it has already won.

Every candidate carries the key, the IV, the KDF, the padding and a standalone
pycryptodome script that reproduces it — the tests run those scripts and check
their output, so what you copy really works.

### TEA and XTEA (`ctfc/core/tea.py`)

Two tiny ciphers, 64-bit block, 128-bit key, 32 rounds around the constant
`delta = 0x9E3779B9` (a nice fingerprint to grep for in a binary — `detect` does).
pycryptodome does not implement them, so ctfc does, in about ten readable lines
each. One catch: the 8-byte block is read as two 32-bit words, and implementations
disagree on the byte order (C on x86 is little-endian, most Python and Java code is
big-endian). ctfc tries both and tells you which one worked.

## 7. Code Lens (`ctfc/core/lens.py`)

The most useful tool here for forensics, because it answers the question you
actually have: **"I found the encryptor, what does it do?"** When you have the
code, you do not have to guess the cipher or the key layout: you mirror it.

### Nothing is ever executed

A sample may be malware, so Code Lens is *static analysis only* (hard rule 3 in
`CLAUDE.md`). It never runs, imports or `eval`s the file. A test parses our own
three lens modules and asserts there is no call to `eval`, `exec`, `compile` or
`__import__` anywhere in them. The *data* a script carries does get decoded (see
"peeling" below) - that is bytes going through base64 and XOR, not code running.

### Python: a real parser

For Python, `ast` gives something regexes cannot: **the order of operations**. In

```python
out = zlib.decompress(base64.b64decode(BLOB))
```

the innermost call runs first, and a parse tree knows it. Code Lens walks each
statement in source order and, inside a statement, visits calls innermost-first.

Values are recovered by **constant folding**: rebuilding what a literal
expression is worth, the way you would read it by hand.

| written in the script | folded to |
|---|---|
| `"ab" + "cd"` | `"abcd"` |
| `"ab" * 3` | `"ababab"` |
| `"hello"[::-1]` | `"olleh"` |
| `bytes([0x41, 0x42, 67])` | `b"ABC"` |
| `bytes.fromhex("414243")` | `b"ABC"` |
| `base64.b64decode("QUJD")` | `b"ABC"` |
| `"".join(["a","b","c"])` | `"abc"` |
| `bytes(range(3))`, `open(f).read()` | **nothing** |

The last line matters: when a value cannot be rebuilt from literals alone, the
answer is `None`. Code Lens says "I could not read this" instead of guessing, and
it never evaluates the expression to find out.

Two details that took a while to get right:

- **`KEY = bytes.fromhex("...")` is not a step in the data path.** An assignment
  to a variable whose name says key / iv / salt / password / secret is *setup*:
  its hex decoding is not reported as "decode hex", otherwise every script with a
  hex key appears to start by decoding hex.
- **the cipher step belongs where the data flows through it.** `AES.new(key, mode,
  iv)` only records the parameters; the operation is emitted at `.decrypt()`.
  Python evaluates `AES.new(...)` *before* the arguments of `.decrypt(...)`, so
  reporting it at `.new()` would put AES before the base64 decode that feeds it.

### The other languages: a rule table

PowerShell, JavaScript, bash and VBScript are matched with a table of rules kept
in `ctfc/data/lens_rules.toml`. Each rule is an id, a regex, an explanation, and
what its captured group means (`blob`, `key`, `iv`, `password`, `url`, `path`...).
Supporting a new API is then **one TOML entry, not code** - which is the point:
during a CTF you can add a rule in thirty seconds.

What you lose: a regex only knows *where* it matched, so operations are ordered by
position in the file. That is right for the straight-line scripts droppers are
made of, and wrong for code that defines a function at the bottom and calls it at
the top. The report always says so in its notes.

Two things regexes cannot do on their own, so they are code:

- **following a variable**: one match sees `-bxor $k`, another sees `$k = 0x3b`,
  and nothing ties them together. `_resolve_variable_keys` looks the name up.
- **telling a guess from a fact**: a key attached to an operation because its
  *size* fits (not because the data flows into it) is marked `key_guessed`, and
  the recovery script then stops before that step rather than producing something
  that crashes or lies.

### Peeling the layers

A dropper usually hides several strings the same way: a URL here, a flag there.
So once the chain is known (`base64 -> xor(0x5a)`), ctfc applies it **to every
embedded blob**, scores each result with `scoring.py` and ranks them. The flag
regexes fire here, which is why the answer is often simply the first row of the
"peeled blobs" table.

### The recovery script

The operations are turned back into `codegen.Step`s - the same ones `auto` and the
symmetric solver use - so the generated script is a normal ctfc snippet. A script
that *decodes* (the usual dropper) is replayed in the same order; a script that
*encodes* is undone in reverse. If a step is missing (an unknown key, a guessed
one), the script stops there, is marked **partial**, and a note says what was left
out and why.

When the cipher uses a **passphrase** rather than a key (`openssl enc -pass`, a
CryptoJS passphrase), Code Lens cannot produce the key - deriving it is exactly
what `ctfc sym` does. So it hands over with the ready-to-run command, for example:

```
ctfc sym <file> --pass "bashpass"
```

### With the encrypted file (`--against`)

Static analysis cannot always say *which* string is the key. In the
"Cave Expedition" ransomware the names are obfuscated (`$a53Va`), the two keys
are base64 strings decoded by a helper function, then passed through two more
functions before reaching `$data -bxor $k1 -bxor $k2`. A regex cannot follow
that. But the key can only be one of the script's own literals, so when you also
have the file it produced:

```
ctfc lens ransom.ps1 --against map.pdf.secured
```

1. every string literal of the script is collected, as written and decoded
   (base64, hex), plus the keys Code Lens extracted itself;
2. the operations say what to try: how many keys the XOR line combines (two
   `-bxor` = two keys), whether a cipher is used, and whether the output was
   base64-encoded (then the file is base64 text: decode it first);
3. every combination is tried on the first 4 KB and scored; the best is
   replayed on the whole file. The reasons name the line and the variable of
   each key, and the generated script writes the result back (`output.pdf`).

It costs milliseconds: a script has a few dozen literals, not millions of keys.

### Limits worth knowing

- A key computed at runtime (from the hostname, a server reply, a timestamp) can
  never be recovered statically. Code Lens reports the KDF call and stops.
- Control flow is not simulated: a loop that builds a string character by
  character with arithmetic is not folded (the char-code *array* form is).
- The rule-based languages see no variable scope, so a name reused for two
  different things can be mixed up. The line numbers in the report let you check.

## 8. RSA (`ctfc/core/rsa.py`, `ctfc/core/rsa_attacks.py`)

Every RSA question in a CTF is a question about one of five numbers:

```
n = p * q              the modulus, public
e                      the public exponent, usually 65537
d = e^-1 mod phi(n)    the private exponent, with phi(n) = (p-1)(q-1)

encrypt:  c = m^e mod n          decrypt:  m = c^d mod n
```

Knowing p and q gives phi(n), which gives d, which gives the message. So the work
is always one of two things: **get p and q**, or **notice that the message itself
was left unprotected**.

### Padding is not a detail

Textbook RSA (`m^e mod n` and nothing more) is deterministic: the same message
always gives the same ciphertext, and `m = 1` stays `1`. Real code wraps the
message first:

- **PKCS#1 v1.5**: `00 02 <random non-zero bytes> 00 <message>`. The padding is
  verifiable, so a wrong key is usually rejected.
- **OAEP**: a mask built from a hash (SHA-1 or SHA-256 - *both exist in the wild
  and they are not interchangeable*). Verifiable too, and much stronger.

ctfc tries OAEP-SHA1, OAEP-SHA256, PKCS#1 v1.5 and textbook, then scores the
results. When a padding scheme *verifies*, that is near-proof the key is right,
so those candidates get a bonus, exactly like valid PKCS7 in section 6.

### The attacks, and the mistake each one punishes

| the mistake | the shortcut | why it works |
|---|---|---|
| p or q tiny | trial division | ctfc divides by every prime below 100000 |
| p and q close | **Fermat** | n = a² - b² = (a-b)(a+b); start at a = ⌈√n⌉ and walk up |
| p-1 only has small factors | **Pollard p-1** | 2^k ≡ 1 (mod p) once (p-1) divides k, so gcd(2^k - 1, n) = p |
| a factor below ~2^60 | **Pollard rho** | a random walk mod n collides mod p first |
| d too small (< n^0.25/3) | **Wiener** | k/d appears in the continued fraction of e/n |
| two keys share a prime | **gcd** | gcd(n1, n2) *is* the shared prime - instant, and it breaks both keys |
| p == q | perfect square | √n; watch out, phi(n) = p(p-1) here, not (p-1)² |
| small e, short message | **e-th root** | if m^e < n nothing wrapped, so m = ᵉ√c - no key at all |

The last one deserves emphasis because it surprises people: with `e = 3` and a
message of a few dozen bytes under a 1024-bit modulus, `m³` never reaches `n`, so
the "encryption" is just a cube. ctfc also tries `c + k*n` for a few hundred `k`,
which covers a message that wrapped a handful of times.

Two practical decisions:

- **Order and budget.** The attacks run cheapest-first, and each gets *its own
  slice* of the time budget. Without that, Pollard rho (which can never say "no")
  would eat everything before Fermat got a chance - which is exactly the bug the
  first version had.
- **Honesty.** If nothing fires, ctfc says so plainly: a properly generated
  modulus will not be factored here, whatever the budget. The note points at the
  ciphertext instead. A tool that keeps "trying" is a tool that wastes your CTF.

`gmpy2` is used for the big-integer roots when it is installed (optional extra
`pip install -e ".[fast]"`); otherwise the same work is done with Newton's method
on plain Python integers.

### RSA that wraps a key rather than a message

A very common shape: RSA carries a 48-byte `key||iv` blob, and a second file holds
the real payload under AES. So when a decryption comes out as 16, 24, 32, 44 or 48
*unreadable* bytes, ctfc does not call it a failure - it says what the length means
and hands over:

```
ctfc blob <that file> --against <the payload>
```

## 9. Hash identification (`ctfc/core/hashes.py`)

ctfc does **not** crack hashes. hashcat and john are far better at it, and writing
a third-rate cracker would be a waste of the time you have during a CTF. What is
useful is the step before: *which format is this, and what is the mode number?*

Three signals, strongest first:

1. a **prefix**: `$2y$` (bcrypt), `$6$` (sha512crypt), `$krb5tgs$`, `{SSHA}`,
   `pbkdf2_sha256$`... nearly certain,
2. a **full-shape regex**: `$mysqlna$<40 hex>*<40 hex>`,
   `user::domain:<16 hex>:<32 hex>:<blob>` (NetNTLMv2), a JWT's three parts,
3. the **length and charset** alone, which is *weak*: 32 hex characters is MD5,
   but equally NTLM, MD4, MD2 and RIPEMD-128.

That third case is where tools usually lie to you by announcing "MD5" with
confidence. ctfc lists every candidate with its mode, ranked, and says in so many
words that the string alone cannot tell them apart - the context (an SAM dump? a
web database? a pcap?) is what decides.

The table lives in `ctfc/data/hashcat_modes.toml`, one entry per format with its
hashcat mode, john format, notes and an example. A test identifies **every
example against its own rule**, which is what caught a one-character typo in the
phpass pattern while this was being written.

One exception to "no cracking": for the unsalted formats (md5, sha1, sha256, NTLM
and friends) ctfc hashes the 10000 embedded passwords and compares. That is the
thirty-second check you would do by hand anyway, it is instant, and it is skipped
for anything salted or iterated - which is precisely why salting exists.

## 10. Recipes, CyberChef and external tools

### Recipes (`ctfc/core/pipeline.py`)

`auto` *searches*. A recipe does the opposite: you already know the steps
("base64, then zlib, then XOR with 4b337921") and you want exactly those, with
the output of **every** step in front of you so you can see where it goes wrong.

A recipe is a small JSON file you can write by hand:

```json
{
  "name": "stage1",
  "steps": [
    {"op": "base64"},
    {"op": "zlib"},
    {"op": "xor", "args": {"key": "4b337921"}},
    {"op": "cipher", "args": {"cipher": "aes", "mode": "cbc",
                              "key": "<hex>", "iv": "<hex>", "unpad": "pkcs7"}}
  ]
}
```

- The operation names are the decoders of `encodings.py` (`base64`, `hex`,
  `zlib`, `gzip`, `rot13`, `reverse`...) plus `xor`, `cipher` and `base64_custom`.
  They are the same names `auto` uses, which is why an `auto` result can be saved
  as a recipe (`ctfc recipe save`, or **Open in Pipeline** in the web UI) and then
  edited.
- A `cipher` step understands the same fields as the Python ctfc generates:
  `iv_from: "prefix"` (the IV is the first `iv_size` bytes of the data),
  `tag` (the data *ends* with this 16-byte GCM tag), `header_skip` (drop N bytes,
  e.g. openssl's 16-byte `Salted__` header). `mode` defaults to `cbc`.
- `"unpad": "pkcs7"` is **strict**: a bad padding stops the recipe with an error,
  exactly like `unpad()` in the exported script. A wrong key then fails loudly
  instead of handing you garbage that looks like a result.
- When a step fails, the run stops there, and the output of the step *before* it
  is kept: that is the data the failing step did not like, the thing to look at.

Every run exports the steps that worked as a Python script and, when every step
has an equivalent, as a CyberChef recipe.

```
ctfc recipe save stage1.json tests/fixtures/layers_b64_zlib_xor.txt   # from auto
ctfc recipe show stage1.json
ctfc recipe run  stage1.json tests/fixtures/layers_b64_zlib_xor.txt --show-code --cyberchef
```

### CyberChef links (`ctfc/core/cyberchef.py`)

A CyberChef deep link is `<base>#recipe=<recipe>&input=<base64 of the data>`.
The format is not documented, so it was read from the CyberChef source and then
**checked by opening ctfc's links in the real CyberChef v11.5.0** (the version
`scripts/fetch_vendor.sh` installs): base64 -> zlib -> XOR, and AES-256-CBC,
both give the flag. Two details mattered:

- the escaping is CyberChef's own `encodeURIFragment`: `&`, `+` and `=` stay
  percent-encoded (they would break base64 input), `@ / ? : , ;` do not;
- argument lists differ per operation and must be exact. `AES Decrypt` takes
  **9** arguments (Key, IV, IV length, Mode, Input, Output, GCM tag, AAD, IV from
  input). An older ctfc emitted 6, so the mode landed in the "IV length" field:
  the recipe still ran, and gave a wrong answer. Those strings are now pinned by
  `tests/test_cyberchef.py`, and a test checks that the version in
  `fetch_vendor.sh` is the one the strings were verified against.

When a recipe *cannot* be expressed (an IV read from the start of the data, a
header to strip), ctfc gives no CyberChef recipe at all rather than a wrong one.

**Which CyberChef opens.** In this order:

1. the **embedded copy** (`make vendor` once, on a machine with internet): the
   web UI serves it at `/vendor/cyberchef/`, the terminal opens it from
   `file://`. Nothing leaves the machine; this is the normal case.
2. a `cyberchef_url` you set in `~/.ctfc/config.toml` (e.g. your own server),
3. the **public instance** at gchq.github.io - only when offline mode is off,
   with a warning, and in the web UI after a confirmation. The data travels in
   the URL fragment: the server does not receive it, but your browser history
   and anything that logs URLs does. Fine for a CTF sample, never for real
   evidence.

Only the first 4096 bytes go in a link: a URL cannot carry a whole dump.

### External tools (`ctfc/core/tools.py`, `ctfc/data/tools.toml`)

ctfc reimplements the *ideas* it needs (XOR solving, signatures, hash
identification) so that it works alone, and points at the real tool when one is
better: xortool, Detect It Easy, hashcat, john, binwalk, openssl, RsaCtfTool,
exiftool, zsteg, steghide/stegseek, tshark, foremost, CyberChef, dcode, factordb.

How a suggestion is chosen:

1. `gather()` runs the cheap analyses ctfc already has and turns them into
   **signals**: every `detect` guess (`xor.repeating 0.70`, `magic.png 0.95`...),
   plus "this is a hash" from the hash identifier. That last one adds the
   candidates up: a 32-hex string is MD5 *or* NTLM (0.50 + 0.45), so the format is
   a coin toss, but "use hashcat" is not.
2. A tool fires when one of its `suggest_when` patterns matches a signal above
   `suggest_threshold` (0.7). At most `max_suggestions` (3) are shown, most
   confident first. Below the threshold, **nothing** is shown: a list of "you
   could also try" is noise during a timed CTF.
3. Placeholders are filled from what ctfc worked out (`{keylen}`, `{hashcat_mode}`,
   `{john_format}`) or reported as still missing (`{wordlist}`, `{password}`).
4. Online tools disappear in offline mode. The embedded CyberChef replaces the
   public one when installed (`prefer_over`), and is hidden when it is not - a
   link to a copy that was never fetched would be dead.

A test checks every `suggest_when` pattern against the rule ids ctfc can really
produce, because a typo (`magic.tiff` instead of `magic.tif`) makes a tool
silently never appear - two such typos were found that way.

**Running a tool** (`ctfc tools <input> --run <id>`, or **Run** in the web UI) is
deliberately boring and safe:

- only programs declared in `tools.toml`, launched with an **argument list**,
  never a shell (hard rule 4). A file called `a; rm -rf ~` stays one argument;
- a value that would form a whole argument and starts with `-` is refused,
  because the tool would read it as an option (`--outfile=~/.bashrc` typed as a
  wordlist name);
- stdin is closed: a tool that asks a question (openssl with no `-pass` prompts
  for a password) fails at once instead of waiting forever for a keyboard;
- pasted data is written to a private temporary file for the tool, deleted
  afterwards; the output is capped and there is a 120 s timeout.

```
ctfc tools tests/fixtures/xor_repeating.bin            # xortool -l 6 ..., CyberChef link
ctfc tools text:482c811da5d5b4bc6d497ffa98491e38       # hashcat -m 0 ...
ctfc tools tests/fixtures/openssl_salted_md5.bin --run openssl --password password123
ctfc tools x --list                                    # the whole registry, what is installed
```

Adding a tool is one `[[tool]]` entry in `ctfc/data/tools.toml`; no code.

## 11. Classical ciphers (`ctfc/core/classical.py`)

Caesar, affine, Atbash, Vigenère and the rail fence only move *letters*, so the
letters themselves say which family you are facing. Two measurements:

- **Letter frequencies** (chi-squared against English and French, as in
  section 2). Low = the text has natural letters.
- The **index of coincidence** (IoC): the chance that two letters picked at
  random in the text are the same. English is about 0.067, French 0.078, and
  random letters 0.038 (= 1/26).

| letters look... | IoC | family | examples |
|---|---|---|---|
| natural, but no words | high | **transposition**: right letters, wrong order | rail fence, columnar |
| wrong | high | **monoalphabetic**: letters renamed one for one | Caesar/ROT-n, affine, Atbash, keyword alphabet |
| wrong | low (~0.04) | **polyalphabetic**: several alphabets mixed | Vigenère |

`ctfc detect` reports exactly this (`classical.transposition`,
`classical.monoalphabetic`, `classical.vigenere` with a key length), and dcode.fr
is suggested.

**Solving** is brute force plus the scorer of section 2:

- Caesar: the 25 shifts. Affine `y = a*x + b`: 12 values of `a` (those with an
  inverse modulo 26) times 26 values of `b`. Atbash: one try. Rail fence: 2 to 12
  rails with every offset.
- **Vigenère** is the interesting one. Each column "every L-th letter" was
  shifted by the same key letter, so:
  1. find L: at the right L each column is a single Caesar, its IoC jumps back
     up to ~0.067. A *multiple* of L works too (with fewer letters per column),
     so each candidate length is solved and the result measured; when the best
     key repeats itself ("keykeykey") its period wins;
  2. solve each column as a Caesar, by frequency (English and French tried);
  3. **refine**: with a short text a column holds only ten letters or so, and
     frequency analysis often gets one key letter wrong. Every key position is
     retried with the 26 letters, keeping what makes the most *words*.
- **The flag as a crib.** If a word of the length of a known prefix sits in
  front of a `{` (`PLOA{` next to the configured `CYBN{`), the letter-by-letter
  differences are the Caesar shift, or the key letters of a Vigenère at that
  position. A lone ciphered flag is solved this way, statistics or not.

Limits worth knowing:
- a Vigenère key needs about ten letters of text per key letter: a 13-letter key
  on a 120-letter message comes out partly wrong (a few letters off - fix them by
  hand with `ctfc classical <input> --cipher vigenere --key ...`);
- a keyword substitution (any shuffled alphabet) is detected but not solved:
  dcode.fr or quipqiup do that by hill-climbing on n-gram statistics;
- a newline added *after* encryption would end up inside a transposition: it
  is left out of the rail fence, and the generated script and CyberChef recipe
  say so.

All five ciphers follow CyberChef v11.5.0 (read in its source: case is kept,
only ASCII letters change, the Vigenère key advances on letters only), and every
recipe was checked by opening it in the real CyberChef.

```
ctfc classical tests/fixtures/classical_vigenere.txt          # forensique, in French
ctfc classical text:'PLOA{fvzcyr_fuvsg}'                       # a lone flag: the crib
ctfc classical msg.txt --cipher affine --key 7,10 --show-code  # a known key
```

## 12. Key hunting (`ctfc/core/keyhunt.py`)

The forensics classic: a memory dump (or a binary, or a `strings` output)
contains the key, and some file was encrypted with it. `ctfc keys <dump>
--against <ciphertext>` looks for candidate keys in five independent ways,
strongest first, then hands each one to the symmetric solver of section 6 with a
small slice of the time budget. The first convincing decryption wins, and the
report says **at which offset** the key was found.

1. **AES key schedules** - the strong one. Before encrypting anything, AES
   expands its 16/24/32-byte key into 176/208/240 bytes of round keys, and
   programs keep that expansion in memory. Every byte of it is computed from
   the key, so "a key followed by its own expansion" practically never happens
   by chance (this is the idea of `aeskeyfind`). The scan is fast: the first
   derived word only needs four S-box lookups, and for a whole dump that test
   is one XOR of three shifted copies of the data (Python does it on big
   integers at C speed, ~15 s per GB). Only the rare matches get the full
   expansion compared; 90% equal bytes is enough, so a slightly damaged dump
   still matches. `ctfc detect` reports a schedule on its own.
2. **Labelled values**: `aes_key = 4f2a...`, `password: hunter2`, `IV=...`.
   The value is read as hex, base64 and text; a labelled IV is tried with the
   labelled keys.
3. **Hex and base64 strings of a key length** (16/24/32 bytes, or 48 = a
   key||iv blob tried with every split). A hash (sha256 = 64 hex digits) looks
   the same: it is tried and fails, which costs a fraction of a second.
4. **ASCII strings of exactly 16, 24 or 32 characters**, including the end of a
   longer run that stops on a NUL byte (a C string), ranked higher when a crypto
   constant (the AES S-box...) sits in the 4 KB before it.
5. **Random-looking windows** of 16/32 bytes - last, and with AES only, because
   compressed data looks random too.

Without `--against`, the candidates are only listed, with their offsets.

```
ctfc keys tests/fixtures/memdump_aes.bin --against tests/fixtures/memdump_aes_ct.bin
ctfc keys tests/fixtures/strings_dump.txt --against tests/fixtures/strings_dump_ct.bin
ctfc keys tests/fixtures/binary_with_key.bin --against tests/fixtures/binary_with_key_ct.bin --show-code
ctfc detect tests/fixtures/memdump_aes.bin       # "AES-256 key in memory at offset 0x5a30"
```

Out of scope, on purpose: RSA private keys in memory (search for `30 82` DER
headers with `binwalk`), keys protected by DPAPI or a TPM, and the BitLocker /
VeraCrypt master keys (Volatility plugins do that).

## 13. Sessions, the write-up, the offline bundle

**Sessions** (`ctfc/core/session.py`). `ctfc session new <name>` creates
`~/.ctfc/sessions/<name>/` and makes it the current session: from then on every
command appends one line to `steps.jsonl` - the command as typed, the input
(copied into `inputs/` up to 10 MB, only its SHA-256 beyond), the best result
with its reasons, the Python script and the CyberChef recipe. Append-only on
purpose: a crash in the middle of a CTF loses at most one line. `ctfc session
note "..."` puts your own words in between. The web UI has the same thing in the
bar at the top. A session name is a folder name and nothing else
(`[A-Za-z0-9_-]`): `../../etc` is refused.

**The write-up** (`ctfc/core/report.py`, `ctfc report <name> --lang fr`) follows
the layout of the user's own write-ups: title, statement, `## Step N` with the
command, what ctfc found and why, the output, "to redo it by hand" and the
CyberChef recipe, then the flag. Steps that found nothing are left out unless a
note follows them (`--all` keeps everything); a retry of the same command shows
once. Sample output is put in code blocks made longer than any backtick run it
contains, so a malicious sample cannot break the Markdown around it. It is a
draft: the commands and code are exact, the story is yours.

**The offline bundle** (`make bundle`, `scripts/make_bundle.sh`): `pip wheel`
collects ctfc and its dependencies into `dist/ctfc-bundle/wheels/` - with the
embedded CyberChef inside the ctfc wheel when `make vendor` was run - plus an
`install.sh` that runs `pip install --no-index --find-links wheels/ ctfc`, and
the "day of the CTF" page (`docs/day-of-the-ctf.md`). The wheels match the
machine that built them (pycryptodome has compiled code):
`BUNDLE_PLATFORM=win_amd64 make bundle` adds the binary wheels of another one.

## 14. Captures (`ctfc/core/pcap.py` and friends)

A forensics flag is very often *inside* a capture. `ctfc pcap <file>` reads one
with the standard library only - both formats are simple enough to parse by hand
- and then hands every payload it finds to the usual decoding chains, so the
flag is printed rather than merely extracted.

```
classic pcap: a 24-byte global header, then (16-byte header + bytes) per packet
pcapng:       a chain of blocks (type, length, body, length again)
```

What happens next depends on the capture's **link type**, which is the field
that says what the frames are. This matters more than it sounds: a capture of a
USB bus is not broken Ethernet, it is a different thing entirely.

### Network captures

Ethernet -> IP(v4/v6) -> TCP/UDP is walked by hand. TCP streams are reassembled
by sequence number (lowest wins, gaps are reported), which is what makes an HTTP
body readable again when it was split across packets. Then:

- **HTTP**: request lines and response bodies, with `Content-Length`, chunked
  transfer-encoding and `Content-Encoding: gzip/deflate` undone. A POST body is
  usually the exfiltration.
- **Mail** (`ctfc/core/mail.py`): IMAP, SMTP and POP3 carry whole RFC 822
  messages. Finding where one starts and stops is the fiddly part, because each
  protocol frames it differently - the IMAP `{N}` literal states the exact size,
  SMTP `DATA` and POP3 `RETR` end at a lone dot on its own line. The MIME tree is
  then parsed with the standard library's `email` package and every part decoded
  out of base64 / quoted-printable. **Bodies are kept as well as attachments**:
  the password of an attached ZIP is routinely written in the HTML next to it.
  An attachment's file name comes from the sample, so `--extract` reduces it to a
  plain basename before writing it.
- **DNS**: a tunnel carries the payload in the subdomain labels. Tools differ, so
  the queries are read generally and the likely variants all offered (one label
  per query, several labels, a leading sequence counter dropped).
- **RADIUS** (`ctfc/core/radius.py`): an Access-Request hides the PAP password
  with RFC 2865 section 5.2 - the password XORed with a chain of
  `MD5(secret + previous block)`. That is not a cipher, so the only unknown is
  the shared secret, and in practice it is a weak well-known word
  (`testing123` is the FreeRADIUS default). ctfc tries the common ones and then
  its embedded password list, so a capture alone yields the password. `ctfc
  radius` does the same from the two blobs if you only have those.
- Anything else is handed over as a raw stream, with a note saying so.

### USB captures (`ctfc/core/usb.py`)

Link types 189, 220 (usbmon, Linux) and 249 (USBPcap, Windows) hold no network
traffic at all, so the walk above is skipped. A standard "boot protocol" keyboard
sends an 8-byte report whenever the set of held keys changes:

```
byte 0   modifiers as bit flags (0x02 = left shift, 0x20 = right shift, ...)
byte 1   reserved, always 0
byte 2-7 up to six HID usage codes of the keys currently held
```

A keycode is **not** ASCII: `0x04` is "a", `0x1E` is "1", `0x28` is Enter.
Releasing every key sends eight zero bytes, which is why a capture is half
zeros. The text comes back by walking the reports in order through the HID usage
table (page 0x07), the shift flag choosing between the two characters printed on
the key. Two details matter in practice: **Backspace is applied as a real
deletion**, because authors type a wrong character on purpose, and reports are
grouped per device, so a keyboard plus a mouse - or two keyboards - do not
interleave into nonsense. The pseudo-header in front of each report is stripped
first (48 or 64 fixed bytes for usbmon; USBPcap's header states its own length).

### A command line hidden in a binary (`psenc`)

Windows writes its event logs and registry values in **UTF-16LE**, so a dropper's
`powershell.exe -enc <base64>` recorded in an `.evtx` is invisible to an ASCII
strings pass, and the `utf16le` decoder cannot help either - it needs the whole
input to be UTF-16LE, not an island of it inside binary noise. The `psenc`
decoder searches three views of the data (the raw bytes, and UTF-16LE at both
byte alignments) for any abbreviation of `-EncodedCommand` - PowerShell accepts
`-e` through `-encodedcommand` - then base64-decodes what follows and reads it as
UTF-16LE source. A match is kept only when the result is readable **ASCII**:
random bytes also decode as UTF-16LE, and land on printable Unicode letters often
enough that `str.isprintable()` alone would let them through. Being a normal
registry entry, it works inside `auto`'s chains, in recipes and in codegen.

## 15. File formats read by hand

Each of these exists because the interesting thing is not what a well-behaved
reader shows you. They share a shape: parse the container defensively (the files
are samples), report what is there with the reason, and hand over to the part of
ctfc that already knows what to do with the bytes.

### Office documents (`ctfc/core/cfb.py`, `ctfc/core/office.py`)

An OLE2 file (`.doc`, `.xls`, `vbaProject.bin`) is **a FAT filesystem in a file**:
512-byte sectors, a FAT saying which sector follows which, a directory of
128-byte entries naming streams and storages, and a "mini stream" packing
everything under 4096 bytes so a 200-byte stream does not waste a sector.

A macro lives in a stream called `VBA/<Module>`, and its source is wrapped in an
MS-OVBA **compressed container**: LZ77 in 4096-byte chunks whose copy tokens
split between offset and length *differently as the chunk fills up*. That is the
only reason a macro looks like binary. A `.docm` is a ZIP with the whole OLE2
container inside it as `word/vbaProject.bin`, so it takes the same path. The
recovered source goes to Code Lens, which reads it as VBS.

### PDF (`ctfc/core/pdf.py`)

A PDF is an object database with an interpreter attached. Four things matter: an
action that fires on open (`/OpenAction`, `/AA`), JavaScript, an embedded file,
and **earlier revisions** - a PDF can be updated incrementally, so text that was
"removed" or covered with a black box is still in the bytes before the first
`%%EOF`.

The parser is tolerant rather than correct, which is the right trade for
hand-edited files: objects are found by scanning for `N G obj` instead of
trusting the cross-reference table, and `/Length` is ignored in favour of
`endstream`. All five real stream filters are implemented. The LZW one widens its
code when `len(table) + 2` reaches the limit, because two off-by-ones stack:
PDF's "early change" widens one code early, and a decoder is always one entry
behind the encoder since it can only add an entry once it has read the next code.

### Images (`ctfc/core/stego.py`)

A pixel's lowest bit can be changed invisibly, so recovering a message means
guessing the bit plane, which samples and in what order, the scan direction, and
the bit order inside a byte - a few hundred combinations, scored by
`scoring.py`. Getting to the pixels is most of the work: a PNG's samples are
zlib-compressed with each scanline filtered against its neighbours (all five
filters, Paeth included), and a BMP pads rows to four bytes and stores them
bottom-up when its height is positive. A BMP also stores **B,G,R**, so labels are
built from the image's real channel order - calling index 0 "red" in both would
make the report lie about where to look.

### Archives (`ctfc/core/zipinfo.py`)

Bit 0 of an entry's flags only says "encrypted", and the two schemes behind it
need **opposite** attacks: ZipCrypto falls to a known-plaintext attack with no
password (bkcrack), WinZip AES does not and must be cracked as a hash. The CRC32
is of the *plaintext* and is stored in clear even for an encrypted entry, so a
file of one to three bytes gives up its content with no password - except under
WinZip AE-2, which zeroes the CRC field, which is why that trick stops working
there. Also reported: a local header that disagrees with the central directory
(different tools believe different ones), traversal paths, and bomb ratios.

### Git (`ctfc/core/gitrepo.py`)

An object is `"<type> <size>\0<content>"`, zlib-compressed, named by its own
SHA-1. The useful question is **not** "what is unreachable" - the commit that
added a removed secret is still an ancestor of the branch, so `git fsck` is
silent. It is "what is in the history but in no branch's current tree". Packs are
walked straight through (zlib says where each object ends) and their deltas
applied, because a cloned repository stores most objects as copy/insert
instructions against another one.

### SQLite (`ctfc/core/sqlitedb.py`)

`DELETE` unlinks a cell and puts the space on a free list; it does not erase.
Rows are carved from freelist pages, the gap between a page's cell pointer array
and its first live cell, and the freeblock chain. What makes carving trustworthy
is anchoring on the **cell** rather than the record: a cell is `payload length,
rowid, record`, and a record read at the wrong offset practically never comes out
exactly the declared length. Note that Debian's SQLite defaults `secure_delete`
to ON, so a database made locally really is wiped - a browser's is not.

### Registry hives (`ctfc/core/hive.py`)

A 4096-byte `regf` header, then hive bins cut into cells whose signed size is
negative when allocated. Values of four bytes or fewer are stored **inline in
their own offset field**, which is the detail that makes a naive reader return
nothing for every DWORD. The boot key is not a value at all: four keys under
`Control\Lsa` carry eight hex characters each as their *class names*, and the
sixteen bytes are unshuffled with a fixed permutation.

### Tokens and timestamps (`ctfc/core/jwt.py`, `ctfc/core/timestamps.py`)

A JWT's header and payload are base64, not encryption, so they read without a
key; everything interesting is the signature, and cracking an HMAC secret is a
*verification* rather than a guess - the recomputed HMAC matches or it does not.
A timestamp is reported under every clock it plausibly fits (Unix, FILETIME,
WebKit, Mac, DOS), filtered to 1990..2100 and to readings more than a day past
their own epoch - without that second rule every number also "reads as" the
epoch itself.
