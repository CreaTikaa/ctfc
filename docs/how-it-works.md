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
