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
