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
| The generic `XXX{....}` shape matches | 0.90 | Can also match code like `else{ ... }` |
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
text_score = printable² × (0.35 + 0.40 × word_rate + 0.25 × frequency_score)
frequency_score = 1 / (1 + chi² / 60)
```

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
