# ctfc cheat sheet

One page, for the day of the CTF. Start a session first, the write-up writes itself:
`ctfc session new <chall> --title "..."` then `ctfc report --lang fr` at the end.

## 0. No idea at all? One command.

`ctfc solve <file>` (or the **Solve** tab of `ctfc serve`) reads the file with whatever reader claims it, follows
everything that comes out of it (archive members, a mail's attachments, a
capture's objects, an overlay, a Docker layer, a decoding chain), and prints the
flag - with the commands that reproduce it - or the three best leads. It never
guesses a password or a key: when one is needed it prints the command that
cracks it. With no flag it ends on **Next steps**: what it found (a sound, a
WPA handshake, random bytes, a SAM hive...), what that usually means, and the
external tool to run next with its command filled in (sox spectrogram,
multimon-ng, aircrack-ng, zsteg, steghide, Volatility...). Everything below is
what it does, step by step, when you want control.

### A folder, not a file?

`ctfc workspace <folder>` reads everything once, pools every password, key and
ciphertext it finds, and tries each secret against each ciphertext - because the
key is never in the same file as the thing it opens. It prints the pairs that
worked ("the password in mail.eml opens backup.zip"), and names what it could
not try. `ctfc scan <folder>` stays the one to rank a folder of carved files.

### "What happened, and in which order?"

`ctfc timeline <file-or-folder>` merges every date the files carry - prefetch
runs, a shortcut's three stamps, event records, archive entries, a PE build
stamp, a Docker build step, a mail's Date - into one table in UTC, each row
naming where it came from. `--since` / `--until` narrow the window. A date in
the future is kept and flagged, not dropped: a forged timestamp is evidence.

## 1. Do you have the code that encrypted it?

**Yes** (a script, a decompiled .pyc, a .NET method, PowerShell from event logs):
mirror the encryptor, do not guess.

- `ctfc lens script.ps1` - what it does, in order, with the keys it hardcodes, and a
  Python script that undoes it. Python, PowerShell, JS, bash, VBS, PHP. Nothing is executed.
- `ctfc lens script.ps1 --against file.secured` - the encrypted file too: the script's
  own literals are tried as its keys (obfuscated names, keys passed through 3 functions,
  two XOR keys at once: Cave Expedition).
- A binary? Find the function in Ghidra / dotPeek / ILSpy, copy the constants, then
  `ctfc xor hex:<data> --key hex:<key>` or `ctfc sym <ct> --key ... --iv ...`.

**No**, only data: go to 2.

## 2. What is this data?

`ctfc detect <file>` - entropy, charset, magic bytes, lengths, constants. Then:

| detect says | next |
|---|---|
| base64 / hex / base32 / charcodes text | `ctfc auto <file>` peels the layers |
| Morse, Bacon, A1Z26, a 5x5 square, Base45/basE91/Z85, uuencode | `ctfc auto <file>` tries all of them: none has a key |
| a known file type, or data after the end of one | `binwalk -e`, `ctfc scan <folder>` |
| a PNG that opens but looks too short | `ctfc repair img.png --out fixed/` - the height is put back |
| a photograph (JPEG) | `ctfc stego photo.jpg` - EXIF, the comment field, the GPS point |
| a WAV | `ctfc stego track.wav` - the low bits of the samples (a spectrogram needs Audacity) |
| `Salted__` | `openssl enc` file: `ctfc sym <file> --passwords` or `--pass <pw>` |
| `gAAAA...` | Fernet: `ctfc sym <file> --key <fernet key>` |
| repeating pattern, period N | repeating-key XOR: `ctfc xor <file> --keylen N` |
| low entropy but unreadable | single-byte XOR / substitution: `ctfc xor <file>` |
| entropy ~8, length % 16 == 0 | AES (or another block cipher): find the key, see 3 |
| entropy ~8, length not aligned | stream cipher (RC4, ChaCha20), CTR/GCM, XOR |
| repeated 16-byte blocks | AES-ECB: the blocks leak the structure |
| letters only, IoC high | Caesar / affine / Atbash: `ctfc classical <file>` |
| letters only, IoC ~0.04 | Vigenère: `ctfc classical <file> --cipher vigenere` (or `--cipher beaufort`: key *minus* text) |
| natural letters, no words | transposition (rail fence): `ctfc classical <file>` |
| `PLOA{` where `CYBN{` belongs | a shifted flag: `ctfc classical <file>` |
| a hash (`$2y$`, 32 hex, `$krb5tgs$`...) | `ctfc hash <hash>` -> hashcat / john command |
| a digest that *signs* a message (MAC, token, cookie) | `ctfc extend <digest> --data ... --append ...` - forge, do not crack |
| PEM / RSA numbers | `ctfc rsa --key k.pem --decrypt ct.bin --attack` |
| the *same message* under several keys | `ctfc rsa --key a.pem --decrypt a.bin --also b.pem=b.bin` (common modulus, Hastad) |
| two signatures (ECDSA/DSA) | `ctfc sig sigs.txt --curve secp256k1` - the same r means the key is already yours |
| a pcap / pcapng | `ctfc pcap cap.pcap --extract out/` then `ctfc scan out/` |
| a .eml / .mbox | `ctfc mail message.eml --extract out/` - headers, body, attachments |
| a ZIP (or .docx/.jar/.apk) | `ctfc zip <file>` - which encryption, and tiny files from their CRC32 |
| a tar / 7z / rar / cab | `ctfc archive <file>` - the listing, the encryption, the contents |
| a Go or Rust binary | `ctfc exe <file>` - `strings` glues their literals; this cuts them exactly |
| a CRC32 of a short file (a ZIP prints them) | `ctfc crc <crc32>` - the content itself, with no password |
| a .lnk / .pf / jump list | `ctfc winartifact <file>` - what ran, when, from which disk |
| an ELF / .class / .jar / .dex | `ctfc exe <file>` - the strings that matter, and what is appended |
| a .NET assembly | `ctfc pe <file>` - the #US heap holds every C# string literal |
| an Amcache.hve / NTUSER.DAT | `ctfc hive <file>` - UserAssist, RecentDocs, every executable seen |
| an Outlook .msg | `ctfc msg <file> --extract att/` - headers, body, attachments |
| an .msi installer | `ctfc msi <file>` - the string pool, the embedded cabinet, what it runs |
| a .doc with an icon in it | `ctfc office <file> --extract obj/` - the embedded object itself |
| a `docker save` tar | `ctfc archive img.tar` - layer order, and the files a later layer deleted |
| zero-width characters | `ctfc auto` (both bit mappings) or a StegCloak decoder |
| a column of big integers (tokens, "random" ids) | `ctfc prng <file>` - 624 of them clone MT19937 |

Not sure? `ctfc tools <file>` names the external tool that fits, with the command.

In the browser (`ctfc serve`)? The **Files** tab reads every format this page lists -
drop the file in and it picks the reader; the dropdown forces one. The search box under
the hexdump has a **Find a flag** button that looks for `CYBN{...}` in clear *and* in
base64 at each of the three alignments, with the offset of every hit. The **Docs** tab
holds this sheet, "How it works" and the day-of-the-CTF page, offline.

Files still arriving? `ctfc watch <folder>` triages each new one as it lands.
Solved it? `ctfc report` writes it up, `ctfc replay` writes the script that re-does it.

## 3. You have a key, an IV, a blob... but not the layout

- `ctfc sym <ct> --key K` - modes, IV places (given, prefix, zeros, = key), paddings
  and key readings (raw, hex, base64, md5/sha of a passphrase) are all tried.
- `ctfc blob <blob> --against <ct>` - 48 bytes = key||iv? iv||key? Every split.
- `ctfc sym <ct> --pass <pw>` - EVP_BytesToKey, PBKDF2 (common counts), scrypt, md5/sha.
- Base64 ciphertext (mails, logs, C2 traffic)? Give it as is: it is decoded first.
- A valid PKCS7 padding (score bonus) is near-proof the key is right.

## 4. No key at all

- `ctfc keys <dump> --against <ct>` - AES key schedules in memory (aeskeyfind's idea),
  `key = ...` lines, hex/base64 of key sizes, 16/24/32-char strings near crypto constants.
- `ctfc sym <ct> --passwords` - the 10000 most common passwords with the openssl KDFs.
- `ctfc xor <ct> --hashed-keys` - md5/sha of common words as the XOR key.
- `ctfc xor <ct> --crib 'CYBN{'` - known plaintext; file headers are tried by themselves.
- Two ciphertexts, same key stream? `ctfc xor c1 --with c2 --crib ' the '`.
- The key *was* random? `ctfc prng tokens.txt` - 624 consecutive 32-bit outputs of
  Python's `random` (or two `java.util.Random` nextInt values) give the whole
  sequence, before and after the capture, so the "random" key comes back.

## 5. Redo it by hand

Every result has `--show-code` (a short standalone Python script) and a CyberChef recipe.
In the web UI (`ctfc serve`): **Show Python**, **Open in CyberChef** (embedded copy, offline),
**Open in Pipeline** (the chain as an editable recipe, each step's output visible).

## Reminders

- Flags: the generic `XXX{...}` shape plus `CYBN{...}`, also searched in base64.
  Add yours in `~/.ctfc/config.toml` (`flag_regexes`, `flag_prefixes`).
- `--wordlist ~/Documents/rockyou.txt` on `ctfc sym`, `ctfc hash` and `ctfc jwt` replaces the
  embedded 10000-password list. It says how much of the file it read; the whole of a real list
  belongs to hashcat, whose command every hash report prints.
- `--offline` (or `offline = true`) hides everything that would send data anywhere.
- `--json` on every command; `ctfc <command> --help` has examples.
