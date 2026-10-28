# ctfc cheat sheet

One page, for the day of the CTF. Start a session first, the write-up writes itself:
`ctfc session new <chall> --title "..."` then `ctfc report --lang fr` at the end.

## 1. Do you have the code that encrypted it?

**Yes** (a script, a decompiled .pyc, a .NET method, PowerShell from event logs):
mirror the encryptor, do not guess.

- `ctfc lens script.ps1` - what it does, in order, with the keys it hardcodes, and a
  Python script that undoes it. Python, PowerShell, JS, bash, VBS. Nothing is executed.
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
| a known file type, or data after the end of one | `binwalk -e`, `ctfc scan <folder>` |
| `Salted__` | `openssl enc` file: `ctfc sym <file> --passwords` or `--pass <pw>` |
| `gAAAA...` | Fernet: `ctfc sym <file> --key <fernet key>` |
| repeating pattern, period N | repeating-key XOR: `ctfc xor <file> --keylen N` |
| low entropy but unreadable | single-byte XOR / substitution: `ctfc xor <file>` |
| entropy ~8, length % 16 == 0 | AES (or another block cipher): find the key, see 3 |
| entropy ~8, length not aligned | stream cipher (RC4, ChaCha20), CTR/GCM, XOR |
| repeated 16-byte blocks | AES-ECB: the blocks leak the structure |
| letters only, IoC high | Caesar / affine / Atbash: `ctfc classical <file>` |
| letters only, IoC ~0.04 | Vigenère: `ctfc classical <file> --cipher vigenere` |
| natural letters, no words | transposition (rail fence): `ctfc classical <file>` |
| `PLOA{` where `CYBN{` belongs | a shifted flag: `ctfc classical <file>` |
| a hash (`$2y$`, 32 hex, `$krb5tgs$`...) | `ctfc hash <hash>` -> hashcat / john command |
| PEM / RSA numbers | `ctfc rsa --key k.pem --decrypt ct.bin --attack` |
| a pcap / pcapng | `ctfc pcap cap.pcap --extract out/` then `ctfc scan out/` |
| zero-width characters | `ctfc auto` (both bit mappings) or a StegCloak decoder |

Not sure? `ctfc tools <file>` names the external tool that fits, with the command.

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

## 5. Redo it by hand

Every result has `--show-code` (a short standalone Python script) and a CyberChef recipe.
In the web UI (`ctfc serve`): **Show Python**, **Open in CyberChef** (embedded copy, offline),
**Open in Pipeline** (the chain as an editable recipe, each step's output visible).

## Reminders

- Flags: the generic `XXX{...}` shape plus `CYBN{...}`, also searched in base64.
  Add yours in `~/.ctfc/config.toml` (`flag_regexes`, `flag_prefixes`).
- `--offline` (or `offline = true`) hides everything that would send data anywhere.
- `--json` on every command; `ctfc <command> --help` has examples.
