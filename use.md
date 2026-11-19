# Using ctfc from the terminal

Every command below has its own `ctfc <command> --help` with examples.
The examples here run as-is from `tests/fixtures/` (they all print a `CYBN{...}`
flag or the expected report).

## 1. Before the CTF (2 minutes)

```sh
ctfc --version                     # works from any folder (~/.local/bin/ctfc -> .venv)
ctfc config --flag 'XYZ{'          # THE most important step: add the CTF's flag format
ctfc config --wordlist ~/Documents/rockyou.txt
ctfc doctor                        # green/red check: flag format, wordlist, CyberChef, tools
```

Without installing anything: `.venv/bin/ctfc ...` or `.venv/bin/python -m ctfc ...`
from the repo folder (the system `python3` does not have `rich`).

## 2. How to give it data

`<input>` is always one of:

| form | meaning |
|---|---|
| `file.bin` | a file path |
| `-` | stdin (`cat x | ctfc auto -`) |
| `hex:48656c6c6f` / `b64:SGVsbG8=` / `text:hello` | inline bytes |
| `SGVsbG8=` | bare hex/base64: auto-detected (a note says so) |

Options every command accepts:

| option | effect |
|---|---|
| `--json` | machine-readable output |
| `--show-code` | print the Python snippet that reproduces the best result |
| `--top N` | how many candidates to show |
| `--offline` | never contact a third party |
| `--session NAME` | record this command in a session (write-up) |
| `--config PATH` | another config.toml (put it **after** the command name) |

Long searches take `--seconds N` (default 30).

## 3. "I have no idea" — start here

| command | what it does | example |
|---|---|---|
| `solve` | one file in, flag out: reads it, follows everything inside, prints the flag or the 3 best leads (runs zsteg/steghide/… on images; `--no-tools` to skip) | `ctfc solve layers_b64_zlib_xor.txt` · `ctfc solve dump.pcap --seconds 60 --steps` |
| `workspace` | a whole folder: pools every password/key/ciphertext and tries each secret on each ciphertext | `ctfc workspace ./challenge --seconds 300` |
| `scan` | detect + auto on every file of a folder, ranked | `ctfc scan ./extracted` |
| `watch` | triage every file that lands in a folder | `ctfc watch ./out` (`--once` = one pass) |
| `detect` | fingerprint: encoding, cipher shape, file type, magic, entropy | `ctfc detect png_with_zip.png` |
| `auto` | "magic": try decoding chains until something readable appears | `ctfc auto layers_b64_zlib_hex.txt --show-code` |
| `cheatsheet` | the one-page decision tree | `ctfc cheatsheet` |
| `tools` | which external tool fits, with the exact command; `--run ID` runs it | `ctfc tools xor_repeating.bin` · `ctfc tools --list` |

## 4. Crypto

| command | what it does | example |
|---|---|---|
| `xor` | single byte, repeating key, known plaintext, two layers, two inputs | `ctfc xor xor_two_layers.bin` · `ctfc xor ct.bin --key text:s3cr3t` · `ctfc xor a.bin --with b.bin --crib 'the '` |
| `sym` | AES/DES/3DES/Blowfish/ChaCha20/Salsa20/RC4/TEA/XTEA, any mode, unknown key/IV layout, passphrases (KDFs, openssl `Salted__`) | `ctfc sym aes_cbc_keyiv_blob.bin --blob key_iv_blob.b64` · `ctfc sym openssl_salted_md5.bin --passwords` · `ctfc sym ct.bin --key hex:00.. --mode cbc` |
| `blob` | an unknown key/IV blob: test every split against a ciphertext | `ctfc blob key_iv_blob.b64 --against aes_cbc_keyiv_blob.bin` |
| `keys` | hunt keys in a memory dump / binary and test them on a ciphertext | `ctfc keys memdump_aes.bin --against memdump_aes_ct.bin` |
| `rsa` | read keys, decrypt, build a key from n,e,p,q/d, weak-key attacks (`--attack`, `--other`, `--also`, `--relation`) | `ctfc rsa --key rsa_private.pem --decrypt rsa_oaep.bin` · `ctfc rsa --key rsa_fermat.pub.pem --decrypt rsa_fermat.bin --attack` |
| `sig` | ECDSA/DSA private key from two signatures with the same nonce | `ctfc sig ecdsa_nonce_reuse.txt --curve secp256k1` |
| `hash` | identify a hash, print the hashcat/john command, try a wordlist; cracks zip2john lines (`--out` writes the file) | `ctfc hash mysqlna_hash.txt` · `ctfc hash '$2y$10$...'` · `ctfc hash zip.hash --wordlist ~/Documents/rockyou.txt --out flag.txt` |
| `jwt` | decode a JWT, list what is wrong, guess the HMAC secret | `ctfc jwt "$(cat jwt.txt)"` · `ctfc jwt <token> --secret mykey` |
| `classical` | Caesar/ROT-n, affine, Atbash, Vigenère, Beaufort, rail fence | `ctfc classical classical_caesar.txt` · `ctfc classical msg.txt --cipher vigenere --key lemon` |
| `crc` | what short content produced this CRC32 (tiny files in an encrypted ZIP) | `ctfc crc 0x1b851995 --length 6` · `ctfc crc 1b851995 --pattern 'CYBN{????}'` |
| `extend` | hash length extension (MD5/SHA-1/SHA-256/SHA-512) | `ctfc extend <digest> --data 'user=guest' --append '&admin=1' --secret-length 1-32` |
| `prng` | clone MT19937 / java.util.Random from its outputs (past + future values) | `ctfc prng prng_mt19937.txt` |
| `radius` | RADIUS PAP password from the captured attribute | `ctfc radius hex:<User-Password> --authenticator hex:<16 bytes>` |

## 5. Scripts and malware (static only, nothing is executed)

| command | what it does | example |
|---|---|---|
| `lens` | what a Python/PowerShell/JS/bash/VBS/PHP script does with crypto + a generated inverse script; `--against` decrypts the file it produced | `ctfc lens lens_dropper.ps1 --show-code` · `ctfc lens writeup_cave_ransom.ps1 --against writeup_cave_map.pdf.secured` |
| `office` | VBA macros of .doc/.xls/.docm/.xlsm read by Code Lens; `--extract` embedded objects | `ctfc office audit_macro.docm --save-macros ./macros` |
| `pe` | Windows .exe/.dll: sections, imports, packing, overlay, .NET strings | `ctfc pe sample.exe --extract ./out` |
| `exe` | ELF, Java .class/.jar, Android .dex, Go/Rust literals | `ctfc exe executable_secret.jar` |
| `pdf` | actions, JavaScript, embedded files, earlier revisions, the page text; decrypts an encrypted PDF (empty password, `--password`, or the 10 000 common ones) | `ctfc pdf audit_malicious.pdf --extract ./out` · `ctfc pdf pdf_encrypted_r6_empty.pdf` · `ctfc pdf locked.pdf --password s3cret` |

## 6. Forensic files

| command | what it reads | example |
|---|---|---|
| `pcap` | HTTP bodies, DNS exfil, TCP streams, USB keyboard, ICMP… | `ctfc pcap capture.pcap --extract ./objects` |
| `disk` | disk/partition images (ext, FAT, NTFS, E01…) incl. deleted files (needs sleuthkit) | `ctfc disk disk_fat12.img --extract ./files` |
| `archive` | tar / 7z / RAR / cab / `docker save` image (incl. files deleted by a later layer) | `ctfc archive archive_docker_image.tar --extract ./layers` |
| `zip` | encryption type, header mismatches, tiny files from their CRC, wordlist | `ctfc zip zipcrypto_wordlist.zip --wordlist ~/Documents/rockyou.txt` |
| `git` | a `.git` folder: secrets committed then removed | `ctfc git ./challenge --extract ./blobs` |
| `sqlite` | a SQLite database, deleted rows included | `ctfc sqlite audit_notes.sqlite` |
| `evtx` | Windows event logs (`--all` for every record) | `ctfc evtx audit_security.evtx` |
| `hive` | registry hives (SAM, SYSTEM, NTUSER.DAT); `--key PATH`, `--list` | `ctfc hive NTUSER.DAT --key 'Microsoft\Windows\CurrentVersion\Run'` |
| `winartifact` | .lnk, prefetch (.pf), jump lists | `ctfc winartifact winartifact_dropper.lnk` |
| `mail` | .eml / .mbox; `--extract` the attachments | `ctfc mail mailfile_message.eml` |
| `msg` | Outlook .msg | `ctfc msg compound_message.msg --extract ./att` |
| `msi` | Windows Installer .msi | `ctfc msi compound_installer.msi --extract ./payload` |
| `stego` | PNG/BMP low bits, EXIF + GPS of a JPEG, WAV low bits | `ctfc stego audit_lsb.png` |
| `repair` | broken magic bytes, shrunk PNG height, data after the end, pasted header | `ctfc repair audit_pixel_rehab.fun --out repaired/` |
| `timeline` | every timestamp of a file or folder in one UTC table | `ctfc timeline ./evidence --since 2023-11-14 --until 2023-11-15` |
| `time` | read a number as a date (Unix, FILETIME, Chrome, Mac, DOS) | `ctfc time 133476575820000000` |

## 7. Recipes (your own chain of steps)

```sh
ctfc recipe save found.json payload.bin      # save the chain that `auto` found
ctfc recipe show found.json                  # print the JSON
ctfc recipe run found.json other.bin --cyberchef   # apply it, + CyberChef link
```

## 8. Write-up: sessions, report, replay

```sh
ctfc session new cave --title 'Cave Expedition' --ctf 'Some CTF' --category Forensics
ctfc session use cave           # from now on every command is recorded
ctfc solve chall.bin            # ... work as usual ...
ctfc session note 'the key is in the event logs'
ctfc session flag 'CYBN{...}'
ctfc session stop
ctfc report cave --lang fr --out writeup.md   # Markdown write-up
ctfc replay cave --out solve.py               # one script that redoes the solve
ctfc session list
ctfc session show cave
```

Sessions live in `~/.ctfc/sessions/<name>/`.

## 9. Setup and web UI

| command | what it does |
|---|---|
| `ctfc config` | show the effective config; `--flag 'XYZ{'`, `--wordlist PATH` write it (`~/.ctfc/config.toml`) |
| `ctfc doctor` | pre-flight check before the CTF |
| `ctfc serve [--port 8137]` | web UI on http://127.0.0.1:8137 (every feature has a tab) |

## 10. Typical day-of-the-CTF flow

1. `ctfc config --flag 'XYZ{'` then `ctfc doctor`.
2. Got a file? `ctfc solve <file>`. Got a folder? `ctfc workspace <folder>`.
3. No flag: read the 3 leads it prints — each one is a command to run next.
4. You know what it is: go straight to the specific command (`sym`, `xor`, `lens`, `pcap`…).
5. `--show-code` on the winning result to understand it and redo it by hand.
