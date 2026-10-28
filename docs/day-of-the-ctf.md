# ctfc - the day of the CTF

## Before (at home, with internet)

```sh
cd ctfc
make venv          # once
make vendor        # the embedded CyberChef (works offline afterwards)
make test          # everything green?
make bundle        # dist/ctfc-bundle/: copy it to the CTF machine if it has no internet
```

On a machine without internet: copy `dist/ctfc-bundle/`, then

```sh
./install.sh                 # installs from wheels/ only, nothing is downloaded
.venv/bin/ctfc cheatsheet    # check it works
```

## During

```sh
ctfc session new cave-expedition --title "Cave Expedition" --ctf "Cyber Apocalypse 2025" --category Forensics
# from now on every command is recorded in that session

ctfc detect suspicious.bin          # what is it?
ctfc auto suspicious.bin            # peel the encodings
ctfc lens dropper.ps1 --against map.pdf.secured   # you have the encryptor: mirror it
ctfc keys memdump.raw --against payload.enc       # the key is somewhere in memory
ctfc session note "the key was in the event logs, base64"   # your own words, for the write-up
ctfc session flag 'CYBN{...}'
```

Or all of it in the browser: `ctfc serve`, then <http://127.0.0.1:8137>. Pick the
session in the bar at the top, everything you run is recorded the same way.

Lost? `ctfc cheatsheet` - the one-page decision tree (also the Cheatsheet tab).

Some reflexes:
- `--show-code` prints the Python that redoes a result: paste it in the write-up.
- `--offline` (or `offline = true` in `~/.ctfc/config.toml`) if the rules forbid
  sending anything anywhere: the public CyberChef, dcode and factordb disappear.
- ctfc uses no AI, no model, no network: fine for CTFs that ban AI tools.
- The flag format is in `~/.ctfc/config.toml` (`flag_regexes`, `flag_prefixes`):
  add the CTF's own (`BZHCTF\{.*?\}`) at the start, it boosts the right results.

## After

```sh
ctfc report --lang fr --out writeup.md     # or --lang en; --all keeps the dead ends
```

A draft in your usual layout: title, statement, `## Step N` with the command,
what came out, the script to redo it by hand and the CyberChef recipe, then the
flag. Add the screenshots and the story, check it, publish.

Sessions are plain files in `~/.ctfc/sessions/<name>/` (`session.json`,
`steps.jsonl`, `inputs/`): you can read, edit or delete them by hand.
