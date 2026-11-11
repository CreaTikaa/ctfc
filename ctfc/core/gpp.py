"""Group Policy Preferences passwords (`cpassword="..."`), decrypted.

**What it is.** Windows domain admins used Group Policy Preferences to push a
local administrator account, a scheduled task or a mapped drive to every
machine. The password went into an XML file on the domain's SYSVOL share
(`Groups.xml`, `ScheduledTasks.xml`, `Services.xml`, `DataSources.xml`,
`Drives.xml`, `Printers.xml`), in an attribute called `cpassword`.

**Why it is not a secret.** The value is AES-256-CBC with an all-zero IV, and
the key is the same on every Windows installation: Microsoft *published it* in
the protocol specification (MS-GPPREF, section 2.2.1.1.4). Anyone who can read
SYSVOL - every domain user - can decrypt it. Microsoft disabled the feature in
2014 (MS14-025), but the files stayed on countless shares, so it remains a
favourite of forensics and Active Directory challenges.

**The recipe** (what `gpp-decrypt` in Kali does):

1. base64-decode the attribute (the padding `=` is usually stripped: add it);
2. AES-256-CBC decrypt with the published key, IV = 16 zero bytes;
3. remove the PKCS#7 padding;
4. the plaintext is UTF-16LE (Windows strings).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# MS-GPPREF 2.2.1.1.4 "Password Encryption": the 32-byte AES key, as published.
GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
GPP_IV = bytes(16)

CPASSWORD_RE = re.compile(r"""cpassword\s*=\s*["']([A-Za-z0-9+/=]{4,})["']""", re.IGNORECASE)
# The account the password belongs to, written in the same XML element.
USER_RE = re.compile(r"""(?:userName|runAs|accountName|newName)\s*=\s*["']([^"']{1,128})["']""")


@dataclass
class GppPassword:
    """One cpassword attribute and what it decrypts to."""

    cpassword: str
    password: str  # "" when it did not decrypt
    user: str  # the account named next to it, if any
    line: int
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "cpassword": self.cpassword,
            "password": self.password,
            "user": self.user,
            "line": self.line,
            "error": self.error,
        }


def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt one cpassword value. Raises ValueError with the reason if it does not."""
    text = cpassword.strip()
    text += "=" * (-len(text) % 4)  # GPP strips the base64 padding
    try:
        blob = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not base64: {exc}") from exc
    if not blob or len(blob) % 16:
        raise ValueError(f"{len(blob)} bytes is not a whole number of AES blocks")
    plain = AES.new(GPP_KEY, AES.MODE_CBC, GPP_IV).decrypt(blob)
    try:
        plain = unpad(plain, 16)
    except ValueError as exc:
        raise ValueError("bad padding: not a GPP cpassword (or a corrupted one)") from exc
    return plain.decode("utf-16-le", errors="replace")


def find_cpasswords(data: bytes) -> list[GppPassword]:
    """Every `cpassword="..."` in the text, decrypted, with the account next to it."""
    text = data.decode("utf-8", errors="replace")
    if "cpassword" not in text.lower():
        return []
    found: list[GppPassword] = []
    for match in CPASSWORD_RE.finditer(text):
        # The element holding the attribute: from the previous "<" to the next ">".
        start = text.rfind("<", 0, match.start())
        end = text.find(">", match.end())
        element = text[max(start, 0) : end if end >= 0 else len(text)]
        user = USER_RE.search(element)
        entry = GppPassword(
            cpassword=match.group(1),
            password="",
            user=user.group(1) if user else "",
            line=text.count("\n", 0, match.start()) + 1,
        )
        try:
            entry.password = decrypt_cpassword(match.group(1))
        except ValueError as exc:
            entry.error = str(exc)
        found.append(entry)
    return found


def snippet(cpassword: str) -> str:
    """Standalone Python (pycryptodome) that decrypts one cpassword by hand."""
    return f'''import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The key Microsoft published in MS-GPPREF 2.2.1.1.4 (the same on every domain).
KEY = bytes.fromhex("{GPP_KEY.hex()}")
cpassword = "{cpassword}"
blob = base64.b64decode(cpassword + "=" * (-len(cpassword) % 4))  # padding was stripped
plain = unpad(AES.new(KEY, AES.MODE_CBC, bytes(16)).decrypt(blob), 16)  # IV = zeros
print(plain.decode("utf-16-le"))  # Windows strings are UTF-16LE
'''
