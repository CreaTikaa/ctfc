"""Turn a ctfc result into a CyberChef recipe and a deep link.

CyberChef is the tool everybody reaches for, and a link that opens it with the
recipe *and* the data already loaded saves a lot of clicking. The format is not
documented, so it was read from the CyberChef source itself (v11.5.0):

    <base>#recipe=<encoded recipe>&input=<encoded base64 of the input>

- the **recipe** is the "pretty" format: `Op_Name(arg,arg)` one after another,
  spaces in the name replaced by underscores, strings in single quotes
  (`Utils.generatePrettyRecipe`),
- the **input** is base64 of the raw bytes (CyberChef reads it back with
  `fromBase64(params.input, null, "byteArray")`),
- both are escaped with `Utils.encodeURIFragment`, which is `encodeURIComponent`
  with a specific set of characters put back as-is. `&`, `+` and `=` stay
  percent-encoded, which matters a lot for base64 input.

Checked against the real source rather than guessed, because a recipe with its
arguments in the wrong order still runs - and silently gives a wrong answer.

**Privacy**: the public instance (`https://gchq.github.io/CyberChef/`) receives
the data in the URL fragment. A fragment is not sent to the server by browsers,
but it does end up in history and in anything that logs URLs, so ctfc treats
building a public link as "sending data to a third party": it is refused when
`offline = true` (or `--offline`) and the UI shows a warning. The embedded copy
(`scripts/fetch_vendor.sh`) has none of these problems and is the default.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

# Characters `Utils.encodeURIFragment` puts back after encodeURIComponent.
# Note which ones are *absent*: & + = stay percent-encoded.
FRAGMENT_SAFE = "-._~!$'()*,;:/?@"
# What encodeURIComponent itself never escapes.
COMPONENT_SAFE = "-_.!~*'()"

PUBLIC_URL = "https://gchq.github.io/CyberChef/"
VERIFIED_AGAINST = "CyberChef v11.5.0"


def encode_uri_fragment(text: str) -> str:
    """Python equivalent of CyberChef's `Utils.encodeURIFragment`.

    `encodeURIComponent` leaves `-_.!~*'()` alone; CyberChef then un-escapes a few
    more (`$ , ; : / ?`). Everything else stays percent-encoded.
    """
    return quote(text, safe=COMPONENT_SAFE + FRAGMENT_SAFE)


def deep_link(recipe: str, data: bytes | None = None, base_url: str = PUBLIC_URL) -> str:
    """Build the URL that opens CyberChef with this recipe (and data) loaded."""
    if not base_url.endswith(("/", "html")):
        base_url += "/"
    parts = []
    if recipe:
        parts.append("recipe=" + encode_uri_fragment(recipe))
    if data:
        encoded = base64.b64encode(data).decode("ascii")
        parts.append("input=" + encode_uri_fragment(encoded))
    if not parts:
        return base_url
    return f"{base_url}#{'&'.join(parts)}"


def is_public(url: str) -> bool:
    """True when this URL would send the data to somebody else's server."""
    return (
        url.startswith(("http://", "https://"))
        and "127.0.0.1" not in url
        and ("localhost" not in url)
    )
