"""Pull e-mails and their attachments out of a captured TCP stream.

The shape this exists for: a capture of someone reading their mail (IMAP), or of
a server receiving it (SMTP), where the challenge is hidden in the message - the
password of an attached ZIP written in the HTML body, a double-extension
`report.pdf.exe`, a base64 blob at the end of the signature. Wireshark will show
you the stream; turning it back into "here is the subject, here are the files"
is the part that costs time.

Three things have to happen:

1. **Find where a message starts and stops** inside the stream. Mail protocols
   frame it differently:

       IMAP   * 1 FETCH (BODY[] {2048}      <- the {N} literal gives the exact size
       SMTP   DATA ... the message ... \r\n.\r\n
       POP3   +OK ... the message ... \r\n.\r\n

2. **Parse the MIME tree**, which the standard library's `email` package does
   properly - including the boundary juggling of a multipart/mixed message with
   an HTML body and two attachments.

3. **Decode each part**, since an attachment is base64 (or quoted-printable) in
   transit. `get_payload(decode=True)` undoes that.

Nothing here executes anything: `email` is a parser. An attachment is returned as
bytes for `ctfc detect` / `ctfc scan` to look at - it is never written or opened.
"""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message

# A header line that only ever appears at the top of a real message. Used to find
# the start of a message when the protocol framing did not give it away.
HEADER_START = re.compile(
    rb"^(?:Return-Path|Received|Message-ID|From|Subject|Date|MIME-Version|To):",
    re.IGNORECASE | re.MULTILINE,
)
# An IMAP literal: the server announces the exact byte count that follows.
IMAP_LITERAL = re.compile(rb"\{(\d{1,9})\}\r?\n")
# The end of a DATA / RETR transfer: a lone dot on its own line.
DOT_TERMINATOR = b"\r\n.\r\n"
MAX_MESSAGE = 8 * 1024 * 1024  # a single message we are willing to parse
# The headers worth showing without being asked.
INTERESTING_HEADERS = ("From", "To", "Cc", "Subject", "Date")


@dataclass
class Attachment:
    """One decoded MIME part."""

    filename: str
    content_type: str
    data: bytes
    is_body: bool = False  # True for the message text itself, not a file


@dataclass
class Mail:
    """One message found in the stream, already decoded."""

    headers: dict[str, str] = field(default_factory=dict)
    parts: list[Attachment] = field(default_factory=list)

    @property
    def subject(self) -> str:
        return self.headers.get("Subject", "")


def find_messages(stream: bytes) -> list[bytes]:
    """Cut the raw TCP stream into candidate RFC 822 messages.

    The IMAP literal is trusted first because it states the length exactly; then
    the dot-terminated forms of SMTP/POP3; failing both, a header block is taken
    to the end of the stream. Overlapping candidates are avoided by always moving
    past the message that was just taken.
    """
    messages: list[bytes] = []
    position = 0
    while position < len(stream):
        literal = IMAP_LITERAL.search(stream, position)
        header = HEADER_START.search(stream, position)
        # Whichever framing comes first decides how this message is cut.
        if literal is not None and (header is None or literal.end() <= header.start()):
            size = min(int(literal.group(1)), MAX_MESSAGE)
            start = literal.end()
            candidate = stream[start : start + size]
            position = start + size
            if HEADER_START.search(candidate):
                messages.append(candidate)
            continue
        if header is None:
            break
        start = _line_start(stream, header.start())
        end = stream.find(DOT_TERMINATOR, start)
        if end == -1:
            candidate = stream[start : start + MAX_MESSAGE]
            position = len(stream)
        else:
            candidate = stream[start:end]
            position = end + len(DOT_TERMINATOR)
        messages.append(candidate)
    return [message for message in messages if len(message) > 16]


def _line_start(data: bytes, offset: int) -> int:
    """Back up to the beginning of the line `offset` is on."""
    newline = data.rfind(b"\n", 0, offset)
    return 0 if newline == -1 else newline + 1


def parse_message(raw: bytes) -> Mail | None:
    """Parse one message and decode every part, or None if it is not a message."""
    try:
        # policy.default also un-wraps RFC 2047 encoded headers ("=?utf-8?B?...?=").
        message = email.message_from_bytes(raw, policy=policy.default)
    except Exception:  # noqa: BLE001 - a truncated capture produces every kind of error
        try:
            message = email.message_from_bytes(raw)
        except Exception:  # noqa: BLE001
            return None
    headers = {}
    for name in INTERESTING_HEADERS:
        try:
            value = message.get(name)
        except Exception:  # noqa: BLE001 - a malformed header can raise on access
            value = None
        if value:
            headers[name] = str(value).strip()[:300]
    if not headers:
        return None
    mail = Mail(headers=headers)
    for part in _walk(message):
        mail.parts.append(part)
    return mail if mail.parts or mail.headers else None


def _walk(message: Message) -> list[Attachment]:
    """Every leaf part of the MIME tree, decoded."""
    parts: list[Attachment] = []
    try:
        leaves = [part for part in message.walk() if part.get_content_maintype() != "multipart"]
    except Exception:  # noqa: BLE001
        return parts
    for part in leaves:
        try:
            data = part.get_payload(decode=True)
            content_type = part.get_content_type()
            filename = part.get_filename() or ""
        except Exception:  # noqa: BLE001 - broken base64 in a cut stream
            continue
        if not data:
            continue
        is_body = not filename and content_type.startswith("text/")
        parts.append(
            Attachment(
                filename=str(filename)[:120],
                content_type=content_type,
                data=data,
                is_body=is_body,
            )
        )
    return parts


def extract(stream: bytes) -> list[Mail]:
    """Every message, with its parts decoded, found in one reassembled stream."""
    mails = []
    for raw in find_messages(stream):
        mail = parse_message(raw)
        if mail is not None and mail.parts:
            mails.append(mail)
    return mails
