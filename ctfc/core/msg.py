"""Read an Outlook `.msg` message: its headers, its body and its attachments.

A `.msg` is not a mail file in the usual sense - there is no `From:` line to
grep. It is an OLE2 compound file (the same container as a `.doc`, see
`core/cfb.py`) holding **MAPI properties**, one per stream, with the property
number written into the stream's name:

    __substg1.0_0037001F     subject, as UTF-16
    __substg1.0_1000001F     the plain-text body
    __substg1.0_007D001F     the transport headers, as the mail server wrote them
    __attach_version1.0_#00000000/__substg1.0_37010102   the first attachment

The name is `__substg1.0_` followed by eight hex digits: four for the property
tag and four for its type. `001F` is UTF-16 text, `001E` is 8-bit text, `0102`
is binary. That is the whole format, and it is why a `.msg` looks like noise to
`strings` - the body is UTF-16 and the names are hex.

What this gets you in a CTF: the real recipients, the full `Received:` chain
(which `core/mail.py` can then read), the body, and the attachments *as files* -
including the ones a mail gateway would have stripped from the `.eml` version.
Nothing is executed; attachments are handed back as bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core import cfb
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.magic import match_signature

SUBSTG = "__substg1.0_"
ATTACH_PREFIX = "__attach_version1.0_"
RECIPIENT_PREFIX = "__recip_version1.0_"
# The MAPI property tags worth naming. Everything else is reported by number.
PROPERTIES = {
    0x0037: "subject",
    0x0C1A: "sender name",
    0x0C1F: "sender address",
    0x0065: "sent representing address",
    0x0E04: "to",
    0x0E03: "cc",
    0x0E02: "bcc",
    0x1000: "body",
    0x1013: "body (HTML)",
    0x007D: "transport headers",
    0x0070: "conversation topic",
    0x0039: "sent at",
    0x3007: "created at",
    0x0C1E: "sender address type",
    0x001A: "message class",
    0x3001: "display name",
    0x3003: "email address",
    0x39FE: "SMTP address",
    0x3704: "attachment name (8.3)",
    0x3707: "attachment name",
    0x370E: "attachment MIME type",
    0x3701: "attachment data",
    0x3702: "attachment encoding",
}
# Property types, by the last four hex digits of the stream name.
TYPE_UNICODE = 0x001F
TYPE_ANSI = 0x001E
TYPE_BINARY = 0x0102
ATTACHMENT_DATA = 0x3701
ATTACHMENT_NAME = 0x3707
ATTACHMENT_SHORT_NAME = 0x3704
ATTACHMENT_MIME = 0x370E
FLAG_SEARCH_LIMIT = 4 << 20


class MsgError(FormatError):
    """The file is not an Outlook message we can read."""


@dataclass
class Attachment:
    """One attached file."""

    name: str
    data: bytes = b""
    mime: str = ""

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class MsgReport:
    """What the message says and carries."""

    headers: dict[str, str] = field(default_factory=dict)  # named properties, as text
    transport_headers: str = ""
    body: str = ""
    html_body: str = ""
    recipients: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    streams: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "headers": dict(self.headers),
            "transport_headers": self.transport_headers,
            "body": self.body,
            "html_body": self.html_body[:20000],
            "recipients": list(self.recipients),
            "attachments": [
                {"name": item.name, "size": item.size, "mime": item.mime}
                for item in self.attachments
            ],
            "flags": list(self.flags),
            "streams": list(self.streams),
            "notes": list(self.notes),
        }


def looks_like_msg(data: bytes) -> bool:
    """A compound file holding MAPI property streams is a .msg."""
    if not cfb.is_cfb(data):
        return False
    try:
        container = cfb.read(data)
    except cfb.CfbError:
        return False
    return is_msg_container(container)


def is_msg_container(container: cfb.CfbFile) -> bool:
    return any(name.startswith(SUBSTG) for name in container.streams)


def _property_of(name: str) -> tuple[int, int] | None:
    """The (tag, type) pair encoded in a `__substg1.0_XXXXYYYY` stream name."""
    leaf = name.rsplit("/", 1)[-1]
    if not leaf.startswith(SUBSTG):
        return None
    digits = leaf[len(SUBSTG) : len(SUBSTG) + 8]
    if len(digits) < 8:
        return None
    try:
        return int(digits[:4], 16), int(digits[4:], 16)
    except ValueError:
        return None


def _as_text(payload: bytes, kind: int) -> str:
    """A property's bytes as text, which means knowing its type: 001F is UTF-16."""
    if kind == TYPE_UNICODE:
        return payload.decode("utf-16-le", "replace").rstrip("\x00")
    return payload.decode("cp1252", "replace").rstrip("\x00")


def analyse(data: bytes, flagset: FlagSet | None = None) -> MsgReport:
    """Read the message, its recipients and its attachments."""
    if not cfb.is_cfb(data):
        raise MsgError(
            "not an Outlook message: a .msg is an OLE2 compound file and this does "
            "not start with d0cf11e0. An .eml is plain text - open it directly"
        )
    try:
        container = cfb.read(data)
    except cfb.CfbError as exc:
        raise MsgError(f"not a readable compound file: {exc}") from exc
    if not is_msg_container(container):
        raise MsgError(
            "this is a compound file but holds no MAPI property stream "
            "(__substg1.0_...): it is probably a .doc or .xls - try `ctfc office`"
        )

    report = MsgReport(streams=sorted(container.streams))
    attachments: dict[str, dict] = {}
    recipients: dict[str, dict] = {}

    for path, payload in container.streams.items():
        parsed = _property_of(path)
        if parsed is None:
            continue
        tag, kind = parsed
        storage = path.rsplit("/", 1)[0] if "/" in path else ""
        bucket: dict | None = None
        if storage.startswith(ATTACH_PREFIX):
            bucket = attachments.setdefault(storage, {})
        elif storage.startswith(RECIPIENT_PREFIX):
            bucket = recipients.setdefault(storage, {})

        if bucket is not None:
            bucket[tag] = payload if kind == TYPE_BINARY else _as_text(payload, kind)
            continue
        if tag == 0x1000:
            report.body = _as_text(payload, kind)
        elif tag == 0x1013:
            report.html_body = _as_text(payload, kind)
        elif tag == 0x007D:
            report.transport_headers = _as_text(payload, kind)
        elif tag in PROPERTIES and kind in (TYPE_UNICODE, TYPE_ANSI):
            report.headers[PROPERTIES[tag]] = _as_text(payload, kind)

    for storage in sorted(recipients):
        values = recipients[storage]
        name = values.get(0x3001, "")
        address = values.get(0x39FE) or values.get(0x3003, "")
        joined = f"{name} <{address}>" if name and address else (name or address)
        if isinstance(joined, str) and joined:
            report.recipients.append(joined)

    for storage in sorted(attachments):
        values = attachments[storage]
        payload = values.get(ATTACHMENT_DATA, b"")
        name = values.get(ATTACHMENT_NAME) or values.get(ATTACHMENT_SHORT_NAME) or storage
        if isinstance(payload, bytes):
            report.attachments.append(
                Attachment(
                    name=str(name),
                    data=payload,
                    mime=str(values.get(ATTACHMENT_MIME, "")),
                )
            )
        else:
            report.notes.append(f"{storage}: the attachment data is not a binary property")

    _add_notes(report, flagset)
    return report


def _add_notes(report: MsgReport, flagset: FlagSet | None) -> None:
    """Flags, and the two observations worth making about a message."""
    found: list[str] = []
    for text in (report.body, report.html_body, report.transport_headers):
        if text:
            found += [hit.text for hit in find_flags(text.encode("utf-8", "replace"), flagset)]
    for value in report.headers.values():
        found += [hit.text for hit in find_flags(value.encode("utf-8", "replace"), flagset)]
    for attachment in report.attachments:
        if attachment.size <= FLAG_SEARCH_LIMIT:
            found += [hit.text for hit in find_flags(attachment.data, flagset)]
    seen: list[str] = []
    for text in found:
        if text not in seen:
            seen.append(text)
    report.flags = seen

    if report.transport_headers:
        report.notes.append(
            "the transport headers are the ones the mail servers wrote: the Received "
            "chain reads bottom-up, oldest hop last"
        )
    if report.attachments:
        report.notes.append(
            f"{len(report.attachments)} attachment(s): --extract writes them out, then "
            "`ctfc scan` that folder"
        )
        # An attachment that is itself a container hides its content from the
        # flag search above - the bytes are compressed. Name the file type so
        # the next command is obvious instead of the flag silently not showing.
        for attachment in report.attachments:
            signature = match_signature(attachment.data)
            if signature is None:
                continue
            command = {
                "zip": "ctfc zip",
                "7z": "ctfc archive",
                "rar": "ctfc archive",
                "cab": "ctfc archive",
                "tar": "ctfc archive",
                "pdf": "ctfc pdf",
                "doc": "ctfc office",
                "png": "ctfc stego",
            }.get(signature.ext, "ctfc detect")
            report.notes.append(
                f"{attachment.name} is a {signature.name}: its content is not searched "
                f"here (it is compressed) - extract it and run `{command}` on it"
            )
    elif not report.body:
        report.notes.append(
            "no body and no attachment: the message may carry its content in the RTF "
            "property (0x1009), which Outlook compresses and ctfc does not decode"
        )
