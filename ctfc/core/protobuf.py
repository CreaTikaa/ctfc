"""Decode a protobuf message without having its `.proto`.

The wire format is almost self-describing, which is why `protoc --decode_raw`
works at all. Every field is a varint *tag* followed by its value:

    tag = (field number << 3) | wire type

    wire type 0  a varint            an integer, a bool, an enum
              1  eight fixed bytes   a double or a 64-bit integer
              2  length-delimited    a string, some bytes, or a nested message
              5  four fixed bytes    a float or a 32-bit integer

What is *not* in the bytes is the field names and which of the overlapping
meanings each one has - a wire type 2 field is a string, a blob and a nested
message all at once as far as the encoding is concerned. So the output names
fields by number and guesses the reading: valid UTF-8 text is shown as a string,
bytes that parse completely as a message are shown nested, anything else as hex.
That is exactly what `--decode_raw` prints, and it is enough to find the field
holding a flag or a key.

The same self-describing quality is a hazard: short runs of arbitrary bytes parse
as protobuf by accident. So a buffer is only accepted when **every** byte is
consumed, field numbers are small, and the result has something readable in it -
see `looks_like_protobuf`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH = 2
WIRE_START_GROUP = 3  # deprecated, but still appears in old captures
WIRE_END_GROUP = 4
WIRE_32BIT = 5
VALID_WIRE_TYPES = (WIRE_VARINT, WIRE_64BIT, WIRE_LENGTH, WIRE_32BIT)
# A field number above this is legal but never seen in a real message, so it is
# the cheapest signal that we are not looking at protobuf at all.
MAX_FIELD_NUMBER = 2048
MAX_DEPTH = 12
MAX_FIELDS = 10_000
MIN_LENGTH = 4  # a buffer shorter than this proves nothing


class ProtobufError(Exception):
    """The bytes are not a protobuf message."""


def read_varint(data: bytes, position: int) -> tuple[int, int]:
    """A base-128 varint, little-endian groups of seven bits."""
    value = 0
    shift = 0
    for _ in range(10):  # a 64-bit varint is at most ten bytes
        if position >= len(data):
            raise ProtobufError("varint runs past the end")
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
    raise ProtobufError("varint longer than ten bytes")


@dataclass
class Field:
    """One decoded field."""

    number: int
    wire_type: int
    value: object  # int, bytes, str, or list[Field] for a nested message
    nested: list[Field] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if self.nested:
            return "message"
        if isinstance(self.value, str):
            return "string"
        if isinstance(self.value, bytes):
            return "bytes"
        return {WIRE_VARINT: "varint", WIRE_64BIT: "fixed64", WIRE_32BIT: "fixed32"}.get(
            self.wire_type, "?"
        )


def parse(data: bytes, depth: int = 0) -> list[Field]:
    """Decode a whole message. Raises unless every byte is accounted for."""
    if depth > MAX_DEPTH:
        raise ProtobufError("nested too deeply")
    fields: list[Field] = []
    position = 0
    while position < len(data):
        if len(fields) > MAX_FIELDS:
            raise ProtobufError("too many fields")
        tag, position = read_varint(data, position)
        number = tag >> 3
        wire_type = tag & 0x07
        if number == 0 or number > MAX_FIELD_NUMBER:
            raise ProtobufError(f"field number {number} is not plausible")
        if wire_type not in VALID_WIRE_TYPES:
            # Groups are deprecated and we do not follow them; refusing is
            # better than guessing where the group ends.
            raise ProtobufError(f"wire type {wire_type} is not supported")
        if wire_type == WIRE_VARINT:
            value, position = read_varint(data, position)
            fields.append(Field(number, wire_type, value))
        elif wire_type == WIRE_64BIT:
            if position + 8 > len(data):
                raise ProtobufError("truncated 64-bit field")
            fields.append(
                Field(number, wire_type, int.from_bytes(data[position : position + 8], "little"))
            )
            position += 8
        elif wire_type == WIRE_32BIT:
            if position + 4 > len(data):
                raise ProtobufError("truncated 32-bit field")
            fields.append(
                Field(number, wire_type, int.from_bytes(data[position : position + 4], "little"))
            )
            position += 4
        else:
            length, position = read_varint(data, position)
            if length > len(data) - position:
                raise ProtobufError("length-delimited field runs past the end")
            body = data[position : position + length]
            position += length
            fields.append(_length_field(number, body, depth))
    return fields


def _length_field(number: int, body: bytes, depth: int) -> Field:
    """A wire type 2 field: decide between text, a nested message, and bytes.

    Text is tried first, because a short string very often also parses as a
    message and reading `"hi"` as a nested field helps nobody. Only a body that
    is not plausible text is offered to the parser - and inside a message that
    has already been accepted, a complete parse is enough to call it nested.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text:
        printable = sum(1 for char in text if " " <= char < "\x7f" or char in "\t\n\r")
        if printable >= 0.9 * len(text):
            return Field(number, WIRE_LENGTH, text)
    if len(body) >= 2:
        try:
            nested = parse(body, depth + 1)
        except ProtobufError:
            nested = []
        if nested:
            return Field(number, WIRE_LENGTH, body, nested)
    return Field(number, WIRE_LENGTH, body)


def _readable(fields: list[Field]) -> bool:
    """Does this decode hold anything a person would call content?

    A nested message of one tiny varint is what arbitrary bytes decode to, so it
    is not enough on its own.
    """
    for item in fields:
        if isinstance(item.value, str) and len(item.value) >= 2:
            return True
        if item.nested:
            return True
    return len(fields) >= 2


def looks_like_protobuf(data: bytes) -> bool:
    """Is this worth presenting as a protobuf message?

    Strict on purpose: the format is loose enough that short arbitrary buffers
    decode by accident, so the whole buffer has to parse and the result has to
    contain something readable.
    """
    if len(data) < MIN_LENGTH:
        return False
    try:
        fields = parse(data)
    except ProtobufError:
        return False
    return bool(fields) and _readable(fields)


def render(fields: list[Field], indent: int = 0) -> str:
    """Print the message the way `protoc --decode_raw` does."""
    pad = "  " * indent
    lines: list[str] = []
    for item in fields:
        if item.nested:
            lines.append(f"{pad}{item.number} {{")
            lines.append(render(item.nested, indent + 1))
            lines.append(f"{pad}}}")
        elif isinstance(item.value, str):
            lines.append(f'{pad}{item.number}: "{item.value}"')
        elif isinstance(item.value, bytes):
            shown = item.value.hex()
            lines.append(f"{pad}{item.number}: {shown[:200]}{'...' if len(shown) > 200 else ''}")
        else:
            lines.append(f"{pad}{item.number}: {item.value}")
    return "\n".join(line for line in lines if line)


def decode_to_text(data: bytes) -> bytes:
    """The decoder entry point: a message in, its readable form out."""
    fields = parse(data)
    if not fields:
        raise ProtobufError("no field decoded")
    return render(fields).encode()
